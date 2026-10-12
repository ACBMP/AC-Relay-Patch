#include "ipv6.h"
#include "logger.h"

#include <WS2tcpip.h>
#include <Windows.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <format>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace ac_relay::ipv6
{
    namespace
    {
        constexpr std::uint8_t kMagic[4] = {0x41, 0x43, 0x56, 0x36}; // "ACV6"
        constexpr std::size_t kMaxDatagram = 2048;
        constexpr std::size_t kMaxPeers = 4096;
        constexpr std::uint64_t kStatsIntervalMs = 60'000;

        // OS source-address selection for this destination decides our
        // published address (connect() on UDP sends nothing).
        constexpr const char* kProbeDestination = "2001:4860:4860::8888";

        struct Endpoint
        {
            in6_addr addr{};
            std::uint16_t port = 0; // host order
        };

        std::atomic<bool> s_active{false};
        std::atomic<bool> s_stop{false};

        SOCKET s_v6 = INVALID_SOCKET;  // AF_INET6, bound to our published address
        SOCKET s_gw = INVALID_SOCKET;  // AF_INET, 127.0.0.1:ephemeral
        sockaddr_in s_gw_addr{};       // network order
        Endpoint s_self{};
        std::uint32_t s_self_vaddr = 0; // host order
        std::uint8_t s_token[8]{};

        std::mutex s_mu;
        sockaddr_in s_game_dest{}; // where peer->game frames go (network order)
        std::unordered_map<std::uint32_t, Endpoint> s_map; // vaddr (host order) -> endpoint
        std::unordered_set<std::uint32_t> s_unknown_logged;

        // Prefer: hide the IPv4 addresses of stations that have an IPv6 URL.
        // All URLs of one station carry its RVCID (ObjDupProtocol::AddLocalURLs
        // stamps every one), which is what ties a v4 URL to the v6 one.
        constexpr std::uint64_t kV6SilentMs = 5'000; // sending this long unanswered = v6 path dead
        struct PathTimes
        {
            std::uint64_t first_send = 0, last_send = 0, last_recv = 0; // ms
        };
        bool s_prefer = false;
        std::unordered_map<std::uint32_t, std::uint32_t> s_rvcid_v6;  // RVCID -> vaddr
        std::unordered_map<std::uint64_t, std::uint32_t> s_v4_rvcid;  // v4 addr:port key -> RVCID
        std::unordered_map<std::uint32_t, PathTimes> s_times;         // vaddr -> traffic times
        std::unordered_set<std::uint64_t> s_hidden_logged;
        std::unordered_set<std::uint32_t> s_dead_logged;              // vaddr

        [[nodiscard]] std::uint64_t v4_key(std::uint32_t ip, std::uint16_t port) // host order
        {
            return (static_cast<std::uint64_t>(ip) << 16) | port;
        }

        // Sending for kV6SilentMs without an answer. Caller holds s_mu.
        [[nodiscard]] bool v6_dead_locked(std::uint32_t vaddr)
        {
            const auto it = s_times.find(vaddr);
            if (it == s_times.end() || it->second.first_send == 0)
                return false;
            const PathTimes& t = it->second;
            const std::uint64_t base = t.last_recv ? t.last_recv : t.first_send;
            return t.last_send > base + kV6SilentMs;
        }

        std::atomic<std::uint64_t> s_in_pkts{0}, s_in_bytes{0}, s_out_pkts{0}, s_out_bytes{0};
        std::atomic<std::uint64_t> s_dropped_unknown{0}, s_dropped_bad_frame{0}, s_send_fail{0};

        void put_u16(std::uint8_t* p, std::uint16_t v)
        {
            p[0] = static_cast<std::uint8_t>(v >> 8);
            p[1] = static_cast<std::uint8_t>(v);
        }

        void put_u32(std::uint8_t* p, std::uint32_t v)
        {
            p[0] = static_cast<std::uint8_t>(v >> 24);
            p[1] = static_cast<std::uint8_t>(v >> 16);
            p[2] = static_cast<std::uint8_t>(v >> 8);
            p[3] = static_cast<std::uint8_t>(v);
        }

        [[nodiscard]] std::uint16_t get_u16(const std::uint8_t* p)
        {
            return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
        }

        [[nodiscard]] std::uint32_t get_u32(const std::uint8_t* p)
        {
            return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
                   (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
        }

        // 240.0.0.0/4 | FNV-1a(addr, port) -- must be identical on every
        // client, it is what the address= of a v6 URL says.
        [[nodiscard]] std::uint32_t virtual_ip(const in6_addr& a, std::uint16_t port)
        {
            std::uint32_t h = 2166136261u;
            const auto* b = reinterpret_cast<const std::uint8_t*>(&a);
            for (int i = 0; i < 16; ++i)
                h = (h ^ b[i]) * 16777619u;
            h = (h ^ static_cast<std::uint8_t>(port >> 8)) * 16777619u;
            h = (h ^ static_cast<std::uint8_t>(port)) * 16777619u;
            std::uint32_t v = 0xF0000000u | (h & 0x0FFFFFFFu);
            if (v == 0xFFFFFFFFu) // limited broadcast, the game special-cases it
                v = 0xFFFFFFFEu;
            return v;
        }

        [[nodiscard]] std::string ip4_text(std::uint32_t ip)
        {
            return std::format("{}.{}.{}.{}", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
        }

        [[nodiscard]] std::string ip6_text(const in6_addr& a)
        {
            char s[INET6_ADDRSTRLEN] = {};
            inet_ntop(AF_INET6, const_cast<in6_addr*>(&a), s, sizeof(s));
            return s;
        }

        [[nodiscard]] std::string endpoint_text(const Endpoint& e)
        {
            return std::format("[{}]:{}", ip6_text(e.addr), e.port);
        }

        [[nodiscard]] std::string hex_text(const in6_addr& a)
        {
            std::string s;
            const auto* b = reinterpret_cast<const std::uint8_t*>(&a);
            for (int i = 0; i < 16; ++i)
                s += std::format("{:02x}", b[i]);
            return s;
        }

        [[nodiscard]] bool parse_hex(std::string_view text, in6_addr& out)
        {
            if (text.size() != 32)
                return false;
            auto* b = reinterpret_cast<std::uint8_t*>(&out);
            for (int i = 0; i < 16; ++i)
            {
                unsigned v = 0;
                for (int j = 0; j < 2; ++j)
                {
                    const char c = text[2 * i + j];
                    v <<= 4;
                    if (c >= '0' && c <= '9')
                        v |= c - '0';
                    else if (c >= 'a' && c <= 'f')
                        v |= c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F')
                        v |= c - 'A' + 10;
                    else
                        return false;
                }
                b[i] = static_cast<std::uint8_t>(v);
            }
            return true;
        }

        [[nodiscard]] bool parse_ip4(std::string_view text, std::uint32_t& out)
        {
            unsigned a, b, c, d;
            char tail;
            if (std::sscanf(std::string(text).c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4 || a > 255 ||
                b > 255 || c > 255 || d > 255)
                return false;
            out = (a << 24) | (b << 16) | (c << 8) | d;
            return true;
        }

        // Value of key in "scheme:/k=v;k=v#k=v", or empty.
        [[nodiscard]] std::string_view url_param(std::string_view url, std::string_view key)
        {
            const auto body = url.find(":/");
            if (body == std::string_view::npos)
                return {};
            url.remove_prefix(body + 2);
            while (!url.empty())
            {
                const auto end = url.find_first_of(";#");
                const std::string_view item = url.substr(0, end);
                const auto eq = item.find('=');
                if (eq != std::string_view::npos && item.substr(0, eq) == key)
                    return item.substr(eq + 1);
                if (end == std::string_view::npos)
                    break;
                url.remove_prefix(end + 1);
            }
            return {};
        }

        [[nodiscard]] bool is_global(const in6_addr& a)
        {
            return (reinterpret_cast<const std::uint8_t*>(&a)[0] & 0xe0) == 0x20; // 2000::/3
        }

        [[nodiscard]] bool pick_source(in6_addr& out)
        {
            const SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (s == INVALID_SOCKET)
                return false;
            sockaddr_in6 dst{};
            dst.sin6_family = AF_INET6;
            dst.sin6_port = htons(53);
            inet_pton(AF_INET6, kProbeDestination, &dst.sin6_addr);
            bool ok = false;
            if (connect(s, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst)) == 0)
            {
                sockaddr_in6 me{};
                int len = sizeof(me);
                if (getsockname(s, reinterpret_cast<sockaddr*>(&me), &len) == 0 && is_global(me.sin6_addr))
                {
                    out = me.sin6_addr;
                    ok = true;
                }
            }
            closesocket(s);
            return ok;
        }

        // Records vaddr -> ep. Caller holds s_mu.
        void remember_locked(std::uint32_t vaddr, const Endpoint& ep, const char* source)
        {
            auto it = s_map.find(vaddr);
            if (it != s_map.end())
            {
                if (std::memcmp(&it->second.addr, &ep.addr, sizeof(in6_addr)) != 0 || it->second.port != ep.port)
                {
                    logger::warn(std::format("ipv6: virtual address {} collision: {} replaces {}", ip4_text(vaddr),
                                             endpoint_text(ep), endpoint_text(it->second)));
                    it->second = ep;
                }
                return;
            }
            if (s_map.size() >= kMaxPeers)
                return;
            s_map.emplace(vaddr, ep);
            logger::info(std::format("ipv6: peer {} is {} (from {})", endpoint_text(ep), ip4_text(vaddr), source));
        }

        void log_stats()
        {
            std::size_t peers = 0;
            {
                std::lock_guard lock(s_mu);
                peers = s_map.size();
            }
            logger::info(std::format("ipv6 stats: known peers={} in={} pkts/{} B out={} pkts/{} B "
                                     "dropped: unknown vaddr={} bad frame={} send failures={}",
                                     peers, s_in_pkts.load(), s_in_bytes.load(), s_out_pkts.load(), s_out_bytes.load(),
                                     s_dropped_unknown.load(), s_dropped_bad_frame.load(), s_send_fail.load()));
        }

        // game -> peer: a frame from the SendTo hook arrived on the gateway.
        void forward_to_peer(const std::uint8_t* data, std::size_t len)
        {
            if (len <= kFrameOverhead || std::memcmp(data, kMagic, 4) != 0 || data[4] != kKindToPeer ||
                std::memcmp(data + 12, s_token, sizeof(s_token)) != 0)
            {
                ++s_dropped_bad_frame;
                return; // also the sink for sends the hooks drop on purpose
            }
            const std::uint32_t vaddr = get_u32(data + 6);
            const std::uint16_t port = get_u16(data + 10);

            Endpoint ep;
            {
                std::lock_guard lock(s_mu);
                const auto it = s_map.find(vaddr);
                if (it == s_map.end())
                {
                    ++s_dropped_unknown;
                    if (s_unknown_logged.insert(vaddr).second && s_unknown_logged.size() < kMaxPeers)
                        logger::warn(std::format("ipv6: game sent to {}:{}, but no URL with that v6 address was "
                                                 "seen; dropped",
                                                 ip4_text(vaddr), port));
                    return;
                }
                ep = it->second;
                PathTimes& t = s_times[vaddr];
                t.last_send = GetTickCount64();
                if (t.first_send == 0)
                    t.first_send = t.last_send;
            }

            sockaddr_in6 to{};
            to.sin6_family = AF_INET6;
            to.sin6_addr = ep.addr;
            to.sin6_port = htons(port); // the game's port; equals ep.port for URL-learned peers
            const int n = static_cast<int>(len - kFrameOverhead);
            if (sendto(s_v6, reinterpret_cast<const char*>(data + kFrameOverhead), n, 0,
                       reinterpret_cast<const sockaddr*>(&to), sizeof(to)) != n)
            {
                ++s_send_fail;
                if (logger::verbose())
                    logger::debug(std::format("ipv6: sendto {} failed, wsa error {}", endpoint_text(ep),
                                              WSAGetLastError()));
                return;
            }
            ++s_out_pkts;
            s_out_bytes += n;
            if (logger::verbose())
                logger::debug(std::format("ipv6: {} B to {} ({})", n, endpoint_text(ep), ip4_text(vaddr)));
        }

        // peer -> game: a datagram arrived on the IPv6 socket.
        void forward_to_game(const std::uint8_t* data, std::size_t len, const sockaddr_in6& from)
        {
            if (len == 0 || len + kFrameOverhead > kMaxDatagram)
                return;
            Endpoint ep;
            ep.addr = from.sin6_addr;
            ep.port = ntohs(from.sin6_port);
            const std::uint32_t vaddr = virtual_ip(ep.addr, ep.port);

            sockaddr_in dest{};
            {
                std::lock_guard lock(s_mu);
                remember_locked(vaddr, ep, "incoming traffic");
                s_times[vaddr].last_recv = GetTickCount64();
                dest = s_game_dest;
            }
            if (dest.sin_port == 0)
                return; // game socket not known yet

            std::uint8_t frame[kMaxDatagram];
            std::memcpy(frame, kMagic, 4);
            frame[4] = kKindToGame;
            frame[5] = 0;
            put_u32(frame + 6, vaddr);
            put_u16(frame + 10, ep.port);
            std::memcpy(frame + 12, s_token, sizeof(s_token));
            std::memcpy(frame + kFrameOverhead, data, len);
            const int n = static_cast<int>(len + kFrameOverhead);
            if (sendto(s_gw, reinterpret_cast<const char*>(frame), n, 0, reinterpret_cast<const sockaddr*>(&dest),
                       sizeof(dest)) != n)
            {
                ++s_send_fail;
                return;
            }
            ++s_in_pkts;
            s_in_bytes += len;
            if (logger::verbose())
                logger::debug(std::format("ipv6: {} B from {} ({})", len, endpoint_text(ep), ip4_text(vaddr)));
        }

        void worker()
        {
            std::uint8_t buf[kMaxDatagram];
            std::uint64_t next_stats = GetTickCount64() + kStatsIntervalMs;

            while (!s_stop.load())
            {
                fd_set rd;
                FD_ZERO(&rd);
                FD_SET(s_v6, &rd);
                FD_SET(s_gw, &rd);
                timeval tv{0, 250'000};
                const int r = select(0, &rd, nullptr, nullptr, &tv);
                if (r == SOCKET_ERROR)
                {
                    Sleep(50);
                    continue;
                }

                if (r > 0 && FD_ISSET(s_v6, &rd))
                {
                    sockaddr_in6 from{};
                    int fl = sizeof(from);
                    const int n = recvfrom(s_v6, reinterpret_cast<char*>(buf), sizeof(buf) - kFrameOverhead, 0,
                                           reinterpret_cast<sockaddr*>(&from), &fl);
                    if (n > 0 && from.sin6_family == AF_INET6)
                        forward_to_game(buf, static_cast<std::size_t>(n), from);
                }
                if (r > 0 && FD_ISSET(s_gw, &rd))
                {
                    sockaddr_in from{};
                    int fl = sizeof(from);
                    const int n = recvfrom(s_gw, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                                           reinterpret_cast<sockaddr*>(&from), &fl);
                    if (n > 0)
                        forward_to_peer(buf, static_cast<std::size_t>(n));
                }

                if (const std::uint64_t now = GetTickCount64(); now >= next_stats)
                {
                    next_stats = now + kStatsIntervalMs;
                    log_stats();
                }
            }
        }
    }

    auto initialize(const config::ipv6_settings& settings) -> bool
    {
        if (!settings.enabled)
        {
            logger::info("ipv6: [IPv6] Enabled=false");
            return false;
        }

        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        {
            logger::error("ipv6: WSAStartup failed");
            return false;
        }

        in6_addr src{};
        if (!pick_source(src))
        {
            logger::info("ipv6: no global IPv6 address/route on this PC; IPv6 path off");
            return false;
        }

        s_v6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        s_gw = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s_v6 == INVALID_SOCKET || s_gw == INVALID_SOCKET)
        {
            logger::error(std::format("ipv6: socket() failed, wsa error {}", WSAGetLastError()));
            return false;
        }

        // Bound to the published address, not ::, so every datagram leaves
        // from it and peers derive the same virtual address for us.
        sockaddr_in6 bind6{};
        bind6.sin6_family = AF_INET6;
        bind6.sin6_addr = src;
        bind6.sin6_port = htons(static_cast<std::uint16_t>(settings.port));
        if (bind(s_v6, reinterpret_cast<const sockaddr*>(&bind6), sizeof(bind6)) != 0)
        {
            if (settings.port == 0)
            {
                logger::error(std::format("ipv6: bind [{}]:0 failed, wsa error {}", ip6_text(src), WSAGetLastError()));
                return false;
            }
            logger::warn(std::format("ipv6: port {} busy (wsa error {}), using a random one", settings.port,
                                     WSAGetLastError()));
            bind6.sin6_port = 0;
            if (bind(s_v6, reinterpret_cast<const sockaddr*>(&bind6), sizeof(bind6)) != 0)
            {
                logger::error(std::format("ipv6: bind failed, wsa error {}", WSAGetLastError()));
                return false;
            }
        }
        int len = sizeof(bind6);
        getsockname(s_v6, reinterpret_cast<sockaddr*>(&bind6), &len);

        sockaddr_in gw{};
        gw.sin_family = AF_INET;
        gw.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(s_gw, reinterpret_cast<const sockaddr*>(&gw), sizeof(gw)) != 0)
        {
            logger::error(std::format("ipv6: gateway bind failed, wsa error {}", WSAGetLastError()));
            return false;
        }
        len = sizeof(gw);
        getsockname(s_gw, reinterpret_cast<sockaddr*>(&gw), &len);

        // generous receive buffers: a burst must not overflow while the worker is busy
        int rcvbuf = 1 << 20;
        setsockopt(s_v6, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
        setsockopt(s_gw, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));

        s_gw_addr = gw;
        s_self.addr = src;
        s_self.port = ntohs(bind6.sin6_port);
        s_self_vaddr = virtual_ip(s_self.addr, s_self.port);

        const std::uint64_t seed = GetTickCount64() ^ (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32) ^
                                   reinterpret_cast<std::uintptr_t>(&seed);
        std::uint64_t x = seed | 1;
        for (auto& b : s_token)
        {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b = static_cast<std::uint8_t>(x >> 24);
        }

        logger::info(std::format("ipv6: listening on {} = virtual {}, gateway 127.0.0.1:{}", endpoint_text(s_self),
                                 ip4_text(s_self_vaddr), ntohs(gw.sin_port)));

        s_prefer = settings.prefer;
        if (s_prefer)
            logger::info("ipv6: Prefer=true: peers with an IPv6 URL are reached over IPv6 only "
                         "(their IPv4 comes back if IPv6 stays unanswered for 5 s)");
        s_stop = false;
        s_active = true;
        std::thread(worker).detach();
        return true;
    }

    auto shutdown() -> void
    {
        // DLL_PROCESS_DETACH: no joins (loader lock); the worker exits on its own
        s_stop = true;
        s_active = false;
    }

    auto active() -> bool
    {
        return s_active.load();
    }

    auto set_game_socket(SOCKET s) -> void
    {
        if (!s_active.load())
            return;
        sockaddr_in local{};
        int len = sizeof(local);
        if (getsockname(s, reinterpret_cast<sockaddr*>(&local), &len) != 0 || local.sin_family != AF_INET)
            return;
        if (local.sin_addr.s_addr == htonl(INADDR_ANY))
            local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        std::lock_guard lock(s_mu);
        s_game_dest = local;
        logger::info(std::format("ipv6: frames for the game go to {}:{}", ip4_text(ntohl(local.sin_addr.s_addr)),
                                 ntohs(local.sin_port)));
    }

    auto is_virtual(const sockaddr_in& addr) -> bool
    {
        return (ntohl(addr.sin_addr.s_addr) & 0xF0000000u) == 0xF0000000u &&
               addr.sin_addr.s_addr != 0xFFFFFFFFu;
    }

    auto gateway_address() -> sockaddr_in
    {
        return s_gw_addr; // written once in initialize() before any hook is installed
    }

    auto is_gateway_address(const sockaddr_in& addr) -> bool
    {
        return s_active.load() && addr.sin_addr.s_addr == s_gw_addr.sin_addr.s_addr &&
               addr.sin_port == s_gw_addr.sin_port;
    }

    auto encode_to_peer(std::uint8_t* out, const sockaddr_in& dest) -> void
    {
        std::memcpy(out, kMagic, 4);
        out[4] = kKindToPeer;
        out[5] = 0;
        put_u32(out + 6, ntohl(dest.sin_addr.s_addr));
        put_u16(out + 10, ntohs(dest.sin_port));
        std::memcpy(out + 12, s_token, sizeof(s_token));
    }

    auto decode_to_game(const std::uint8_t* data, std::size_t len, sockaddr_in& peer) -> bool
    {
        if (len <= kFrameOverhead || std::memcmp(data, kMagic, 4) != 0 || data[4] != kKindToGame ||
            std::memcmp(data + 12, s_token, sizeof(s_token)) != 0)
            return false;
        peer = {};
        peer.sin_family = AF_INET;
        peer.sin_addr.s_addr = htonl(get_u32(data + 6));
        peer.sin_port = htons(get_u16(data + 10));
        return true;
    }

    auto local_url(std::string& url, std::string& vaddr_text, std::uint16_t& port) -> bool
    {
        if (!s_active.load())
            return false;
        vaddr_text = ip4_text(s_self_vaddr);
        port = s_self.port;
        url = std::format("prudp:/address={};port={};v6={}", vaddr_text, port, hex_text(s_self.addr));
        return true;
    }

    auto learn_url(const char* url) -> void
    {
        if (!url || !s_active.load())
            return;
        const std::string_view text(url);
        const auto v6 = std::strstr(url, "v6=") ? url_param(text, "v6") : std::string_view{};

        // Prefer: remember which station each IPv4 URL belongs to
        unsigned rvcid = 0;
        if (s_prefer)
            if (const auto r = url_param(text, "RVCID"); !r.empty())
                std::sscanf(std::string(r).c_str(), "%u", &rvcid);
        if (v6.empty())
        {
            std::uint32_t ip = 0;
            unsigned p = 0;
            if (rvcid != 0 && parse_ip4(url_param(text, "address"), ip) &&
                std::sscanf(std::string(url_param(text, "port")).c_str(), "%u", &p) == 1 && p != 0 && p <= 0xffff)
            {
                std::lock_guard lock(s_mu);
                if (s_v4_rvcid.size() < kMaxPeers * 4)
                    s_v4_rvcid[v4_key(ip, static_cast<std::uint16_t>(p))] = rvcid;
            }
            return;
        }

        Endpoint ep;
        std::uint32_t claimed = 0;
        unsigned port = 0;
        const auto port_text = url_param(text, "port");
        if (!parse_hex(v6, ep.addr) || !parse_ip4(url_param(text, "address"), claimed) ||
            std::sscanf(std::string(port_text).c_str(), "%u", &port) != 1 || port == 0 || port > 0xffff)
            return;
        ep.port = static_cast<std::uint16_t>(port);

        const std::uint32_t vaddr = virtual_ip(ep.addr, ep.port);
        std::lock_guard lock(s_mu);
        if (vaddr != claimed)
        {
            if (s_unknown_logged.insert(claimed).second && s_unknown_logged.size() < kMaxPeers)
                logger::warn(std::format("ipv6: URL '{}' claims {} but its v6 endpoint hashes to {}; ignored", text,
                                         ip4_text(claimed), ip4_text(vaddr)));
            return;
        }
        remember_locked(vaddr, ep, "station URL");
        const bool self = std::memcmp(&ep.addr, &s_self.addr, sizeof(in6_addr)) == 0 && ep.port == s_self.port;
        if (s_prefer && rvcid != 0 && !self && s_rvcid_v6.size() < kMaxPeers)
            s_rvcid_v6[rvcid] = vaddr;
    }

    auto note_probe_sender(const sockaddr_in& addr, std::uint32_t rvcid) -> void
    {
        if (!s_prefer || !s_active.load() || rvcid == 0 || is_virtual(addr))
            return;
        std::lock_guard lock(s_mu);
        if (s_v4_rvcid.size() < kMaxPeers * 4)
            s_v4_rvcid[v4_key(ntohl(addr.sin_addr.s_addr), ntohs(addr.sin_port))] = rvcid;
    }

    auto hide_ipv4(const sockaddr_in& addr, const char* direction) -> bool
    {
        if (!s_prefer || !s_active.load() || is_virtual(addr))
            return false;
        const std::uint64_t key = v4_key(ntohl(addr.sin_addr.s_addr), ntohs(addr.sin_port));
        std::lock_guard lock(s_mu);
        const auto r = s_v4_rvcid.find(key);
        if (r == s_v4_rvcid.end())
            return false;
        const auto v = s_rvcid_v6.find(r->second);
        if (v == s_rvcid_v6.end())
            return false;
        if (v6_dead_locked(v->second))
        {
            if (s_dead_logged.insert(v->second).second)
                logger::warn(std::format("ipv6: no answer from {} over IPv6 for {} s; allowing station RVCID {}'s "
                                         "IPv4 addresses again",
                                         ip4_text(v->second), kV6SilentMs / 1000, r->second));
            return false;
        }
        if (s_hidden_logged.insert(key).second && s_hidden_logged.size() < kMaxPeers)
            logger::info(std::format("ipv6: Prefer: station RVCID {} has IPv6 ({}); dropping traffic {} its IPv4 "
                                     "address {}:{}",
                                     r->second, ip4_text(v->second), direction, ip4_text(ntohl(addr.sin_addr.s_addr)),
                                     ntohs(addr.sin_port)));
        return true;
    }
}
