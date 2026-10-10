#include "relay.h"
#include "logger.h"
#include "protocol.h"

#include <WS2tcpip.h>
#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <format>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace ac_relay::relay
{
    namespace
    {
        namespace proto = ac_relay::protocol;

        // ---- timing (ms) --------------------------------------------------
        constexpr std::uint64_t kKeepaliveIntervalMs = 15'000;   // PROTOCOL.md: every 15 s
        constexpr std::uint64_t kSilenceTimeoutMs = 50'000;      // ~3 missed acks, lease is 60 s
        constexpr std::uint64_t kAllocRetryBaseMs = 2'000;       // unanswered ALLOCATE retry
        constexpr std::uint64_t kAllocRetryMaxMs = 30'000;
        constexpr std::uint64_t kDeniedBackoffBaseMs = 5'000;    // DENIED 2/4
        constexpr std::uint64_t kDeniedBackoffMaxMs = 60'000;
        constexpr std::uint64_t kStatsIntervalMs = 60'000;
        constexpr std::uint32_t kAttemptsBeforeUnreachable = 3;  // stop blocking URL publication after this
        constexpr std::size_t kMaxPeers = 4096;

        enum class State
        {
            NoSocket,   // game socket not seen yet
            Allocating, // ALLOCATE due / in flight
            Backoff,    // DENIED pool/rate -- retry later
            Allocated,  // have relay_ip:alloc_port
            Stopped,    // DENIED bad password / bad version -- give up
        };

        [[nodiscard]] constexpr const char* state_name(State s)
        {
            switch (s)
            {
            case State::NoSocket: return "no-socket";
            case State::Allocating: return "allocating";
            case State::Backoff: return "backoff";
            case State::Allocated: return "allocated";
            case State::Stopped: return "stopped";
            }
            return "?";
        }

        struct Peer
        {
            bool via_relay = false;
        };

        std::mutex s_mu;
        std::condition_variable s_cv;
        bool s_initialized = false;
        bool s_stop = false;

        // config
        std::string s_password;
        std::string s_server_text;
        sockaddr_in s_server{}; // network order

        // session
        SOCKET s_sock = INVALID_SOCKET;
        std::uint16_t s_local_port = 0;
        State s_state = State::NoSocket;
        std::uint32_t s_alloc_nonce = 0;
        std::uint32_t s_alloc_attempts = 0;
        std::uint64_t s_next_alloc_at = 0;
        std::uint64_t s_backoff_ms = kDeniedBackoffBaseMs;
        std::uint32_t s_keepalive_nonce = 0;
        std::uint64_t s_last_keepalive_sent = 0;
        std::uint64_t s_last_heard = 0;
        bool s_have_alloc = false;      // relay_ip/alloc_port valid (also while re-allocating)
        std::uint32_t s_relay_ip = 0;   // host order
        std::uint16_t s_alloc_port = 0; // host order

        std::unordered_map<std::uint64_t, Peer> s_peers;

        // counters (atomics: bumped on the game's network thread)
        std::atomic<std::uint64_t> s_relay_in_pkts{0}, s_relay_in_bytes{0};
        std::atomic<std::uint64_t> s_relay_out_pkts{0}, s_relay_out_bytes{0};
        std::atomic<std::uint64_t> s_control_in{0}, s_control_out{0}, s_control_send_fail{0};
        std::uint64_t s_next_stats_at = 0;

        [[nodiscard]] std::uint64_t now_ms()
        {
            return GetTickCount64();
        }

        [[nodiscard]] std::uint64_t peer_key(const sockaddr_in& a)
        {
            return (static_cast<std::uint64_t>(a.sin_addr.s_addr) << 16) | a.sin_port;
        }

        [[nodiscard]] std::string ip_str(std::uint32_t host_ip)
        {
            return std::format("{}.{}.{}.{}", (host_ip >> 24) & 0xff, (host_ip >> 16) & 0xff,
                               (host_ip >> 8) & 0xff, host_ip & 0xff);
        }

        [[nodiscard]] std::string addr_str(const sockaddr_in& a)
        {
            return std::format("{}:{}", ip_str(ntohl(a.sin_addr.s_addr)), ntohs(a.sin_port));
        }

        [[nodiscard]] std::uint32_t make_nonce()
        {
            static std::uint32_t x = static_cast<std::uint32_t>(GetTickCount64()) ^ (GetCurrentProcessId() << 16) ^ 0x9e3779b9u;
            // xorshift32; nonce 0 is reserved-ish (server uses it for unsolicited acks)
            do
            {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
            } while (x == 0);
            return x;
        }

        // Sends one control datagram from the game's socket. Caller holds s_mu.
        // The game owns the socket and may close it at any time; the SO_TYPE
        // probe makes sure the handle is (still) a UDP socket before writing to
        // it, so a recycled handle can't get relay bytes injected into a TCP
        // stream.
        bool send_control_locked(const std::uint8_t* data, int len)
        {
            if (s_sock == INVALID_SOCKET)
                return false;

            int type = 0;
            int optlen = sizeof(type);
            if (getsockopt(s_sock, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &optlen) != 0 ||
                type != SOCK_DGRAM)
            {
                ++s_control_send_fail;
                return false;
            }

            const int r = sendto(s_sock, reinterpret_cast<const char*>(data), len, 0,
                                 reinterpret_cast<const sockaddr*>(&s_server), sizeof(s_server));
            if (r != len)
            {
                ++s_control_send_fail;
                if (logger::verbose())
                    logger::debug(std::format("relay: control sendto failed, wsa error {}", WSAGetLastError()));
                return false;
            }
            ++s_control_out;
            return true;
        }

        void send_allocate_locked(std::uint64_t now)
        {
            if (s_alloc_attempts == 0)
                s_alloc_nonce = make_nonce();

            std::uint8_t buf[proto::kHeaderSize + 4 + 1 + 255];
            const std::size_t n = proto::encode_allocate(buf, sizeof(buf), s_alloc_nonce, s_password);
            const bool ok = n && send_control_locked(buf, static_cast<int>(n));

            ++s_alloc_attempts;
            const std::uint64_t delay =
                std::min<std::uint64_t>(kAllocRetryBaseMs << std::min<std::uint32_t>(s_alloc_attempts - 1, 4),
                                        kAllocRetryMaxMs);
            s_next_alloc_at = now + delay;

            logger::info(std::format("relay: ALLOCATE #{} to {} from game socket (local port {}){}", s_alloc_attempts,
                                     s_server_text, s_local_port, ok ? "" : " -- send FAILED"));
            if (s_alloc_attempts == kAttemptsBeforeUnreachable)
                logger::warn(std::format("relay: no answer from {} after {} ALLOCATEs; relay unreachable so far, "
                                         "game traffic stays direct (still retrying every {} s)",
                                         s_server_text, s_alloc_attempts, kAllocRetryMaxMs / 1000));
        }

        void send_keepalive_locked(std::uint64_t now)
        {
            s_keepalive_nonce = make_nonce();
            std::uint8_t buf[proto::kHeaderSize + 4];
            const std::size_t n = proto::encode_keepalive(buf, sizeof(buf), s_keepalive_nonce);
            (void)send_control_locked(buf, static_cast<int>(n));
            s_last_keepalive_sent = now;
            if (logger::verbose())
                logger::debug(std::format("relay: KEEPALIVE nonce {:08x}", s_keepalive_nonce));
        }

        void restart_allocation_locked(std::uint64_t now, const char* why)
        {
            logger::warn(std::format("relay: re-allocating ({})", why));
            s_state = State::Allocating;
            s_alloc_attempts = 0;
            s_next_alloc_at = now;
            s_cv.notify_all();
        }

        void log_stats_locked()
        {
            std::size_t via_relay = 0;
            for (const auto& [k, p] : s_peers)
                via_relay += p.via_relay ? 1 : 0;

            logger::info(std::format(
                "relay stats: state={} alloc={} peers_via_relay={} in={} pkts/{} B out={} pkts/{} B control in={} out={} send_fail={}",
                state_name(s_state),
                s_have_alloc ? std::format("{}:{}", ip_str(s_relay_ip), s_alloc_port) : std::string("none"),
                via_relay, s_relay_in_pkts.load(), s_relay_in_bytes.load(), s_relay_out_pkts.load(),
                s_relay_out_bytes.load(), s_control_in.load(), s_control_out.load(), s_control_send_fail.load()));
        }

        void worker()
        {
            std::unique_lock lock(s_mu);
            s_next_stats_at = now_ms() + kStatsIntervalMs;

            while (!s_stop)
            {
                s_cv.wait_for(lock, std::chrono::milliseconds(250));
                if (s_stop)
                    break;

                const std::uint64_t now = now_ms();

                switch (s_state)
                {
                case State::NoSocket:
                case State::Stopped:
                    break;

                case State::Backoff:
                    if (now >= s_next_alloc_at)
                    {
                        s_state = State::Allocating;
                        s_alloc_attempts = 0;
                        s_next_alloc_at = now;
                    }
                    break;

                case State::Allocating:
                    if (now >= s_next_alloc_at)
                        send_allocate_locked(now);
                    break;

                case State::Allocated:
                    if (now - s_last_keepalive_sent >= kKeepaliveIntervalMs)
                        send_keepalive_locked(now);
                    if (now - s_last_heard >= kSilenceTimeoutMs)
                        restart_allocation_locked(now, "no reply from relay for 50 s");
                    break;
                }

                if (now >= s_next_stats_at)
                {
                    s_next_stats_at = now + kStatsIntervalMs;
                    if (s_state != State::NoSocket)
                        log_stats_locked();
                }
            }
        }

        // "host[:port]" -> sockaddr_in via getaddrinfo (IPv4 only)
        [[nodiscard]] bool resolve(const std::string& text, sockaddr_in& out)
        {
            std::string host = text;
            std::string port = std::to_string(proto::kDefaultControlPort);
            if (const auto colon = text.rfind(':'); colon != std::string::npos)
            {
                host = text.substr(0, colon);
                port = text.substr(colon + 1);
            }
            host.erase(0, host.find_first_not_of(" \t"));
            host.erase(host.find_last_not_of(" \t") + 1);
            if (host.empty() || port.empty())
                return false;

            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;
            addrinfo* res = nullptr;
            if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res)
                return false;

            bool ok = false;
            for (addrinfo* ai = res; ai; ai = ai->ai_next)
            {
                if (ai->ai_family == AF_INET && ai->ai_addrlen >= sizeof(sockaddr_in))
                {
                    std::memcpy(&out, ai->ai_addr, sizeof(sockaddr_in));
                    ok = out.sin_port != 0 && out.sin_addr.s_addr != 0;
                    break;
                }
            }
            freeaddrinfo(res);
            return ok;
        }
    }

    auto initialize(const config::relay_settings& settings) -> bool
    {
        if (settings.server.empty())
        {
            logger::info("relay: Server not set in ac_relay.ini; patch is a no-op");
            return false;
        }

        // The game calls WSAStartup itself, but possibly after us; it's refcounted.
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        {
            logger::error("relay: WSAStartup failed; patch is a no-op");
            return false;
        }

        sockaddr_in server{};
        if (!resolve(settings.server, server))
        {
            logger::error(std::format("relay: cannot resolve Server '{}' (IPv4 host:port expected); patch is a no-op",
                                      settings.server));
            return false;
        }

        {
            std::lock_guard lock(s_mu);
            s_server = server;
            s_server_text = std::format("{} ({})", settings.server, addr_str(server));
            s_password = settings.password;
            s_initialized = true;
            s_stop = false;
        }

        logger::info(std::format("relay: server {} resolved, password {}", s_server_text,
                                 settings.password.empty() ? "none" : "set"));

        std::thread(worker).detach();
        return true;
    }

    auto shutdown() -> void
    {
        // Called from DLL_PROCESS_DETACH: no joins, no sends (loader lock).
        // The relay frees the port when the lease runs out.
        {
            std::lock_guard lock(s_mu);
            s_stop = true;
        }
        s_cv.notify_all();
    }

    auto set_game_socket(SOCKET s, std::uint16_t local_port) -> void
    {
        std::lock_guard lock(s_mu);
        if (!s_initialized || s == s_sock)
            return;

        const bool replacing = s_sock != INVALID_SOCKET;
        logger::info(std::format("relay: {} game UDP socket {:#x} (local port {})",
                                 replacing ? "switching to new" : "captured", static_cast<std::uintptr_t>(s),
                                 local_port));
        s_sock = s;
        s_local_port = local_port;
        s_peers.clear();

        if (s_state == State::Stopped)
            return;

        // New socket = new NAT mapping = (probably) a new allocation.
        s_state = State::Allocating;
        s_alloc_attempts = 0;
        s_next_alloc_at = 0;
        s_cv.notify_all();
    }

    auto game_socket() -> SOCKET
    {
        std::lock_guard lock(s_mu);
        return s_sock;
    }

    auto server_address() -> sockaddr_in
    {
        return s_server; // written once in initialize() before any hook is installed
    }

    auto is_relay_address(const sockaddr_in& addr) -> bool
    {
        // s_server is written once in initialize() before any hook is installed
        return addr.sin_addr.s_addr == s_server.sin_addr.s_addr && addr.sin_port == s_server.sin_port;
    }

    auto handle_control(const std::uint8_t* data, std::size_t len) -> void
    {
        if (!proto::has_magic(data, len))
            return;
        ++s_control_in;

        std::lock_guard lock(s_mu);
        if (!s_initialized)
            return;

        if (data[4] != proto::kVersion)
        {
            logger::warn(std::format("relay: control datagram with version {}, ignored", data[4]));
            return;
        }

        const std::uint64_t now = now_ms();
        const auto type = static_cast<proto::Type>(data[5]);

        switch (type)
        {
        case proto::Type::Allocated:
        {
            proto::Allocated a{};
            if (!proto::parse_allocated(data, len, a))
                return;
            if (s_state == State::Stopped)
                return;
            if (a.nonce != s_alloc_nonce)
            {
                if (logger::verbose())
                    logger::debug(std::format("relay: ALLOCATED with stale nonce {:08x}, ignored", a.nonce));
                return;
            }
            if (a.relay_ip == 0 || a.alloc_port == 0)
            {
                logger::warn("relay: ALLOCATED carries 0.0.0.0 / port 0, ignored");
                return;
            }

            const bool changed = !s_have_alloc || a.relay_ip != s_relay_ip || a.alloc_port != s_alloc_port;
            s_have_alloc = true;
            s_relay_ip = a.relay_ip;
            s_alloc_port = a.alloc_port;
            s_state = State::Allocated;
            s_alloc_attempts = 0;
            s_backoff_ms = kDeniedBackoffBaseMs;
            s_last_heard = now;
            s_last_keepalive_sent = now;

            logger::info(std::format("relay: ALLOCATED {}:{} (we appear as {}:{}, lease {} s){}", ip_str(a.relay_ip),
                                     a.alloc_port, ip_str(a.observed_ip), a.observed_port, a.lease_seconds,
                                     changed ? "" : " -- unchanged"));
            s_cv.notify_all();
            return;
        }

        case proto::Type::Denied:
        {
            if (len < proto::kHeaderSize + 5)
                return;
            const std::uint32_t nonce = proto::get_u32(data + 6);
            const std::uint8_t reason = data[10];
            if (nonce != s_alloc_nonce && logger::verbose())
                logger::debug(std::format("relay: DENIED for nonce {:08x} (current {:08x})", nonce, s_alloc_nonce));

            if (reason == static_cast<std::uint8_t>(proto::DenyReason::BadPassword) ||
                reason == static_cast<std::uint8_t>(proto::DenyReason::BadVersion))
            {
                logger::error(std::format("relay: DENIED by {}: {} -- giving up, patch is now a passthrough. "
                                          "Fix ac_relay.ini and restart the game.",
                                          s_server_text, proto::deny_reason_name(reason)));
                s_state = State::Stopped;
                s_have_alloc = false;
                s_peers.clear();
            }
            else
            {
                logger::warn(std::format("relay: DENIED by {}: {} -- retrying in {} s", s_server_text,
                                         proto::deny_reason_name(reason), s_backoff_ms / 1000));
                s_state = State::Backoff;
                s_next_alloc_at = now + s_backoff_ms;
                s_backoff_ms = std::min(s_backoff_ms * 2, kDeniedBackoffMaxMs);
            }
            s_cv.notify_all();
            return;
        }

        case proto::Type::KeepaliveAck:
        {
            if (len < proto::kHeaderSize + 6)
                return;
            const std::uint32_t nonce = proto::get_u32(data + 6);
            const std::uint16_t lease = proto::get_u16(data + 10);
            s_last_heard = now;

            // lease 0 = relay has no allocation for us. Also arrives with
            // nonce 0 as the answer to a SEND from an unknown owner, so it is
            // honoured regardless of nonce.
            if (lease == 0)
            {
                if (s_state == State::Allocated)
                    restart_allocation_locked(now, std::format("KEEPALIVE_ACK lease 0, nonce {:08x}", nonce).c_str());
                return;
            }
            if (logger::verbose())
                logger::debug(std::format("relay: KEEPALIVE_ACK nonce {:08x} lease {} s", nonce, lease));
            return;
        }

        default:
            if (logger::verbose())
                logger::debug(std::format("relay: unexpected control type {:#04x} from relay, dropped", data[5]));
            return;
        }
    }

    auto note_relay_recv(const sockaddr_in& peer, std::size_t payload_len) -> void
    {
        ++s_relay_in_pkts;
        s_relay_in_bytes += payload_len;

        std::lock_guard lock(s_mu);
        auto it = s_peers.find(peer_key(peer));
        if (it == s_peers.end())
        {
            if (s_peers.size() >= kMaxPeers)
                return;
            it = s_peers.emplace(peer_key(peer), Peer{}).first;
        }
        if (!it->second.via_relay)
        {
            it->second.via_relay = true;
            logger::info(std::format("relay: peer {} path direct -> RELAY", addr_str(peer)));
        }
        if (logger::verbose())
            logger::debug(std::format("relay: RECV {} B from {}", payload_len, addr_str(peer)));
    }

    auto note_direct_recv(const sockaddr_in& peer) -> void
    {
        std::lock_guard lock(s_mu);
        if (s_peers.empty())
            return;
        // Only peers we've ever heard through the relay are tracked; unknown
        // peers are direct by default.
        const auto it = s_peers.find(peer_key(peer));
        if (it != s_peers.end() && it->second.via_relay)
        {
            it->second.via_relay = false;
            logger::info(std::format("relay: peer {} path RELAY -> direct", addr_str(peer)));
        }
    }

    auto should_relay(const sockaddr_in& peer) -> bool
    {
        std::lock_guard lock(s_mu);
        if (!s_have_alloc || s_state == State::Stopped || s_peers.empty())
            return false;
        const auto it = s_peers.find(peer_key(peer));
        return it != s_peers.end() && it->second.via_relay;
    }

    auto note_relay_send(const sockaddr_in& peer, std::size_t payload_len) -> void
    {
        ++s_relay_out_pkts;
        s_relay_out_bytes += payload_len;
        if (logger::verbose())
            logger::debug(std::format("relay: SEND {} B to {}", payload_len, addr_str(peer)));
    }

    auto wait_allocation(std::uint32_t timeout_ms, std::uint32_t& relay_ip, std::uint16_t& alloc_port) -> bool
    {
        std::unique_lock lock(s_mu);
        if (!s_initialized)
            return false;

        const auto ready = [] { return s_state == State::Allocated; };
        if (!ready())
        {
            // Only block while an ALLOCATE is plausibly about to be answered.
            const bool worth_waiting = (s_state == State::Allocating || s_state == State::NoSocket) &&
                                       s_alloc_attempts < kAttemptsBeforeUnreachable;
            if (timeout_ms == 0 || !worth_waiting)
                return false;
            s_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                          [] { return s_state == State::Allocated || s_state == State::Stopped || s_stop; });
            if (!ready())
                return false;
        }

        relay_ip = s_relay_ip;
        alloc_port = s_alloc_port;
        return true;
    }
}
