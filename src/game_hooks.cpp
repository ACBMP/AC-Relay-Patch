#include "game_hooks.h"
#include "logger.h"
#include "protocol.h"
#include "relay.h"

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Windows.h>

#include <safetyhook.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// =============================================================================
// ACBMP.exe (Windows build, image base 0x00400000, no ASLR). Every constant
// below is written as (Ghidra VA - 0x00400000) on purpose -- see
// docs/RE_NOTES.md and acb2's "Ghidra VA vs RVA" note. The Mac build
// (acbmp_sf.exe, full symbols) was used to name each function; the Windows
// twins were matched by structure, string anchors and call graph.
//
// The Windows Quazal socket layer is OVERLAPPED (WSASendTo/WSARecvFrom with
// an event per op), so the data path is NOT hooked at RecvFrom (data isn't
// there yet when it returns) but at the completion consumer:
//
//   UDPTransport::ServiceIOCompletions (0x01d1e4f0)
//     for each QueuingSocket:
//       if recv op state == 2 (complete):
//         buf = QueuingSocket::CompleteBufferRecv(qs)   <-- hook (post)
//         if buf: copy qs+0xb0 (source InetAddress), dispatch packet
//         QueuingSocket::Recv (re-posts WSARecvFrom)
//
// Returning nullptr from CompleteBufferRecv (after releasing the buffer) is
// exactly what the original does for an empty/failed receive, so relay
// control datagrams are hidden from the game that way.
// =============================================================================

namespace ac_relay::game_hooks
{
    namespace
    {
        namespace proto = ac_relay::protocol;

        constexpr std::uintptr_t kImageBase = 0x00400000;

        // Quazal::BerkeleySocketDriver::BerkeleySocket::SendTo
        //   int __thiscall SendTo(BerkeleySocket*, u8* buf, u32 len, InetAddress* to, IOOp* op)  RET 0x10
        constexpr std::uintptr_t kSendToRva = 0x01cc08c0 - kImageBase;
        constexpr std::array<std::uint8_t, 16> kSendToSig{
            0x8b, 0x44, 0x24, 0x08, 0x83, 0xec, 0x08, 0x53, 0x8b, 0x5c, 0x24, 0x10, 0x55, 0x56, 0x8b, 0x74};

        // Quazal::QueuingSocket::CompleteBufferRecv
        //   Buffer* __thiscall CompleteBufferRecv(QueuingSocket*)  RET
        constexpr std::uintptr_t kCompleteBufferRecvRva = 0x01cc1540 - kImageBase;
        constexpr std::array<std::uint8_t, 16> kCompleteBufferRecvSig{
            0x51, 0x53, 0x56, 0x8b, 0xf1, 0x8b, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x33, 0xdb, 0x57, 0x8b, 0x78};

        // Quazal::Network::AddLocalURL(const StationURL&)  __thiscall, RET 4
        constexpr std::uintptr_t kAddLocalUrlRva = 0x01d1cba0 - kImageBase;
        constexpr std::array<std::uint8_t, 16> kAddLocalUrlSig{
            0x83, 0xec, 0x08, 0x80, 0x3d, 0xe4, 0x95, 0x68, 0x02, 0x00, 0x55, 0x56, 0x8b, 0xf1, 0x8d, 0x6e};

        // Quazal::SecureConnectionClient::PrepareURLs(qList<StationURL>&)
        // (copies Network's local URLs for RegisterURLs/RegisterURLsEx at login)
        constexpr std::uintptr_t kPrepareUrlsRva = 0x01d3dba0 - kImageBase;
        constexpr std::array<std::uint8_t, 16> kPrepareUrlsSig{
            0x51, 0x80, 0x3d, 0x4c, 0x96, 0x68, 0x02, 0x00, 0x53, 0x55, 0x56, 0x57, 0x8b, 0xf1, 0x74, 0x10};

        // Quazal::ObjDupProtocol::AddLocalURLs(Station*)  __thiscall, RET 4
        // (stamps RVCID on every Network local URL and copies them into the
        // local Station's ConnectionInfo = what peers dial)
        constexpr std::uintptr_t kObjDupAddLocalUrlsRva = 0x01ab5d50 - kImageBase;
        constexpr std::array<std::uint8_t, 16> kObjDupAddLocalUrlsSig{
            0x51, 0x80, 0x3d, 0x4c, 0x96, 0x68, 0x02, 0x00, 0x74, 0x10, 0xb9, 0xd0, 0xae, 0x68, 0x02, 0xe8};

        // Quazal::ConnectionInfo::SetURL(int slot, const char* url)  __thiscall, RET 8
        // ConnectionInfo holds only 5 URL slots (Quazal::String at +8..+0x18).
        // ConnectionInfo::AddURL (0x01a87ef0) silently drops a 6th URL, so on
        // a PC with many interfaces (VPNs, Docker bridges, Hyper-V) the relay
        // URL, added last, never reached the station URLs peers dial or the
        // session URLs (createSession/migrateSession read the same slots).
        constexpr std::uintptr_t kConnInfoSetUrlRva = 0x01a87e20 - kImageBase;
        constexpr std::array<std::uint8_t, 16> kConnInfoSetUrlSig{
            0x8b, 0x44, 0x24, 0x04, 0x83, 0xf8, 0x04, 0x77, 0x54, 0xff, 0x24, 0x85, 0x80, 0x7e, 0xa8, 0x01};

        // Quazal::StationURL::StationURL(const char*)  __thiscall, RET 4
        constexpr std::uintptr_t kStationUrlCtorRva = 0x01d0acc0 - kImageBase;
        constexpr std::array<std::uint8_t, 16> kStationUrlCtorSig{
            0x56, 0x8b, 0xf1, 0x8d, 0x44, 0x24, 0x08, 0x50, 0x8d, 0x4c, 0x24, 0x0c, 0x51, 0x8d, 0x4e, 0x08};

        // Quazal::StationURL::~StationURL()  __thiscall
        // (byte 15 is the low byte of a relocated address; image relocations
        // move in 64 KiB steps, so it never changes)
        constexpr std::uintptr_t kStationUrlDtorRva = 0x01d0ae60 - kImageBase;
        constexpr std::array<std::uint8_t, 16> kStationUrlDtorSig{
            0x56, 0x57, 0x8b, 0xf9, 0x8b, 0x47, 0x74, 0x85, 0xc0, 0x74, 0x67, 0x8d, 0x70, 0xfc, 0xa1, 0x00};

        // Network::GetInstance() is inlined everywhere as:
        //   if (!g_multiContext) net = g_networkHolder ? g_networkHolder->[+0xc] : 0
        constexpr std::uintptr_t kMultiContextFlagRva = 0x0268964c - kImageBase; // u8
        constexpr std::uintptr_t kNetworkHolderRva = 0x02689728 - kImageBase;    // ptr
        constexpr std::uintptr_t kHolderNetworkOffset = 0x0c;

        // BerkeleySocket / QueuingSocket layout (Windows)
        constexpr std::size_t kSockIsDatagram = 0x88; // u8, Open(true) = UDP
        constexpr std::size_t kSockHandle = 0x90;     // SOCKET
        constexpr std::size_t kSockAltDriver = 0x9c;  // non-null = console-style driver, not Winsock
        constexpr std::size_t kQsSourceAddr = 0xb0;   // InetAddress (0x20 B, sockaddr_in at +0)

        // Quazal::Buffer layout
        constexpr std::size_t kBufData = 0x08;     // u8*
        constexpr std::size_t kBufSize = 0x0c;     // content size
        constexpr std::size_t kBufCapacity = 0x10; // allocated size
        constexpr std::size_t kBufReleaseVtblSlot = 2; // vtable+8, __thiscall()

        // Quazal::Station / ConnectionInfo layout (Windows; Mac has it at +0x70)
        constexpr std::size_t kStationConnInfo = 0x84;
        constexpr std::size_t kConnInfoUrls = 0x08; // 5 x Quazal::String, char* at +0
        constexpr int kConnInfoSlots = 5;

        // Quazal::StationURL layout
        constexpr std::size_t kStationUrlSize = 0x7c;     // list node alloc 0x84 = 8 + 0x7c
        constexpr std::size_t kUrlInetPtr = 0x00;         // InetAddress* (sockaddr_in at +0)
        constexpr std::size_t kUrlParsedFlag = 0x78;      // u8

        using StationUrlCtorFn = void*(__thiscall*)(void* self, const char* url);
        using StationUrlDtorFn = void(__thiscall*)(void* self);
        using AddLocalUrlFn = void(__thiscall*)(void* network, const void* url);
        using ConnInfoSetUrlFn = void(__thiscall*)(void* conninfo, int slot, const char* url);
        using BufferReleaseFn = void(__thiscall*)(void* buffer);

        std::uintptr_t s_base = 0;
        bool s_active = false;

        SafetyHookInline s_send_to_hook{};
        SafetyHookInline s_recv_hook{};
        SafetyHookInline s_add_local_url_hook{};
        SafetyHookMid s_prepare_urls_hook{};
        SafetyHookInline s_objdup_add_local_urls_hook{};

        StationUrlCtorFn s_url_ctor = nullptr;
        StationUrlDtorFn s_url_dtor = nullptr;
        AddLocalUrlFn s_add_local_url_original = nullptr; // trampoline (or the raw fn if not hooked)
        ConnInfoSetUrlFn s_conninfo_set_url = nullptr;

        std::atomic<void*> s_network{nullptr};       // captured from AddLocalURL's this
        std::atomic<std::uint16_t> s_main_port{0};   // port StartListen stamped on the local URLs

        // ---- signature helper ------------------------------------------------
        // ACBMP.exe has DYNAMIC_BASE and a .reloc table: Wine loads it at its
        // preferred 0x00400000, Windows (ASLR) usually elsewhere, and the loader
        // then rewrites every absolute address in the code. `abs_offsets` lists
        // where a signature holds such an address (written for base
        // 0x00400000); those 4 bytes are compared relocated to the actual base.
        template <std::size_t N>
        [[nodiscard]] bool check_sig(std::uintptr_t rva, const std::array<std::uint8_t, N>& sig, const char* what,
                                     std::initializer_list<std::size_t> abs_offsets = {})
        {
            std::array<std::uint8_t, N> expected = sig;
            const auto delta = static_cast<std::uint32_t>(s_base - kImageBase);
            for (const std::size_t off : abs_offsets)
            {
                std::uint32_t v = 0;
                std::memcpy(&v, expected.data() + off, 4);
                v += delta;
                std::memcpy(expected.data() + off, &v, 4);
            }

            const auto* p = reinterpret_cast<const std::uint8_t*>(s_base + rva);
            if (std::memcmp(p, expected.data(), N) != 0)
            {
                std::string found, wanted;
                for (std::size_t i = 0; i < N; ++i)
                {
                    found += std::format("{:02x} ", p[i]);
                    wanted += std::format("{:02x} ", expected[i]);
                }
                logger::warn(std::format("{} (VA {:#010x}, at {:#010x}) byte signature mismatch -- different game "
                                         "build or hooked by another mod? found [{}] expected [{}]",
                                         what, rva + kImageBase, s_base + rva, found, wanted));
                return false;
            }
            return true;
        }

        // ---- SEH-guarded POD helpers -----------------------------------------
        // MSVC C2712: no objects with destructors in a function using __try,
        // so every guarded game-memory access lives in its own POD-only helper.

        std::uint16_t read_url_port_seh(const std::uint8_t* url)
        {
            __try
            {
                if (!url || url[kUrlParsedFlag] == 0)
                    return 0;
                const auto* inet = *reinterpret_cast<const std::uint8_t* const*>(url + kUrlInetPtr);
                if (!inet)
                    return 0;
                return ntohs(*reinterpret_cast<const std::uint16_t*>(inet + 2));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 0;
            }
        }

        void* network_from_globals_seh(std::uintptr_t base)
        {
            __try
            {
                if (*reinterpret_cast<const std::uint8_t*>(base + kMultiContextFlagRva) != 0)
                    return nullptr; // per-thread contexts: can't resolve without the game's TLS lookup
                const auto holder = *reinterpret_cast<const std::uintptr_t*>(base + kNetworkHolderRva);
                if (!holder)
                    return nullptr;
                return *reinterpret_cast<void* const*>(holder + kHolderNetworkOffset);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return nullptr;
            }
        }

        // Builds a StationURL from `url` with the game's own ctor, hands it to
        // Network::AddLocalURL (which copies it into the list, deduplicating),
        // then destroys ours. Returns 0 on success, 1 on fault.
        int add_local_url_seh(StationUrlCtorFn ctor, StationUrlDtorFn dtor, AddLocalUrlFn add, void* network,
                              const char* url)
        {
            alignas(16) unsigned char storage[0x100]; // >= sizeof(StationURL) (0x7c)
            std::memset(storage, 0, sizeof(storage));
            __try
            {
                ctor(storage, url);
                add(network, storage);
                dtor(storage);
                return 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // leak the half-built URL rather than risk a second fault
                return 1;
            }
        }

        using SlotText = char[256];

        // Copies the 5 ConnectionInfo URL strings of `station` (empty = unused).
        // Returns 0 on success, 1 on fault.
        int read_station_slots_seh(const std::uint8_t* station, SlotText* out)
        {
            __try
            {
                const std::uint8_t* ci = station + kStationConnInfo;
                for (int i = 0; i < kConnInfoSlots; ++i)
                {
                    out[i][0] = '\0';
                    const char* p = *reinterpret_cast<const char* const*>(ci + kConnInfoUrls + 4 * i);
                    if (!p)
                        continue;
                    int n = 0;
                    for (; n < static_cast<int>(sizeof(SlotText)) - 1 && p[n]; ++n)
                        out[i][n] = p[n];
                    out[i][n] = '\0';
                }
                return 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 1;
            }
        }

        int set_station_slot_seh(ConnInfoSetUrlFn set_url, std::uint8_t* station, int slot, const char* url)
        {
            __try
            {
                set_url(station + kStationConnInfo, slot, url);
                return 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 1;
            }
        }

        // ---- socket classification ---------------------------------------------
        struct SockCacheEntry
        {
            const void* obj = nullptr;
            SOCKET sock = INVALID_SOCKET;
            bool is_main = false;
        };

        std::mutex s_cache_mu;
        std::array<SockCacheEntry, 8> s_cache{};
        std::size_t s_cache_next = 0;

        // Decides whether `self` is the game's main PRUDP socket (the one whose
        // port the game publishes in its station URLs) and tells the relay
        // session about it. Cheap after the first call per socket.
        void classify_socket(const std::uint8_t* self)
        {
            const SOCKET sock = *reinterpret_cast<const SOCKET*>(self + kSockHandle);
            if (sock == INVALID_SOCKET || sock == 0)
                return;
            if (*reinterpret_cast<const std::uintptr_t*>(self + kSockAltDriver) != 0)
                return;
            if (self[kSockIsDatagram] == 0)
                return;

            {
                std::lock_guard lock(s_cache_mu);
                for (const auto& e : s_cache)
                    if (e.obj == self && e.sock == sock)
                        return;
            }

            sockaddr_in local{};
            int namelen = sizeof(local);
            std::uint16_t port = 0;
            if (getsockname(sock, reinterpret_cast<sockaddr*>(&local), &namelen) == 0)
                port = ntohs(local.sin_port);

            const std::uint16_t main_port = s_main_port.load();
            bool is_main;
            if (main_port != 0)
                is_main = port == main_port;
            else
                // StartListen ran before our hooks: take the first UDP socket
                // the game sends on (the RDV login traffic).
                is_main = relay::game_socket() == INVALID_SOCKET;

            {
                std::lock_guard lock(s_cache_mu);
                s_cache[s_cache_next] = {self, sock, is_main};
                s_cache_next = (s_cache_next + 1) % s_cache.size();
            }

            logger::info(std::format("game UDP socket {:#x} local port {}: {}", static_cast<std::uintptr_t>(sock), port,
                                     is_main ? (main_port ? "main PRUDP socket (matches published port)"
                                                          : "assumed main PRUDP socket (published port unknown)")
                                             : "not the main socket, ignored"));
            if (is_main)
                relay::set_game_socket(sock, port);
        }

        // PRUDP v0 header: byte 0/1 = source/destination VPort, (stream type
        // << 4) | port. Stream type 5 is the NAT traversal probe stream
        // (URLProbe); connection traffic is stream 1 (DO).
        [[nodiscard]] bool is_nat_probe(const std::uint8_t* data, std::size_t len)
        {
            return len >= 2 && (data[0] >> 4) == 5 && (data[1] >> 4) == 5;
        }

        // URLProbe datagram (24 B): header up to byte 9, [10] msg (0 request,
        // 1 reply), [11..14] sender RVCID, [15..18] the requester's time (a
        // reply echoes the request's), all little-endian.
        struct ProbeMsg
        {
            bool ok = false;
            std::uint8_t msg = 0;
            std::uint32_t rvcid = 0; // sender's
            std::uint32_t time = 0;
        };

        [[nodiscard]] ProbeMsg parse_probe(const std::uint8_t* data, std::size_t len)
        {
            ProbeMsg m;
            if (!is_nat_probe(data, len) || len < 19)
                return m;
            m.ok = true;
            m.msg = data[10];
            std::memcpy(&m.rvcid, data + 11, 4);
            std::memcpy(&m.time, data + 15, 4);
            return m;
        }

        // ---- send path ---------------------------------------------------------
        // The send is overlapped: the buffer and destination must stay valid
        // until the game sees the op complete. Each socket has exactly one send
        // op (QueuingSocket+0xa4) and never posts a second send before the first
        // completes (QueuingSocket+0xac "send pending"), so one wrap buffer per
        // op pointer is enough and is reused only after completion.
        struct WrapBuffer
        {
            alignas(8) std::uint8_t data[2048];
            alignas(8) std::uint8_t to[0x20]; // InetAddress: sockaddr_in + padding
        };

        std::mutex s_wrap_mu;
        std::unordered_map<const void*, std::unique_ptr<WrapBuffer>> s_wrap_buffers;

        [[nodiscard]] WrapBuffer* wrap_buffer_for(const void* op)
        {
            std::lock_guard lock(s_wrap_mu);
            auto& slot = s_wrap_buffers[op];
            if (!slot)
                slot = std::make_unique<WrapBuffer>();
            return slot.get();
        }

        int __fastcall hk_send_to(std::uint8_t* self, void* /*edx*/, const std::uint8_t* buf, std::uint32_t len,
                                  const std::uint8_t* to, void* op)
        {
            if (self && to && buf && op)
            {
                classify_socket(self);

                const SOCKET sock = *reinterpret_cast<const SOCKET*>(self + kSockHandle);
                const auto& dest = *reinterpret_cast<const sockaddr_in*>(to);

                bool wrap = false;
                if (sock == relay::game_socket() && !relay::is_relay_address(dest))
                {
                    if (relay::is_second_address(dest, "to"))
                    {
                        // Can't just skip an overlapped send (the game waits
                        // for it to complete): send it to the relay's control
                        // port instead, which drops anything without its magic.
                        WrapBuffer* w = wrap_buffer_for(op);
                        std::memset(w->to, 0, sizeof(w->to));
                        const sockaddr_in relay_addr = relay::server_address();
                        std::memcpy(w->to, &relay_addr, sizeof(sockaddr_in));
                        return s_send_to_hook.unsafe_thiscall<int>(self, buf, len, w->to, op);
                    }
                    if (is_nat_probe(buf, len))
                    {
                        // Probe replies go back the way their request came
                        // (relay::route_probe_reply). Our own requests go
                        // direct, plus a delayed relay copy
                        // (relay::queue_relayed_probe_copy).
                        const ProbeMsg p = parse_probe(buf, len);
                        if (p.ok && p.msg == 1)
                            wrap = relay::route_probe_reply(dest, p.time);
                        else if (p.ok && p.msg == 0)
                            relay::queue_relayed_probe_copy(dest, buf, len);
                    }
                    else
                        wrap = relay::should_relay(dest);
                }
                if (wrap && len + proto::kDataOverhead <= sizeof(WrapBuffer::data))
                {
                    WrapBuffer* w = wrap_buffer_for(op);
                    proto::encode_send_header(w->data, ntohl(dest.sin_addr.s_addr), ntohs(dest.sin_port));
                    std::memcpy(w->data + proto::kDataOverhead, buf, len);

                    std::memset(w->to, 0, sizeof(w->to));
                    const sockaddr_in relay_addr = relay::server_address();
                    std::memcpy(w->to, &relay_addr, sizeof(sockaddr_in));

                    relay::note_relay_send(dest, len);
                    return s_send_to_hook.unsafe_thiscall<int>(self, w->data,
                                                                static_cast<std::uint32_t>(len + proto::kDataOverhead),
                                                                w->to, op);
                }
            }
            return s_send_to_hook.unsafe_thiscall<int>(self, buf, len, to, op);
        }

        // ---- receive path ------------------------------------------------------
        void release_buffer(void* buffer)
        {
            auto** vtbl = *reinterpret_cast<void***>(buffer);
            reinterpret_cast<BufferReleaseFn>(vtbl[kBufReleaseVtblSlot])(buffer);
        }

        void* __fastcall hk_complete_buffer_recv(std::uint8_t* self)
        {
            void* buffer = s_recv_hook.unsafe_thiscall<void*>(self);
            if (!buffer || !self)
                return buffer;

            const SOCKET sock = *reinterpret_cast<const SOCKET*>(self + kSockHandle);
            if (sock != relay::game_socket())
                return buffer;

            auto* b = static_cast<std::uint8_t*>(buffer);
            auto* data = *reinterpret_cast<std::uint8_t**>(b + kBufData);
            auto& size = *reinterpret_cast<std::uint32_t*>(b + kBufSize);
            const std::uint32_t capacity = *reinterpret_cast<const std::uint32_t*>(b + kBufCapacity);
            auto& from = *reinterpret_cast<sockaddr_in*>(self + kQsSourceAddr);

            if (!data || size == 0 || size > capacity)
                return buffer;

            if (relay::is_relay_address(from) && proto::has_magic(data, size))
            {
                if (data[4] == proto::kVersion && data[5] == static_cast<std::uint8_t>(proto::Type::Recv) &&
                    size >= proto::kDataOverhead)
                {
                    const std::uint32_t peer_ip = proto::get_u32(data + 6);
                    const std::uint16_t peer_port = proto::get_u16(data + 10);
                    const std::uint32_t payload = size - static_cast<std::uint32_t>(proto::kDataOverhead);

                    if (payload != 0 && peer_ip != 0 && peer_port != 0)
                    {
                        std::memmove(data, data + proto::kDataOverhead, payload);
                        size = payload;
                        from.sin_family = AF_INET;
                        from.sin_addr.s_addr = htonl(peer_ip);
                        from.sin_port = htons(peer_port);
                        const ProbeMsg p = parse_probe(data, payload);
                        if (p.ok)
                            relay::note_probe_sender(from, p.rvcid);
                        if (relay::is_second_address(from, "from"))
                        {
                            release_buffer(buffer);
                            return nullptr;
                        }
                        const bool session = !is_nat_probe(data, payload);
                        if (session)
                            relay::note_session_from(from);
                        relay::note_relay_recv(from, payload, session);
                        if (p.ok && p.msg == 0)
                            relay::note_probe_request(from, p.time, true);
                        return buffer; // game sees a datagram from peer_ip:peer_port
                    }
                }
                else
                {
                    relay::handle_control(data, size);
                }

                // Hide it: same as the original's "nothing received" path.
                release_buffer(buffer);
                return nullptr;
            }

            const ProbeMsg p = parse_probe(data, size);
            if (p.ok)
                relay::note_probe_sender(from, p.rvcid);
            if (relay::is_second_address(from, "from"))
            {
                release_buffer(buffer);
                return nullptr;
            }
            const bool session = !is_nat_probe(data, size);
            if (session)
                relay::note_session_from(from);
            relay::note_direct_recv(from, session);
            if (p.ok && p.msg == 0)
                relay::note_probe_request(from, p.time, false);
            return buffer;
        }

        // ---- URL publication ---------------------------------------------------
        void __fastcall hk_add_local_url(void* self, void* /*edx*/, const std::uint8_t* url)
        {
            if (self)
                s_network.store(self);

            // First caller is UDPTransport::StartListen, with the per-interface
            // URL whose port it just set to the bound PRUDP port.
            if (url && s_main_port.load() == 0)
            {
                if (const std::uint16_t port = read_url_port_seh(url); port != 0)
                {
                    std::uint16_t expected = 0;
                    if (s_main_port.compare_exchange_strong(expected, port))
                        logger::info(std::format("game PRUDP port (from Network::AddLocalURL): {}", port));
                }
            }

            s_add_local_url_hook.unsafe_thiscall<void>(self, url);
        }

        std::mutex s_url_mu;
        std::uint32_t s_published_ip = 0;
        std::uint16_t s_published_port = 0;
        std::uint32_t s_published_observed_ip = 0;
        std::uint16_t s_published_observed_port = 0;

        [[nodiscard]] std::string ip_text(std::uint32_t ip)
        {
            return std::format("{}.{}.{}.{}", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
        }

        // Value of `key` in a StationURL string ("prudp:/address=..;port=..;RVCID=.."), or empty.
        [[nodiscard]] std::string_view url_param(std::string_view url, std::string_view key)
        {
            const auto body = url.find(":/");
            if (body == std::string_view::npos)
                return {};
            url.remove_prefix(body + 2);
            while (!url.empty())
            {
                const auto end = url.find(';');
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

        // Docker/WSL/Hyper-V bridges (172.16/12) and link-local (169.254/16):
        // the first candidates to give up a slot for the relay.
        [[nodiscard]] bool is_throwaway_address(std::string_view address)
        {
            unsigned a = 0, b = 0;
            if (std::sscanf(std::string(address).c_str(), "%u.%u", &a, &b) != 2)
                return false;
            return (a == 172 && b >= 16 && b <= 31) || (a == 169 && b == 254);
        }

        void publish_relay_url(const char* stage)
        {
            if (!s_url_ctor || !s_url_dtor || !s_add_local_url_original)
                return;

            void* network = s_network.load();
            if (!network)
                network = network_from_globals_seh(s_base);
            if (!network)
            {
                logger::warn(std::format("{}: Quazal::Network instance not found; relay URL not published", stage));
                return;
            }

            std::uint32_t ip = 0;
            std::uint16_t port = 0;
            if (!relay::wait_allocation(2000, ip, port))
            {
                logger::warn(std::format("{}: no relay allocation (yet); relay URL not published here", stage));
                return;
            }

            char url[96];
            std::snprintf(url, sizeof(url), "prudp:/address=%u.%u.%u.%u;port=%u", (ip >> 24) & 0xff,
                          (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff, static_cast<unsigned>(port));

            std::lock_guard lock(s_url_mu);
            // Called every time: the game's list may have been rebuilt (re-login),
            // and AddLocalURL itself skips a URL that is already present.
            if (add_local_url_seh(s_url_ctor, s_url_dtor, s_add_local_url_original, network, url) != 0)
            {
                logger::error(std::format("{}: fault while adding relay URL '{}' -- not published", stage, url));
                return;
            }

            // Our public address as the relay saw it. Players reaching the
            // lobby over a VPN otherwise never learn each other's real
            // address, so direct hole punching can't even be tried.
            std::uint32_t oip = 0;
            std::uint16_t oport = 0;
            if (relay::observed_address(oip, oport))
            {
                char observed[96];
                std::snprintf(observed, sizeof(observed), "prudp:/address=%u.%u.%u.%u;port=%u", (oip >> 24) & 0xff,
                              (oip >> 16) & 0xff, (oip >> 8) & 0xff, oip & 0xff, static_cast<unsigned>(oport));
                if (add_local_url_seh(s_url_ctor, s_url_dtor, s_add_local_url_original, network, observed) != 0)
                    logger::error(std::format("{}: fault while adding public URL '{}'", stage, observed));
                else if (oip != s_published_observed_ip || oport != s_published_observed_port)
                {
                    s_published_observed_ip = oip;
                    s_published_observed_port = oport;
                    logger::info(std::format("{}: published public URL '{}' (our address as the relay sees it)",
                                             stage, observed));
                }
            }

            if (ip != s_published_ip || port != s_published_port)
            {
                if (s_published_port != 0)
                    logger::warn(std::format("relay allocation changed; the old relay URL stays in the game's list "
                                             "until restart (harmless, its probes just fail)"));
                s_published_ip = ip;
                s_published_port = port;
                logger::info(std::format("{}: published relay URL '{}' as a local station URL", stage, url));
            }
            else
            {
                logger::debug(std::format("{}: relay URL '{}' (re)offered to Network::AddLocalURL", stage, url));
            }
        }

        void mid_prepare_urls(safetyhook::Context& /*ctx*/)
        {
            publish_relay_url("RegisterURLs (SecureConnectionClient::PrepareURLs)");
        }

        // Makes sure the relay URL (and the public address the relay sees)
        // occupy a station URL slot: a free one, else one holding a
        // throwaway address, else the last. Slot 0 is never touched: the
        // game puts its public URL there.
        void ensure_station_urls(std::uint8_t* station)
        {
            if (!s_conninfo_set_url || !station)
                return;

            std::uint32_t ip = 0;
            std::uint16_t port = 0;
            if (!relay::wait_allocation(0, ip, port))
                return;

            struct Wanted
            {
                std::string address;
                std::uint16_t port;
                const char* what;
            };
            std::vector<Wanted> wanted{{ip_text(ip), port, "relay"}};
            std::uint32_t oip = 0;
            std::uint16_t oport = 0;
            if (relay::observed_address(oip, oport))
                wanted.push_back({ip_text(oip), oport, "public"});

            SlotText raw[kConnInfoSlots];
            if (read_station_slots_seh(station, raw) != 0)
            {
                logger::warn("station URLs: fault reading the station's URL slots; relay URL may be missing");
                return;
            }
            std::array<std::string, kConnInfoSlots> slots;
            for (int i = 0; i < kConnInfoSlots; ++i)
                slots[i] = raw[i];

            // AddLocalURLs returns early (no URLs at all) for stations it
            // doesn't publish; leave those alone.
            if (slots[0].empty())
                return;

            std::string rvcid;
            for (const auto& u : slots)
                if (const auto v = url_param(u, "RVCID"); !v.empty())
                {
                    rvcid = v;
                    break;
                }

            const auto holds = [&](int i, const Wanted& w) {
                return url_param(slots[i], "address") == w.address &&
                       url_param(slots[i], "port") == std::to_string(w.port);
            };

            std::array<bool, kConnInfoSlots> keep{};
            keep[0] = true;
            for (int i = 0; i < kConnInfoSlots; ++i)
                for (const auto& w : wanted)
                    if (holds(i, w))
                        keep[i] = true;

            for (const auto& w : wanted)
            {
                bool present = false;
                for (int i = 0; i < kConnInfoSlots && !present; ++i)
                    present = holds(i, w);
                if (present)
                    continue;

                // slots are read up to the first empty one: use that if any
                int target = -1;
                for (int i = 0; i < kConnInfoSlots && target < 0; ++i)
                    if (slots[i].empty())
                        target = i;
                for (int i = kConnInfoSlots - 1; i > 0 && target < 0; --i)
                    if (!keep[i] && is_throwaway_address(url_param(slots[i], "address")))
                        target = i;
                for (int i = kConnInfoSlots - 1; i > 0 && target < 0; --i)
                    if (!keep[i])
                        target = i;
                if (target < 0)
                {
                    logger::warn(std::format("station URLs: no slot left for the {} URL {}:{}", w.what, w.address,
                                             w.port));
                    continue;
                }

                std::string url = std::format("prudp:/address={};port={}", w.address, w.port);
                if (!rvcid.empty())
                    url += std::format(";RVCID={}", rvcid);
                if (set_station_slot_seh(s_conninfo_set_url, station, target, url.c_str()) != 0)
                {
                    logger::error(std::format("station URLs: fault writing slot {}", target));
                    return;
                }
                logger::info(std::format("station URLs: slot {} {} -> '{}' ({} URL)", target,
                                         slots[target].empty() ? std::string("(empty)")
                                                               : std::format("'{}'", slots[target]),
                                         url, w.what));
                slots[target] = url;
                keep[target] = true;
            }

            if (logger::verbose())
                for (int i = 0; i < kConnInfoSlots; ++i)
                    logger::debug(std::format("station URL slot {}: '{}'", i, slots[i]));
        }

        int __fastcall hk_objdup_add_local_urls(void* self, void* /*edx*/, std::uint8_t* station)
        {
            publish_relay_url("station URLs (ObjDupProtocol::AddLocalURLs)");
            const int result = s_objdup_add_local_urls_hook.unsafe_thiscall<int>(self, station);
            ensure_station_urls(station);
            return result;
        }
    }

    auto initialize() -> bool
    {
        s_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!s_base)
        {
            logger::error("failed to get ACBMP.exe module handle");
            return false;
        }

        logger::info(std::format("ACBMP.exe loaded at {:#010x}{}", s_base,
                                 s_base == kImageBase ? " (preferred base)" : " (relocated by ASLR)"));

        // ---- data path: both or nothing --------------------------------------
        const bool send_ok = check_sig(kSendToRva, kSendToSig, "BerkeleySocket::SendTo");
        const bool recv_ok = check_sig(kCompleteBufferRecvRva, kCompleteBufferRecvSig, "QueuingSocket::CompleteBufferRecv");
        if (!send_ok || !recv_ok)
        {
            logger::error("socket hooks not installed; patch is a no-op");
            return false;
        }

        s_recv_hook = safetyhook::create_inline(reinterpret_cast<void*>(s_base + kCompleteBufferRecvRva),
                                                reinterpret_cast<void*>(&hk_complete_buffer_recv));
        s_send_to_hook = safetyhook::create_inline(reinterpret_cast<void*>(s_base + kSendToRva),
                                                   reinterpret_cast<void*>(&hk_send_to));
        if (!s_recv_hook || !s_send_to_hook)
        {
            logger::error("failed to install socket hooks; patch is a no-op");
            s_send_to_hook = {};
            s_recv_hook = {};
            return false;
        }
        logger::info(std::format("hooked BerkeleySocket::SendTo (VA {:#010x}) and QueuingSocket::CompleteBufferRecv (VA {:#010x})",
                                 kSendToRva + kImageBase, kCompleteBufferRecvRva + kImageBase));

        // ---- URL publication ---------------------------------------------------
        const bool ctor_ok = check_sig(kStationUrlCtorRva, kStationUrlCtorSig, "StationURL::StationURL(const char*)");
        const bool dtor_ok = check_sig(kStationUrlDtorRva, kStationUrlDtorSig, "StationURL::~StationURL");
        const bool add_ok = check_sig(kAddLocalUrlRva, kAddLocalUrlSig, "Network::AddLocalURL", {5});

        int publish_points = 0;
        if (ctor_ok && dtor_ok && add_ok)
        {
            s_url_ctor = reinterpret_cast<StationUrlCtorFn>(s_base + kStationUrlCtorRva);
            s_url_dtor = reinterpret_cast<StationUrlDtorFn>(s_base + kStationUrlDtorRva);

            s_add_local_url_hook = safetyhook::create_inline(reinterpret_cast<void*>(s_base + kAddLocalUrlRva),
                                                             reinterpret_cast<void*>(&hk_add_local_url));
            if (s_add_local_url_hook)
                s_add_local_url_original =
                    reinterpret_cast<AddLocalUrlFn>(s_add_local_url_hook.trampoline().address());
            else
            {
                logger::warn("could not hook Network::AddLocalURL; using it unhooked (no port/instance capture)");
                s_add_local_url_original = reinterpret_cast<AddLocalUrlFn>(s_base + kAddLocalUrlRva);
            }

            // login registration (RegisterEx): needs AddLocalURL to add our URLs
            if (check_sig(kPrepareUrlsRva, kPrepareUrlsSig, "SecureConnectionClient::PrepareURLs", {3}))
            {
                s_prepare_urls_hook =
                    safetyhook::create_mid(reinterpret_cast<void*>(s_base + kPrepareUrlsRva), mid_prepare_urls);
                publish_points += s_prepare_urls_hook ? 1 : 0;
            }
        }
        else
        {
            logger::warn("StationURL/AddLocalURL unavailable: the relay URL is not registered at login; "
                         "station/session URLs are still fixed up below");
        }

        // station + session URLs (what peers dial): independent of AddLocalURL,
        // the relay/public URLs are written straight into the station's slots
        if (check_sig(kConnInfoSetUrlRva, kConnInfoSetUrlSig, "ConnectionInfo::SetURL", {12}))
            s_conninfo_set_url = reinterpret_cast<ConnInfoSetUrlFn>(s_base + kConnInfoSetUrlRva);
        else
            logger::warn("ConnectionInfo::SetURL unavailable: relay URL is dropped on PCs with more than 4 "
                         "network interfaces, and not published at all without AddLocalURL");
        if (check_sig(kObjDupAddLocalUrlsRva, kObjDupAddLocalUrlsSig, "ObjDupProtocol::AddLocalURLs", {3, 11}))
        {
            s_objdup_add_local_urls_hook =
                safetyhook::create_inline(reinterpret_cast<void*>(s_base + kObjDupAddLocalUrlsRva),
                                          reinterpret_cast<void*>(&hk_objdup_add_local_urls));
            publish_points += s_objdup_add_local_urls_hook ? 1 : 0;
        }

        if (publish_points == 0)
            logger::error("no URL publication hook installed: peers will never learn the relay address");
        else
            logger::info(std::format("relay URL publication hooks installed: {}/2", publish_points));

        s_active = true;
        return true;
    }

    auto shutdown() -> void
    {
        if (!s_active)
            return;
        s_prepare_urls_hook = {};
        s_objdup_add_local_urls_hook = {};
        s_add_local_url_hook = {};
        s_send_to_hook = {};
        s_recv_hook = {};
        s_active = false;
    }
}
