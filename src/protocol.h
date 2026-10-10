#pragma once

// AC Relay protocol v1, owner side. See docs/PROTOCOL.md -- the wire format
// is shared with the relay server (ac-relay-server); do not change it here
// alone. Everything is big-endian. Pure functions only, no Winsock, so this
// header can also be compiled into a host-side test harness.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace ac_relay::protocol
{
    inline constexpr std::uint8_t kMagic[4] = {0x41, 0x43, 0x52, 0x4C}; // "ACRL"
    inline constexpr std::uint8_t kVersion = 1;
    inline constexpr std::size_t kHeaderSize = 6;
    inline constexpr std::uint16_t kDefaultControlPort = 21100;

    // SEND/RECV: header + u32 peer_ip + u16 peer_port
    inline constexpr std::size_t kDataOverhead = kHeaderSize + 6; // 12
    inline constexpr std::size_t kMaxDatagram = 1500;

    enum class Type : std::uint8_t
    {
        Allocate = 0x01,
        Allocated = 0x02,
        Denied = 0x03,
        Keepalive = 0x04,
        KeepaliveAck = 0x05,
        Send = 0x06,
        Recv = 0x07,
        Release = 0x08,
    };

    enum class DenyReason : std::uint8_t
    {
        BadPassword = 1,
        PoolExhausted = 2,
        BadVersion = 3,
        RateLimited = 4,
    };

    [[nodiscard]] constexpr std::string_view deny_reason_name(std::uint8_t r) noexcept
    {
        switch (r)
        {
        case 1: return "bad password";
        case 2: return "pool exhausted";
        case 3: return "bad version";
        case 4: return "rate limited / per-IP cap";
        default: return "unknown";
        }
    }

    inline void put_u16(std::uint8_t* p, std::uint16_t v) noexcept
    {
        p[0] = static_cast<std::uint8_t>(v >> 8);
        p[1] = static_cast<std::uint8_t>(v);
    }

    inline void put_u32(std::uint8_t* p, std::uint32_t v) noexcept
    {
        p[0] = static_cast<std::uint8_t>(v >> 24);
        p[1] = static_cast<std::uint8_t>(v >> 16);
        p[2] = static_cast<std::uint8_t>(v >> 8);
        p[3] = static_cast<std::uint8_t>(v);
    }

    [[nodiscard]] inline std::uint16_t get_u16(const std::uint8_t* p) noexcept
    {
        return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
    }

    [[nodiscard]] inline std::uint32_t get_u32(const std::uint8_t* p) noexcept
    {
        return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
               (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
    }

    inline void put_header(std::uint8_t* p, Type type) noexcept
    {
        std::memcpy(p, kMagic, 4);
        p[4] = kVersion;
        p[5] = static_cast<std::uint8_t>(type);
    }

    // True if the datagram carries the ACRL magic (any version/type).
    [[nodiscard]] inline bool has_magic(const std::uint8_t* p, std::size_t len) noexcept
    {
        return len >= kHeaderSize && std::memcmp(p, kMagic, 4) == 0;
    }

    // ALLOCATE: u32 nonce, u8 pwlen, pw[pwlen]. Returns bytes written, 0 if
    // the buffer is too small. Passwords longer than 255 bytes are truncated.
    [[nodiscard]] inline std::size_t encode_allocate(std::uint8_t* out, std::size_t cap, std::uint32_t nonce,
                                                     std::string_view password) noexcept
    {
        const std::size_t pwlen = password.size() > 255 ? 255 : password.size();
        const std::size_t need = kHeaderSize + 4 + 1 + pwlen;
        if (cap < need)
            return 0;
        put_header(out, Type::Allocate);
        put_u32(out + 6, nonce);
        out[10] = static_cast<std::uint8_t>(pwlen);
        if (pwlen)
            std::memcpy(out + 11, password.data(), pwlen);
        return need;
    }

    // KEEPALIVE: u32 nonce
    [[nodiscard]] inline std::size_t encode_keepalive(std::uint8_t* out, std::size_t cap, std::uint32_t nonce) noexcept
    {
        if (cap < kHeaderSize + 4)
            return 0;
        put_header(out, Type::Keepalive);
        put_u32(out + 6, nonce);
        return kHeaderSize + 4;
    }

    // RELEASE: no payload
    [[nodiscard]] inline std::size_t encode_release(std::uint8_t* out, std::size_t cap) noexcept
    {
        if (cap < kHeaderSize)
            return 0;
        put_header(out, Type::Release);
        return kHeaderSize;
    }

    // SEND header (12 bytes); the payload follows at out + kDataOverhead.
    // peer_ip / peer_port are HOST byte order.
    inline void encode_send_header(std::uint8_t* out, std::uint32_t peer_ip, std::uint16_t peer_port) noexcept
    {
        put_header(out, Type::Send);
        put_u32(out + 6, peer_ip);
        put_u16(out + 10, peer_port);
    }

    struct Allocated
    {
        std::uint32_t nonce;
        std::uint32_t relay_ip;      // host order
        std::uint16_t alloc_port;    // host order
        std::uint32_t observed_ip;   // host order
        std::uint16_t observed_port; // host order
        std::uint16_t lease_seconds;
    };

    // p/len = whole datagram, header already validated
    [[nodiscard]] inline bool parse_allocated(const std::uint8_t* p, std::size_t len, Allocated& out) noexcept
    {
        if (len < kHeaderSize + 18) // 4+4+2+4+2+2
            return false;
        p += kHeaderSize;
        out.nonce = get_u32(p);
        out.relay_ip = get_u32(p + 4);
        out.alloc_port = get_u16(p + 8);
        out.observed_ip = get_u32(p + 10);
        out.observed_port = get_u16(p + 14);
        out.lease_seconds = get_u16(p + 16);
        return true;
    }
}
