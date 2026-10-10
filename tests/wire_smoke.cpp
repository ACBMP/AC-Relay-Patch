// Host-side (Linux) smoke test: drives a running ac-relay-server with the
// patch's own encoder/decoder from src/protocol.h. Not part of the .asi build.
//   g++ -std=c++20 -I src tests/wire_smoke.cpp -o /tmp/wire_smoke
//   ac-relay --public-ip 127.0.0.1 --password pw &   /tmp/wire_smoke 127.0.0.1 21100 pw
#include "protocol.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace p = ac_relay::protocol;

static int udp(uint16_t* port_out)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (sockaddr*)&a, sizeof(a));
    socklen_t l = sizeof(a);
    getsockname(s, (sockaddr*)&a, &l);
    *port_out = ntohs(a.sin_port);
    timeval tv{2, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return s;
}

static int rx(int s, uint8_t* buf, size_t cap, sockaddr_in* from = nullptr)
{
    sockaddr_in f{};
    socklen_t l = sizeof(f);
    int n = (int)recvfrom(s, buf, cap, 0, (sockaddr*)&f, &l);
    if (from) *from = f;
    return n;
}

#define CHECK(c) do { if (!(c)) { std::printf("FAIL: %s (line %d)\n", #c, __LINE__); return 1; } } while (0)

int main(int argc, char** argv)
{
    if (argc < 3) { std::printf("usage: %s relay_ip control_port [password]\n", argv[0]); return 2; }
    sockaddr_in relay{};
    relay.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &relay.sin_addr);
    relay.sin_port = htons((uint16_t)std::atoi(argv[2]));
    const char* pw = argc > 3 ? argv[3] : "";

    uint16_t owner_port, peer_port;
    int owner = udp(&owner_port), peer = udp(&peer_port);
    uint8_t b[2048];

    // ALLOCATE -> ALLOCATED
    size_t n = p::encode_allocate(b, sizeof(b), 0x11223344, pw);
    sendto(owner, b, n, 0, (sockaddr*)&relay, sizeof(relay));
    int r = rx(owner, b, sizeof(b));
    CHECK(r > 0 && p::has_magic(b, r) && b[4] == p::kVersion);
    CHECK(b[5] == (uint8_t)p::Type::Allocated);
    p::Allocated a{};
    CHECK(p::parse_allocated(b, r, a));
    CHECK(a.nonce == 0x11223344 && a.alloc_port != 0 && a.observed_port == owner_port);
    std::printf("ALLOCATED port %u lease %u observed port %u\n", a.alloc_port, a.lease_seconds, a.observed_port);

    // KEEPALIVE -> KEEPALIVE_ACK
    n = p::encode_keepalive(b, sizeof(b), 0x55667788);
    sendto(owner, b, n, 0, (sockaddr*)&relay, sizeof(relay));
    r = rx(owner, b, sizeof(b));
    CHECK(r >= 12 && b[5] == (uint8_t)p::Type::KeepaliveAck && p::get_u32(b + 6) == 0x55667788 && p::get_u16(b + 10) > 0);

    // peer -> alloc port -> RECV at owner
    sockaddr_in alloc = relay;
    alloc.sin_port = htons(a.alloc_port);
    const char msg[] = "hello-from-peer";
    sendto(peer, msg, sizeof(msg), 0, (sockaddr*)&alloc, sizeof(alloc));
    r = rx(owner, b, sizeof(b));
    CHECK(r == (int)(p::kDataOverhead + sizeof(msg)) && b[5] == (uint8_t)p::Type::Recv);
    CHECK(p::get_u32(b + 6) == INADDR_LOOPBACK && p::get_u16(b + 10) == peer_port);
    CHECK(std::memcmp(b + p::kDataOverhead, msg, sizeof(msg)) == 0);

    // SEND -> peer receives payload from alloc port
    const char reply[] = "hello-from-owner";
    p::encode_send_header(b, INADDR_LOOPBACK, peer_port);
    std::memcpy(b + p::kDataOverhead, reply, sizeof(reply));
    sendto(owner, b, p::kDataOverhead + sizeof(reply), 0, (sockaddr*)&relay, sizeof(relay));
    sockaddr_in from{};
    r = rx(peer, b, sizeof(b), &from);
    CHECK(r == (int)sizeof(reply) && std::memcmp(b, reply, sizeof(reply)) == 0 && ntohs(from.sin_port) == a.alloc_port);

    // RELEASE, then SEND from an unknown owner -> KEEPALIVE_ACK nonce 0 lease 0
    n = p::encode_release(b, sizeof(b));
    sendto(owner, b, n, 0, (sockaddr*)&relay, sizeof(relay));
    usleep(100000);
    p::encode_send_header(b, INADDR_LOOPBACK, peer_port);
    std::memcpy(b + p::kDataOverhead, reply, sizeof(reply));
    sendto(owner, b, p::kDataOverhead + sizeof(reply), 0, (sockaddr*)&relay, sizeof(relay));
    r = rx(owner, b, sizeof(b));
    CHECK(r >= 12 && b[5] == (uint8_t)p::Type::KeepaliveAck && p::get_u16(b + 10) == 0);
    std::printf("unknown-owner SEND -> KEEPALIVE_ACK nonce %08x lease 0\n", p::get_u32(b + 6));

    std::printf("OK\n");
    return 0;
}
