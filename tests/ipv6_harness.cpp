// Two-process end-to-end check of src/ipv6.cpp without the game (run under
// Wine or on Windows, needs global IPv6):
//
//   ipv6_harness.exe A <dir>  &  ipv6_harness.exe B <dir>
//
// Each process plays one station: a UDP "game socket" on 0.0.0.0, the IPv6
// module, its URL written to <dir>/<role>.url. It learns the other's URL
// the way the StationURL::Parse hook would (with the RVCID the game appends),
// sends one framed datagram through its gateway and expects the other's
// datagram to arrive on its game socket from the gateway, with the source
// the other's virtual address. Prints PASS/FAIL.
//
// Build: i686-w64-mingw32-g++ -std=c++23 -O1 -static -Isrc tests/ipv6_harness.cpp src/ipv6.cpp -lws2_32

#include "ipv6.h"
#include "logger.h"

#include <WS2tcpip.h>
#include <Windows.h>

#include <cstdio>
#include <filesystem>
#include <string_view>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace ac_relay::logger
{
    auto initialize(const std::filesystem::path&, bool) -> bool { return true; }
    auto shutdown() -> void {}
    auto verbose() -> bool { return true; }
    auto debug(std::string_view m) -> void { std::printf("  [debug] %.*s\n", (int)m.size(), m.data()); }
    auto info(std::string_view m) -> void { std::printf("  [info] %.*s\n", (int)m.size(), m.data()); }
    auto warn(std::string_view m) -> void { std::printf("  [warn] %.*s\n", (int)m.size(), m.data()); }
    auto error(std::string_view m) -> void { std::printf("  [error] %.*s\n", (int)m.size(), m.data()); }
}

namespace
{
    std::string param(const std::string& url, const std::string& key)
    {
        const auto at = url.find(key + "=");
        if (at == std::string::npos)
            return {};
        const auto start = at + key.size() + 1;
        return url.substr(start, url.find(';', start) - start);
    }

    int fail(const char* why)
    {
        std::printf("FAIL: %s\n", why);
        std::fflush(stdout);
        return 1;
    }
}

int main(int argc, char** argv)
{
    using namespace ac_relay;
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc != 3)
        return fail("usage: ipv6_harness A|B <dir>");
    const std::string role = argv[1], peer_role = role == "A" ? "B" : "A", dir = argv[2];

    config::ipv6_settings cfg;
    if (!ipv6::initialize(cfg))
        return fail("ipv6::initialize (no global IPv6?)");

    const SOCKET game = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in any{};
    any.sin_family = AF_INET;
    bind(game, reinterpret_cast<sockaddr*>(&any), sizeof(any));
    ipv6::set_game_socket(game);

    std::string url, vaddr;
    std::uint16_t port = 0;
    if (!ipv6::local_url(url, vaddr, port))
        return fail("local_url");
    std::ofstream(dir + "/" + role + ".url.tmp") << url;
    MoveFileA((dir + "/" + role + ".url.tmp").c_str(), (dir + "/" + role + ".url").c_str());
    std::printf("%s publishes %s\n", role.c_str(), url.c_str());

    std::string peer_url;
    for (int i = 0; i < 100 && peer_url.empty(); ++i, Sleep(100))
        std::getline(std::ifstream(dir + "/" + peer_role + ".url"), peer_url);
    if (peer_url.empty())
        return fail("peer URL never appeared");

    // what a peer's URL looks like after the game stamped it (Format order)
    ipv6::learn_url((peer_url + ";RVCID=305419896").c_str());
    ipv6::learn_url(url.c_str()); // our own URL gets parsed too; must be harmless
    ipv6::learn_url("prudp:/address=240.1.2.3;port=1;v6=20010db8000000000000000000000001"); // bad hash: ignored

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    inet_pton(AF_INET, param(peer_url, "address").c_str(), &peer.sin_addr);
    peer.sin_port = htons(static_cast<std::uint16_t>(std::stoi(param(peer_url, "port"))));
    if (!ipv6::is_virtual(peer))
        return fail("peer address not in 240/4");

    // what the SendTo hook does
    const std::string text = "hello from " + role;
    std::uint8_t frame[256];
    ipv6::encode_to_peer(frame, peer);
    std::memcpy(frame + ipv6::kFrameOverhead, text.data(), text.size());
    const sockaddr_in gw = ipv6::gateway_address();
    // twice the IPv6 probe ritual: the first copy can hit the other side's
    // firewall before it has sent anything (both run on one host here, so
    // it won't, but keep the shape of the real exchange)
    for (int i = 0; i < 3; ++i, Sleep(200))
        sendto(game, reinterpret_cast<const char*>(frame), static_cast<int>(ipv6::kFrameOverhead + text.size()), 0,
               reinterpret_cast<const sockaddr*>(&gw), sizeof(gw));
    // to an address nobody published: must be dropped by the gateway
    sockaddr_in unknown = peer;
    unknown.sin_addr.s_addr = htonl(0xF1234567);
    ipv6::encode_to_peer(frame, unknown);
    sendto(game, reinterpret_cast<const char*>(frame), static_cast<int>(ipv6::kFrameOverhead + text.size()), 0,
           reinterpret_cast<const sockaddr*>(&gw), sizeof(gw));

    // what the CompleteBufferRecv hook does
    DWORD timeout = 5000;
    setsockopt(game, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    std::uint8_t in[2048];
    sockaddr_in from{};
    int fl = sizeof(from);
    const int n = recvfrom(game, reinterpret_cast<char*>(in), sizeof(in), 0, reinterpret_cast<sockaddr*>(&from), &fl);
    if (n <= 0)
        return fail("nothing arrived on the game socket");
    if (!ipv6::is_gateway_address(from))
        return fail("datagram did not come from the gateway");
    sockaddr_in src{};
    if (!ipv6::decode_to_game(in, static_cast<std::size_t>(n), src))
        return fail("decode_to_game rejected the frame");
    if (src.sin_addr.s_addr != peer.sin_addr.s_addr || src.sin_port != peer.sin_port)
        return fail("source is not the peer's published virtual address");
    const std::string got(reinterpret_cast<char*>(in) + ipv6::kFrameOverhead, n - ipv6::kFrameOverhead);
    if (got != "hello from " + peer_role)
        return fail("payload mismatch");

    in[13] ^= 1; // token
    if (ipv6::decode_to_game(in, static_cast<std::size_t>(n), src))
        return fail("frame with a wrong token accepted");

    std::printf("PASS %s: got '%s' from %s:%u (peer's virtual address)\n", role.c_str(), got.c_str(),
                param(peer_url, "address").c_str(), ntohs(src.sin_port));
    Sleep(1500); // let the peer finish receiving
    return 0;
}
