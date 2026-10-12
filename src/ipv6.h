#pragma once

#include "config.h"

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>

#include <cstddef>
#include <cstdint>
#include <string>

// IPv6 transport for the game's IPv4-only PRUDP. See docs/IPV6.md.
//
// The game can't hold an IPv6 address (Quazal InetAddress = sockaddr_in), so
// every IPv6 peer gets a VIRTUAL IPv4 in 240.0.0.0/4: a hash of its IPv6
// address and port, identical on every machine. Stations publish
//   prudp:/address=<vaddr>;port=<v6 port>;v6=<32 hex digits>
// and the game carries the unknown v6 param through Parse/Format unchanged.
// A hook on StationURL::Parse feeds every URL string to learn_url(), which
// records vaddr -> [v6]:port.
//
// Data path: the game sends to vaddr:port; the SendTo hook redirects the
// datagram (framed, see below) to an in-process gateway on 127.0.0.1, which
// forwards it over an AF_INET6 socket. Datagrams arriving on that socket are
// framed and sent to the game's socket over loopback; the CompleteBufferRecv
// hook strips the frame and rewrites the source to vaddr:port.
//
// Loopback frame (both directions), big-endian:
//   [0..3] "ACV6"  [4] kind (1 game->peer, 2 peer->game)  [5] 0
//   [6..9] vaddr   [10..11] port   [12..19] per-process token
//   [20..] the game's datagram
namespace ac_relay::ipv6
{
    inline constexpr std::size_t kFrameOverhead = 20;
    inline constexpr std::uint8_t kKindToPeer = 1;
    inline constexpr std::uint8_t kKindToGame = 2;

    // Picks the OS-preferred global IPv6 source, binds the IPv6 and gateway
    // sockets and starts the worker. False = no usable IPv6 (feature off).
    [[nodiscard]] auto initialize(const config::ipv6_settings& settings) -> bool;
    auto shutdown() -> void;
    [[nodiscard]] auto active() -> bool;

    // The game's main PRUDP socket (frames to the game go to its address).
    auto set_game_socket(SOCKET s) -> void;

    // addr (network order) is in 240.0.0.0/4, i.e. a virtual IPv6 peer.
    [[nodiscard]] auto is_virtual(const sockaddr_in& addr) -> bool;
    // The gateway's loopback address (network order).
    [[nodiscard]] auto gateway_address() -> sockaddr_in;
    [[nodiscard]] auto is_gateway_address(const sockaddr_in& addr) -> bool;

    // Writes a game->peer frame header for dest (network order) into out
    // (>= kFrameOverhead bytes); the payload follows at out + kFrameOverhead.
    auto encode_to_peer(std::uint8_t* out, const sockaddr_in& dest) -> void;
    // A peer->game frame from the gateway: fills peer (network order) and
    // returns true if magic, kind and token match.
    [[nodiscard]] auto decode_to_game(const std::uint8_t* data, std::size_t len, sockaddr_in& peer) -> bool;

    // Our station URL for the IPv6 path ("prudp:/address=..;port=..;v6=..").
    // False if inactive.
    [[nodiscard]] auto local_url(std::string& url, std::string& vaddr_text, std::uint16_t& port) -> bool;

    // Every StationURL string the game parses: v6 URLs give vaddr -> [v6]:port;
    // with Prefer also the station (RVCID) behind each IPv4 URL.
    auto learn_url(const char* url) -> void;

    // [IPv6] Prefer: addr (network order) is an IPv4 address of a station
    // that published an IPv6 URL, so the hooks drop traffic to/from it and
    // the game can only connect over IPv6. False again once IPv6 to that
    // station stays unanswered for 5 s (fallback to IPv4 / the relay).
    // direction is only for the log ("to" / "from").
    // A NAT probe from addr names its sender's RVCID: covers IPv4 URLs that
    // reached us without one (e.g. from the lobby).
    auto note_probe_sender(const sockaddr_in& addr, std::uint32_t rvcid) -> void;
    [[nodiscard]] auto hide_ipv4(const sockaddr_in& addr, const char* direction) -> bool;
}
