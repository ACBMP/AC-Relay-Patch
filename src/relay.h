#pragma once

#include "config.h"

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>

#include <cstddef>
#include <cstdint>

// Owner-side relay session: allocation state machine, keepalives, per-peer
// path table. Game-agnostic -- game_hooks.cpp feeds it the game's UDP
// socket and the datagrams it sees.
namespace ac_relay::relay
{
    // Resolves Server and starts the keepalive worker. Returns false (and the
    // patch stays a no-op) if Server is unset or can't be resolved.
    [[nodiscard]] auto initialize(const config::relay_settings& settings) -> bool;
    auto shutdown() -> void;

    // The game's PRUDP socket was found (or replaced). Resets the allocation
    // if the socket changed; the worker then sends ALLOCATE from it.
    auto set_game_socket(SOCKET s, std::uint16_t local_port) -> void;
    [[nodiscard]] auto game_socket() -> SOCKET;

    // Relay control address (network-order sockaddr_in), fixed after initialize().
    [[nodiscard]] auto server_address() -> sockaddr_in;

    // True if addr (network-order sockaddr_in) is the relay control address.
    [[nodiscard]] auto is_relay_address(const sockaddr_in& addr) -> bool;

    // A non-RECV control datagram from the relay (ALLOCATED, DENIED,
    // KEEPALIVE_ACK, ...). data/len = whole datagram incl. header.
    auto handle_control(const std::uint8_t* data, std::size_t len) -> void;

    // Path bookkeeping. peer = network-order sockaddr_in of the remote peer.
    // session = the datagram is connection traffic, not a NAT probe; only
    // connection traffic decides a peer's path (probes arrive both ways while
    // the game races its URLs, and must not flip an established connection).
    auto note_relay_recv(const sockaddr_in& peer, std::size_t payload_len, bool session) -> void;
    auto note_direct_recv(const sockaddr_in& peer, bool session) -> void;
    // Whether connection traffic to peer goes through the relay: the path its
    // connection traffic last came on; before there is any, direct if we've
    // heard from the peer directly in the last 15 s, else relay if it ever
    // reached us through the relay.
    [[nodiscard]] auto should_relay(const sockaddr_in& peer) -> bool;
    auto note_relay_send(const sockaddr_in& peer, std::size_t payload_len) -> void;

    // A NAT probe datagram the game sends directly to peer: if peer ever
    // reached us through the relay, also send a copy through the relay
    // RelayProbeDelayMs later, so both of the peer's URLs for us get an answer
    // and the direct one, when it works, answers first.
    auto queue_relayed_probe_copy(const sockaddr_in& peer, const std::uint8_t* payload, std::size_t len) -> void;

    // Current allocation (host-order ip/port). If none exists yet and an
    // ALLOCATE is in flight, waits up to timeout_ms for ALLOCATED.
    [[nodiscard]] auto wait_allocation(std::uint32_t timeout_ms, std::uint32_t& relay_ip,
                                       std::uint16_t& alloc_port) -> bool;

    // Our public address as the relay saw it in the last ALLOCATED (host
    // order). False before the first allocation.
    [[nodiscard]] auto observed_address(std::uint32_t& ip, std::uint16_t& port) -> bool;
}
