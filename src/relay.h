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

    // NAT probe bookkeeping, keyed by the requester's timestamp that the
    // reply echoes. A request that reached us via the relay is answered via
    // the relay, one that came direct is answered direct: each of the
    // peer's URLs for us gets the answer (and ping) of its own path.
    auto note_probe_request(const sockaddr_in& peer, std::uint32_t time, bool via_relay) -> void;
    // True if this reply (to peer, echoing time) must go through the relay.
    [[nodiscard]] auto route_probe_reply(const sockaddr_in& peer, std::uint32_t time) -> bool;

    // A NAT probe request the game sends directly to peer: if peer ever
    // reached us through the relay, a copy goes through the relay
    // RelayProbeDelayMs later, unless the peer reached us directly within the
    // last 3 s. So the relay URL only gets probe answers (and can only win
    // the game's URL race) when the direct path doesn't work.
    auto queue_relayed_probe_copy(const sockaddr_in& peer, const std::uint8_t* payload, std::size_t len) -> void;

    // Current allocation (host-order ip/port). If none exists yet and an
    // ALLOCATE is in flight, waits up to timeout_ms for ALLOCATED.
    [[nodiscard]] auto wait_allocation(std::uint32_t timeout_ms, std::uint32_t& relay_ip,
                                       std::uint16_t& alloc_port) -> bool;

    // Our public address as the relay saw it in the last ALLOCATED (host
    // order). False before the first allocation.
    [[nodiscard]] auto observed_address(std::uint32_t& ip, std::uint16_t& port) -> bool;
}
