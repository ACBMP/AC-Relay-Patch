#pragma once

#include <filesystem>
#include <string>

namespace ac_relay::config
{
    struct relay_settings
    {
        // master switch; false = the patch installs no hooks at all
        bool enabled = true;

        // relay control endpoint, "host:port" (port defaults to 21100).
        // Empty = not configured = no-op.
        std::string server;

        // sent in every ALLOCATE (also refreshes); empty if the relay has none
        std::string password;

        // log every relayed / control packet
        bool verbose = false;

        // Our own NAT probe requests also go through the relay this much later
        // than the direct copy, unless the peer reached us directly in the
        // meantime (then the relay copy is dropped). 0 = no wait. (Replies
        // always go back the way their request came.)
        int relay_probe_delay_ms = 80;

        // Keep each peer at one address: once a peer's connection runs on
        // one address, drop traffic to/from its other addresses (e.g. its own
        // relay URL while it already reaches us through ours). See relay.h.
        bool one_address_per_peer = true;
    };

    struct ipv6_settings
    {
        // carry game traffic over IPv6 to peers that also publish an IPv6
        // URL (docs/IPV6.md); off by itself when the PC has no global IPv6
        bool enabled = true;

        // UDP port of the IPv6 socket; 0 = random. Taken: falls back to random.
        int port = 0;

        // Reach peers that have an IPv6 URL over IPv6 only: their IPv4
        // addresses (incl. relay URLs) are hidden from the game unless IPv6 to
        // them stays unanswered for 5 s.
        bool prefer = false;
    };

    struct settings
    {
        relay_settings relay;
        ipv6_settings ipv6;
    };

    [[nodiscard]] auto initialize(const std::filesystem::path& config_path) -> bool;
    [[nodiscard]] auto load() -> bool;
    [[nodiscard]] auto save() -> bool;
    [[nodiscard]] auto get() -> settings&;
    [[nodiscard]] auto exists() -> bool;
    [[nodiscard]] auto get_path() -> const std::filesystem::path&;
}
