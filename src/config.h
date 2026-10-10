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
    };

    struct settings
    {
        relay_settings relay;
    };

    [[nodiscard]] auto initialize(const std::filesystem::path& config_path) -> bool;
    [[nodiscard]] auto load() -> bool;
    [[nodiscard]] auto save() -> bool;
    [[nodiscard]] auto get() -> settings&;
    [[nodiscard]] auto exists() -> bool;
    [[nodiscard]] auto get_path() -> const std::filesystem::path&;
}
