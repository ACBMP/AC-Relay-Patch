#include "config.h"
#include "logger.h"

#define INIPP_IMPLEMENTATION
#include <inipp/inipp.h>

#include <algorithm>
#include <format>
#include <fstream>

namespace ac_relay::config
{
    namespace
    {
        settings s_settings;
        std::filesystem::path s_config_path;
        bool s_initialized = false;

        [[nodiscard]] constexpr bool parse_bool(std::string_view str) noexcept
        {
            return str == "true" || str == "1" || str == "yes";
        }
    }

    auto initialize(const std::filesystem::path& config_path) -> bool
    {
        s_config_path = config_path;
        s_initialized = true;
        s_settings = {};
        return true;
    }

    auto load() -> bool
    {
        if (!s_initialized || !exists())
            return false;

        try
        {
            std::ifstream file(s_config_path);
            if (!file.is_open())
                return false;

            inipp::Ini<char> ini;
            ini.parse(file);

            auto& sec = ini.sections["Relay"];
            if (std::string v; inipp::get_value(sec, "Enabled", v))
                s_settings.relay.enabled = parse_bool(v);
            inipp::get_value(sec, "Server", s_settings.relay.server);
            inipp::get_value(sec, "Password", s_settings.relay.password);
            if (std::string v; inipp::get_value(sec, "Verbose", v))
                s_settings.relay.verbose = parse_bool(v);
            if (std::string v; inipp::get_value(sec, "RelayProbeDelayMs", v))
            {
                try
                {
                    s_settings.relay.relay_probe_delay_ms = std::clamp(std::stoi(v), 0, 1000);
                }
                catch (const std::exception&)
                {
                }
            }

            return true;
        }
        catch (const std::exception& e)
        {
            logger::error(std::format("failed to load config: {}", e.what()));
            return false;
        }
    }

    auto save() -> bool
    {
        if (!s_initialized)
            return false;

        try
        {
            std::ofstream file(s_config_path);
            if (!file.is_open())
                return false;

            file << "[Relay]\n";
            file << "; false = ac_relay.asi does nothing at all\n";
            file << std::format("Enabled={}\n", s_settings.relay.enabled ? "true" : "false");
            file << "; relay control endpoint host:port (port defaults to 21100); empty = off\n";
            file << std::format("Server={}\n", s_settings.relay.server);
            file << "; relay password, if the relay was started with --password\n";
            file << std::format("Password={}\n", s_settings.relay.password);
            file << "; log every relayed/control packet to ac_relay.log\n";
            file << std::format("Verbose={}\n", s_settings.relay.verbose ? "true" : "false");
            file << "; wait (ms) before a NAT probe reply also goes via the relay; skipped if the peer reached us directly\n";
            file << std::format("RelayProbeDelayMs={}\n", s_settings.relay.relay_probe_delay_ms);
            return true;
        }
        catch (const std::exception& e)
        {
            logger::error(std::format("failed to save config: {}", e.what()));
            return false;
        }
    }

    auto get() -> settings&
    {
        return s_settings;
    }

    auto exists() -> bool
    {
        std::error_code ec;
        return std::filesystem::exists(s_config_path, ec);
    }

    auto get_path() -> const std::filesystem::path&
    {
        return s_config_path;
    }
}
