#pragma once

#include <filesystem>
#include <string_view>

// version info
inline constexpr std::string_view AC_RELAY_VERSION = "0.1.0";
inline constexpr std::string_view AC_RELAY_NAME = "ac_relay";

// file names (both live next to ACBMP.exe)
inline constexpr std::string_view CONFIG_FILENAME = "ac_relay.ini";
inline constexpr std::string_view LOG_FILENAME = "ac_relay.log";

namespace ac_relay
{
    [[nodiscard]] std::filesystem::path get_base_path();
}
