#pragma once

#include <filesystem>
#include <string_view>

namespace ac_relay::logger
{
    [[nodiscard]] auto initialize(const std::filesystem::path& log_path, bool verbose) -> bool;
    auto shutdown() -> void;

    [[nodiscard]] auto verbose() -> bool;

    auto debug(std::string_view message) -> void;
    auto info(std::string_view message) -> void;
    auto warn(std::string_view message) -> void;
    auto error(std::string_view message) -> void;
}
