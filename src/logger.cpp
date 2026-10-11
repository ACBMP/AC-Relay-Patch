#include "logger.h"
#include "ac_relay.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <format>
#include <memory>
#include <string>
#include <system_error>

namespace ac_relay::logger
{
    namespace
    {
        std::shared_ptr<spdlog::logger> s_logger;
        bool s_verbose = false;
    }

    auto initialize(const std::filesystem::path& log_path, bool verbose) -> bool
    {
        s_verbose = verbose;

        // keep the previous runs' logs: ac_relay.log.1 (newest) .. .5
        {
            constexpr int kKeep = 5;
            std::error_code ec;
            auto numbered = [&](int i) { return std::filesystem::path(log_path.string() + "." + std::to_string(i)); };
            std::filesystem::remove(numbered(kKeep), ec);
            for (int i = kKeep - 1; i >= 1; --i)
                std::filesystem::rename(numbered(i), numbered(i + 1), ec);
            std::filesystem::rename(log_path, numbered(1), ec);
        }

        try
        {
            s_logger = spdlog::basic_logger_mt("ac_relay", log_path.string(), true);
            s_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
            s_logger->flush_on(spdlog::level::debug);
            s_logger->set_level(verbose ? spdlog::level::debug : spdlog::level::info);

            s_logger->info("logger initialized");
            s_logger->info(std::format("{} v{}", AC_RELAY_NAME, AC_RELAY_VERSION));
            s_logger->info(std::format("verbose (per-packet) logging: {}", verbose ? "on" : "off"));
            return true;
        }
        catch (const spdlog::spdlog_ex&)
        {
            return false;
        }
    }

    auto shutdown() -> void
    {
        if (s_logger)
        {
            s_logger->info("logger shutting down");
            s_logger->flush();
            spdlog::drop("ac_relay");
            s_logger.reset();
        }
    }

    auto verbose() -> bool
    {
        return s_verbose && s_logger;
    }

    auto debug(std::string_view message) -> void
    {
        if (s_logger)
            s_logger->debug(message);
    }

    auto info(std::string_view message) -> void
    {
        if (s_logger)
            s_logger->info(message);
    }

    auto warn(std::string_view message) -> void
    {
        if (s_logger)
            s_logger->warn(message);
    }

    auto error(std::string_view message) -> void
    {
        if (s_logger)
            s_logger->error(message);
    }
}
