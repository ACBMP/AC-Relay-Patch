#include "ac_relay.h"
#include "config.h"
#include "crash_log.h"
#include "game_hooks.h"
#include "logger.h"
#include "relay.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <filesystem>
#include <format>
#include <string>

namespace
{
    [[nodiscard]] bool is_target_process()
    {
        wchar_t module_path[MAX_PATH];
        if (GetModuleFileNameW(nullptr, module_path, MAX_PATH) == 0)
            return false;

        const wchar_t* filename = wcsrchr(module_path, L'\\');
        filename = filename ? filename + 1 : module_path;

        // only inject into the multiplayer executable
        return _wcsicmp(filename, L"ACBMP.exe") == 0;
    }

    void init()
    {
        const auto base_path = ac_relay::get_base_path();
        const auto config_path = base_path / std::string(CONFIG_FILENAME);

        if (!ac_relay::config::initialize(config_path))
            return;

        if (ac_relay::config::exists())
            (void)ac_relay::config::load();
        else
            (void)ac_relay::config::save(); // write a commented default ini

        const auto& settings = ac_relay::config::get().relay;

        if (!ac_relay::logger::initialize(base_path / std::string(LOG_FILENAME), settings.verbose))
            return; // no log, but also nothing else: stay a no-op

        ac_relay::logger::info(std::format("base path: {}", base_path.string()));
        ac_relay::crash_log::install();

        if (!settings.enabled)
        {
            ac_relay::logger::info("[Relay] Enabled=false: no hooks installed");
            return;
        }

        // Resolve the relay before touching the game: unconfigured or
        // unresolvable = install nothing.
        if (!ac_relay::relay::initialize(settings))
            return;

        if (!ac_relay::game_hooks::initialize())
        {
            ac_relay::relay::shutdown();
            return;
        }

        ac_relay::logger::info("initialization complete");
    }

    // Same as acb2: DLL_PROCESS_ATTACH runs under the loader lock, so all real
    // work happens on a separate thread after a short delay.
    constexpr DWORD kStartupDelayMs = 1000;

    DWORD WINAPI init_thread(LPVOID)
    {
        Sleep(kStartupDelayMs);
        init();
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, [[maybe_unused]] LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        if (!is_target_process())
            return TRUE;

        if (HANDLE h = CreateThread(nullptr, 0, init_thread, nullptr, 0, nullptr))
            CloseHandle(h);
        break;

    case DLL_PROCESS_DETACH:
        ac_relay::game_hooks::shutdown();
        ac_relay::relay::shutdown();
        ac_relay::logger::shutdown();
        break;
    }
    return TRUE;
}

namespace ac_relay
{
    std::filesystem::path get_base_path()
    {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        return std::filesystem::path(path).parent_path();
    }
}
