#pragma once

// Logs fatal exceptions (access violation, stack overflow, ...) in the game
// process to ac_relay.log with module+offset, the ACBMP.exe Ghidra VA, the
// registers and the code addresses found on the stack. Diagnostics only: it
// never handles an exception, the game crashes exactly as it would without it.
namespace ac_relay::crash_log
{
    auto install() -> void;
}
