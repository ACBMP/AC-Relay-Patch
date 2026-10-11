#pragma once

// Logs fatal exceptions (access violation, stack overflow, ...) in the game
// process to ac_relay.log with module+offset, the ACBMP.exe Ghidra VA, the
// registers and the code addresses found on the stack. Also logs the exits that
// raise no exception: the CRT's /GS, invalid-parameter and abort() paths
// (kernel32!UnhandledExceptionFilter), pure virtual calls (ExitProcess),
// TerminateProcess on ourselves, and anything reaching the game's own
// top-level filter. Diagnostics only: it never handles an exception, the game
// crashes exactly as it would without it.
namespace ac_relay::crash_log
{
    auto install() -> void;
}
