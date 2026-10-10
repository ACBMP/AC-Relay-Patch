#pragma once

// ACBMP.exe hooks: socket send/receive interception and relay URL
// publication. See docs/RE_NOTES.md for every address and the evidence.
namespace ac_relay::game_hooks
{
    // Installs all hooks. Returns false (and installs nothing) if the
    // socket hooks can't be installed -- the patch is then a no-op.
    [[nodiscard]] auto initialize() -> bool;
    auto shutdown() -> void;
}
