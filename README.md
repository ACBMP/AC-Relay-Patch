# AC Relay

AC Relay is a standalone ASI patch for **Assassin's Creed Brotherhood
multiplayer** (`ACBMP.exe`, 32-bit Windows, also under Wine/Proton). It lets
peer-to-peer (Quazal PRUDP) traffic go through a UDP relay server when two
players' NATs can't reach each other directly.

It does one thing: client-side ("owner") support for the AC Relay protocol
in [docs/PROTOCOL.md](docs/PROTOCOL.md). The relay server is a separate
project, `ac-relay-server`.

## What it does

1. **Allocates a port on your relay.** It finds the game's own PRUDP UDP
   socket and sends `ALLOCATE` *from that socket*, so the relay and the
   game share one NAT mapping. It then sends `KEEPALIVE` every 15 s and
   re-allocates when the relay reports lease 0 or goes silent.
2. **Publishes the relay as one of your own addresses.** It adds
   `prudp:/address=<relay_ip>;port=<alloc_port>` to the game's local
   station URL list, next to your per-interface URLs. The game then stamps
   its usual RVCID on it, registers it with the RDV server, and hands it to
   other players. Their games probe it like any other address, and the
   game's own probe race (lowest ping wins) picks direct or relayed per
   peer. No game logic is changed.
3. **Unwraps and wraps traffic.**
   - A datagram from the relay with `RECV` is unwrapped and handed to the
     game as if it came from the original peer. That peer is remembered as
     "via relay".
   - Relay control replies (`ALLOCATED`, `DENIED`, `KEEPALIVE_ACK`) are
     consumed and never reach the game.
   - Sends to a peer whose last datagram came via the relay are wrapped as
     `SEND` and go to the relay from the same socket. Everything else
     passes through untouched.
4. **Fails safe.** With `Enabled=false`, no `Server`, an unresolvable
   server, an unreachable relay, or a game build whose bytes don't match,
   it installs nothing or passes everything through. Players without the
   patch can still reach you directly, and they can reach your relayed URL
   too, because the relay forwards raw game packets.

Only the player whose NAT is the problem needs a relay. Peers don't need
the patch to *reach* a relayed player.

## Install

1. You need an ASI loader, as with acb2 (for example Ultimate ASI Loader
   as `dinput8.dll` next to `ACBMP.exe`).
2. Copy `ac_relay.asi` and `ac_relay.ini` next to `ACBMP.exe`.
3. Set `Server=` to your relay. Start the game. Check `ac_relay.log` next
   to `ACBMP.exe`.

If `ac_relay.ini` is missing, a commented default is written on first start
(with `Server` empty, which means off).

### ac_relay.ini

```ini
[Relay]
; false = ac_relay.asi does nothing at all
Enabled=true
; relay control endpoint host:port (port defaults to 21100); empty = off
Server=relay.example.org:21100
; relay password, if the relay was started with --password
Password=
; log every relayed/control packet to ac_relay.log
Verbose=false
```

### What the log tells you

- `relay: server ... resolved`, then `captured game UDP socket ... (local port N)`
- `relay: ALLOCATED <relay_ip>:<port> (we appear as <ip>:<port>, lease 60 s)`
- `published relay URL 'prudp:/address=...;port=...' as a local station URL`
- `relay: peer a.b.c.d:p path direct -> RELAY` / `RELAY -> direct`
- `relay stats: ...` every 60 s
- `DENIED`:
  - `bad password` / `bad version`: the patch gives up and passes
    everything through. Fix the ini.
  - `pool exhausted` / `rate limited`: it retries with backoff from 5 s up
    to 60 s.

## Coexisting with acb2

AC Relay can be loaded next to acb2's `patch.asi`. It hooks only Quazal
networking functions that acb2 does not touch:

| function | ACBMP.exe VA | RVA |
|---|---|---|
| `BerkeleySocket::SendTo` | `0x01cc08c0` | `0x018c08c0` |
| `QueuingSocket::CompleteBufferRecv` | `0x01cc1540` | `0x018c1540` |
| `Network::AddLocalURL` | `0x01d1cba0` | `0x0191cba0` |
| `SecureConnectionClient::PrepareURLs` (entry) | `0x01d3dba0` | `0x0193dba0` |
| `ObjDupProtocol::AddLocalURLs` (entry) | `0x01ab5d50` | `0x016b5d50` |

None of these RVAs or VAs appear on any acb2 branch (checked with grep).
Only one SafetyHook can sit on any address, so if a future acb2 module
wants one of them, it has to call into this patch's hook instead of
installing a second one there.

Every hook checks a byte signature first and skips the hook if the bytes
don't match.

## Build

The real build is MSVC (Visual Studio 2026) on Windows:

```bat
build_windows.bat            :: -> build\bin\Release\ac_relay.asi
```

`build_linux.sh` cross-compiles with clang-cl in Docker (the same `llwin`
image acb2 uses). **It is only a compile check.** clang-cl accepts code
that real MSVC rejects (for example C2712, `__try` next to objects with
destructors), and acb2 found that the `.asi` it produces doesn't run
in-game.

`tests/wire_smoke.cpp` is a host-side Linux test of `src/protocol.h`
against a running `ac-relay-server`. See the comment at the top of the file.

## Docs

- [docs/PROTOCOL.md](docs/PROTOCOL.md): wire protocol (shared with the
  server; don't change it here alone)
- [docs/RE_NOTES.md](docs/RE_NOTES.md): every game address used, the
  evidence for it, and what is still unverified
