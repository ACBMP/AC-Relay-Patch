# IPv6 for ACB multiplayer: investigation + design

Status 2026-10-12: **implemented, not tested in game.** Code: `src/ipv6.*`, plus
the IPv6 branches in `src/game_hooks.cpp` (SendTo, CompleteBufferRecv, and a new
mid-hook on `StationURL::Parse` at VA 0x01d082f0), the IPv6 slot in the station
URLs, and the `[IPv6]` ini section. The clang-cl build is clean.
`tests/ipv6_harness.cpp` runs two processes under Wine. Each learns the other's
URL, and datagrams go game socket -> gateway -> real IPv6 -> gateway -> game
socket with the virtual source. Both sides pass. The lobby side is in
acb-rdv-py `caller_candidates`, which now keeps `v6=`.

Measured on the dev box (Vodafone cable) against patrick.munni.ch (now with
IPv6): unsolicited inbound IPv6 UDP is dropped, and replies after our own send
get through. So the firewall is stateful, and the game's two-way probes open it.

## TL;DR

- The game cannot speak IPv6 itself. Quazal's `InetAddress` is a 32-bit
  `sockaddr_in`, sockets are created with `AF_INET`, and lengths are hardcoded to 16.
  Patching that is out of scope.
- It can be **carried** over IPv6 by this ASI with the mechanism the relay already
  uses. Each IPv6 peer gets a **virtual IPv4** (`240.0.0.0/4`). SendTo to a virtual
  address goes to an in-process gateway that forwards it over an `AF_INET6` socket.
  Datagrams that arrive on that socket are handed back to the game's socket with
  the source rewritten in `CompleteBufferRecv`.
- **Address exchange:** a station publishes
  `prudp:/address=<vaddr>;port=<p>;v6=<32 hex>` (plus the RVCID the game stamps).
  `vaddr = 240/4 | hash28(v6addr, port)` is **deterministic**, so every peer derives
  the same vaddr from the same IPv6 endpoint. Receivers learn `vaddr -> [v6]:port`
  by hooking `StationURL::Parse`.
- It must live in **this ASI** and not a second one, because it needs the same hook
  RVAs (SendTo, CompleteBufferRecv, AddLocalURL/AddLocalURLs slots). Only one hook
  can sit on each RVA.
- IPv4-only peers still need the relay. This design only adds a path for pairs where
  both have IPv6, which is the DS-Lite/CGNAT case (e.g. Vodafone cable, which this
  dev box is on: `2a02:8071::/32`).

## RE findings (new; extends RE_NOTES.md)

Mac = acbmp_sf.exe (symbols). Win = ACBMP.exe VA (RVA = VA - 0x00400000).

| What | Mac | Win VA | Finding |
|---|---|---|---|
| `StationURL::Parse` | 0x0204afce | **0x01d082f0** | `__fastcall(this)`. Sets parsed flag `+0x78`, raw string `char*` at `+0x74` (matches RE_NOTES' layout). Calls ParseParams twice (before/after `#`). ~30 callers, incl. `ValidateData` paths. |
| `StationURL::ParseParams` | 0x0204af00 | 0x01d08260 | splits on `;` |
| `StationURL::ParseParam` | 0x0204ad32 | 0x01d044f0 | `address` -> `SetAddress` (Win 0x01cb2810), `port` -> atoi, **any other key -> stored in a `map<String,String>`** (`Set`). Values containing `=` make the parse fail. |
| `StationURL::Format` | 0x020426f2 | 0x01cd9f80 | Rebuilds the string: `address=` from the **resolved** InetAddress (`inet_ntoa`, ws2 ord 12), `port=`, then **every stored string param**, then the int params. |
| `InetAddress::SetAddress(const char*)` | 0x0202e0d8 | n/a | `inet_addr`, and on failure **`gethostbyname`** (+ `BadEvents::Signal(7)`). |
| `StationURL::GetAddress` | 0x0204d19c | n/a | formats the resolved InetAddress, not the original text |
| `URLProbeList::FindProbe` / `StationURL::IsMatching` | 0x0204d25a / 0x0204d816 | | compare `GetAddress()` strings, i.e. resolved dotted quads (+RVCID / +port) |

Consequences:

1. **A hostname in `address=` does not work as a carrier.** The game would
   resolve it, but every setter (`SetRVConnectionID`, `SetPortNumber`, ...)
   clears the "string valid" flag `+0x79` / Mac `+0x55`. The next `Format()` then
   writes the *locally resolved* IP. `ObjDupProtocol::AddLocalURLs` calls
   `SetRVConnectionID` on every published URL, so peers would receive our
   local-only vaddr.
2. **An extra param survives.** Unknown keys round-trip through Parse and
   Format, and the mesh (`ConnectionInfo` slots are `Quazal::String`) and the
   lobby carry the string as is. That is why the IPv6 address goes in `v6=`
   and `address=` holds a value every peer computes identically.
3. Probe matching works unchanged. Replies from the gateway appear to come from
   `vaddr`, and `FindProbe` compares the resolved `vaddr` with the URL's resolved
   `vaddr`.
4. Nothing classifies remote addresses by range (no IsPrivate/routable checks on
   either binary; sorting is by the `type` param only), so `240/4` is accepted.
   It is also never assigned to a real interface. An *unpatched* peer that tries
   it gets a local send error (no route), the same as vanilla dialling someone
   else's unroutable LAN/VPN URLs, which happens all the time.

## Wine check (tools/v6probe.cpp, i686 mingw, run under wine on the dev box)

`GetAdaptersAddresses(AF_INET6)` lists both global addresses (DAD preferred).
A connected UDP socket plus `getsockname` gives the OS-preferred source
(`2a02:...::d722`). The probe binds `AF_INET6` UDP to it and round-trips a
datagram (`fromlen=28`). Wine needs nothing special.

Largest game datagram in the relay captures (`/tmp/acrelay*.pcapng`): UDP length
984. Over IPv6 that is ~1024 B on the wire, well below the 1280 IPv6 minimum MTU,
so there is no fragmentation even through 6in4 tunnels.

## Design

```
game SendTo(vaddr:p) --hook--> SendTo(127.0.0.1:gw, SEND hdr+payload)   [game's own overlapped op completes normally]
   gw thread: vaddr -> [v6]:p  --> sendto(v6sock)
v6sock recv from [v6]:p --> gw: vaddr = map/hash([v6]:p) --> sendto(game port @127.0.0.1, RECV hdr{vaddr,p}+token+payload)
   CompleteBufferRecv hook: src==127.0.0.1:gw && token ok -> strip, write vaddr:p into qs+0xb0
```

This is the relay data path with the relay running in-process. Reuse the
`protocol.h` SEND/RECV framing and the existing wrap-buffer-per-IOOp logic. Add a
random per-process token to the loopback RECV frames so other local processes
can't inject datagrams.

1. **Startup:** if `[IPv6] Enabled`, pick the OS-preferred global source
   (connect+getsockname to `2606:4700:4700::1111`; this respects temporary-address
   policy). Bind an `AF_INET6` UDP socket to *that address*, so the source of every
   send equals the published address and inbound hashes to the same vaddr. Use the
   game's port number if free, else ephemeral. Bind the gateway on `127.0.0.1:0`.
   If there is no global v6, the feature is off.
2. **Publish:** `Network::AddLocalURL("prudp:/address=<selfvaddr>;port=<v6port>;v6=<hex>")`
   at the same two points as the relay URL (PrepareURLs, ObjDup::AddLocalURLs).
   The game stamps the RVCID. The slot fixer must reserve a slot for it next to the
   relay and public URLs (5-slot limit, RE_NOTES "Station URL slots"). Priority
   when slots are scarce: game slot 0 > v6 > relay > relay-observed public >
   interfaces.
3. **Learn:** mid-hook at Parse entry (Win 0x01d082f0, read `char*` at
   `ECX+0x74`). If the string contains `v6=`, parse `address`/`port`/`v6`, check
   `address == hash(v6, port)`, and record `vaddr -> [v6]:port` in a locked map. It
   is called often, so a cheap `strstr` reject keeps it fast. Inbound from an
   unknown v6 source: insert `hash(src)` as well, so replies route.
4. **Route:** SendTo hook: dest in `240/4` -> gateway. Unknown vaddr, or we have
   no v6: drop by redirecting to the gateway, which discards it (the op still
   completes, the same trick as OneAddressPerPeer). Everything else keeps the
   existing direct/relay logic.
5. **Firewalls:** IPv6 home routers and OS firewalls are stateful (no NAT, but
   unsolicited inbound is blocked). The game's NAT probing already makes both sides
   send to each other (connect job probes plus server-pushed InitiateProbe), which
   opens the 5-tuple. Ports are fixed (socket bound once), so no port prediction
   is needed.
6. **One address per peer:** an IPv6-capable peer now has its v4 URLs *and* a v6
   URL. If A dials B over v6 while B dials A over v4, two PRUDP connections exist
   between the same stations, the suspected launch-crash pattern in RE_NOTES.
   The existing RVCID pinning (`OneAddressPerPeer`) covers vaddrs as long as the
   gateway path is treated like any other address. A stronger, symmetric option is
   to hook `StationContactInfo::SortAndFilterTarget` (Win 0x01d21fa0). When we
   have v6 and the target URL list contains a v6 URL, move it to the front, so
   both sides prefer the same path. GetPreferredURL is "first probe answer", so
   front-of-list plus the existing direct-probe delay trick biases strongly
   towards it.
7. **Lobby (acb-rdv-py):** `tagged_candidates` passes registered URLs through
   verbatim, which is fine. `NatService.caller_candidates` (expand_caller) rebuilds
   URLs from address/port only and **drops `v6=`**. That needs a one-line change to
   copy `params["v6"]` when present. The AN-API C# backend is not checked.
   The lobby itself can stay IPv4.

## `[IPv6] Prefer` (default false)

With `Prefer=true`, and when we have IPv6, every IPv4 address of a station
that published an IPv6 URL is hidden from the game. That covers its interface
URLs, its public URL and its relay URL. Sends to those addresses go to the sink,
and traffic from them is dropped, so the game's URL race can only succeed over
IPv6, and both sides pick the same path. Stations are matched by RVCID: every
URL a station publishes carries it, and NAT probes carry the sender's RVCID. The
probes cover IPv4 URLs that arrive without one, e.g. from the lobby.

Fallback: if we have been sending to a station over IPv6 for 5 s without any
answer, its IPv4 addresses are allowed again (log: `no answer from .. over IPv6
for 5 s`). The game's connect job may still fail its first attempt in that
case; its retry then goes over IPv4 or the relay.

Use it to prove the IPv6 path in a test. As a default it needs live data on
how often IPv6 works between players first.

## Open / to verify live

- Router v6 firewall behaviour. Not testable from here because patrick.munni.ch
  has no IPv6. Expect "stateful, punch works".
- Parse threading. The map needs a lock, and the hook must never allocate through
  game allocators.
- Whether any game path sends to a peer before a URL carrying `v6=` was parsed
  on that machine. If one does, the send is dropped until the mapping exists,
  which is harmless and gets retried.
- Temporary-address expiry mid-session (valid for days, so a non-issue in
  practice). Re-pick at each login.
- Windows ASLR: the Parse hook signature must use relocation-aware `check_sig`
  (RE_NOTES "ASLR").
