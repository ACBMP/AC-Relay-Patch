# AC Relay: reverse-engineering notes

Target: `ACBMP.exe`, the Windows ACB multiplayer build. It is 32-bit, has no
symbols, and has image base `0x00400000` with no ASLR. Every address was
derived in Ghidra by comparing it with `acbmp_sf.exe`, the Mac build, which
has full symbols. **Ghidra shows VAs. The code always uses `RVA = VA - 0x00400000`
and adds that to `GetModuleHandleW(nullptr)`.** In the source each constant is
written as an explicit `0x01cc08c0 - kImageBase` subtraction.

Legend:
- **[D]** verified by decompile on both builds, matching structure, strings and callers.
- **[A]** verified by disassembly (instruction-level) on ACBMP.exe.
- **[S]** byte signature taken from ACBMP.exe in Ghidra. The patch checks it at runtime and skips the hook on mismatch.
- **[?]** assumed or inferred and not verified. See "Unverified" below.

## 1. Hooked / called addresses

| What | Mac symbol (acbmp_sf.exe) | ACBMP.exe VA | RVA | How used | Evidence |
|---|---|---|---|---|---|
| `Quazal::BerkeleySocketDriver::BerkeleySocket::SendTo` | `0x0203479a` | `0x01cc08c0` | `0x018c08c0` | inline hook | [D][A][S] `__thiscall (this, u8* buf, u32 len, InetAddress* to, IOOp* op)`, `RET 0x10` |
| `Quazal::QueuingSocket::CompleteBufferRecv` | `0x02025d8c` | `0x01cc1540` | `0x018c1540` | inline hook (post-call) | [D][A][S] ECX=QueuingSocket, no stack args, plain `RET`, returns `Buffer*` or 0 |
| `Quazal::Network::AddLocalURL(const StationURL&)` | `0x02051840` | `0x01d1cba0` | `0x0191cba0` | inline hook (captures `this` + bound port); its trampoline is called to add the relay URL | [D][A][S] `__thiscall`, 1 arg. The epilogue tail-jumps to `LeaveCriticalSection` after reusing the arg slot, so the callee pops 4 bytes |
| `Quazal::SecureConnectionClient::PrepareURLs` | `0x01f44676` | `0x01d3dba0` | `0x0193dba0` | mid hook at entry -> publish relay URL | [D][S] the only user of the `"prudp"` string at `0x022de7c4` (`StreamTable::FindStream("prudp")`) + the `SetStreamID` loop; 2 callers `0x01d3dc80`/`0x01d3dd20` = RegisterURLs / RegisterURLsEx |
| `Quazal::ObjDupProtocol::AddLocalURLs(Station*)` | `0x01fd3982` | `0x01ab5d50` | `0x016b5d50` | mid hook at entry -> publish relay URL | [D][S] NAT engine `GetLocalCID`, topology==1 && StationID!=1 early-out, `IsPublic(front)` -> `ConnectionInfo::SetURL(0,..)`, loop `SetRVConnectionID` + `ConnectionInfo::AddURL`; callers `0x01ab79d0`, `0x01ade430` |
| `Quazal::StationURL::StationURL(const char*)` | n/a | `0x01d0acc0` | `0x0190acc0` | called | [D][A][S] `GetLocalURLs` twin calls it as `PUSH "prudp:/"; LEA ECX,[local]; CALL` |
| `Quazal::StationURL::~StationURL` | n/a | `0x01d0ae60` | `0x0190ae60` | called | [D][A][S] called on that same local at the end of each loop iteration |

No hook RVA overlaps acb2's. Every branch of `/home/a/vbox/acb2` was grepped
for `018c08c0|018c1540|0191cba0|0193dba0|016b5d50` and the VA prefixes, and
nothing matched. `acb2_shared_hook_address_pattern` says only one
SafetyHook may sit on each address, and this patch keeps to that.

## 2. Why the receive hook is CompleteBufferRecv, not RecvFrom

The Windows Quazal socket layer is **overlapped**:

- `BerkeleySocket::Open` (`0x01cc06c0`, Mac `0x02034b12`) [D]:
  `WSASocketA(AF_INET, dgram?SOCK_DGRAM:SOCK_STREAM, dgram?17:6, 0, 0, WSA_FLAG_OVERLAPPED)`
  stores the SOCKET at **this+0x90**. The datagram flag is at **+0x88**. It
  also calls `ioctlsocket(FIONBIO,1)`. **+0x9c** is an alternate
  (non-Winsock) driver. It is null on PC. The patch ignores sockets where
  it is set.
- `SendTo` / `RecvFrom` (`0x01cc0a10`, Mac `0x020348de`) [D] fill an IO-op
  struct and call `WSASendTo` / `WSARecvFrom` with `op+0x1c` as the
  OVERLAPPED. Op layout: +0 buf, +4 len, +8 bytes transferred, +0xc error,
  +0x10 InetAddress*, +0x14 state (1 pending, 2 complete), +0x15 kind
  (2 send, 3 recv), +0x1c OVERLAPPED (hEvent at +0x2c), +0x30 WSABUF, and
  +0x38 the socket.
- So when `RecvFrom` returns, the datagram usually has **not** arrived yet.
- Completion: `FUN_01cc8ac0` runs `WSAWaitForMultipleEvents` and sets op
  state=2. Then `UDPTransport::ServiceIOCompletions` (`0x01d1e4f0`, Mac
  `0x0205eb72`) [D] does this for each QueuingSocket whose recv op
  (+0xa0) is in state 2:
  `buf = CompleteBufferRecv(qs)`. If buf is non-null, it copies the
  0x20-byte source InetAddress at **qs+0xb0** and dispatches
  (`FUN_01d18170`). It then re-posts the recv (`QueuingSocket::Recv`,
  `0x01cefe80`, Mac `0x0205b0fc`). That function calls
  `RecvFrom(buf->data, buf->capacity, qs+0xb0, qs->recvOp)`.
- `CompleteBufferRecv` [D][A] calls `WSAGetOverlappedResult` (wrapper
  `0x01cc0b90`) and sets `Buffer+0xc` (content size). If the result is an
  error or zero bytes, it calls the buffer's vtable slot 2 (+8, release)
  and **returns 0**. The patch hides relay control datagrams by doing the
  same thing: release, then return nullptr. ServiceIOCompletions then
  re-posts the receive as normal.

Layouts used [D]:
- `Quazal::Buffer`: +8 data ptr, +0xc content size, +0x10 capacity. These
  come from Mac `GetContentPtr`, `GetContentSize` and `GetSize`, and match
  how Windows `QueuingSocket::Recv` and `SendBuffer` pass them.
- `Quazal::InetAddress`: 0x20 bytes with a raw `sockaddr_in` at +0. The
  port is at +2 and the address at +4, both in network order (Mac
  `GetPortNumber`, `GetAddress`, `operator=` memcpy 0x20). Windows passes
  `qs+0xb0` straight to `WSARecvFrom` as `lpFrom`.

For a RECV, the patch moves the payload to the start of the buffer, sets
`Buffer+0xc = len-12`, and writes the peer ip:port into `qs+0xb0`.
ServiceIOCompletions reads `qs+0xb0` *after* the hooked call returns, so
the game sees a normal datagram from the peer.

**Send side:** the hook wraps by calling the original SendTo with a
replacement buffer (`SEND` header + payload) and the relay address. The
send is overlapped, so that buffer must stay alive until completion. Each
QueuingSocket has exactly one send op (+0xa4). `DeliverOutgoing` never
queues a second send while +0xac ("send pending") is set (Mac
`QueuingSocket::SendPending`, Windows ServiceIOCompletions clears it on
state 2). So the patch keeps one wrap buffer per op pointer and reuses it
only after completion. Send completion doesn't look at the byte count
beyond freeing the Buffer at op+0x18, which the game set and still owns.

Only `SendTo` callers [D]: `0x01cc14d0` (QueuingSocket::SendBuffer twin)
and `0x01cc8780` (an alternate-driver retry path, used only when the
global `0x02689638` is set, which is not the case on PC).

**Socket selection:** UDPTransport can listen on more than one UDP port
(`LANSessionDiscovery`, `0x01ab8530`, opens one with traffic type 1 and
publishes no URLs). The patch picks "the" game socket like this:
`Network::AddLocalURL`'s first caller is `UDPTransport::StartListen`
(`0x01d1f9f0`, Mac `0x0205b3ce`) [D][A]. It passes each per-interface URL
right after setting its port to the bound port (`MOV [EDI+2],AX` at
`0x01d1fbb4`). The hook reads that port (StationURL+0 -> InetAddress* ->
+2, but only when parsed flag +0x78 is set). The socket whose
`getsockname` port matches becomes the game socket. If the hooks were
installed after StartListen had already run, the fallback is the first
UDP socket the game sends on, which is the RDV login traffic.

## 3. URL publication

How the game builds and publishes its own URLs [D]:

1. `UDPTransport::StartListen` (Win `0x01d1f9f0`) calls
   `TransportAdapter::GetLocalURLs` (Win `0x01d1d550` via
   `DAT_0268963c->vtbl[1]`; Mac `0x02052576` via vtbl+8). That function
   makes one `prudp:/` URL per interface. [A] confirms the Windows twin:
   both `"prudp:/"` refs (`0x022dab4c`/`0x022dab54`) are ctor args, it
   skips interfaces with flag bit 4 or address 0, and it falls back to
   interface 0 when the list is empty. The decompiler output for it is
   broken, so the disassembly was used.
   **StartListen then overwrites each URL's port with the bound port**
   (`SetPortNumber`, inlined) and calls `Network::AddLocalURL` (Win
   `0x01d1cba0`) for each one. That list (Mac `Network+0x34`, a
   `qProtectedList<StationURL>`) holds the game's own local URLs.
   => Injecting in `GetLocalURLs` would be wrong twice over: the port gets
   overwritten, and at that point the socket has only just been created, so
   no allocation can exist yet.
2. Login: `JobBackEndServicesLogin::RegisterURLs` ->
   `SecureConnectionClient::RegisterURLs(Ex)` -> **`PrepareURLs`** (Win
   `0x01d3dba0`) copies `Network`'s local URL list and stamps the prudp
   stream id on the copies. The copies go to the secure server
   (`CallRegister`/`CallRegisterEx`). `CompleteLogin` (Win `0x01d49c10`,
   anchored by the string `"JobBackEndServicesLogin::DisconnectFromAuthenticationService"`)
   sets the RVCID on the server-returned public URL and, when
   AdvertisePublicUrl is set, also adds it with `Network::AddLocalURL`.
3. Session/station creation: `Station::InitLocalStationInfo` ->
   **`ObjDupProtocol::AddLocalURLs`** (Win `0x01ab5d50`) walks the same
   list. It calls `SetRVConnectionID(NATTraversalEngine::GetLocalCID())`
   on **every** entry and `ConnectionInfo::AddURL`s each one into
   `Station+0x70`. Peers dial those URLs: the host's welcome message carries
   every station's `Station::GetStationURLs` (`AddBootstrapStationURLs`,
   Mac `0x01fc7154` -> `ExtractBootstrapStationURLs` -> `RecordStationURLs`).

**Chosen injection:** the patch calls the game's own
`Network::AddLocalURL(StationURL("prudp:/address=<relay_ip>;port=<alloc_port>"))`.
It does this from a mid-hook at the entry of **PrepareURLs**, so the relay
URL is in what gets registered with the RDV server, and from a mid-hook at
the entry of **ObjDupProtocol::AddLocalURLs**, so it is in the Station
ConnectionInfo that peers receive. Because the relay URL sits in the same
list as the interface URLs:
- It gets the **same RVCID stamp** as the game's other URLs, from the game
  itself (step 3). That is what `URLProbeList::FindProbe` (Mac
  `0x0204d25a`, IP string + RVCID) needs to match the probe reply that
  comes from `relay_ip:alloc_port`.
- Its port is never rewritten, because StartListen has already run.
- `AddLocalURL` deduplicates (`std::find` + `push_back` only if missing).
  Calling it at both points, and again after each re-login, is therefore
  safe. The URL goes to the **back** of the list, so `front()`, the URL
  that `AddLocalURLs` uses for `ConnectionInfo::SetURL(0, ..)` when it is
  public, is unchanged.
- The patch waits up to 2 s for `ALLOCATED` at these points, but only while
  an ALLOCATE is actually in flight (fewer than 3 unanswered attempts). In
  practice the allocation exists long before either point: ALLOCATE goes
  out on the first PRUDP send, during the auth login, before
  RegisterURLs.

**Will the far side drop it?** [D] `StationContactInfo::SortAndFilterTarget`
(Mac `0x020518e8`, Win `0x01d21fa0`) reorders the remote URLs
(non-public first, then public) and drops non-public ones only when
`s_bForcePublic` is set. On Windows that flag is the byte at `0x02689627`.
Its only xref is the **read** in `0x01d21fa0`, with no writers (on Mac,
`ForcePublicURLInSortAndFilter` `0x02024e6e` has no callers either). So
it is always false, and the relay URL is kept and probed by
`ConnectivityManager::InitiateProbes` (Mac `0x02051d12`) like any other
URL. `IsPublic` = the `type` URL param `& 2` (Win `0x01d11f10`, key at
`0x026896b8`). The relay URL has no `type`, so it is a non-public URL,
the same as an interface URL.

The game's `StationURL` (Windows) [D][A]: sizeof 0x7c (a list node is
0x84 = next+prev+0x7c). +0 is `InetAddress*` (0x80-byte heap block,
`sockaddr_in` at +0), +0x74 is the cached string, +0x78 is the "parsed"
flag, and +0x79 is the "string valid" flag. The patch builds its URL in a
zeroed 0x100-byte stack buffer with the game's ctor, passes it to
AddLocalURL (which copies it into the list), and destroys it with the
game's dtor. All of this happens inside a POD-only `__try` helper, as
MSVC C2712 requires.

## 4. Network instance

`Network::GetInstance()` is inlined everywhere as
`if (!*(u8*)0x0268964c) net = *(0x02689728) ? *(*(0x02689728) + 0xc) : 0;`
with a per-thread context lookup when the flag is set [A] (StartListen
`0x01d1fbde..0x01d1fc21`). The patch normally takes `Network*` from
`AddLocalURL`'s `this`. It falls back to the global read only when the
flag is 0.

## 5. Unverified ([?]) -- must be live-tested

1. **The whole thing is untested in game.** It is only build-checked with
   clang-cl through `build_linux.sh`. That compiler does not enforce
   MSVC-only rules such as C2712, so the real MSVC build may still fail.
2. `PrepareURLs` / `AddLocalURLs` threads are unknown. If either runs on
   the thread that services IO completions, the 2 s wait cannot succeed.
   That is harmless (it times out and logs), and the other hook point
   still publishes. Usually the allocation is ready long before.
3. Whether the RDV/secure server (acb-rdv / AN-API) passes a client-
   registered extra URL on to joiners (`GetSessionURLs`) unchanged, or
   rewrites or filters it, is unknown. The mesh path (station
   ConnectionInfo -> bootstrap) does not depend on the server.
4. The relay URL is added without a `type` param and gets RVCID from
   `AddLocalURLs`, but only if `NATTraversalEngine::GetLocalCID() != 0`.
   That is the same condition the game's own URLs need. Check
   `ac_relay.log` and a peer's received URL list. A peer's probe should
   reach us as a RECV and our reply should go out as a SEND.
5. `GetPreferredURL` picks by lowest probe ping, so the relay only wins
   when direct probes fail or are slower. That is by design, but not seen
   yet.
6. If the allocation changes (relay restart or lease lost), the old relay
   URL stays in Network's list until the game restarts. Removing it would
   need `Network::RemoveLocalURL`'s Windows twin, which has not been
   located. A stale URL only causes failing probes.
7. Socket selection fallback (when the game listened before the hooks
   went in) assumes the first UDP send is the main socket. In LAN mode a
   discovery socket might come first.

## Station URL slots (5 max)

- `ObjDupProtocol::AddLocalURLs` (VA 0x01ab5d50) copies the Network local URLs
  into the local Station's `ConnectionInfo` (Station+0x84 on Windows, +0x70 on
  Mac). It does this with `ConnectionInfo::AddURL` (0x01a87ef0).
- `ConnectionInfo` has exactly 5 URL slots: Quazal::String at +0x08..+0x18,
  written by `SetURL(int, const char*)` at 0x01a87e20 (`thiscall`, `RET 8`).
  `AddURL` silently drops a 6th URL.
- `createSession` and `migrateSession` read the session URLs from the same
  slots (`Station::GetStationURLs`), and so does the mesh (`JobConnectStation`).
- So on a PC with more than 4 interfaces (VPNs, Docker bridges, Hyper-V), the
  relay URL, which is added last, was never seen by anyone. The first live test
  (8 interfaces under Wine) showed exactly that.
- Fix: `AddLocalURLs` is now an inline hook. After the original runs, the
  patch makes sure the relay URL, and the public address the relay saw in
  ALLOCATED, have a slot. It uses a free slot first, then one holding a
  172.16/12 or 169.254/16 address, then the last slot. It never uses slot 0
  (the game's public URL). The RVCID is copied from the game's own slots.
