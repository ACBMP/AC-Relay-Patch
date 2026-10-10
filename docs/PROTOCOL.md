# AC Relay protocol v1

TURN-style UDP relay for Assassin's Creed (Quazal PRUDP) peer-to-peer traffic.
Each player picks a relay server manually. That player's patch (the
"owner") allocates one public UDP port on the relay. The patch then makes
the game publish `prudp:/address=<relay_ip>;port=<alloc_port>` as one more
of its own station URLs. Other players' games dial that URL like any other
address. Their raw packets reach the relay's allocation port, and the relay
hands them to the owner wrapped with the sender's address. The game's own
probe race (lowest probe ping wins, `JobConnectEndPoint::GetPreferredURL`)
then picks direct vs relayed per peer, with no game-logic changes.

The game's NAT probe engine matches a probe reply to a peer by **IP string +
RVCID** (`URLProbeList::FindProbe`). The relayed URL is published by the
owner's own game, so it carries the owner's RVCID. Replies come from
`relay_ip:alloc_port`, which is exactly the probed URL, so matching works.

## Endpoints

- **Control port** (default UDP 21100): every owner<->relay message, in both
  directions.
- **Allocation ports** (default pool UDP 40200-40999): one per owner. They
  receive raw game datagrams from any peer and send raw datagrams to peers.

The relay identifies an owner by the source address (ip:port) its control
datagrams come from. The owner MUST send every control datagram from the
game's own UDP socket. That keeps one NAT mapping, and peers' raw packets
are then indistinguishable from direct traffic at the game level.

## Wire format

All integers are big-endian (network byte order). Every control datagram
starts with:

| off | size | field |
|----:|-----:|-------|
| 0 | 4 | magic `"ACRL"` (0x41 0x43 0x52 0x4C) |
| 4 | 1 | version = 1 |
| 5 | 1 | type |

Datagrams with a bad magic or an unknown type are dropped. A bad version
gets `DENIED reason=3`.

| type | name | dir | payload after the 6-byte header |
|-----:|------|-----|---------------------------------|
| 0x01 | ALLOCATE | owner->relay | u32 nonce, u8 pwlen, pw[pwlen] |
| 0x02 | ALLOCATED | relay->owner | u32 nonce, u32 relay_ip, u16 alloc_port, u32 observed_ip, u16 observed_port, u16 lease_seconds |
| 0x03 | DENIED | relay->owner | u32 nonce, u8 reason (1 bad password, 2 pool exhausted, 3 bad version, 4 rate limited) |
| 0x04 | KEEPALIVE | owner->relay | u32 nonce |
| 0x05 | KEEPALIVE_ACK | relay->owner | u32 nonce, u16 lease_seconds_remaining (0 = no allocation, re-ALLOCATE) |
| 0x06 | SEND | owner->relay | u32 peer_ip, u16 peer_port, payload... -> relay sends `payload` to peer **from alloc_port** |
| 0x07 | RECV | relay->owner | u32 peer_ip, u16 peer_port, payload... = a raw datagram that arrived on alloc_port from peer |
| 0x08 | RELEASE | owner->relay | (none) - frees the allocation immediately |

SEND/RECV overhead is 12 bytes. The max datagram is 1500 bytes, so the max
payload is 1488. The relay drops a RECV that would exceed this and counts it.

## Semantics

- ALLOCATE is idempotent per owner address. Re-sending it returns the same
  allocation and refreshes the lease. `relay_ip` is the relay's configured
  public IPv4. `observed_*` is the owner's address as seen by the relay.
- Lease: 60 s by default. It is refreshed by any ALLOCATE, KEEPALIVE or SEND
  from the owner. Owners send KEEPALIVE every 15 s. On expiry the port goes
  back to the pool.
- If the relay is configured with a password, ALLOCATE must carry it. An
  empty password is accepted only when the relay has none.
- SEND from an address with no allocation: drop, and reply `KEEPALIVE_ACK`
  with lease 0 (rate-limited) so the owner re-allocates.
- Allocation ports accept datagrams from any source (open relay for inbound).
  Every datagram becomes a RECV to the owner.
- Owner-side routing rule (patch): remember, per peer ip:port, the path of the
  last datagram received from it (relay RECV vs direct). Send to that peer
  via the same path (relay = wrap in SEND). Unknown peers go direct.
- IPv4 only (the game is IPv4-only).
