# W6 authority application pre-handshake QUIC admission / bounded resources

Status: laboratory Draft stacked on PR #41. This profile is NOT a
network-layer denial-of-service guarantee or proof of safe public exposure.

## Discovered gap

The earlier anchor test fixtures each implemented their own bounded
semaphore after accepting an Iroh Incoming event. One fixture initially
used only four slots, causing real trusted multi-writer tests to return
Unavailable instead of policy Conflict. Other paths did not enforce
the same handshake timeout or transport receive-window bounds.

More importantly, Iroh/noq runs its own UDP listener and QUIC packet
parser BEFORE the application receives Incoming. An application-level
permit before awaiting Incoming is valuable and testable, but cannot
bound *all* kernel UDP buffers, Initial packet parsing, retry-token
validation, or CPU/memory spent by noq before the application boundary.
Do not market this as complete pre-TLS DoS immunity.

## Enforced shared application profile

A reusable `AnchorAdmission` instance must be shared by the whole
authority endpoint, not recreated for every connection. It enforces:

- At most 16 concurrently accepted handshake/RPC tasks by default;
  configuration validates an absolute maximum of 64.
- Monotonic token bucket, default 64 newly admitted handshakes/second
  and burst 64, with finite caps (rate <=256/sec, burst <=512).
  No queued jobs, no blocking waiter list: exhausted arrivals are
  dropped before polling their TLS Future.
- QUIC Retry for any Incoming without a validated transport address,
  before starting any TLS/QUIC handshake Future. Retry is the pinned
  Roha/noq stateless address-validation mechanism; the client must prove
  reachability by returning a valid transport token. Initial and retried
  attempts each consume admission rate budget; a spoofed source address
  does not get to reserve a long-lived TLS application worker.
- A separate handshake completion deadline (default 2 seconds, max 10)
  and whole per-connection service deadline (default 8 seconds, max 10).
  A single semaphore permit spans handshake, request parse, response,
  and receipt ACK; all exits/aborts return permits through RAII.
- Do not trust peer IP, claimed DeviceId, domain or route string to
  raise any quota. TLS peer identity is unavailable before handshake.
  Overload may deny honest clients too; availability fairness among
  unrelated users is NOT established by global admission.
- One authenticated QUIC connection receives exactly one bounded W6
  application RPC (GET, signed CAS, BEGIN or FINISH). No 0-RTT
  administrative mutation or open-ended bidirectional stream processing.

At endpoint creation, pass `anchor_transport_config()` into the
pinned Roha Endpoint builder BEFORE bind:

```text
max_concurrent_bidi_streams = 1
max_concurrent_uni_streams = 1
stream_receive_window = 4096 bytes
connection receive_window = 8192 bytes
send_window = 8192 bytes
idle_timeout = 8 seconds
```

W6 signed CAS is 339 bytes; BEGIN/FINISH 105 bytes, successful response
73 bytes; the existing guarded decoder also applies a fixed
`CAS_BYTES` maximum before decoding or SQLite mutation.

Both real Roha/noq QUIC loopback authority test fixtures — in-process
multi-client and independent OS child — are refactored to call the
SAME `AnchorAdmission::dispatch`. No fixture may bypass the common
application limiter with its own unbounded `tokio::spawn`.

## Required CI

1. Deterministic rate-token exhaustion and refill under a monotonic
   injected Instant, without test sleeps or accepting extra work.
2. Bounded in-flight permits: refusal at capacity, recovery after
   release, invalid/unbounded configuration refused.
3. Real Roha/noq QUIC saturation: an authorized TLS writer is rejected
   when the application admission permit is already occupied; on release
   the reader can GET the **unchanged** independent authority state.
4. All existing independent writer TLS credentials, signed CAS, orphan
   recovery, process restart, W4/W5 ENOSPC and strict Clippy remain
   green at the final SHA in both GitHub push and PR workflows.

## Explicit remaining boundaries

Only a laboratory QUIC endpoint is wired here; a dedicated production
authority runtime/service deployment must also wire this admission code
and undergo its own socket resource audit. Iroh/noq internal pre-Incoming
parsing remains outside the application permit, so production work must
independently bound UDP receive queues, QUIC Retry/stateful Initial cost,
pending handshakes inside the transport, per-origin abuse and aggregate
connection memory at the network edge/transport layer. Network-edge
filters must not assume a source IP is a trustworthy identity.

The global exclusive Mailbox writer fence still trades availability for
cross-host revocation correctness. Stale process/storage fencing,
anti-rollback authority custody, signed physical isolation evidence,
true multi-device LAN tests and Android battery/background mode are
separate P0. No merge into main or public listener acceptance on this
application-side CI alone.
