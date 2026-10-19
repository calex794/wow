# W6-RoHA-PREINCOMING-01 — transport-side Incoming limits

**Status:** Draft implementation patch and CI probe in `calex794/wow`, stacked
on #42. **NOT applied to or merged into `calex794/roha`.** The
GitHub App has read access but a create-branch attempt returned
`403 Resource not accessible by integration` on 2026-10-19.
Do not describe this work as a completed upstream fork change.

## Threat boundary

The application-side `AnchorAdmission` implemented in wow PR #42 can
reject an `Incoming` *before polling the TLS future*. But noq has already
received/parsed an Initial packet to create the `Incoming` object; its
pending queue and packet buffers are allocated before the application gate.

The pinned Roha fork (SHA
`a42ad5aef1626df80d39398e05dac6e362bf6e49`) exposes the
underlying noq `ServerConfig` limits only through the
`ServerConfigBuilder` used with `Incoming::accept_with`. That is
too late to cap the transport queue before `Endpoint::accept()` emits
an `Incoming`.

## Proposed upstream Roha API

The deterministic patch script
[`tools/w6_roha_preincoming_patch.py`](../tools/w6_roha_preincoming_patch.py)
changes exactly `iroh/src/endpoint.rs` and `iroh/src/socket.rs`
in a clean checkout of the pinned SHA. It refuses unexpected source
anchors, local changes and different commits.

It adds public, validated
`iroh::endpoint::ServerIncomingLimits::new(max_pending, per_bytes, total_bytes)`
and `Endpoint::Builder::server_incoming_limits(limits)`.
An invalid zero or total-smaller-than-per budget is refused. The builder
passes a comparison-free immutable policy into `StaticConfig`, which
sets underlying noq `ServerConfig::max_incoming`,
`incoming_buffer_size`, and `incoming_buffer_size_total` **before
the endpoint binds**. The same method reapplies limits when
`Endpoint::set_alpns()` regenerates its server config.

Endpoints without the optional setting preserve existing upstream
defaults; this is a fork-compatible additive opt-in API, not a
protocol or ALPN change.

## Intended W6 authority profile

For the authority listener specifically (not a global change to all
Roha clients):

| Control | Proposed lab setting |
|---|---:|
| Pending unauthenticated Incoming objects | 32 |
| Extra packet buffer per pending Incoming | 4 KiB |
| Aggregate extra buffered Incoming packet bytes | 64 KiB |
| App-side in-flight TLS/RPC workers | 16 (PR #42) |
| App-side admission | 64/sec, burst 64 (PR #42) |
| QUIC retry address validation | Enabled (PR #42) |

**Important caveat:** the incoming byte limits exclude each client's
*first* packet. Their total bound is NOT an upper bound on transport
memory; additional overhead includes Incoming metadata, Initial
packet, parser/crypto CPU, UDP kernel receive queues, path discovery,
relay traffic and active established QUIC connections.

## Executable evidence

The dedicated `.github/workflows/w6-roha-preincoming-probe.yml` job:

1. Fetches a public, pinned Roha source SHA into a disposable sibling
   checkout on GitHub Actions (no upstream write).
2. Applies only the guarded patch and emits a downloadable
   `roha-preincoming.patch` Git diff for upstream code review.
3. Compiles Roha/noq and runs constructor validation unit tests.
4. Runs a standalone Rust/Tokio probe with the pinned noq Git patch
   checking the public API, localhost TLS handshake and
   `set_alpns()` compatibility.

Passing these tests proves the patch compiles and the updated server
still serves authenticated connections. It **does not by itself prove**
absolute CPU/memory DoS resistance, packet queue performance under an
external flood, or safe public deployment. A separate pre-Incoming
adversarial load test and patched wow end-to-end integration are
still needed before acceptance. The actual Roha fork needs
write-permission/normal PR review before wow can switch its pinned
`iroh` dependency to a reviewed, signed upstream commit.

## Acceptance and next step

1. Exact-head patch/probe CI green, including the artifact Git diff.
2. Actual Roha branch/PR created with appropriate repository permission;
   peer review and independent transport tests; no main merge merely
   for the sake of a passing build.
3. Pin the accepted Roha Git SHA in wow and its Cargo.lock, wire
   `server_incoming_limits` in the authority endpoint *before bind*.
4. Preserve PR #42's app-side admission and signed W6 fencing.
5. Validate upstream internal queue/memory under malformed Initial
   floods and authenticated reconnection bursts. Measure resource use;
   avoid claiming DoS immunity from application-level testing alone.

No Android device or second PC is needed at this development stage.
