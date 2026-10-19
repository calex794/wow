# W6-ROHA-PREINCOMING-INTEGRATION-02 — fork write restored

Status: stacked laboratory Draft, **Roha #8 -> wow #44 -> wow #43 -> #42**.

## Repository custody

The connected GitHub integration now has explicit write permission to
`calex794/roha`. Branch
`fix/w6-noq-preincoming-limits-20261019` was created FROM
`integration/roha-noq-forks-20261018` at exact parent
`a42ad5aef1626df80d39398e05dac6e362bf6e49`.
[Roha Draft PR #8](https://github.com/calex794/roha/pull/8)
carries the code, with formatted head
`396a6006b15e4c3a63e111a720b84416fe6220f1`.
No main branch or any adjacent relay experiments were changed.

The source is the same two-file change tested in
[wow patch probe #43](https://github.com/calex794/wow/pull/43).
Source truth is now the actual pinned Roha Git commit, NOT the
disposable CI patch. The original read-only 403 blocker is resolved.

## Exact dependency chain

* Wow `Cargo.toml` pins `iroh` from `calex794/roha` at
  `396a6006b15e4c3a63e111a720b84416fe6220f1`.
* All four Roha component crates (`iroh`, `iroh-base`,
  `iroh-dns`, `iroh-relay`) must resolve to that exact Git tree.
* noq/noq-proto/noq-udp remain pinned together to
  `calex794/noq` SHA
  `2eabf9895d40c263aa3369afd66efcf4a5d95056`.
* `scripts/check_dependency_chain.py` checks the **resolved** Cargo
  metadata and lockfile, not just manifest text. Any other tree
  or unpinned crates.io substitute fails CI.

## Transport boundary and ordering

A W6 authority endpoint MUST configure both layers BEFORE `bind()`:

1. `ServerIncomingLimits::new(32, 4096, 65536)` through
   `Endpoint::Builder::server_incoming_limits`. Noq limits
   simultaneously outstanding transport-level `Incoming` objects
   and **additional buffered packets**, including `set_alpns` rebuild.
2. `anchor_transport_config()`: 1 bidi stream, 1 uni ACK stream,
   4 KiB stream window, 8 KiB connection receive/send windows.
3. `AnchorAdmission` app worker quota: default 16 concurrent
   handshakes/RPCs and monotonic 64 attempts/second burst 64,
   with bounded 2s TLS and 8s end-to-end RPC deadlines.
4. `Incoming::retry()` validates the transport address before
   admitting a TLS worker; successful TLS authenticates the
   independently pinned writer EndpointId. These are separate gates,
   not interchangeable quotas.

The first QUIC Initial UDP packet, noq parser CPU/crypto and
kernel socket receive queues are **outside** buffered-packet budgets.
Furthermore, `max_incoming` limits *pending unaccepted* Incoming,
not established connections. Other quotas must still handle
sustained authenticated connection and repeated-retry abuse.

## Laboratory tests and limits

* Roha baseline CI requires Rust 1.91 fmt/check/library tests, and
  separate Akula lab patchbay / relay tests.
* Wow #44 integration binds the exact Roha limits in both
  independent authority OS-child and in-process multiwriter QUIC
  fixtures. No runtime path may claim protection if it has not
  called the builder setter.
* A separate real socket regression deliberately configures
  `max_incoming=1`, holds one unaccepted Initial, proves another
  Incoming cannot be surfaced before capacity is released, then
  admits a distinct peer after release.
* Exact-head GitHub push AND PR suites must pass: pinned Git chain,
  W6 QUIC tests, strict Clippy, W4/W5 real Linux ENOSPC and
  non-transport Rust tests.

These tests do NOT certify public exposure or independent malicious
traffic isolation. A proper external/UDP malformed-Initial flood test,
memory/CPU observation, independent host custody, authority
anti-rollback and crash-safe physical writer fencing remain open.

## Merge strategy

Keep both PRs Draft while evaluating CI and adversarial behavior.
Merge upstream Roha #8 into its reviewed *integration* base only
when accepted; do not merge into Roha main by default. Pin a
reviewed stable Git commit (either this PR head or a later reviewed
squash) in wow, rerun all exact-SHA tests after changing the pin.
Do not advance either main branch as part of this work without
separate release review.
