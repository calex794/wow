# NOQ fork review — wave 01 / code-level comparison

Snapshot: 2026-10-19. Research-only, no runtime code or production deployment.
Related [17-part DAG evidence](https://github.com/calex794/wow/actions/runs/39256244357),
[deduplicated triage run](https://github.com/calex794/wow/actions/runs/39269451973),
[Notion AK-FORKS-04](https://app.notion.com/p/3fd32a84beec815e9a56e8e838f77e7d).

## Evidence and method

Read complete commit metadata + changed-file patches for SEVEN selected fork
commits through the GitHub API. Compared the relevant implementation
regions against both `n0-computer/noq:main` and the **actually pinned**
`calex794/noq@2eabf9895d40c263aa3369afd66efcf4a5d95056`.
A missing exact API or source pattern is **not** enough to prove a remote
exploit or successful transfer. Existing compiled versions may contain
semantically equivalent fixes under different code.

| Source, exact commit | Candidate / verified code difference | Against pinned noq | Next gate |
|---|---|---|---|
| [emrul/noq@643db5ed77357462688d588361ca201088bea71a](https://github.com/emrul/noq/commit/643db5ed77357462688d588361ca201088bea71a) | Caps the peer-supplied ACK range count to 512; replaces a panic branch in `PacketNumber::new` with a fallible return (plus call-site handling) | Current `frame.rs::read_ack_blocks` has no `MAX_ACK_RANGES` bound and current `packet.rs::PacketNumber::new` still panics in the large-range branch; upstream main also has those shapes | **P0 candidate**, independent malformed-frame reproduction, compatibility/legitimate ACK-range test, then isolated patch + RED/GREEN. Not adopted. |
| [emrul/noq@552e75c153dbae7180c45ef6f6ffa82c88e7524d](https://github.com/emrul/noq/commit/552e75c153dbae7180c45ef6f6ffa82c88e7524d) | Replaces `ack.delay << exponent` by `checked_shl(exponent).unwrap_or(u64::MAX)` | Pinned and upstream use the original left shift | **REJECT EXACT PATCH / needs corrected P0 candidate**: Rust `checked_shl` only validates the shift count, NOT bits shifted out of a u64; `(1u64 << 44).checked_shl(20)` returns `Some(0)`. Need `checked_mul(1u64 << exponent)` or another proven saturated bound, plus an independent regression. |
| [mp0rta/noq@e207f2ba8dd41c2fa5de034764587b72cd2b030c](https://github.com/mp0rta/noq/commit/e207f2ba8dd41c2fa5de034764587b72cd2b030c) | On connection termination, drains pending `open_path` senders with `ValidationFailed`; includes async closed-connection regression | Exact `open_path.drain()` not found in pinned `noq/src/connection.rs` | **P1**: reproduce permanently pending `OpenPath`, ensure no double notification or locks; then adapt to current API. |
| [zshenker/noq@e605c83acc257643ae616f1ee7f72e865dad05d5](https://github.com/zshenker/noq/commit/e605c83acc257643ae616f1ee7f72e865dad05d5) | Tracks unread connection-level flow-control credit for stopped+reset streams and avoids double credit | No `unread_credit` or `take_unread_credit` in pinned recv/state stream modules | **P1** with possible safety implications: STOP/RESET interleavings; account for already-consumed bytes; RED/GREEN against bytes and total stream limits. |
| [saronic-technologies/noq@4be7e7dd994295a5865a4527a037e6dcaab4a6be](https://github.com/saronic-technologies/noq/commit/4be7e7dd994295a5865a4527a037e6dcaab4a6be) | Stores `last_local_ip`; announces local IP migration after learning a different valid source IP; includes migration test edits | `last_local_ip` absent in pinned path metadata | **P1**: validate with Roha and multiple IPv4/IPv6 paths, no duplicate migration notification or unauthorized switch. |
| [eleboucher/noq@77b0c5c21b51800e9bf60362bc913894d52c49e1](https://github.com/eleboucher/noq/commit/77b0c5c21b51800e9bf60362bc913894d52c49e1) | Changes BBR3 `else if app_limited` to an independent `if`, and adds a keepalive/idle `max_bw` regression | Pinned BBR3 still uses `else if app_limited` | **P1**: run their timer/BW simulation on the pinned BBR3 with RED, then adapt minimal fix and guard throughput after idle. |
| [kixelated/noq@2373049291d02fe91bbf93746284cac9f1668f6e](https://github.com/kixelated/noq/commit/2373049291d02fe91bbf93746284cac9f1668f6e) | ONLY drops an unnecessary borrow in a `RecvStream` debug assertion; no GSO slicing behavior | Pinned contains the prior `.contains_key(&self.stream)` | **P3 / false positive**. Earlier notes associated this particular SHA with GSO slicing: that attribution was wrong. Search a *different exact source commit* for a real GSO feature; do not report this SHA as such. |

## Audit counts are not features

Deduplication of all 17 machine-evidence archives yields **75 public
source-confirmed repos**, **4,348 branch refs**, **466 globally distinct head
SHAs**, and **7,272 unique root-upstream-unmerged commit SHAs**. These are
commit IDs across historical/experimental branches, not 7,272 novel
behaviors. **49** of those SHA IDs appear in the branch history of our own
fork; this only proves exact-Git-object overlap. A total of **2,187**
commit SHA candidates appear in a scanned fork AND that fork's directly
listed parent; those are not independent inventions of the child.
Some file-name inventories were truncated; each such candidate remains
`file_list_pending` until full source inspection.

The 17-way raw code scan succeeded. [Triage run](https://github.com/calex794/wow/actions/runs/39269451973)
and [its CSV/JSON/Markdown evidence](https://github.com/calex794/wow/actions/runs/39269451973/artifacts/12195395588)
succeeded as a separate, read-only, fully deduplicated aggregation
using the exact pinned successful source scan SHA. Priority P0?/P1?/P2?
in that CSV is a **text-matching queue**, not a proven security severity.

## Next bounded engineering experiments

1. **First test**: untrusted ACK Range Count and packet number size
   across Initial/Handshake/Data/PathAck variants; proof of finite work and
   no process panic on invalid encoded fields; preserve legal frames.
2. Independently show why `checked_shl` is insufficient for saturating
   ACK-delay multiplication before accepting any candidate fix.
3. STOP/RESET two-direction credit accounting; independent test with the
   pinned assembly, then evaluate the candidate only after RED.
4. BBR3 keepalive/idle simulation and path closure.
5. In all cases: compare source SHA, patch digest, license and pinned
   `calex794/noq`; validate against real Roha/noq locked CI and
   never merge an unproven security fix into `main`.

Nothing in this report is declared implemented or production-safe.
