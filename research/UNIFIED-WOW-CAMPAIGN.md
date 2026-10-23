# WOW unified verification campaign

Opened from the user's requested single comprehensive test cycle. CI matrix: seven separate jobs in `.github/workflows/wow-unified-campaign.yml` running in parallel, `fail-fast: false`. Additional five LABO synthetic suites run from [LABO PR #31](https://github.com/calex794/labo/pull/31).

| Group | What executes | Not claimed |
|---|---|---|
| Crypto/security | W12 signed signer/epoch/route/revoke and exact W3 byte idempotence | No general STORE/FETCH capability authorization |
| Causality | Signed W13, W14 with genuine W8/W9/W10 cross-links | No guarantee of real physical storage |
| Crash/recovery | W12 process abort and SQLite W13 snapshot rollback | No SSD power loss |
| Adversarial | Three seeded 1/5/10/20/40/70/90% fake-claim matrices | Not 1000 compromised physical peers |
| Offline/time | Fail-closed W12 cause without current UTC | No RTC reset hardware |
| QUIC | Opt-in Roha/iRoh Rust transport tests | No external NAT/relay or physically separate nodes |
| Resources | Runtime time/RSS of scoped Rust tests | Not real 1000-node throughput or memory model |

All tests are *existing Rust primitives*, not an end-to-end production service deployment. Success only means the implemented invariants survived that scenario. Green does not establish actor honesty or physical operator independence.

**Mandatory release blockers not yet implemented:** complete STORE/FETCH capability enforcement for new W12 entry point; encrypted private scopes/controlled metadata dissemination for witnesses; continuation proofs before advancing a W13 pinned chain; three independently controlled physical machines and real power-failure/ENOSPC testing; actual W8 recipient W4 path across real transport; clock-recovery physical evidence and a long-running pilot.

**Safety:** W12/W14 signatures are source/witness statements. W4 can only be issued by authorized recipient on actual durable open of W3. A signed custodian claim cannot be promoted into W4 or an external UTC anchor. The tests never release automatically to production. Review the per-job artifacts for limitations and failure explanations.
