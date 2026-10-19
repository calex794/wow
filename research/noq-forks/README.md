# NOQ-82-FORK-AUDIT — full source and branch census

**Start:** 2026-10-19. **Status:** systematic audit IN PROGRESS;
the contents of a CI artifact are evidence only after the exact run
finishes. This does not claim all forks or all commits have been reviewed.

## Existing evidence, not a replacement

- [AK-FORKS-04](https://app.notion.com/p/3fd32a84beec815e9a56e8e838f77e7d)
  identified 73 public source-confirmed noq forks out of the prior
  GitHub count 80. The main-branch census distinguished 10 forks
  containing ahead commits, 60 behind copies, and three equal to
  upstream. A branch with no main changes may still have valuable
  fix/feat branches. Preserve the original evidence and SHA links.
- GitHub currently reports **82 forks** at `n0-computer/noq`. The public
  search `"noq, a QUIC implementation in Rust" fork:only` returns 75
  candidate names. This is a discovery result, not 75 verified
  descendants. Search and the historical report were unioned,
  deduplicated and saved as
  [candidates.json](../research/noq-forks/candidates.json).
- The old sample's 73 source-confirmed entries and today's search 75
  are **different metrics**, not proof that only seven remain.
  Private, renamed, archived and nested descendants may be missing.

## Audit contract: 17 review parts

The dedicated [auditor](../research/noq-forks/audit.py) and
[GitHub Actions workflow](../.github/workflows/noq-fork-census.yml)
were added to the independent `calex794/wow` audit branch. Direct
branch creation in `calex794/noq` returned GitHub 403; source code
of our noq fork was not altered.

The source-verification job reads all 75 candidates from GitHub and
compares **real `fork`, `source.full_name` and
`parent.full_name`**, recording missing and inaccessible records.
Its artifact carries JSON and an explicit discrepancy with GitHub's
fork counter. Do not create/claim invisible repositories.

The branch census creates **17 reproducible, balanced parts** from
priority-ranked fork families, enumerates ALL published
`refs/heads/*` with `git ls-remote` (not the first GitHub API
page), and records exact head SHA, duplicate SHAs, name-based priority,
parent lineage and upstream base SHA.

To limit API quota and avoid starving the already-running Akula/СТАЯ
CI, the first pass compares only the first **eight distinct SHA
tips per public fork**. The full list of unexamined branch tips
remains in the JSON and `pending_unique_heads` is reported as an
unresolved gap; a success status from the workflow is **not** proof
that every branch was diffed or independently tested. Follow-up
passes require explicit chunk offsets or separate per-fork review.

Each diff is compared by **commit SHA** against the upstream main
commit checked at audit time, not solely by branch name. A candidate
with inherited changes from a nested parent requires an independent
parent comparison before calling it original. Only changes verified by
file-level diff, tests, and relevance to the current pinned
`calex794/noq` count as viable adoption candidates.

## Candidate priorities (first group)

- `HeikoBornholdt/noq`: disappearance of last path and
  abandoned-path retention; prevent panics/timeouts.
- `mp0rta/noq`: open-path cancellation and keepalive timing.
- `rayfish/noq`: nondefault branches and route/stream changes.
- `saronic-technologies/noq`: authenticated path migration/IP
  events in paired Iroh fork.
- `moq-dev/noq`: assembly memory bounds, BBR and WebTransport;
  historical fork marked frozen, not a new product dependency.
- `emrul/noq`: ACK ranges and large packet-number bounds.
- `eleboucher/noq`: BBR app-limited regression after idle.
- `zshenker/noq`: stream affinity, multi-socket, reset-at.
- `calex794/noq`: **our own fork**, baseline for applicability, not an
  independent external idea.

## What counts as complete

1. Reconcile the GitHub count against parent/source-verified
   public forks. Document any inaccessible or undiscoverable gap.
2. Enumerate ALL accessible published branches per confirmed fork;
   independently deduplicate inherited/identical tips.
3. Compare unique meaningful tips vs both *upstream* and direct
   *parent*. Record every distinct commit SHA, files, and test
   evidence. Uncompared SHA heads remain tracked, not closed.
4. Deduplicate features/bugs already in upstream, already in our
   `noq`, or already fixed in Roha/Akula.
5. Link real `RED -> minimal patch -> GREEN` to separate Draft PRs
   and full locked Roha/noq CI; do not merge merely because a fork
   has an ahead count.
6. Update the existing Notion [function matrix](https://app.notion.com/p/8b7dad5ab74a4a26a84d5a9c8898cc23)
   and `AK-FORK-FEATURE-MATRIX-08` only with source-corroborated
   candidates and explicit statuses.

**No claim of full completion** before the 17-part artifacts and all
uncompared heads have been reconciled. GitHub API limits,
network access and history comparisons may leave documented gaps.
