# NOQ fork intelligence — 17-part automated GitHub audit

This tool periodically enumerates the **public GitHub fork network** of
[n0-computer/noq](https://github.com/n0-computer/noq), including fork-of-fork
descendants exposed by GitHub's official forks endpoint.

It is hosted in `calex794/wow` because this connected GitHub application
currently cannot create a branch in `calex794/noq` (403 on 2026-10-19).
The scan reads `calex794/noq` as the **reference for our implementation**.
It never changes any source fork, never executes untrusted fork code, and never
automatically cherry-picks, merges or approves changes.

## What gets checked

1. Paginated upstream `/forks` inventory; compare the total to GitHub's
   counter. For every selected fork, re-check the original `source.full_name`.
2. **Every publicly listed branch**, not only `main` / `master`.
   A per-fork branch page cap is explicit; the report marks truncation.
3. Cross-fork comparison with the current upstream default branch:
   `ahead`, `behind`, and available unique commit SHAs. Large ahead
   ranges beyond the first 300 sampled commits are marked **incomplete**.
4. Heuristic comparison against `calex794/noq`, plus a bounded number of
   commit-level changed-file lists to propose triage priorities P0–P3.
   Similar patches can have different SHAs. **Priority != accepted vulnerability
   or proof the feature is missing from our fork.**
5. Reproducible raw `audit.json`, `branches.csv`, `candidates.csv`,
   `README.md`, and **17 JSON part files** uploaded as GitHub Actions artifacts.
   GitHub issue index is updated in place by scheduled/manual runs.

## Activation and schedule

Workflow: `.github/workflows/noq-fork-audit.yml`.

- **Push / pull request:** runs unit tests + a bounded **five-fork preview**
  using read-only GitHub API access. Preview data cannot update the index.
- **Every day at 04:27 UTC:** rotate through 1 of 17 stable, hashed partitions.
  A full cycle covers every discoverable fork in **17 days**, subject to API
  availability, rate limits, private/deleted forks and branch/commit caps.
  Existing part summaries remain in **one** GitHub issue; raw evidence is in
  each Actions run artifact (retention 60 days).
- **Manual workflow_dispatch:** choose `full`, `daily` or an exact
  `part` (1–17). A full scan is budgeted for at most 900 GitHub REST calls;
  when it cannot finish it reports partial coverage instead of claiming
  completeness. Run larger networks as individual partitions.

**Important:** GitHub Actions schedule and workflow_dispatch require the
workflow YAML to exist on the repository's **default branch**. While this
feature is only in a Draft PR, push/PR preview checks run, but **the daily
schedule has not been activated**. Merge only after CI and review.

## Run locally

Python 3.10+ and a GitHub token with public repository read access:

```bash
python3 -m unittest discover -s tools/noq_fork_audit/tests -v
GITHUB_TOKEN=... python3 -m tools.noq_fork_audit.cli scan --part 0 --max-requests 900
```

The workflow provides `GITHUB_TOKEN` automatically. It grants
`contents:read` and `issues:write` to the **wow repository only**.
The issue-write step runs solely for schedule/manual events. Fork names and
branch names never become shell commands or executable code.

## Scope limits and handoff

This is an inventory and **research candidate generator**. It does not
automatically check out or compile every fork or solve semantic patch
equivalence, so an unreviewed P0 label is not a verified vulnerability.
The 2026-10-18 manual Notion baseline contains **73 confirmed forks**;
GitHub's public count later rose to **82**. If inaccessible forks are
missing, the audit explicitly reports that coverage gap.

Human research still needs to inspect the top candidate diffs, compare
against upstream *and our current pinned noq*, add tests, and record
adoption decisions in the existing Notion function matrix. Automatic
Notion editing would additionally require an explicitly connected Notion
integration and configured credentials; no secrets are assumed.
