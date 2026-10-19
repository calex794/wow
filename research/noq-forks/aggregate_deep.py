#!/usr/bin/env python3
"""Deduplicate evidence from all 17 full-DAG noq fork audit parts.

Read-only triage: commit subjects and changed-file names are leads, not
confirmed fixes, security ratings or permission to transplant patches.
No GitHub API or execution of untrusted fork code is performed here.
"""
import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import re

PARTS = frozenset(range(1, 18))
PINNED_FORK = "calex794/noq"
SHA = re.compile(r"^[0-9a-f]{40}$")
P0_TERMS = re.compile(
    r"\b(panic|crash|deadlock|overflow|oom|denial.of.service|"
    r"unbounded|use.after.free|memory.leak|resource.exhaustion|"
    r"security|untrusted|infinite.loop|stuck|hang)\b", re.I
)
P1_TERMS = re.compile(
    r"\b(ack|rtt|gso|congestion|bbr|flow.control|close|"
    r"transport|retry|reset|buffer|loss|path|migration|"
    r"timeout|packet|udp|stream|datagram|cipher)\b", re.I
)
IGNORE_PREFIXES = ("docs/", ".github/", "examples/", "fuzz/")
COLUMNS = [
    "sha", "provisional_priority", "score", "subject", "sample_fork",
    "source_forks", "direct_parent_inheritance_possible",
    "same_sha_in_our_fork", "source_changed_files", "file_list_pending",
    "review_status", "source_url",
]


def load_parts(evidence_dir):
    by_part = {}
    for path in sorted(Path(evidence_dir).rglob("deep-part-*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        number = data.get("part")
        if number not in PARTS:
            raise ValueError(f"Unexpected part number in {path}: {number}")
        if number in by_part:
            raise ValueError(f"Duplicate evidence for part {number}")
        if data.get("parts") != 17 or data.get("not_product_acceptance") is not True:
            raise ValueError(f"Missing safety envelope in {path}")
        if data.get("fatal_error") or data.get("totals", {}).get("errors"):
            raise ValueError(f"Unfinished Git-DAG scan in part {number}")
        by_part[number] = data
    if set(by_part) != PARTS:
        raise ValueError(f"Need all 17 parts; missing {sorted(PARTS - set(by_part))}")
    baselines = {part.get("base_sha") for part in by_part.values()}
    if len(baselines) != 1 or not SHA.fullmatch(next(iter(baselines)) or ""):
        raise ValueError("Pinned upstream SHA mismatch or missing")
    return [by_part[n] for n in sorted(PARTS)]


def priority(subject, files):
    text = (subject + " " + " ".join(files)).replace("_", " ").replace("-", " ")
    code_paths = [x for x in files if
                  (x.endswith(".rs") or x.endswith(".toml")) and
                  not x.startswith(IGNORE_PREFIXES)]
    if not code_paths:
        return "P3", 0
    if P0_TERMS.search(text):
        return "P0?", 90
    if P1_TERMS.search(text):
        return "P1?", 60
    return "P2?", 30


def classify(parts, expected_forks=75):
    fork_names = set()
    refs_by_sha = defaultdict(set)
    changes = {}
    pinned_shas = set()
    branch_count = 0
    incomplete_files = 0
    explicit_parent_links = {}
    for part in parts:
        for repo in part["repositories"]:
            name = repo["name"]
            if name in fork_names:
                raise ValueError(f"Duplicate fork in two shards: {name}")
            fork_names.add(name)
            if repo.get("verified") is not True or repo.get("error"):
                raise ValueError(f"Unverified fork or fetch failure: {name}")
            explicit_parent_links[name] = repo.get("parent")
            branch_count += repo["branch_count"]
            for b in repo["branches"]:
                tip = b["head_sha"]
                if not SHA.fullmatch(tip):
                    raise ValueError(f"Invalid SHA in {name}")
                refs_by_sha[tip].add(name)
            for c in repo["unique_commits"]:
                sha = c["sha"]
                if not SHA.fullmatch(sha):
                    raise ValueError(f"Invalid foreign commit SHA in {name}")
                if name == PINNED_FORK:
                    pinned_shas.add(sha)
                entry = changes.setdefault(sha, {
                    "sha": sha, "subjects": set(), "forks": set(),
                    "files": set(), "file_list_pending": False
                })
                entry["subjects"].add(c.get("subject") or "")
                entry["forks"].add(name)
                entry["files"].update(c.get("files", []))
                entry["file_list_pending"] |= bool(
                    c.get("file_diff_pending") or c.get("file_list_truncated"))
                if c.get("file_diff_pending") or c.get("file_list_truncated"):
                    incomplete_files += 1
    if len(fork_names) != expected_forks:
        raise ValueError(f"Got {len(fork_names)} forks; require {expected_forks}")
    if PINNED_FORK not in fork_names:
        raise ValueError("Our own noq fork missing from comparison evidence")
    summaries = []
    for sha, raw in changes.items():
        sources = sorted(raw["forks"], key=str.lower)
        subject = sorted(raw["subjects"], key=lambda x: (-len(x), x))[0]
        files = sorted(raw["files"])
        p, score = priority(subject, files)
        parents = [n for n in sources
                   if explicit_parent_links.get(n) in raw["forks"]]
        contains_ours = sha in pinned_shas
        if contains_ours:
            score -= 75
        if parents:
            score -= 10
        if raw["file_list_pending"]:
            score -= 5
        # Shared SHA across many forks is ONE candidate, not many features.
        sample = next((n for n in sources if n != PINNED_FORK), sources[0])
        summaries.append({
            "sha": sha,
            "provisional_priority": p,
            "score": score,
            "subject": subject[:220],
            "sample_fork": sample,
            "source_forks": sources,
            "direct_parent_inheritance_possible": parents,
            "same_sha_in_our_fork": contains_ours,
            "source_changed_files": files,
            "file_list_pending": raw["file_list_pending"],
            "review_status": "sha-identical-in-our-fork" if contains_ours
                             else "needs-code-diff-and-test",
            "source_url": f"https://github.com/{sample}/commit/{sha}",
        })
    summaries.sort(key=lambda row: (
        row["same_sha_in_our_fork"],
        -row["score"],
        row["sha"]))
    top = [r for r in summaries
           if not r["same_sha_in_our_fork"] and r["source_changed_files"]][:50]
    totals = {
        "parts": len(parts), "forks": len(fork_names),
        "branch_refs": branch_count, "global_unique_head_shas": len(refs_by_sha),
        "unique_foreign_commit_shas": len(changes),
        "same_shas_in_our_fork": sum(x["same_sha_in_our_fork"] for x in summaries),
        "direct_parent_shared_sha_candidates":
            sum(bool(x["direct_parent_inheritance_possible"]) for x in summaries),
        "commit_references_with_incomplete_file_list": incomplete_files,
        "provisional_priorities": dict(Counter(x["provisional_priority"]
                                                for x in summaries)),
        "pinned_upstream_sha": parts[0]["base_sha"],
        "warning": (
            "SHA equality is not code-equivalence; no source diff was "
            "reviewed and no independent RED/GREEN tests were executed."
        ),
    }
    return {
        "totals": totals, "ranked": summaries, "human_review_queue": top,
        "tip_duplication_samples": sorted(
            [{"sha": k, "forks": sorted(v)} for k, v in refs_by_sha.items()
             if len(v) > 1],
            key=lambda x: (-len(x["forks"]), x["sha"]))[:25],
    }


def output(result, dest, run_id):
    out = Path(dest)
    out.mkdir(parents=True, exist_ok=True)
    (out / "deduplicated.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8")
    with (out / "triage-candidates.csv").open("w", encoding="utf-8",
                                               newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=COLUMNS)
        writer.writeheader()
        for row in result["ranked"]:
            writer.writerow({key: (
                "; ".join(row[key]) if isinstance(row[key], list) else row[key]
            ) for key in COLUMNS})
    t = result["totals"]
    lines = [
        "# NOQ 17-part evidence deduplication and review queue", "",
        f"Evidence: https://github.com/calex794/wow/actions/runs/{run_id}", "",
        "The Git-DAG evidence has been aggregated across ALL 17 parts; "
        "changed-file names and commit titles are research hints, not vetted "
        "features, fixes or security claims.", "",
        "| Metric | Observed |", "|---|---:|",
    ]
    for key in ("parts", "forks", "branch_refs", "global_unique_head_shas",
                "unique_foreign_commit_shas", "same_shas_in_our_fork",
                "direct_parent_shared_sha_candidates",
                "commit_references_with_incomplete_file_list"):
        lines.append(f"| {key} | {t[key]} |")
    lines.extend([
        "", f"Pinned root main SHA: {t['pinned_upstream_sha']}", "",
        "## Highest-ranked unreviewed leads (heuristics, not acceptance)", "",
        "| Provisional | SHA | Example fork | Subject | Identical SHA in our fork? |",
        "|---|---|---|---|---|",
    ])
    for row in result["human_review_queue"]:
        sub = row["subject"].replace("|", "\\|").replace("\n", " ")[:90]
        lines.append(
            f"| {row['provisional_priority']} | "
            f"[{row['sha'][:12]}]({row['source_url']}) | "
            f"{row['sample_fork']} | {sub} | No SHA match found |"
        )
    lines.extend([
        "", "## Rules before any code change", "",
        "1. Inspect full diff and real direct-parent lineage: a duplicated "
        "commit SHA appearing in many forks is only one original change.",
        "2. Compare against the exact current calex794/noq source and "
        "upstream: a different SHA may still be a cherry-pick of an "
        "already fixed bug.",
        "3. Preserve source SHA, branch, license and relevant protocol "
        "version; prohibit copying an entire old fork.",
        "4. RED on the pinned noq baseline, minimal isolated candidate "
        "patch, independent GREEN with Roha/noq feature and strict CI.",
        "5. Only then promote a candidate to the Notion function matrix "
        "as implemented. All rows here are explicitly unreviewed.",
        "",
        "Source evidence is retained in the original 17 GitHub Actions "
        "artifacts; this report only indexes and deduplicates it.",
    ])
    (out / "TRIAGE.md").write_text("\n".join(lines) + "\n",
                                  encoding="utf-8")
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--run", required=True, type=int)
    parser.add_argument("--expected-forks", type=int, default=75)
    args = parser.parse_args()
    parts = load_parts(args.evidence)
    result = classify(parts, args.expected_forks)
    output(result, args.out, args.run)
    print(json.dumps(result["totals"], sort_keys=True))


if __name__ == "__main__":
    main()
