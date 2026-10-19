#!/usr/bin/env python3
"""Exhaustive public-branch DAG census for 17 shards of n0-computer/noq forks.

Fetch every branch ref into a separate namespace in one bare Git repository,
compare with one pinned upstream SHA locally, and report distinct foreign
commits, files and direct-parent lineage. This is research, not adoption.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from audit import API, PARTS, UPSTREAM, read_candidates, shard, source_record, write

class GitError(RuntimeError):
    pass

def git(repo, *cmd, timeout=360):
    args = ["git", "-c", "gc.auto=0", "-C", str(repo), *cmd]
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(str(exc)) from exc
    if p.returncode:
        raise GitError(" ".join(cmd[:4]) + " status=" + str(p.returncode) +
                       ": " + p.stderr[-300:])
    return p.stdout.strip()

def fetch(repo, name, refspec):
    return git(repo, "fetch", "--no-tags", "--filter=blob:none",
               "https://github.com/" + name + ".git", refspec, timeout=480)

def branches(repo, prefix):
    value = git(repo, "for-each-ref", "--format=%(objectname)\t%(refname)", prefix)
    result = {}
    for line in value.splitlines():
        sha, _, ref = line.partition("\t")
        if ref.startswith(prefix) and re.fullmatch(r"[0-9a-f]{40}", sha):
            result[ref[len(prefix):]] = sha
    return result

def ahead_behind(repo, base, tip):
    data = git(repo, "rev-list", "--left-right", "--count",
               base + "..." + tip, timeout=60).split()
    if len(data) != 2:
        raise GitError("Unable to compare " + tip)
    return int(data[1]), int(data[0])

def foreign(repo, tips, upstream):
    if not tips:
        return []
    text = git(repo, "rev-list", *tips, "--not", upstream, timeout=180)
    return [t for t in text.splitlines() if re.fullmatch(r"[0-9a-f]{40}", t)]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--part", type=int, required=True)
    ap.add_argument("--out", default="audit-output")
    ap.add_argument("--file-cap", type=int, default=7000)
    args = ap.parse_args()
    if not 1 <= args.part <= PARTS:
        ap.error("part must be in 1..17")
    candidates, _ = read_candidates()
    api = API()
    chosen = shard(candidates, args.part)
    report = {"part": args.part, "parts": PARTS,
              "base": UPSTREAM, "method": "full local git DAG, no REST comparison cap",
              "repositories": [], "not_product_acceptance": True}
    try:
        with tempfile.TemporaryDirectory(prefix="noq-git-") as tmp:
            bare = Path(tmp) / "refs.git"
            git(tmp, "init", "--bare", str(bare), timeout=30)
            fetch(bare, UPSTREAM, "+refs/heads/main:refs/audit/base/main")
            base = git(bare, "rev-parse", "refs/audit/base/main")
            report["base_sha"] = base
            file_budget = args.file_cap
            for i, name in enumerate(chosen):
                row = source_record(api, name)
                row.update({"branches": [], "unique_commits": [],
                            "branch_count": 0, "ahead_head_count": 0})
                if not row["verified"]:
                    row["error"] = "Unverified source, refuse analysis"
                    report["repositories"].append(row)
                    continue
                try:
                    prefix = "refs/audit/fork" + str(i) + "/"
                    fetch(bare, name, "+refs/heads/*:" + prefix + "*")
                    heads = branches(bare, prefix)
                    if not heads:
                        raise GitError("Fork has no retrievable refs/heads")
                    row["branch_count"] = len(heads)
                    sha_groups = {}
                    for name_branch, sha in sorted(heads.items()):
                        sha_groups.setdefault(sha, []).append(name_branch)
                    row["distinct_head_count"] = len(sha_groups)
                    for sha, labels in sha_groups.items():
                        ahead, behind = ahead_behind(bare, base, sha)
                        row["branches"].append({
                            "head_sha": sha, "names": labels,
                            "ahead_vs_upstream": ahead,
                            "behind_vs_upstream": behind})
                        if ahead:
                            row["ahead_head_count"] += 1
                    tips = list(sha_groups)
                    ids = foreign(bare, tips, base)
                    row["new_commit_count_vs_upstream"] = len(ids)
                    # A nested fork may merely inherit changes from a
                    # non-root parent. Record independent parent baseline.
                    parent = row.get("parent")
                    if parent and parent != UPSTREAM:
                        parent_rec = api.get("/repos/" + parent)
                        if "_error" not in parent_rec:
                            default = parent_rec.get("default_branch", "main")
                            ref = "refs/audit/parent" + str(i) + "/base"
                            try:
                                fetch(bare, parent, "+refs/heads/" + default + ":" + ref)
                                parent_sha = git(bare, "rev-parse", ref)
                                row["parent_baseline_sha"] = parent_sha
                                row["new_commit_count_vs_direct_parent"] = len(
                                    foreign(bare, tips, parent_sha))
                            except GitError as ex:
                                row["parent_compare_error"] = str(ex)
                        else:
                            row["parent_compare_error"] = parent_rec["_error"]
                    for sha in ids:
                        title = git(bare, "show", "-s", "--format=%s", sha, timeout=40)
                        rec = {"sha": sha, "subject": title.splitlines()[0][:240]}
                        if file_budget > 0:
                            files = git(bare, "diff-tree", "--root", "--no-commit-id",
                                        "--name-only", "-r", sha, timeout=50).splitlines()
                            rec["files"] = files[:120]
                            rec["file_list_truncated"] = len(files)>120
                            file_budget -= 1
                        else:
                            rec["file_diff_pending"] = True
                        row["unique_commits"].append(rec)
                except GitError as ex:
                    row["error"] = str(ex)
                report["repositories"].append(row)
            report["examined_file_diffs"] = args.file_cap - file_budget
    except GitError as ex:
        report["fatal_error"] = str(ex)
    report["totals"] = {
        "forks": len(report["repositories"]),
        "branches": sum(x["branch_count"] for x in report["repositories"]),
        "heads_with_new_upstream_commits": sum(x["ahead_head_count"] for x in report["repositories"]),
        "foreign_commit_references": sum(x.get("new_commit_count_vs_upstream",0) for x in report["repositories"]),
        "errors": [x["name"] for x in report["repositories"] if x.get("error")]}
    write(args.out, "deep-part-%02d.json" % args.part, report)
    lines = ["# noq Git DAG census part %02d/17" % args.part, "",
             "Pinned upstream SHA: " + str(report.get("base_sha")), "",
             "| Fork | Branches | Ahead heads | Unmerged commits | Error |",
             "|---|---:|---:|---:|---|"]
    for x in report["repositories"]:
        lines.append("| " + x["name"] + " | " + str(x["branch_count"]) +
                     " | " + str(x["ahead_head_count"]) + " | " +
                     str(x.get("new_commit_count_vs_upstream",0)) +
                     " | " + str(x.get("error",""))[:80] + " |")
    lines.extend(["", "## Commit subjects (not yet adopted)"])
    for row in report["repositories"]:
        if row["unique_commits"]:
            lines.append("### " + row["name"])
            for c in row["unique_commits"][:80]:
                lines.append("- SHA " + c["sha"] + ": " + c["subject"] +
                             " [" + ", ".join(c.get("files",[])[:4]) + "]")
            if len(row["unique_commits"])>80:
                lines.append("Full unique SHA set is in JSON, not suppressed.")
    lines.extend(["", "A branch head with an upstream-unmerged commit is "
                  "NOT automatically a useful patch or new feature. Independently "
                  "verify ancestry, source diff, current fork applicability, "
                  "RED/GREEN and Roha/noq integration before adoption."])
    write(args.out, "deep-part-%02d.md" % args.part, "\n".join(lines)+"\n")
    print(json.dumps(report["totals"],sort_keys=True))
    if report.get("fatal_error") or report["totals"]["errors"]:
        print("Incomplete Git history: " + str(report.get("fatal_error")
              or report["totals"]["errors"]), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
