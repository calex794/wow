#!/usr/bin/env python3
"""Source-aware, branch-aware fork census for n0-computer/noq.

No GitHub writes; operates on an independently pinned candidate list.
Usage:
  python3 research/noq-forks/audit.py inventory --out report
  python3 research/noq-forks/audit.py part --part 1 --out report

One shard (part) scans all branch refs in its forks and compares up to
MAX_DIFFS unique high-signal tips. Any unexamined tips are explicitly marked.
The report never confuses a GitHub forks_count with a verified inventory.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

UPSTREAM = "n0-computer/noq"
PARTS = 17
MAX_DIFFS = 8
SPECIAL = [
    "HeikoBornholdt/noq", "mp0rta/noq", "rayfish/noq",
    "saronic-technologies/noq", "moq-dev/noq", "emrul/noq",
    "eleboucher/noq", "zshenker/noq", "drlukeangel/noq",
    "colinmarc/noq", "KevinRoebert/noq", "dignakov/noq",
    "calex794/noq",
]
SIGNAL = re.compile(
    r"(^|[/_-])(fix|bug|p0|p1|security|cve|bbr|loss|timeout|sleep|"
    r"congestion|frag|panic|memory|multi|path|nat|quic|udp|stream|"
    r"priority|affinity|relay|close|shutdown|drain|handshake|"
    r"rate|transport|mtu|keepalive|qnt|qad|reset|flow|socket)([/_-]|$)",
    re.I,
)

class Problem(Exception):
    pass

class API:
    def __init__(self):
        self.token = os.getenv("GH_TOKEN", "")
        self.count = 0
    def get(self, path):
        url = "https://api.github.com" + path
        hdr = {"Accept": "application/vnd.github+json", "User-Agent": "wow-noq-fork-audit-v1",
               "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            hdr["Authorization"] = "Bearer " + self.token
        for attempt in range(3):
            try:
                req = Request(url, headers=hdr)
                with urlopen(req, timeout=45) as resp:
                    self.count += 1
                    return json.load(resp)
            except HTTPError as exc:
                self.count += 1
                if exc.code == 404:
                    return {"_error": "404"}
                if exc.code in (403, 429, 502, 503) and attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                return {"_error": str(exc.code), "detail": exc.read(160).decode("utf8", "replace")}
            except (URLError, TimeoutError, ValueError) as exc:
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                return {"_error": type(exc).__name__ + ": " + str(exc)[:140]}
        return {"_error": "retries_exhausted"}

def read_candidates():
    p = Path(__file__).with_name("candidates.json")
    content = json.loads(p.read_text(encoding="utf8"))
    values = content["candidates"]
    if len(values) != len(set(values)):
        raise Problem("Duplicate repository candidate")
    return sorted(values, key=str.lower), content["metadata"]

def sort_for_review(names):
    head = [n for n in SPECIAL if n in names]
    return head + [n for n in names if n not in head]

def shard(names, part):
    """Contiguous balanced shards: first parts hold priority fork families."""
    ordered = sort_for_review(names)
    left = ((part - 1) * len(ordered)) // PARTS
    right = (part * len(ordered)) // PARTS
    return ordered[left:right]

def source_record(api, name):
    doc = api.get("/repos/" + name)
    if "_error" in doc:
        return {"name": name, "verified": False, "status": "unavailable", "error": doc["_error"]}
    source = (doc.get("source") or {}).get("full_name")
    parent = (doc.get("parent") or {}).get("full_name")
    valid = doc.get("fork") is True and source == UPSTREAM
    return {
        "name": name, "verified": valid,
        "status": "confirmed" if valid else "not_upstream_fork",
        "parent": parent, "source": source,
        "default_branch": doc.get("default_branch", "main"),
        "archived": bool(doc.get("archived")), "pushed_at": doc.get("pushed_at"),
        "html_url": doc.get("html_url"), "repo_id": doc.get("id")
    }

def refs(name):
    """git ls-remote lists ALL branches, not only first API page.
    The explicit timeout and error field prevent silently accepting truncation.
    """
    cmd = ["git", "-c", "credential.helper=", "ls-remote",
           "--heads", "https://github.com/" + name + ".git"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=110, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {}, str(exc)
    if result.returncode:
        return {}, "git exit " + str(result.returncode) + ": " + result.stderr[:200]
    rows = {}
    for row in result.stdout.splitlines():
        sha, tab, ref = row.partition("\t")
        if tab and ref.startswith("refs/heads/") and re.fullmatch(r"[0-9a-f]{40}", sha):
            rows[ref[len("refs/heads/"):]] = sha
    if not rows:
        return {}, "no_heads_or_unavailable"
    return rows, None

def compare(api, base, head):
    # Commit-SHA comparison avoids branch slash URL ambiguity in APIs.
    x = api.get("/repos/" + UPSTREAM + "/compare/" + base + "..." + head)
    if "_error" in x:
        return {"status": "unavailable", "error": x["_error"]}
    return {
        "status": x.get("status"),
        "ahead_by": x.get("ahead_by"),
        "behind_by": x.get("behind_by"),
        "total_commits": x.get("total_commits"),
        "compare_files_count_returned": len(x.get("files", [])),
        "files_may_be_truncated": len(x.get("files", [])) >= 300,
        "top_changed_files": [
            {"file": y.get("filename"), "status": y.get("status"),
             "additions": y.get("additions"), "deletions": y.get("deletions")}
            for y in x.get("files", [])[:25]
        ],
        "commits_sample": [
            {"sha": y.get("sha"), "message": (y.get("commit", {}).get("message") or "").split("\n")[0][:160]}
            for y in x.get("commits", [])[-8:]
        ],
    }

def inventory(api, names, meta, out):
    rows = [source_record(api, n) for n in names]
    write(out, "inventory.json", {"meta": meta, "source": UPSTREAM, "rows": rows})
    verified = [r for r in rows if r["verified"]]
    missing = [r for r in rows if not r["verified"]]
    tally = {"candidate_count": len(rows), "verified_public": len(verified),
             "unverified": len(missing), "github_counter_snapshot": meta["github_forks_count_at_start"],
             "gap_to_counter": max(0, meta["github_forks_count_at_start"]-len(verified))}
    md = ["# noq public fork census (verified source/parent)",
          "", "This counts publicly visible forks, not all private/renamed descendants.",
          "Source= n0-computer/noq. Snapshot GitHub fork counter: "
          + str(meta["github_forks_count_at_start"]), "",
          json.dumps(tally), "", "## Unverified candidates"]
    md.extend("- " + r["name"] + " (" + r["status"] + ": " + str(r.get("error") or r.get("source")) + ")"
              for r in missing)
    md.extend(["", "## Confirmed forks"])
    md.extend("- " + r["name"] + " | parent " + str(r.get("parent")) for r in verified)
    write(out, "inventory.md", "\n".join(md) + "\n")
    return tally

def part(api, names, number, out):
    upstream = api.get("/repos/" + UPSTREAM + "/branches/main")
    upstream_sha = upstream.get("commit", {}).get("sha")
    if not upstream_sha:
        raise Problem("Cannot independently verify upstream main SHA")
    selected = shard(names, number)
    result = []
    for name in selected:
        entry = source_record(api, name)
        entry["branches"] = []
        if not entry["verified"]:
            result.append(entry)
            continue
        branches, error = refs(name)
        entry["branch_census_error"] = error
        entry["branch_count"] = len(branches)
        if error:
            result.append(entry)
            continue
        default = entry["default_branch"]
        ordered = sorted(branches.items(),
            key=lambda item: (item[0] != default, not bool(SIGNAL.search(item[0])), item[0]))
        seen = set()
        for branch_name, sha in ordered:
            duplicate = sha in seen
            seen.add(sha)
            entry["branches"].append({
                "branch": branch_name, "sha": sha, "default": branch_name == default,
                "name_signal": bool(SIGNAL.search(branch_name)),
                "same_sha_as_other_branch": duplicate,
                "comparison": None,
            })
        todo = [x for x in entry["branches"] if
                not x["same_sha_as_other_branch"]]
        entry["unique_sha_heads"] = len(todo)
        for x in todo[:MAX_DIFFS]:
            x["comparison"] = compare(api, upstream_sha, x["sha"])
        entry["compared_unique_heads"] = min(len(todo), MAX_DIFFS)
        entry["pending_unique_heads"] = max(0, len(todo) - MAX_DIFFS)
        result.append(entry)
    outdoc = {"part": number, "parts_total": PARTS, "source": UPSTREAM,
              "upstream_sha": upstream_sha, "repositories": result,
              "api_calls": api.count, "max_comparisons_per_repo": MAX_DIFFS}
    write(out, "part-%02d.json" % number, outdoc)
    lines = [
        "# noq fork audit part %02d/17" % number,
        "", "Pinned current upstream " + upstream_sha, "",
        "| Repository | Parent | Branches | Unique heads | Compared | Pending |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for row in result:
        lines.append("| "+row["name"]+" | "+str(row.get("parent", "?"))+
                     " | "+str(row.get("branch_count", 0))+
                     " | "+str(row.get("unique_sha_heads", 0))+
                     " | "+str(row.get("compared_unique_heads", 0))+
                     " | "+str(row.get("pending_unique_heads", 0))+" |")
    lines.extend(["", "## Candidate branches with ahead commits"])
    for row in result:
        for item in row["branches"]:
            c = item.get("comparison") or {}
            if c.get("ahead_by", 0) > 0:
                lines.append("- **"+row["name"]+":"+item["branch"]+"** "
                             +item["sha"][:12]+" ahead="+str(c["ahead_by"])
                             +" behind="+str(c.get("behind_by"))
                             +" ["+str(c.get("status"))+"]")
    lines.extend(["", "## Unresolved coverage"])
    for row in result:
        if row.get("branch_census_error") or row.get("pending_unique_heads") or not row["verified"]:
            lines.append("- " + row["name"] + ": branch error " +
                         str(row.get("branch_census_error")) +
                         ", unexamined heads " + str(row.get("pending_unique_heads", "unknown")))
    lines.append("")
    lines.append("Comparing heads does not certify changes. Require file-level diff, "
                 "independent RED/GREEN, Roha compatibility and a decision before adoption.")
    write(out, "part-%02d.md" % number, "\n".join(lines)+"\n")
    return {"part": number, "repos": len(result),
            "branch_count": sum(r.get("branch_count", 0) for r in result),
            "compared": sum(r.get("compared_unique_heads", 0) for r in result),
            "pending": sum(r.get("pending_unique_heads", 0) for r in result),
            "errors": [r["name"] for r in result if r.get("branch_census_error") or not r["verified"]]}

def write(out, file, content):
    p = Path(out)
    p.mkdir(parents=True, exist_ok=True)
    (p / file).write_text(json.dumps(content, ensure_ascii=False, indent=2)+"\n"
                          if isinstance(content, (dict,list)) else content,
                          encoding="utf8")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("mode", choices=["inventory","part"])
    p.add_argument("--part", type=int, default=1)
    p.add_argument("--out", default="research/noq-forks/output")
    args=p.parse_args()
    if args.mode=="part" and not (1<=args.part<=PARTS):
        p.error("--part must be 1..17")
    names,meta=read_candidates()
    api=API()
    report=inventory(api,names,meta,args.out) if args.mode=="inventory" else part(api,names,args.part,args.out)
    print(json.dumps(report,ensure_ascii=False,sort_keys=True))
    if args.mode=="part" and report["errors"]:
        print("WARNING: Some branch censuses failed; report explicitly marks incomplete coverage.",file=sys.stderr)

if __name__=="__main__":
    main()
