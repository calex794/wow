"""Seventeen stable fork slices with honest partial-coverage reporting."""
import hashlib
import re
from collections import Counter
from datetime import datetime, timezone

from .api import AuditError, QuotaStop, Github, SOURCE, OURS, PARTS, compare

NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SECURITY = re.compile(r"panic|crash|deadlock|overflow|security|denial.of.service|dos\b|out.of.memory|memory leak|reentrancy|attack|authentication", re.I)
NETWORK = re.compile(r"migrat|path|nat|hole.?punch|relay|route|socket|network change|ip address", re.I)
PERF = re.compile(r"bbr|congestion|bandwidth|pacing|throughput|rtt|loss recovery|ack frequency", re.I)
STREAM = re.compile(r"webtransport|datagram|stream|transport parameter|http.?3|zero.copy", re.I)
MAINT = re.compile(r"format|ci\b|workflow|dependabot|doc|readme|release|chore", re.I)


def part_of(repo):
    return 1 + int.from_bytes(
        hashlib.sha256(repo.casefold().encode()).digest()[:8], "big"
    ) % PARTS


def label(title, files=()):
    text = title + " " + " ".join(files)
    topics = []
    for name, rx in (
        ("security", SECURITY), ("network", NETWORK), ("performance", PERF),
        ("streams", STREAM), ("maintenance", MAINT),
    ):
        if rx.search(text):
            topics.append(name)
    if "security" in topics:
        priority = "P0"
    elif any(x in topics for x in ("network", "performance", "streams")):
        priority = "P1"
    elif topics == ["maintenance"]:
        priority = "P3"
    else:
        priority = "P2"
    return priority, topics


def scan(api: Github, shard=0, max_forks=0, detail_limit=80, max_branch_pages=10):
    if not 0 <= shard <= PARTS or max_forks < 0 or detail_limit < 0:
        raise ValueError("Invalid scan limits")
    upstream = api.get("/repos/" + SOURCE)
    ours = api.get("/repos/" + OURS)
    origin = upstream["default_branch"]
    mine = ours["default_branch"]
    listed, truncated = api.list("/repos/" + SOURCE + "/forks", max_pages=10)
    forks = {
        f["full_name"]: f for f in listed
        if NAME.fullmatch(str(f.get("full_name", "")))
    }
    all_selected = [n for n in sorted(forks) if shard == 0 or part_of(n) == shard]
    selected = all_selected[:max_forks] if max_forks else all_selected
    notes = []
    errors = []
    if truncated:
        notes.append("The upstream forks API listing exceeded its 10-page cap")
    reported = int(upstream.get("forks_count", 0))
    if len(forks) < reported:
        notes.append(f"GitHub reports {reported} forks; only {len(forks)} public forks listed")
    if shard:
        notes.append(f"Shard {shard}/{PARTS}, NOT a full cross-network snapshot")
    if len(selected) < len(all_selected):
        notes.append(f"Preview mode: {len(selected)} of {len(all_selected)} chosen forks")
    mine_shas = set()
    try:
        own = compare(api, origin, OURS.split("/")[0], mine)
        mine_shas = {x["sha"] for x in own["commits"]}
        if own["truncated"]:
            notes.append("Our fork compare yielded an incomplete commit list")
    except (AuditError, QuotaStop, ValueError) as error:
        errors.append({"where": "ours", "reason": str(error)})
        notes.append("Could not compare our fork; novelty must be checked manually")
    rows = []
    inventory = []
    candidates = {}
    halted = False
    for full_name in selected:
        if halted:
            break
        observed = forks[full_name]
        entry = {
            "repo": full_name, "part": part_of(full_name),
            "default_branch": observed.get("default_branch"),
            "archived": bool(observed.get("archived", False)),
            "lineage": "unverified", "branch_count": 0, "branches_truncated": False,
            "candidate_branches": 0,
        }
        inventory.append(entry)
        try:
            details = api.get("/repos/" + full_name)
            if (details.get("source") or {}).get("full_name") != SOURCE:
                notes.append(full_name + ": ancestry not confirmed")
                entry["lineage"] = "unconfirmed"
                continue
            entry["lineage"] = "verified"
            branches, too_many = api.list(
                "/repos/" + full_name + "/branches", max_pages=max_branch_pages
            )
            entry["branch_count"] = len(branches)
            entry["branches_truncated"] = too_many
            if too_many:
                notes.append(full_name + ": branch listing truncated")
            for ref in branches:
                branch = ref.get("name", "")
                if not branch:
                    continue
                sha = (ref.get("commit") or {}).get("sha", "")
                row = {
                    "repo": full_name, "part": part_of(full_name),
                    "branch": branch, "sha": sha, "ahead": None, "behind": None,
                    "status": "unknown", "comparison": "missing",
                    "ahead_of_ours": None, "candidate_count": 0,
                    "truncated_commits": False, "error": "",
                }
                rows.append(row)
                try:
                    comp = compare(api, origin, full_name.split("/")[0], branch)
                    row.update(
                        ahead=comp["ahead"], behind=comp["behind"],
                        status=comp["status"], comparison="upstream",
                        truncated_commits=comp["truncated"],
                    )
                    if comp["truncated"]:
                        notes.append(full_name + ":" + branch + " commit list truncated")
                    if comp["ahead"] > 0:
                        entry["candidate_branches"] += 1
                        try:
                            relative = compare(api, f"{OURS.split('/')[0]}:{mine}",
                                               full_name.split("/")[0], branch)
                            row["ahead_of_ours"] = relative["ahead"]
                        except (AuditError, ValueError):
                            # Cross-fork ancestry can be ambiguous. Never
                            # interpret an unavailable compare as no changes.
                            pass
                        for item in comp["commits"]:
                            key = item["sha"]
                            if not re.fullmatch("[0-9a-f]{40}", str(key)):
                                continue
                            old = candidates.setdefault(key, {
                                "sha": key, "repo": full_name,
                                "title": item["title"], "branches": [],
                                "priority": "", "topics": [], "files": [],
                                "exact_sha_present_in_ours": key in mine_shas,
                                "files_checked": False,
                            })
                            old["branches"].append({"repo": full_name, "branch": branch})
                            row["candidate_count"] += 1
                except QuotaStop:
                    raise
                except (AuditError, ValueError, KeyError) as error:
                    row["error"] = str(error)[:300]
                    errors.append({"where": full_name + ":" + branch,
                                   "reason": row["error"]})
        except QuotaStop as error:
            halted = True
            notes.append("Budget/rate cap: " + str(error))
        except (AuditError, ValueError) as error:
            errors.append({"where": full_name, "reason": str(error)[:300]})

    for item in candidates.values():
        item["priority"], item["topics"] = label(item["title"])
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    ranked = sorted(candidates.values(), key=lambda item: (
        order[item["priority"]], item["repo"], item["sha"]
    ))
    checked = 0
    for item in ranked[:detail_limit]:
        try:
            detail = api.get("/repos/" + item["repo"] + "/commits/" + item["sha"])
            item["files"] = [
                f.get("filename", "") for f in detail.get("files", [])[:250]
            ]
            item["priority"], item["topics"] = label(item["title"], item["files"])
            item["files_checked"] = True
            checked += 1
        except QuotaStop as error:
            notes.append("Commit-detail budget cap: " + str(error))
            break
        except (AuditError, ValueError) as error:
            errors.append({"where": "commit " + item["sha"], "reason": str(error)[:300]})
    if checked < len(candidates):
        notes.append(f"Only {checked}/{len(candidates)} commit file lists checked")
    if len(inventory) < len(selected):
        notes.append(f"Only {len(inventory)}/{len(selected)} selected forks scanned")
    if errors:
        notes.append(f"{len(errors)} upstream API/lineage/comparison errors")
    notes = list(dict.fromkeys(notes))
    public_inventory_complete = (
        len(selected) == len(all_selected)
        and len(inventory) == len(selected)
        and all(x["lineage"] == "verified" and not x["branches_truncated"]
                for x in inventory)
        and len(rows) == sum(x["branch_count"] for x in inventory)
        and all(x["comparison"] == "upstream"
                and not x["truncated_commits"] for x in rows)
    )
    grouped = Counter(x["priority"] for x in candidates.values())
    return {
        "schema": "noq-fork-audit-v1",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "upstream": SOURCE, "our_fork": OURS,
        "source_default_branch": origin, "our_default_branch": mine,
        "shard": shard, "shard_count": PARTS, "preview_limit": max_forks,
        "coverage": {
            "github_reported_forks": reported, "public_listed_forks": len(forks),
            "selected_forks": len(selected), "visited_forks": len(inventory),
            "verified_lineage_forks": sum(x["lineage"] == "verified" for x in inventory),
            "branches": len(rows),
            "compared_branches": sum(x["comparison"] == "upstream" for x in rows),
            "ahead_branches": sum((x["ahead"] or 0) > 0 for x in rows),
            "distinct_candidate_shas": len(candidates),
            "checked_commit_details": checked,
            "triage_priorities": dict(grouped),
            "api_calls": api.calls, "rate_remaining": api.remaining,
            "public_branch_inventory_complete": public_inventory_complete,
            "commit_details_complete": checked == len(candidates),
            "partial": bool(notes), "partial_reasons": notes[:100],
        },
        "forks": inventory, "branches": rows,
        "candidates": sorted(ranked, key=lambda x: (
            order[x["priority"]], x["repo"], x["sha"]
        )),
        "errors": errors[:300],
    }
