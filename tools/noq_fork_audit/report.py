"""Report generator: raw evidence, CSV triage and 17 reproducible partitions."""
import csv
import json
from pathlib import Path
from urllib.parse import quote

from .api import PARTS
from .scan import part_of


def summary(data, run_url=""):
    c = data["coverage"]
    status = "PARTIAL / requires continuation" if c["partial"] else "PUBLIC SNAPSHOT COMPLETE"
    groups = c["triage_priorities"]
    lines = [
        "# noq forks: automated 17-part research",
        "",
        f"Captured {data['timestamp']}; **{status}**.",
        f"Source: https://github.com/{data['upstream']}. Our fork: https://github.com/{data['our_fork']}.",
        f"Part: {data['shard'] or 'all'}/{PARTS}. Discovered public forks:"
        f" {c['public_listed_forks']} (GitHub counter: {c['github_reported_forks']}).",
        f"Selected {c['selected_forks']}; visited {c['visited_forks']};"
        f" confirmed lineage {c['verified_lineage_forks']}.",
        f"Enumerated branches {c['branches']}; source comparisons {c['compared_branches']};"
        f" branches ahead {c['ahead_branches']}; unique SHA candidates"
        f" {c['distinct_candidate_shas']}.",
        f"Details examined {c['checked_commit_details']}; API calls {c['api_calls']}. "
        f"Triage suggestions: P0={groups.get('P0',0)}, P1={groups.get('P1',0)}, "
        f"P2={groups.get('P2',0)}, P3={groups.get('P3',0)}.",
        "",
        "**Priorities are automatic hypotheses, not verified bugs or safe fixes.** "
        "A differing commit SHA does not prove the feature is absent from our "
        "code: cherry-picks, reverted patches and upstream equivalents must "
        "be manually reconciled. Fork code is never executed.",
    ]
    if run_url:
        lines += ["", "Workflow and downloadable JSON/CSV evidence: " + run_url]
    if c["partial_reasons"]:
        lines += ["", "## Coverage limits (not silently counted as analyzed)", ""]
        lines += ["- " + x for x in c["partial_reasons"][:40]]
    lines += ["", "## Candidate queue", ""]
    for item in data["candidates"][:50]:
        title = item["title"].replace("\n", " ").replace("|", "/")[:120]
        file_status = "file list checked" if item["files_checked"] else "commit title only"
        url = f"https://github.com/{item['repo']}/commit/{item['sha']}"
        lines.append(
            f"- **{item['priority']}** [{title}]({url})"
            f" — {item['repo']}; {', '.join(item['topics']) or 'uncategorized'};"
            f" {file_status}"
        )
    lines += [
        "", "## Audit method",
        "1. Paginate the source repository's official forks API.",
        "2. Verify lineage and enumerate every public branch of each selected fork.",
        "3. Compare each branch with the current upstream branch; record ahead/behind"
        " separately and flag unlisted commit pages, errors or rate-limit stops.",
        "4. Compare ahead branches to our fork for triage; deduplicate exact commit"
        " SHAs and inspect bounded commit-level file paths.",
        "5. Reconcile suspected functions against current upstream, our actual"
        " tree, tests and protocol compatibility BEFORE any adoption.",
        "6. No automatic code cherry-picks, executable third-party code, or"
        " security acceptance decisions.",
        "",
    ]
    return "\n".join(lines)


def emit(data, path, run_url=""):
    out = Path(path)
    out.mkdir(parents=True, exist_ok=True)
    (out / "audit.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report = summary(data, run_url)
    (out / "README.md").write_text(report, encoding="utf-8")
    with (out / "branches.csv").open("w", newline="", encoding="utf-8") as file:
        names = ["repo", "part", "branch", "sha", "ahead", "behind",
                 "status", "comparison", "ahead_of_ours", "candidate_count",
                 "truncated_commits", "error", "url"]
        writer = csv.DictWriter(file, fieldnames=names)
        writer.writeheader()
        for row in data["branches"]:
            base = dict(row)
            base["url"] = (
                "https://github.com/" + row["repo"] + "/tree/"
                + quote(row["branch"], safe="/")
            )
            writer.writerow(base)
    with (out / "candidates.csv").open("w", newline="", encoding="utf-8") as file:
        names = ["sha", "repo", "priority", "title", "topics", "files",
                 "branches", "files_checked", "exact_sha_present_in_ours", "url"]
        writer = csv.DictWriter(file, fieldnames=names)
        writer.writeheader()
        for candidate in data["candidates"]:
            writer.writerow({
                "sha": candidate["sha"], "repo": candidate["repo"],
                "priority": candidate["priority"], "title": candidate["title"],
                "topics": ", ".join(candidate["topics"]),
                "files": ";".join(candidate["files"]),
                "branches": ";".join(
                    x["repo"] + ":" + x["branch"] for x in candidate["branches"]
                ),
                "files_checked": candidate["files_checked"],
                "exact_sha_present_in_ours": candidate["exact_sha_present_in_ours"],
                "url": "https://github.com/" + candidate["repo"] + "/commit/"
                       + candidate["sha"],
            })
    (out / "parts").mkdir(exist_ok=True)
    for part in range(1, PARTS + 1):
        forks = [x for x in data["forks"] if x["part"] == part]
        branches = [x for x in data["branches"] if x["part"] == part]
        record = {
            "part": part, "timestamp": data["timestamp"],
            "forks": forks, "branches": branches,
            "checked": len(forks),
            "compare_count": sum(b["comparison"] == "upstream" for b in branches),
        }
        (out / "parts" / f"part_{part:02d}.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return report
