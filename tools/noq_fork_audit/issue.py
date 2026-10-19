"""Idempotent GitHub issue index of the latest 17 partial snapshots."""
import base64
import json
import re
import urllib.request

from .api import Github, PARTS

TITLE = "NOQ fork audit — 17-part automated index"
MARKER = "<!-- NOQ_FORK_AUDIT_INDEX_V1:"
PATTERN = re.compile(r"<!-- NOQ_FORK_AUDIT_INDEX_V1:([A-Za-z0-9_-]+) -->")


def record_part(data, part, run_url):
    forks = [f for f in data["forks"] if f["part"] == part]
    branches = [b for b in data["branches"] if b["part"] == part]
    candidates = [
        c for c in data["candidates"]
        if any(f["repo"] in {x["repo"] for x in c["branches"]} for f in forks)
    ]
    missed = sum(bool(b["error"]) or b["truncated_commits"] for b in branches)
    return {
        "forks": len(forks), "branches": len(branches),
        "candidates": len(candidates), "uncertain_branches": missed,
        "snapshot": data["timestamp"], "run": run_url,
        "preview": bool(data["preview_limit"]),
        "inventory_complete": bool(
            data["coverage"]["public_branch_inventory_complete"]
        ),
        "details_complete": bool(data["coverage"]["commit_details_complete"]),
        "partial": bool(data["coverage"]["partial_reasons"]),
    }


def encode_state(state):
    raw = json.dumps(state, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_state(body):
    match = PATTERN.search(body or "")
    if not match:
        return {"schema": 1, "parts": {}}
    encoded = match.group(1)
    try:
        state = json.loads(base64.urlsafe_b64decode(
            encoded + "=" * ((-len(encoded)) % 4)
        ))
        if state.get("schema") == 1 and isinstance(state.get("parts"), dict):
            return state
    except (ValueError, TypeError):
        pass
    return {"schema": 1, "parts": {}}


def render_index(state, data):
    p = state["parts"]
    completed = sum(
        str(i) in p and p[str(i)].get("inventory_complete")
        and not p[str(i)].get("preview")
        for i in range(1, PARTS + 1)
    )
    lines = [
        "# NOQ fork audit: 17-part index",
        "",
        "Automated read-only audit of the public fork network of "
        "[n0-computer/noq](https://github.com/n0-computer/noq).",
        "**Every part can be captured on a different day; this is NOT one "
        "atomic global snapshot.**",
        f"Parts with verified public-branch inventory: **{completed}/{PARTS}**.",
        f"Latest Github fork counter: **{data['coverage']['github_reported_forks']}**; "
        f"public listings: **{data['coverage']['public_listed_forks']}**.",
        "All candidate priorities are unreviewed suggestions. No fork code "
        "is executed or automatically adopted.",
        "",
        "| Part | Forks | Branches | SHA candidates | Uncertain | Inventory | Last updated | Evidence |",
        "|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for i in range(1, PARTS + 1):
        one = p.get(str(i))
        if not one:
            lines.append(f"| {i:02d} | — | — | — | — | not scanned | — | — |")
            continue
        status = " preview" if one.get("preview") else ""
        verified = "complete" if one.get("inventory_complete") else "partial"
        url = one["run"]
        lines.append(
            f"| {i:02d} | {one['forks']} | {one['branches']} | "
            f"{one['candidates']} | {one['uncertain_branches']} | {verified} | "
            f"{one['snapshot'][:10]}{status} | [Actions]({url}) |"
        )
    lines += [
        "", "**How to investigate:** open the relevant run and download its "
        "JSON/CSV/17-part artifacts. The audit flags truncated/unavailable comparisons "
        "instead of calling them empty.",
        "",
        "After 17 scheduled daily runs all parts should have a snapshot, "
        "subject to API budgets, fork visibility and errors. Existing data "
        "remains visible while individual parts are refreshed.",
        "",
        "Current code: https://github.com/calex794/wow/tree/main/tools/noq_fork_audit",
    ]
    lines.append(MARKER + encode_state(state) + " -->")
    return "\n".join(lines) + "\n"


def write_issue(api: Github, method, repo, number, body):
    if repo != "calex794/wow":
        raise ValueError("Publishing is restricted to the wow audit repository")
    endpoint = f"/repos/{repo}/issues" + (f"/{number}" if number else "")
    req = urllib.request.Request(
        "https://api.github.com" + endpoint,
        data=json.dumps({"title": TITLE, "body": body}).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": "Bearer " + api.token,
            "User-Agent": "wow-noq-fork-audit",
            "Content-Type": "application/json",
        },
        method=method,
    )
    if not api.token:
        raise ValueError("GITHUB_TOKEN is required to publish an issue")
    with urllib.request.urlopen(req, timeout=25) as response:
        return json.loads(response.read())


def publish(api: Github, data, repo, run_url):
    if not run_url.startswith("https://github.com/calex794/wow/actions/runs/"):
        raise ValueError("Refusing an untrusted evidence URL")
    issues, truncated = api.list(f"/repos/{repo}/issues?state=all", max_pages=12)
    if truncated:
        raise ValueError("Issue listing truncated: cannot safely deduplicate")
    found = next((
        issue for issue in issues
        if issue.get("title") == TITLE
        and "pull_request" not in issue
        and MARKER in (issue.get("body") or "")
    ), None)
    state = decode_state(found.get("body")) if found else {"schema": 1, "parts": {}}
    if data["preview_limit"]:
        raise ValueError("Never publish a truncated preview as a durable part")
    if data["shard"]:
        parts = [data["shard"]]
    else:
        parts = list(range(1, PARTS + 1))
    for i in parts:
        state["parts"][str(i)] = record_part(data, i, run_url)
    body = render_index(state, data)
    if found:
        result = write_issue(api, "PATCH", repo, found["number"], body)
    else:
        result = write_issue(api, "POST", repo, None, body)
    return result["html_url"]
