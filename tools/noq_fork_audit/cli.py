"""Run a bounded, read-only NOQ fork audit from GitHub Actions."""
import argparse
import json
import os
from datetime import date
from pathlib import Path

from .api import Github
from .scan import scan
from .report import emit
from .issue import publish


def main():
    p = argparse.ArgumentParser()
    p.add_argument("operation", choices=["scan", "publish"])
    p.add_argument("--part", type=int, default=0)
    p.add_argument("--max-forks", type=int, default=0)
    p.add_argument("--max-requests", type=int, default=900)
    p.add_argument("--detail-limit", type=int, default=80)
    p.add_argument("--out", default="out/noq-forks")
    a = p.parse_args()
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        p.error("Requires GitHub Actions API authentication")
    run = os.getenv("GITHUB_RUN_ID", "")
    url = "https://github.com/calex794/wow/actions/runs/" + run
    if a.operation == "scan":
        part = (date.today() - date(2026, 10, 19)).days % 17 + 1 if a.part == -1 else a.part
        data = scan(Github(token, budget=a.max_requests), shard=part,
                    max_forks=a.max_forks, detail_limit=a.detail_limit)
        report = emit(data, Path(a.out), url if run else "")
        print(report[:18000])
        step = os.getenv("GITHUB_STEP_SUMMARY", "")
        if step:
            with open(step, "a", encoding="utf-8") as f:
                f.write(report[:47000])
    else:
        data = json.loads((Path(a.out) / "audit.json").read_text(encoding="utf-8"))
        if data.get("schema") != "noq-fork-audit-v1" or not run.isdigit():
            p.error("Unexpected input or invalid run")
        print(publish(Github(token, budget=80), data, "calex794/wow", url))


if __name__ == "__main__":
    main()
