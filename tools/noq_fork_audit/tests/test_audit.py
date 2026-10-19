"""Offline regression tests; no GitHub API requests or fork code execution."""
import json
import tempfile
import unittest
from pathlib import Path

from tools.noq_fork_audit.api import compare
from tools.noq_fork_audit.issue import decode_state, encode_state, record_part, render_index
from tools.noq_fork_audit.report import emit
from tools.noq_fork_audit.scan import label, part_of, scan


SHA_A = "a" * 40
SHA_B = "b" * 40


class FakeGithub:
    calls = 0
    remaining = 800

    def get(self, path):
        self.calls += 1
        if path == "/repos/n0-computer/noq":
            return {"default_branch": "main", "forks_count": 2}
        if path == "/repos/calex794/noq":
            return {"default_branch": "main"}
        if path in ("/repos/alpha/noq", "/repos/beta/noq"):
            return {"source": {"full_name": "n0-computer/noq"}}
        if "/commits/" in path:
            return {"files": [{"filename": "noq-proto/src/connection.rs"}]}
        if "/compare/" in path:
            if "alpha:feat%2Freconnect" in path:
                return {"ahead_by": 1, "behind_by": 2, "status": "diverged", "commits": [
                    {"sha": SHA_A, "commit": {"message": "Fix crash on network migration\nDetails"}}
                ]}
            if "beta:main" in path:
                return {"ahead_by": 1, "behind_by": 4, "status": "diverged", "commits": [
                    {"sha": SHA_B, "commit": {"message": "Improve BBR pacing"}}
                ]}
            return {"ahead_by": 0, "behind_by": 5, "status": "behind", "commits": []}
        raise AssertionError("Unexpected API endpoint: " + path)

    def list(self, endpoint, max_pages=12):
        if endpoint.endswith("/forks"):
            return [
                {"full_name": "alpha/noq", "default_branch": "main"},
                {"full_name": "beta/noq", "default_branch": "main"},
            ], False
        if endpoint.endswith("/alpha/noq/branches"):
            return [
                {"name": "main", "commit": {"sha": "1" * 40}},
                {"name": "feat/reconnect", "commit": {"sha": SHA_A}},
            ], False
        if endpoint.endswith("/beta/noq/branches"):
            return [{"name": "main", "commit": {"sha": SHA_B}}], False
        raise AssertionError("Unexpected list: " + endpoint)


class AuditTests(unittest.TestCase):
    def test_stable_parts_and_trust_classes(self):
        self.assertIn(part_of("alpha/noq"), range(1, 18))
        self.assertEqual(part_of("alpha/noq"), part_of("ALPHA/NOQ"))
        self.assertEqual(label("Fix crash on network migration")[0], "P0")
        self.assertEqual(label("Improve BBR pacing")[0], "P1")
        self.assertEqual(label("chore: fix CI workflow")[0], "P3")

    def test_compare_escapes_branch_slashes(self):
        payload = compare(FakeGithub(), "main", "alpha", "feat/reconnect")
        self.assertEqual(payload["ahead"], 1)
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["commits"][0]["sha"], SHA_A)

    def test_full_scan_enumerates_nondefault_branch(self):
        data = scan(FakeGithub(), detail_limit=5)
        self.assertFalse(data["coverage"]["partial"])
        self.assertEqual(data["coverage"]["public_listed_forks"], 2)
        self.assertEqual(data["coverage"]["verified_lineage_forks"], 2)
        self.assertEqual(data["coverage"]["branches"], 3)
        self.assertEqual(data["coverage"]["ahead_branches"], 2)
        self.assertEqual(data["coverage"]["distinct_candidate_shas"], 2)
        self.assertTrue(any(r["branch"] == "feat/reconnect" and r["ahead"] == 1
                            for r in data["branches"]))
        self.assertTrue(all(c["files_checked"] for c in data["candidates"]))
        with tempfile.TemporaryDirectory() as temp:
            report = emit(data, Path(temp), "https://github.com/calex794/wow/actions/runs/1")
            self.assertIn("Candidate queue", report)
            self.assertEqual(len(list((Path(temp) / "parts").glob("part_*.json"))), 17)
            self.assertEqual(len((Path(temp) / "branches.csv").read_text().splitlines()), 4)
            self.assertEqual(len(json.loads((Path(temp) / "audit.json").read_text())["candidates"]), 2)

    def test_preview_and_shard_are_honestly_partial(self):
        data = scan(FakeGithub(), max_forks=1, detail_limit=0)
        self.assertTrue(data["coverage"]["partial"])
        self.assertEqual(data["coverage"]["visited_forks"], 1)
        self.assertTrue(any("Preview mode" in s for s in data["coverage"]["partial_reasons"]))
        p = part_of("alpha/noq")
        subset = scan(FakeGithub(), shard=p, detail_limit=3)
        self.assertTrue(subset["coverage"]["partial"])
        self.assertTrue(any("Shard" in s for s in subset["coverage"]["partial_reasons"]))

    def test_issue_marker_round_trip_without_live_mutation(self):
        data = scan(FakeGithub(), detail_limit=5)
        run = "https://github.com/calex794/wow/actions/runs/123"
        state = {"schema": 1, "parts": {}}
        k = str(part_of("alpha/noq"))
        state["parts"][k] = record_part(data, int(k), run)
        body = render_index(state, data)
        decoded = decode_state(body)
        self.assertEqual(decoded["parts"][k]["snapshot"], data["timestamp"])
        self.assertEqual(decode_state("unrelated user text")["parts"], {})
        self.assertTrue(encode_state(state) in body)


if __name__ == "__main__":
    unittest.main()
