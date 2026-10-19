"""Offline acceptance tests for the 17-part noq triage aggregator."""
import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aggregate_deep import classify, load_parts, output


class AggregateDeepTests(unittest.TestCase):
    def fixtures(self):
        own_sha = "a" * 40
        candidate_sha = "b" * 40
        root = "c" * 40
        parts = [
            {"part": k, "parts": 17, "base_sha": root,
             "not_product_acceptance": True,
             "totals": {"errors": []}, "repositories": []}
            for k in range(1, 18)
        ]
        parts[0]["repositories"] = [
            {
                "name": "calex794/noq", "verified": True,
                "parent": "n0-computer/noq", "branch_count": 2,
                "branches": [
                    {"head_sha": own_sha, "names": ["main"]},
                    {"head_sha": candidate_sha, "names": ["test"]},
                ],
                "unique_commits": [
                    {"sha": own_sha, "subject": "fix harmless panic",
                     "files": ["noq-proto/src/connection/mod.rs"]},
                ],
            },
            {
                "name": "emrul/noq", "verified": True,
                "parent": "calex794/noq", "branch_count": 3,
                "branches": [
                    {"head_sha": own_sha, "names": ["dup-main"]},
                    {"head_sha": candidate_sha, "names": ["fix/ack-range"]},
                ],
                "unique_commits": [
                    {"sha": own_sha, "subject": "fix harmless panic",
                     "files": ["noq-proto/src/connection/mod.rs"]},
                    {"sha": candidate_sha, "subject": "prevent packet number overflow",
                     "files": ["noq-proto/src/connection/mod.rs"]},
                ],
            },
        ]
        return parts

    def test_duplicate_sha_is_one_candidate_not_two_fixes(self):
        found = classify(self.fixtures(), expected_forks=2)
        self.assertEqual(found["totals"]["parts"], 17)
        self.assertEqual(found["totals"]["forks"], 2)
        self.assertEqual(found["totals"]["branch_refs"], 5)
        self.assertEqual(found["totals"]["global_unique_head_shas"], 2)
        self.assertEqual(found["totals"]["unique_foreign_commit_shas"], 2)
        self.assertEqual(found["totals"]["same_shas_in_our_fork"], 1)
        self.assertEqual(found["totals"]["direct_parent_shared_sha_candidates"], 1)
        self.assertEqual(len(found["human_review_queue"]), 1)
        self.assertEqual(found["human_review_queue"][0]["sha"], "b" * 40)
        self.assertEqual(found["human_review_queue"][0]["provisional_priority"], "P0?")
        self.assertEqual(found["ranked"][-1]["review_status"],
                         "sha-identical-in-our-fork")

    def test_incomplete_scan_is_not_success(self):
        data = self.fixtures()
        data[0]["totals"]["errors"] = ["emrul/noq"]
        with tempfile.TemporaryDirectory() as d:
            for part in data:
                Path(d, f"deep-part-{part['part']:02}.json").write_text(
                    json.dumps(part), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unfinished"):
                load_parts(d)

    def test_all_parts_and_baseline_are_mandatory(self):
        with tempfile.TemporaryDirectory() as d:
            parts = self.fixtures()
            for part in parts[:-1]:
                Path(d, f"deep-part-{part['part']:02}.json").write_text(
                    json.dumps(part), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "all 17 parts"):
                load_parts(d)
            last = parts[-1]
            last["base_sha"] = "d" * 40
            Path(d, "deep-part-17.json").write_text(json.dumps(last))
            with self.assertRaisesRegex(ValueError, "upstream SHA mismatch"):
                load_parts(d)

    def test_reports_never_claim_code_verified(self):
        found = classify(self.fixtures(), expected_forks=2)
        with tempfile.TemporaryDirectory() as d:
            output(found, d, 123)
            md = Path(d, "TRIAGE.md").read_text()
            csv = Path(d, "triage-candidates.csv").read_text()
            self.assertIn("not vetted", md)
            self.assertIn("needs-code-diff-and-test", csv)
            self.assertIn("sha-identical-in-our-fork", csv)


if __name__ == "__main__":
    unittest.main()
