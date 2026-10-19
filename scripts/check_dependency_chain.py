#!/usr/bin/env python3
"""Reject mixed crates.io/upstream transport deps in STAYA WOW W6 iroh lab.

Executed against the *resolved* Cargo dependency graph, not just Cargo.toml.
Adapted from the existing Akula fork validation. This is a safety gate, not a substitute for pinning Cargo.lock.
"""
from __future__ import annotations

import json
import pathlib
import sys
import tomllib

ROHA_REV = "396a6006b15e4c3a63e111a720b84416fe6220f1"
NOQ_REV = "2eabf9895d40c263aa3369afd66efcf4a5d95056"
EXPECTED = {
    "iroh": ("roha", "1.3.0", ROHA_REV),
    "iroh-base": ("roha", "1.3.0", ROHA_REV),
    "iroh-dns": ("roha", "1.3.0", ROHA_REV),
    "iroh-relay": ("roha", "1.3.0", ROHA_REV),
    "noq": ("noq", "1.4.0", NOQ_REV),
    "noq-proto": ("noq", "1.4.0", NOQ_REV),
    "noq-udp": ("noq", "1.4.0", NOQ_REV),
}


def verify_source(name: str, version: str, source: str | None) -> None:
    fork, expected_version, revision = EXPECTED[name]
    expected_prefix = f"git+https://github.com/calex794/{fork}?rev={revision}#{revision}"
    if version != expected_version or source != expected_prefix:
        raise AssertionError(
            f"{name}: expected {expected_version} from {expected_prefix}; "
            f"got {version} from {source!r}"
        )


def verify(metadata: dict, lock: dict) -> None:
    # Cargo metadata lists all resolved packages (including build/dev deps).
    packages = metadata["packages"]
    for name in EXPECTED:
        matches = [p for p in packages if p["name"] == name]
        if len(matches) != 1:
            raise AssertionError(f"{name}: expected one resolved package, got {len(matches)}")
        p = matches[0]
        verify_source(name, p["version"], p.get("source"))

    # Verify that the selected graph really reaches the pinned packages.
    resolve = metadata.get("resolve") or {}
    root_id = resolve.get("root")
    if not root_id:
        raise AssertionError("cargo metadata must have a root package")
    nodes = {node["id"]: node for node in resolve.get("nodes", [])}
    seen = set()
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        node = nodes.get(package_id)
        if node is None:
            raise AssertionError(f"missing resolution node: {package_id}")
        pending.extend(node.get("dependencies", []))
    for name in EXPECTED:
        matched_id = next(p["id"] for p in packages if p["name"] == name)
        if matched_id not in seen:
            raise AssertionError(f"{name}: pinned package is not reachable from lab")

    # Prevent a stale/alternate copy in the checked-in lockfile.
    locked = lock["package"]
    for name in EXPECTED:
        matches = [p for p in locked if p["name"] == name]
        if len(matches) != 1:
            raise AssertionError(f"{name}: expected one lockfile package, got {len(matches)}")
        verify_source(name, matches[0]["version"], matches[0].get("source"))


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python check_dependency_chain.py metadata.json Cargo.lock")
    metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    lock = tomllib.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
    verify(metadata, lock)
    for name, (fork, version, revision) in EXPECTED.items():
        print(f"VERIFIED {name} {version} calex794/{fork} {revision}")
    print("PASS: no registry/upstream or duplicate Roha/noq packages in the resolved graph")


if __name__ == "__main__":
    main()
