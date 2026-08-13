#!/usr/bin/env python3
"""Print the workspace's crates.io publish order, dependencies first.

The order is derived from `cargo metadata` so that adding a crate, renaming one,
or changing an intra-workspace dependency cannot leave a stale hand-written list
behind. Crates with `publish = false` are omitted; a version that disagrees with
the workspace version is an error, because a release publishes exactly one
version across the workspace.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path


class PublishOrderError(RuntimeError):
    """The workspace cannot yield a single-version publish order."""


def workspace_version(root: Path) -> str:
    """Read the canonical workspace package version."""
    document = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    try:
        return document["workspace"]["package"]["version"]
    except KeyError as error:
        raise PublishOrderError("missing workspace.package.version") from error


def load_metadata(root: Path) -> dict:
    """Read `cargo metadata` for the workspace at ``root``."""
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PublishOrderError(f"cargo metadata failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def publish_order(metadata: dict, version: str) -> list[str]:
    """Topologically order publishable workspace members, dependencies first."""
    members = set(metadata["workspace_members"])
    packages = [p for p in metadata["packages"] if p["id"] in members]
    if not packages:
        raise PublishOrderError("workspace has no members")
    mismatched = sorted(
        f"{p['name']} {p['version']}" for p in packages if p["version"] != version
    )
    if mismatched:
        raise PublishOrderError(
            f"workspace version is {version} but found {', '.join(mismatched)}"
        )
    publishable = {p["name"]: p for p in packages if p.get("publish") != []}
    edges = {
        name: {
            dependency["name"]
            for dependency in package["dependencies"]
            if dependency["name"] in publishable and dependency.get("kind") != "dev"
        }
        for name, package in publishable.items()
    }
    ordered: list[str] = []
    placed: set[str] = set()
    while len(ordered) < len(edges):
        ready = sorted(
            name for name, deps in edges.items() if name not in placed and deps <= placed
        )
        if not ready:
            raise PublishOrderError(
                f"dependency cycle among {sorted(set(edges) - placed)}"
            )
        ordered.extend(ready)
        placed.update(ready)
    return ordered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    version = workspace_version(root)
    for crate in publish_order(load_metadata(root), version):
        print(crate)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PublishOrderError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
