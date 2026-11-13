#!/usr/bin/env python3
"""Offline integrity gate for the published forensic-evidence manifest.

Does not execute forensic probes or access any private runtime material.
"""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "repo-v0.1-manifest.csv"
CURRENT = ROOT / "manifests" / "current-tree-blobs.csv"
HEX = re.compile(r"[a-fA-F0-9]{64}\Z")


def verify_manifest(root: Path = ROOT, manifest: Path = MANIFEST) -> dict:
    root = Path(root).resolve()
    rows = list(csv.DictReader(Path(manifest).open(encoding="utf-8-sig", newline="")))
    if not rows:
        raise ValueError("Empty publication manifest")
    expected_fields = {"PublishedPath", "Size", "SHA256", "HashBasis"}
    if not expected_fields.issubset(rows[0]):
        raise ValueError("Publication manifest missing integrity columns")
    paths = set()
    for index, row in enumerate(rows, start=1):
        name = row["PublishedPath"]
        relative = Path(name)
        if (not name or relative.is_absolute() or ".." in relative.parts
                or relative.parts[0] not in ("sana", "phoenix")
                or "\\" in name):
            raise ValueError(f"Row {index}: unsafe publication path")
        if name in paths:
            raise ValueError(f"Row {index}: duplicated path")
        paths.add(name)
        target = root / relative
        if not target.is_file() or target.is_symlink() or not target.resolve().is_relative_to(root):
            raise ValueError(f"Row {index}: published artifact missing/unsafe: {name}")
        if row["HashBasis"] != "published_content_sha256":
            raise ValueError(f"Row {index}: unsupported digest basis")
        digest = row["SHA256"]
        if HEX.fullmatch(digest) is None:
            raise ValueError(f"Row {index}: invalid SHA256")
        try:
            size = int(row["Size"])
        except ValueError as exc:
            raise ValueError(f"Row {index}: invalid size") from exc
        if size < 0 or target.stat().st_size != size:
            raise ValueError(f"Row {index}: size mismatch: {name}")
        hashed = hashlib.sha256()
        with target.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                hashed.update(chunk)
        if hashed.hexdigest().casefold() != digest.casefold():
            raise ValueError(f"Row {index}: SHA256 mismatch: {name}")
    return {"verified_artifacts": len(rows), "scope": "pinned_published_content_only"}


def verify_current_blobs(root: Path = ROOT, manifest: Path = CURRENT) -> dict:
    """Compare bytes to a separately pinned snapshot of current Git blobs.

    This is NOT certification of the historical v0.1 SHA256 manifest.
    """
    root = Path(root).resolve()
    with Path(manifest).open(encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        if reader.fieldnames != ["PublishedPath", "GitBlobSHA1"]:
            raise ValueError("Current Git blob manifest needs exact columns")
        rows = list(reader)
    if not rows:
        raise ValueError("Empty current Git blob manifest")
    paths = set()
    for index, row in enumerate(rows, start=1):
        name = row.get("PublishedPath", "")
        relative = Path(name)
        if (not name or relative.is_absolute() or ".." in relative.parts
                or "\\" in name or relative.parts[0] not in ("sana", "phoenix")):
            raise ValueError(f"Row {index}: unsafe publication path")
        if name in paths:
            raise ValueError(f"Row {index}: duplicate current path")
        paths.add(name)
        target = root / relative
        if (not target.is_file() or target.is_symlink()
                or not target.resolve().is_relative_to(root)):
            raise ValueError(f"Row {index}: current file missing or unsafe")
        expected = row.get("GitBlobSHA1", "")
        if re.fullmatch(r"[a-fA-F0-9]{40}", expected) is None:
            raise ValueError(f"Row {index}: malformed Git blob SHA1")
        # Git's blob object ID covers exact file bytes, including BOM/newlines.
        # Hash in chunks to avoid loading large forensic JSON into RAM.
        size = target.stat().st_size
        checksum = hashlib.sha1()
        checksum.update(b"blob " + str(size).encode("ascii") + b"\x00")
        with target.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                checksum.update(chunk)
        if checksum.hexdigest().casefold() != expected.casefold():
            raise ValueError(f"Row {index}: current Git blob mismatch: {name}")
    return {"verified_artifacts": len(rows), "scope": "current_git_blob_snapshot_only"}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-strict", action="store_true",
                        help="Compare old SHA-256/size manifest (known drift, fails closed)")
    args = parser.parse_args()
    report = verify_manifest() if args.legacy_strict else verify_current_blobs()
    print("Forensic evidence manifest:", report)
