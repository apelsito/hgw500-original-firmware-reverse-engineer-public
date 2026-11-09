#!/usr/bin/env python3
"""Verify the preserved readable files against their explicit source manifest."""
import hashlib
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "analysis/source-manifest.json").read_text())
    for member in manifest["files"]:
        path = (root / member["path"]).resolve(strict=True)
        if root not in path.parents:
            raise ValueError("manifest path resolves outside repository")
        data = path.read_bytes()
        if len(data) != member["bytes"] or hashlib.sha256(data).hexdigest() != member["sha256"]:
            raise ValueError("source digest differs: " + member["path"])
    ras = json.loads((root / "analysis/ras-structure.json").read_text())
    if not ras["header"]["header_crc32_valid"] or not ras["header"]["payload_crc32_valid"]:
        raise ValueError("recorded RAS checks did not pass")
    print(f"Verified {len(manifest['files'])} preserved files and recorded RAS CRC checks")


if __name__ == "__main__":
    main()
