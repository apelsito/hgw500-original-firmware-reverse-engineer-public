#!/usr/bin/env python3
"""Project REA evidence into numeric metadata and reviewed file-name inventories."""
import argparse
import hashlib
import json
from pathlib import Path

PRIVATE_NAMES = ("private", "shadow", "passwd", "authorized_keys", "certificate", ".pem", ".key", "_key", "dropbear", "/tls/", "calibration", "store", "hostapd", "machine-id")


def load(path):
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private_directory", type=Path)
    parser.add_argument("analysis_directory", type=Path)
    args = parser.parse_args()
    entropy, entropy_sha = load(args.private_directory / "inspect-byte-entropy.stdout")
    value = entropy["normalized_result"]
    save(args.analysis_directory / "rea-entropy.json", {"source_evidence_sha256": entropy_sha, "input_bytes": value["artifact"]["bytes"], "input_sha256": value["artifact"]["sha256"], **{key: value[key] for key in ("block_size", "window", "file_entropy", "thresholds", "blocks", "runs", "limitations")}})
    extraction, extraction_sha = load(args.private_directory / "extract-firmware.stdout")
    value = extraction["normalized_result"]
    files = []
    excluded_count = 0
    for member in value["files"]:
        if any(word in member["relative_path"].lower() for word in PRIVATE_NAMES):
            excluded_count += 1
            continue
        files.append({key: member[key] for key in ("relative_path", "size", "sha256", "analysis_depth", "original_file_range")})
    save(args.analysis_directory / "rea-extraction.json", {"source_evidence_sha256": extraction_sha, "provider": extraction["provider"], "engine": {key: value["engine"][key] for key in ("name", "version", "executable_sha256", "worker_count")}, "selection": value["selection"], "coverage": value["coverage"], "total_regular_files": len(value["files"]), "excluded_private_path_count": excluded_count, "files": files, "limitations": extraction["limitations"]})
    print(f"Exported REA entropy and {len(files)} file metadata entries")


if __name__ == "__main__":
    main()
