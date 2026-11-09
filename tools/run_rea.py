#!/usr/bin/env python3
"""Run installed REA on an explicit firmware input, keeping raw evidence private."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("private_directory", type=Path)
    parser.add_argument("summary", type=Path)
    args = parser.parse_args()
    private = args.private_directory.resolve()
    if "out" not in private.parts:
        parser.error("raw evidence must stay under ignored out")
    private.mkdir(parents=True, exist_ok=False)
    image = private / "input.ras.bin"
    shutil.copyfile(args.image, image)
    commands = [
        ("version", ["--version"]),
        ("inspect-artifact", ["inspect-artifact", str(image), "--format", "json"]),
        ("inspect-byte-entropy", ["inspect-byte-entropy", str(image), "--format", "json"]),
        ("extract-firmware", ["extract-firmware", str(image), str(private / "extracted"), "--max-depth", "2", "--max-output-bytes", "134217728", "--max-output-files", "6000", "--analysis-timeout-ms", "120000", "--format", "json"]),
    ]
    results = []
    for operation, arguments in commands:
        command = ["/usr/local/bin/rea", *arguments]
        completed = subprocess.run(command, capture_output=True, timeout=180, check=False)
        (private / f"{operation}.stdout").write_bytes(completed.stdout)
        (private / f"{operation}.stderr").write_bytes(completed.stderr)
        result = {"operation": operation, "exit_code": completed.returncode, "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest()}
        if operation == "version":
            result["version"] = completed.stdout.decode().strip()
        else:
            try:
                value = json.loads(completed.stdout)
                if completed.returncode:
                    result.update({key: value[key] for key in ("error", "code", "category", "message") if key in value})
                else:
                    result["json_top_level_keys"] = list(value) if isinstance(value, dict) else []
            except (ValueError, UnicodeDecodeError):
                result["json_output"] = False
        results.append(result)
        print(f"REA {operation}: exit {completed.returncode}", flush=True)
    summary = {"schema": "openmitrastar.rea-run-summary/v1", "input_bytes": image.stat().st_size, "input_sha256": hashlib.sha256(image.read_bytes()).hexdigest(), "hardware_accessed": False, "raw_evidence_distribution": "local ignored out", "operations": results}
    with args.summary.open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
