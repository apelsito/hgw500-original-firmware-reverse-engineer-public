#!/usr/bin/env python3
"""Recover the reviewed OEM startup scripts and embedded kernel configuration."""
import argparse
import gzip
import hashlib
import json
import lzma
import re
import shutil
import subprocess
from pathlib import Path

EXPECTED_SHA256 = "f39ed40cc66010287574bdc41c9fc18a6ba7d674f7c0acd7d7d47f8ab633a42f"
PRIVATE_PATTERN = re.compile(r"(?:passw(?:or)?d|psk|secret|credential|authorized|BEGIN.*PRIVATE|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", re.I)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("private_directory", type=Path)
    parser.add_argument("readable_output", type=Path)
    args = parser.parse_args()
    if "out" not in args.private_directory.resolve().parts:
        parser.error("private intermediate files require ignored out")
    blob = args.image.read_bytes()
    if hashlib.sha256(blob).hexdigest() != EXPECTED_SHA256:
        parser.error("input differs from the inspected OEM provider package")
    args.private_directory.mkdir(parents=True, exist_ok=False)
    args.readable_output.mkdir(parents=True, exist_ok=False)
    squashfs = args.private_directory / "rootfs.squashfs"
    squashfs.write_bytes(blob[1245184:6729728])
    scripts = args.private_directory / "oem-scripts"
    completed = subprocess.run(["unsquashfs", "-no-progress", "-no-xattrs", "-processors", "2", "-d", str(scripts), str(squashfs), "etc/init.d", "etc/inittab"], capture_output=True, check=True)
    (args.private_directory / "unsquashfs.stdout").write_bytes(completed.stdout)
    (args.private_directory / "unsquashfs.stderr").write_bytes(completed.stderr)
    members = []
    excluded = 0
    for source in scripts.rglob("*"):
        if not source.is_file():
            continue
        if PRIVATE_PATTERN.search(source.read_text(errors="replace")):
            excluded += 1
            continue
        relative = source.relative_to(scripts)
        output = args.readable_output / "oem-rootfs-scripts" / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output)
        members.append({"path": output.relative_to(args.readable_output).as_posix(), "bytes": output.stat().st_size, "sha256": hashlib.sha256(output.read_bytes()).hexdigest()})
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 * 1024 * 1024)
    kernel = decoder.decompress(blob[8192:], max_length=64 * 1024 * 1024)
    if not decoder.eof:
        raise ValueError("OEM kernel decompression is incomplete")
    config = gzip.decompress(kernel[2471444:2478405])
    text = config.decode()
    selected = [line for line in text.splitlines() if not line.startswith(("CONFIG_CMDLINE=", "CONFIG_INITRAMFS_SOURCE=", "CONFIG_BOOTCOMMAND="))]
    (args.readable_output / "oem-kernel.config.sanitized").write_text("\n".join(selected) + "\n")
    report = {"input_sha256": EXPECTED_SHA256, "script_files_exported": len(members), "files_omitted_by_private_content_filter": excluded, "scripts": members, "original_kernel_config_sha256": hashlib.sha256(config).hexdigest(), "config_redacted_lines": len(text.splitlines()) - len(selected), "extracted_code_executed": False, "hardware_accessed": False}
    (args.readable_output / "extraction.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Recovered {len(members)} exact scripts and sanitized kernel configuration")


if __name__ == "__main__":
    main()
