#!/usr/bin/env python3
"""Read the HGW500 RAS/uImage contract and bounded container metadata offline."""
import argparse
import hashlib
import json
import lzma
import struct
import zlib
from pathlib import Path

PAYLOAD_OFFSET = 0x2000
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def positions(data, marker):
    result = []
    start = 0
    while len(result) < 100:
        position = data.find(marker, start)
        if position < 0:
            break
        result.append(position)
        start = position + len(marker)
    return result


def cpio_inventory(data):
    """Inventory regular members without exporting file contents or private paths."""
    candidates = positions(data, b"070701")
    excluded = ("private", "shadow", "passwd", "authorized_keys", "certificate", ".pem", ".key", "_key", "dropbear", "/tls/", "calibration", "store", "hostapd", "machine-id")
    for start in candidates:
        cursor = start
        members = []
        private_members = 0
        try:
            for unused in range(10000):
                if data[cursor:cursor + 6] not in (b"070701", b"070702"):
                    raise ValueError("invalid newc magic")
                fields = [int(data[cursor + 6 + i * 8:cursor + 14 + i * 8], 16) for i in range(13)]
                mode, size, namesize = fields[1], fields[6], fields[11]
                if not 1 <= namesize <= 4096 or size > len(data):
                    raise ValueError("invalid newc size")
                name_start = cursor + 110
                raw_name = data[name_start:name_start + namesize]
                if len(raw_name) != namesize or raw_name[-1:] != b"\0":
                    raise ValueError("invalid newc name")
                name = raw_name[:-1].decode("utf-8", "replace")
                body_start = (name_start + namesize + 3) & ~3
                end = body_start + size
                if end > len(data):
                    raise ValueError("newc body exceeds input")
                if name == "TRAILER!!!":
                    return {"offset": start, "end_exclusive": (end + 3) & ~3, "exported_member_count": len(members), "private_member_count": private_members, "members": members}
                if any(word in name.lower() for word in excluded):
                    private_members += 1
                else:
                    member = {"path": name, "mode": oct(mode), "bytes": size, "body_offset": body_start}
                    if mode & 0o170000 == 0o100000:
                        member["sha256"] = digest(data[body_start:end])
                    members.append(member)
                cursor = (end + 3) & ~3
        except (ValueError, IndexError):
            continue
    return None


def squashfs_headers(data):
    results = []
    for offset in positions(data, b"hsqs"):
        if len(data) - offset < 96:
            continue
        fields = struct.unpack_from("<5I6H8Q", data, offset)
        if fields[9] != 4 or fields[3] < 4096 or fields[3] > 1048576:
            continue
        results.append({"offset": offset, "inodes": fields[1], "block_size": fields[3], "compression_id": fields[5], "version": f"{fields[9]}.{fields[10]}", "bytes_used": fields[12], "fits_input": offset + fields[12] <= len(data)})
    return results


def inspect(path, private_directory=None):
    blob = path.read_bytes()
    if len(blob) < PAYLOAD_OFFSET:
        raise ValueError("input is shorter than the RAS header area")
    fields = struct.unpack(">7I4B32s", blob[:64])
    magic, hcrc, timestamp, size, load, entry, dcrc = fields[:7]
    if magic != 0x27051956 or PAYLOAD_OFFSET + size > len(blob):
        raise ValueError("invalid RAS magic or payload bounds")
    header = bytearray(blob[:64])
    header[4:8] = b"\0" * 4
    payload = blob[PAYLOAD_OFFSET:PAYLOAD_OFFSET + size]
    result = {
        "schema": "openmitrastar.ras-analysis/v1", "bytes": len(blob), "sha256": digest(blob),
        "header": {"magic": hex(magic), "header_bytes": 64, "header_area_bytes": PAYLOAD_OFFSET, "timestamp": timestamp, "payload_bytes": size, "load": hex(load), "entry": hex(entry), "os": fields[7], "arch": fields[8], "type": fields[9], "compression": fields[10], "name": fields[11].split(b"\0")[0].decode("ascii", "replace"), "header_crc32_valid": zlib.crc32(header) & 0xffffffff == hcrc, "payload_crc32_valid": zlib.crc32(payload) & 0xffffffff == dcrc},
        "payload_sha256": digest(payload), "trailing_bytes": len(blob) - PAYLOAD_OFFSET - size,
        "squashfs_candidates_in_file": squashfs_headers(blob), "hardware_accessed": False,
    }
    if fields[10] == 3:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 * 1024 * 1024)
        raw = decoder.decompress(payload, max_length=MAX_DECOMPRESSED_BYTES + 1)
        if len(raw) > MAX_DECOMPRESSED_BYTES or not decoder.eof:
            raise ValueError("decompressed payload exceeds budget or is incomplete")
        result["lzma"] = {"dictionary_bytes": struct.unpack_from("<I", payload, 1)[0], "declared_uncompressed_bytes": struct.unpack_from("<Q", payload, 5)[0], "decompressed_bytes": len(raw), "decompressed_sha256": digest(raw), "unused_compressed_input_bytes": len(decoder.unused_data)}
        result["newc_inventory"] = cpio_inventory(raw)
        result["squashfs_candidates_in_decompressed_payload"] = squashfs_headers(raw)
        if private_directory:
            private_directory.mkdir(parents=True, exist_ok=False)
            (private_directory / "payload.raw").write_bytes(raw)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--private-directory", type=Path)
    args = parser.parse_args()
    if args.private_directory and "out" not in args.private_directory.resolve().parts:
        parser.error("private extraction must be under an ignored out directory")
    result = inspect(args.image, args.private_directory)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"RAS analyzed: {result['bytes']} bytes, header/payload CRC {result['header']['header_crc32_valid']}/{result['header']['payload_crc32_valid']}")


if __name__ == "__main__":
    main()
