#!/usr/bin/env python3
import sys
import json
import struct
import datetime
from pathlib import Path

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def error(msg: str) -> None:
    """Print error JSON to stdout and exit with non‑zero code."""
    sys.stdout.write(json.dumps({"error": msg}, ensure_ascii=False))
    sys.exit(1)


def read_bytes(data: memoryview, offset: int, size: int) -> bytes:
    if offset + size > len(data):
        raise ValueError("unexpected end of file")
    return data[offset : offset + size].tobytes()


def unpack_from(fmt: str, data: memoryview, offset: int):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError("unexpected end of file")
    return struct.unpack_from(fmt, data, offset), offset + size


def filetime_to_iso(ft: int) -> str:
    """Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01) to ISO‑8601 UTC."""
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    # 1 FILETIME unit = 100 ns = 0.1 µs
    microseconds = ft // 10
    dt = epoch + datetime.timedelta(microseconds=microseconds)
    return dt.isoformat(timespec='seconds')


def parse_string(data: memoryview, offset: int, is_unicode: bool):
    (cnt_raw,), offset = unpack_from("<H", data, offset)
    char_count = cnt_raw
    byte_len = char_count * (2 if is_unicode else 1)
    raw = read_bytes(data, offset, byte_len)
    offset += byte_len
    try:
        if is_unicode:
            s = raw.decode("utf-16le", errors="replace")
        else:
            s = raw.decode("utf-8", errors="replace")
    except Exception:
        s = ""
    return s, offset


# ----------------------------------------------------------------------
# Main parsing routine
# ----------------------------------------------------------------------
def parse_lnk(path: Path):
    try:
        raw = path.read_bytes()
    except Exception as e:
        error(f"cannot read file: {e}")

    data = memoryview(raw)
    offset = 0

    # ---- ShellLinkHeader (76 bytes) ----
    if len(data) < 76:
        error("file too short for ShellLinkHeader")

    # HeaderSize
    (header_size,), offset = unpack_from("<I", data, offset)
    if header_size != 0x4C:
        error("invalid HeaderSize")

    # LinkCLSID
    link_clsid_bytes, offset = read_bytes(data, offset, 16), offset + 16
    expected_clsid = bytes.fromhex("0114020000000000C000000000000046")
    if link_clsid_bytes != expected_clsid:
        error("invalid LinkCLSID")

    # LinkFlags
    (link_flags,), offset = unpack_from("<I", data, offset)

    # FileAttributes (skip, not needed)
    (_,), offset = unpack_from("<I", data, offset)

    # CreationTime, AccessTime, WriteTime
    (creation_ft,), offset = unpack_from("<Q", data, offset)
    (access_ft,), offset = unpack_from("<Q", data, offset)
    (write_ft,), offset = unpack_from("<Q", data, offset)

    # FileSize (unsigned 32‑bit)
    (file_size,), offset = unpack_from("<I", data, offset)

    # IconIndex (signed 32‑bit)
    (icon_index,), offset = unpack_from("<i", data, offset)

    # Skip ShowCommand, HotKey, Reserved1‑3 (total 12 bytes)
    offset += 12

    # ---- Optional IDList ----
    HAS_IDLIST = 0x00000001
    if link_flags & HAS_IDLIST:
        (idlist_size,), offset = unpack_from("<H", data, offset)
        offset += idlist_size
        if offset > len(data):
            error("IDList exceeds file size")

    # ---- Optional LinkInfo ----
    HAS_LINKINFO = 0x00000002
    if link_flags & HAS_LINKINFO:
        (linkinfo_size,), offset = unpack_from("<I", data, offset)
        if linkinfo_size < 4:
            error("invalid LinkInfoSize")
        offset += linkinfo_size - 4  # we already consumed the size field
        if offset > len(data):
            error("LinkInfo exceeds file size")

    # ---- StringData sections (order matters) ----
    IS_UNICODE = bool(link_flags & 0x00000080)
    strings = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
    }

    flag_map = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]

    for bit, key in flag_map:
        if link_flags & bit:
            try:
                s, offset = parse_string(data, offset, IS_UNICODE)
                strings[key] = s
            except Exception:
                error(f"failed to read {key}")

    # We ignore any extra data blocks after StringData.

    # ---- Build result ----
    result = {
        "name_string": strings["name_string"],
        "relative_path": strings["relative_path"],
        "working_dir": strings["working_dir"],
        "command_line_arguments": strings["command_line_arguments"],
        "icon_location": strings["icon_location"],
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_ft),
        "access_time": filetime_to_iso(access_ft),
        "write_time": filetime_to_iso(write_ft),
    }

    sys.stdout.write(json.dumps(result, ensure_ascii=False))
    sys.exit(0)


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)

    path = Path(sys.argv[1])
    if not path.is_file():
        error("path does not point to a file")

    parse_lnk(path)


if __name__ == "__main__":
    main()