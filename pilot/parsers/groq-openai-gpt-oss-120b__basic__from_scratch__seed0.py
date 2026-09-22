#!/usr/bin/env python3
import sys
import struct
import json
import datetime
from pathlib import Path

# LinkFlags bits
HAS_LINK_TARGET_ID_LIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080

EXPECTED_HEADER_SIZE = 0x4C  # 76 bytes
EXPECTED_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'


def filetime_to_iso(ft):
    """Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01) to ISO‑8601 with UTC offset."""
    try:
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = base + datetime.timedelta(microseconds=ft // 10)
        return dt.isoformat()
    except Exception:
        raise ValueError("invalid FILETIME")


def read_struct(data, offset, fmt):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError("unexpected end of file")
    return struct.unpack_from(fmt, data, offset), offset + size


def parse_lnk(path_bytes):
    data = path_bytes
    offset = 0
    # ----- Header -----
    (header_size,), offset = read_struct(data, offset, "<I")
    if header_size != EXPECTED_HEADER_SIZE:
        raise ValueError("invalid header size")
    (clsid,), offset = read_struct(data, offset, "<16s")
    if clsid != EXPECTED_CLSID:
        raise ValueError("invalid CLSID")
    (link_flags,), offset = read_struct(data, offset, "<I")
    # skip FileAttributes
    (_,), offset = read_struct(data, offset, "<I")
    (creation_ft,), offset = read_struct(data, offset, "<Q")
    (access_ft,), offset = read_struct(data, offset, "<Q")
    (write_ft,), offset = read_struct(data, offset, "<Q")
    (file_size,), offset = read_struct(data, offset, "<I")
    (icon_index,), offset = read_struct(data, offset, "<i")
    # skip remaining header fields (ShowCommand, HotKey, Reserved1, Reserved2, Reserved3)
    offset += 4 + 2 + 2 + 4 + 4  # total 16 bytes

    # ----- Optional structures before StringData -----
    if link_flags & HAS_LINK_TARGET_ID_LIST:
        (idlist_size,), offset = read_struct(data, offset, "<H")
        offset += idlist_size
        if offset > len(data):
            raise ValueError("truncated LinkTargetIDList")

    if link_flags & HAS_LINK_INFO:
        (linkinfo_size,), offset = read_struct(data, offset, "<I")
        if linkinfo_size < 4:
            raise ValueError("invalid LinkInfo size")
        offset += linkinfo_size - 4
        if offset > len(data):
            raise ValueError("truncated LinkInfo")

    # ----- StringData -----
    def read_string(is_unicode):
        (char_count,), cur = read_struct(data, offset, "<H")
        bytes_needed = char_count * (2 if is_unicode else 1)
        if cur + bytes_needed > len(data):
            raise ValueError("truncated string data")
        raw = data[cur:cur + bytes_needed]
        cur += bytes_needed
        if is_unicode:
            # UTF‑16LE, strip possible trailing null
            s = raw.decode('utf-16le', errors='replace')
        else:
            s = raw.decode('utf-8', errors='replace')
        # Remove terminating null if present
        if s and s[-1] == '\x00':
            s = s[:-1]
        return s, cur

    strings = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
    }

    is_unicode = bool(link_flags & IS_UNICODE)

    # Order is fixed
    if link_flags & HAS_NAME:
        strings["name_string"], offset = read_string(is_unicode)
    if link_flags & HAS_RELATIVE_PATH:
        strings["relative_path"], offset = read_string(is_unicode)
    if link_flags & HAS_WORKING_DIR:
        strings["working_dir"], offset = read_string(is_unicode)
    if link_flags & HAS_ARGUMENTS:
        strings["command_line_arguments"], offset = read_string(is_unicode)
    if link_flags & HAS_ICON_LOCATION:
        strings["icon_location"], offset = read_string(is_unicode)

    # ----- Build result -----
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
    return result


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: parser.py <path-to-lnk-file>"}))
        sys.exit(1)

    try:
        raw = Path(sys.argv[1]).read_bytes()
    except Exception as e:
        print(json.dumps({"error": f"cannot read file: {e}"}))
        sys.exit(1)

    try:
        out = parse_lnk(raw)
        print(json.dumps(out, ensure_ascii=False))
        sys.exit(0)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)


if __name__ == "__main__":
    main()