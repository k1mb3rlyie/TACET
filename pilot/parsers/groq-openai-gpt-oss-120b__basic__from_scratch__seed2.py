#!/usr/bin/env python3
import sys
import struct
import json
from datetime import datetime, timezone, timedelta

# ---------- helpers ----------
def read_uint16(data, off):
    if off + 2 > len(data):
        raise EOFError
    return struct.unpack_from("<H", data, off)[0], off + 2

def read_uint32(data, off):
    if off + 4 > len(data):
        raise EOFError
    return struct.unpack_from("<I", data, off)[0], off + 4

def read_uint64(data, off):
    if off + 8 > len(data):
        raise EOFError
    return struct.unpack_from("<Q", data, off)[0], off + 8

def filetime_to_iso(ft):
    if ft == 0:
        return None
    # FILETIME is 100‑nanosecond intervals since 1601‑01‑01 UTC
    base = datetime(1601, 1, 1, tzinfo=timezone.utc)
    try:
        dt = base + timedelta(microseconds=ft // 10)
    except OverflowError:
        return None
    return dt.isoformat()

def read_string(data, off, is_unicode):
    """Return (string_or_None, new_offset). If length is zero, returns empty string."""
    length, off = read_uint16(data, off)          # number of characters (Unicode) or bytes (ANSI)
    if is_unicode:
        byte_len = length * 2
        if off + byte_len > len(data):
            raise EOFError
        raw = data[off:off + byte_len]
        try:
            s = raw.decode('utf-16le')
        except UnicodeDecodeError:
            raise ValueError("invalid UTF‑16LE string")
        off += byte_len
    else:
        if off + length > len(data):
            raise EOFError
        raw = data[off:off + length]
        try:
            s = raw.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            raise ValueError("invalid ANSI string")
        off += length
    return s, off

def parse_lnk(path):
    with open(path, "rb") as f:
        data = f.read()

    # ---- Shell Link Header (76 bytes) ----
    if len(data) < 76:
        raise ValueError("file too short for header")
    header_size, = struct.unpack_from("<I", data, 0)
    if header_size != 0x4C:
        raise ValueError("invalid header size")
    # skip CLSID (16 bytes)
    link_flags, = struct.unpack_from("<I", data, 20)

    # timestamps
    creation_ft, off = read_uint64(data, 28)
    access_ft, off = read_uint64(data, 36)
    write_ft, off = read_uint64(data, 44)

    file_size, = struct.unpack_from("<I", data, 52)
    icon_index, = struct.unpack_from("<I", data, 56)

    # flags we care about
    HAS_LINK_TARGET_ID_LIST = 0x00000001
    HAS_LINK_INFO           = 0x00000002
    HAS_NAME                = 0x00000004
    HAS_RELATIVE_PATH       = 0x00000008
    HAS_WORKING_DIR         = 0x00000010
    HAS_ARGUMENTS           = 0x00000020
    HAS_ICON_LOCATION       = 0x00000040
    IS_UNICODE              = 0x00000080

    is_unicode = bool(link_flags & IS_UNICODE)

    # ---- optional structures after header ----
    offset = 76

    # LinkTargetIDList
    if link_flags & HAS_LINK_TARGET_ID_LIST:
        idlist_size, offset = read_uint16(data, offset)
        if offset + idlist_size > len(data):
            raise EOFError
        offset += idlist_size

    # LinkInfo
    if link_flags & HAS_LINK_INFO:
        linkinfo_size, offset = read_uint32(data, offset)
        if offset - 4 + linkinfo_size > len(data):
            raise EOFError
        offset += linkinfo_size - 4  # we already consumed 4 bytes for size

    # ---- StringData ----
    def maybe_read(flag):
        return (link_flags & flag) != 0

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    try:
        if maybe_read(HAS_NAME):
            name_string, offset = read_string(data, offset, is_unicode)
        if maybe_read(HAS_RELATIVE_PATH):
            relative_path, offset = read_string(data, offset, is_unicode)
        if maybe_read(HAS_WORKING_DIR):
            working_dir, offset = read_string(data, offset, is_unicode)
        if maybe_read(HAS_ARGUMENTS):
            command_line_arguments, offset = read_string(data, offset, is_unicode)
        if maybe_read(HAS_ICON_LOCATION):
            icon_location, offset = read_string(data, offset, is_unicode)
    except (EOFError, ValueError) as e:
        raise ValueError(f"failed to read string data: {e}")

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_ft),
        "access_time": filetime_to_iso(access_ft),
        "write_time": filetime_to_iso(write_ft)
    }

    # Convert absent timestamps (None) to null in JSON (they already are None)
    return result

# ---------- main ----------
def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\\n")
        sys.exit(1)

    try:
        out = parse_lnk(sys.argv[1])
        json.dump(out, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\\n")
        sys.exit(0)
    except Exception as e:
        err_obj = {"error": str(e)}
        json.dump(err_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\\n")
        sys.exit(1)

if __name__ == "__main__":
    main()