#!/usr/bin/env python3
import sys
import struct
import json
import datetime

# -------------------- Helpers -------------------- #

def filetime_to_iso(ft):
    """Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01 UTC) to ISO 8601."""
    if ft == 0:
        return None
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    try:
        dt = epoch + datetime.timedelta(microseconds=ft // 10)
    except OverflowError:
        return None
    return dt.isoformat()

def read_uint16(data, off):
    if off + 2 > len(data):
        raise ValueError("unexpected end of data while reading uint16")
    return struct.unpack_from("<H", data, off)[0], off + 2

def read_uint32(data, off):
    if off + 4 > len(data):
        raise ValueError("unexpected end of data while reading uint32")
    return struct.unpack_from("<I", data, off)[0], off + 4

def read_uint64(data, off):
    if off + 8 > len(data):
        raise ValueError("unexpected end of data while reading uint64")
    return struct.unpack_from("<Q", data, off)[0], off + 8

def read_string(data, off, is_unicode):
    """Read a (possibly Unicode) string prefixed by a 2‑byte length."""
    length, off = read_uint16(data, off)

    if is_unicode:
        byte_len = length * 2
        if off + byte_len > len(data):
            raise ValueError("string exceeds file size")
        raw = data[off:off + byte_len]
        try:
            s = raw.decode("utf-16le")
        except UnicodeDecodeError as e:
            raise ValueError("cannot decode Unicode string") from e
        off += byte_len
        # optional null terminator (2 bytes)
        if off + 2 <= len(data) and data[off:off + 2] == b"\x00\x00":
            off += 2
    else:
        if off + length > len(data):
            raise ValueError("string exceeds file size")
        raw = data[off:off + length]
        try:
            s = raw.decode("utf-8")  # best‑effort for ANSI strings
        except UnicodeDecodeError as e:
            raise ValueError("cannot decode ANSI string") from e
        off += length
        # optional null terminator (1 byte)
        if off < len(data) and data[off] == 0:
            off += 1
    return s, off

# -------------------- Main parser -------------------- #

def parse_lnk(data):
    if len(data) < 76:
        raise ValueError("file too short for LNK header")

    # Header
    header_size, off = read_uint32(data, 0)
    if header_size != 0x4C:
        raise ValueError("invalid header size")
    # CLSID (16 bytes)
    clsid = data[off:off + 16]
    off += 16
    expected_clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
    if clsid != expected_clsid:
        raise ValueError("invalid CLSID")
    link_flags, off = read_uint32(data, off)
    file_attrib, off = read_uint32(data, off)

    creation_ft, off = read_uint64(data, off)
    access_ft, off = read_uint64(data, off)
    write_ft, off = read_uint64(data, off)

    file_size, off = read_uint32(data, off)
    icon_index, off = read_uint32(data, off)

    # skip ShowCommand (4), HotKey (2), Reserved1 (2), Reserved2 (4), Reserved3 (4)
    off += 4 + 2 + 2 + 4 + 4

    # Optional structures
    HAS_LINKTARGET_IDLIST = 0x00000001
    HAS_LINKINFO = 0x00000002
    HAS_NAME = 0x00000004
    HAS_RELATIVE_PATH = 0x00000008
    HAS_WORKING_DIR = 0x00000010
    HAS_ARGUMENTS = 0x00000020
    HAS_ICON_LOCATION = 0x00000040
    IS_UNICODE = 0x00000080

    # LinkTargetIDList
    if link_flags & HAS_LINKTARGET_IDLIST:
        idlist_size, off = read_uint16(data, off)
        if off + idlist_size > len(data):
            raise ValueError("LinkTargetIDList exceeds file size")
        off += idlist_size

    # LinkInfo
    if link_flags & HAS_LINKINFO:
        linkinfo_size, off_tmp = read_uint32(data, off)
        if off + linkinfo_size > len(data):
            raise ValueError("LinkInfo exceeds file size")
        off += linkinfo_size

    # StringData (order matters)
    is_unicode = bool(link_flags & IS_UNICODE)

    def maybe_read(flag):
        return bool(link_flags & flag)

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if maybe_read(HAS_NAME):
        name_string, off = read_string(data, off, is_unicode)
    if maybe_read(HAS_RELATIVE_PATH):
        relative_path, off = read_string(data, off, is_unicode)
    if maybe_read(HAS_WORKING_DIR):
        working_dir, off = read_string(data, off, is_unicode)
    if maybe_read(HAS_ARGUMENTS):
        command_line_arguments, off = read_string(data, off, is_unicode)
    if maybe_read(HAS_ICON_LOCATION):
        icon_location, off = read_string(data, off, is_unicode)

    # Build result
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
        "write_time": filetime_to_iso(write_ft),
    }
    return result

# -------------------- Entry point -------------------- #

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        sys.stderr.write(f"Failed to read file: {e}\n")
        sys.exit(1)

    try:
        out = parse_lnk(data)
        json.dump(out, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as e:
        # Output error JSON as required
        err = {"error": str(e)}
        json.dump(err, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)

if __name__ == "__main__":
    main()