#!/usr/bin/env python3
import sys
import struct
import json
import datetime

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def error(msg):
    """Print error JSON to stdout and exit with non‑zero code."""
    sys.stdout.write(json.dumps({"error": msg}, ensure_ascii=False))
    sys.exit(1)


def read_bytes(data, pos, size):
    if pos + size > len(data):
        error("Unexpected end of file while reading")
    return data[pos:pos + size]


def read_uint16(data, pos):
    return struct.unpack_from("<H", data, pos)[0]


def read_uint32(data, pos):
    return struct.unpack_from("<I", data, pos)[0]


def read_int32(data, pos):
    return struct.unpack_from("<i", data, pos)[0]


def read_uint64(data, pos):
    return struct.unpack_from("<Q", data, pos)[0]


def filetime_to_iso(ft):
    """Convert Windows FILETIME (uint64) to ISO‑8601 with UTC offset."""
    try:
        # FILETIME is number of 100‑ns intervals since 1601‑01‑01 UTC
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        microseconds = ft // 10
        dt = base + datetime.timedelta(microseconds=microseconds)
        return dt.isoformat()
    except Exception:
        error("Invalid FILETIME value")


def decode_string(data, pos, char_count, is_unicode):
    """Return (string, new_position)."""
    if is_unicode:
        byte_len = char_count * 2
        raw = read_bytes(data, pos, byte_len)
        try:
            s = raw.decode("utf-16le", errors="replace")
        except Exception:
            error("Failed to decode UTF‑16LE string")
        return s, pos + byte_len
    else:
        byte_len = char_count
        raw = read_bytes(data, pos, byte_len)
        try:
            s = raw.decode("utf-8", errors="replace")
        except Exception:
            error("Failed to decode ANSI string")
        return s, pos + byte_len


# ----------------------------------------------------------------------
# Main parsing routine
# ----------------------------------------------------------------------
def parse_lnk(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        error(f"Cannot read file: {e}")

    pos = 0
    # ----- ShellLinkHeader (76 bytes) -----
    if len(data) < 76:
        error("File too short for ShellLinkHeader")

    header_size = read_uint32(data, pos)
    if header_size != 0x4C:
        error("Invalid HeaderSize")
    pos += 4

    link_clsid = read_bytes(data, pos, 16)
    expected_clsid = bytes.fromhex(
        "01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46".replace(" ", "")
    )
    if link_clsid != expected_clsid:
        error("Invalid LinkCLSID")
    pos += 16

    link_flags = read_uint32(data, pos)
    pos += 4

    # FileAttributes (ignored for output but must be read)
    _file_attrs = read_uint32(data, pos)
    pos += 4

    # Timestamps
    creation_ft = read_uint64(data, pos)
    pos += 8
    access_ft = read_uint64(data, pos)
    pos += 8
    write_ft = read_uint64(data, pos)
    pos += 8

    file_size = read_uint32(data, pos)
    pos += 4

    icon_index = read_int32(data, pos)
    pos += 4

    # Remaining header fields (ignored for output)
    pos += 4 + 2 + 2 + 4 + 4  # ShowCommand, HotKey, Reserved1, Reserved2, Reserved3

    # ----- Optional IDList -----
    HAS_IDLIST = link_flags & 0x00000001
    if HAS_IDLIST:
        if pos + 2 > len(data):
            error("Truncated IDList size")
        idlist_size = read_uint16(data, pos)
        pos += 2
        # Skip the IDList bytes
        if pos + idlist_size > len(data):
            error("Truncated IDList data")
        pos += idlist_size

    # ----- Optional LinkInfo -----
    HAS_LINKINFO = link_flags & 0x00000002
    if HAS_LINKINFO:
        if pos + 4 > len(data):
            error("Truncated LinkInfo size")
        linkinfo_size = read_uint32(data, pos)
        if linkinfo_size < 4:
            error("Invalid LinkInfo size")
        if pos + linkinfo_size > len(data):
            error("Truncated LinkInfo data")
        pos += linkinfo_size

    # ----- StringData sections -----
    IS_UNICODE = bool(link_flags & 0x00000080)

    # Mapping of flag bits to field names and presence bits
    string_defs = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]

    strings = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
    }

    for flag_bit, field_name in string_defs:
        if link_flags & flag_bit:
            if pos + 2 > len(data):
                error(f"Truncated {field_name} length")
            char_count = read_uint16(data, pos)
            pos += 2
            s, pos = decode_string(data, pos, char_count, IS_UNICODE)
            strings[field_name] = s
        else:
            strings[field_name] = None

    # ----- Build output -----
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
if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    parse_lnk(sys.argv[1])