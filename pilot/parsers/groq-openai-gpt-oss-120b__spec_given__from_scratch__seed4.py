#!/usr/bin/env python3
import sys
import struct
import json
import datetime

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------
def fail(msg: str):
    """Print error JSON and exit with non‑zero code."""
    sys.stdout.write(json.dumps({"error": msg}, ensure_ascii=False))
    sys.exit(1)


def read_struct(fmt: str, data: bytes, offset: int):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        fail("Unexpected end of file while reading structure")
    return struct.unpack_from(fmt, data, offset), offset + size


def read_uint16(data: bytes, offset: int):
    (val,), offset = read_struct("<H", data, offset)
    return val, offset


def read_uint32(data: bytes, offset: int):
    (val,), offset = read_struct("<I", data, offset)
    return val, offset


def read_int32(data: bytes, offset: int):
    (val,), offset = read_struct("<i", data, offset)
    return val, offset


def read_uint64(data: bytes, offset: int):
    (val,), offset = read_struct("<Q", data, offset)
    return val, offset


def filetime_to_iso(ft: int) -> str:
    """Convert Windows FILETIME to ISO‑8601 with UTC offset."""
    try:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        # FILETIME is in 100‑nanosecond intervals
        dt = epoch + datetime.timedelta(microseconds=ft // 10)
        return dt.isoformat()
    except Exception:
        fail("Invalid FILETIME value")


def skip_bytes(data: bytes, offset: int, length: int):
    if offset + length > len(data):
        fail("Unexpected end of file while skipping bytes")
    return offset + length


# ------------------------------------------------------------
# Main parsing routine
# ------------------------------------------------------------
def parse_lnk(path: str):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        fail(f"Cannot read file: {e}")

    if len(data) < 0x4C:
        fail("File too short for ShellLinkHeader")

    # ---- ShellLinkHeader (76 bytes) ----
    offset = 0
    header_size, offset = read_uint32(data, offset)
    if header_size != 0x4C:
        fail("Invalid HeaderSize")

    link_clsid, offset = read_struct("<16s", data, offset)
    expected_clsid = bytes.fromhex(
        "01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46".replace(" ", "")
    )
    if link_clsid[0] != expected_clsid:
        fail("Invalid LinkCLSID")

    link_flags, offset = read_uint32(data, offset)
    file_attrs, offset = read_uint32(data, offset)

    creation_ft, offset = read_uint64(data, offset)
    access_ft, offset = read_uint64(data, offset)
    write_ft, offset = read_uint64(data, offset)

    file_size, offset = read_uint32(data, offset)
    icon_index, offset = read_int32(data, offset)

    # Skip ShowCommand (4), HotKey (2), Reserved1 (2), Reserved2 (4), Reserved3 (4)
    offset = skip_bytes(data, offset, 4 + 2 + 2 + 4 + 4)

    # ---- Optional IDList ----
    HAS_LINK_TARGET_IDLIST = 0x00000001
    if link_flags & HAS_LINK_TARGET_IDLIST:
        # IDList size (2 bytes) + that many bytes
        idlist_size, offset = read_uint16(data, offset)
        offset = skip_bytes(data, offset, idlist_size)

    # ---- Optional LinkInfo ----
    HAS_LINK_INFO = 0x00000002
    if link_flags & HAS_LINK_INFO:
        linkinfo_size, offset = read_uint32(data, offset)
        offset = skip_bytes(data, offset, linkinfo_size - 4)  # size includes the field itself

    # ---- StringData sections ----
    IS_UNICODE = 0x00000080
    unicode = bool(link_flags & IS_UNICODE)

    # Mapping of flag bits to JSON keys in the required order
    string_sections = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]

    result_strings = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
    }

    for flag, key in string_sections:
        if link_flags & flag:
            char_count, offset = read_uint16(data, offset)
            byte_len = char_count * (2 if unicode else 1)
            if offset + byte_len > len(data):
                fail(f"Unexpected end of file while reading {key}")
            raw = data[offset : offset + byte_len]
            offset += byte_len
            try:
                if unicode:
                    # UTF‑16LE, strip possible trailing null
                    s = raw.decode("utf-16le", errors="replace")
                else:
                    s = raw.decode("utf-8", errors="replace")
            except Exception:
                fail(f"Failed to decode {key}")
            result_strings[key] = s

    # ---- Build final JSON object ----
    output = {
        "name_string": result_strings["name_string"],
        "relative_path": result_strings["relative_path"],
        "working_dir": result_strings["working_dir"],
        "command_line_arguments": result_strings["command_line_arguments"],
        "icon_location": result_strings["icon_location"],
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_ft),
        "access_time": filetime_to_iso(access_ft),
        "write_time": filetime_to_iso(write_ft),
    }

    sys.stdout.write(json.dumps(output, ensure_ascii=False))
    sys.exit(0)


# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")
    parse_lnk(sys.argv[1])