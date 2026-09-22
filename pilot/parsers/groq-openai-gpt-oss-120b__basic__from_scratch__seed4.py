#!/usr/bin/env python3
import sys
import struct
import json
import datetime
import os

# Constants
HEADER_SIZE = 0x4C
EXPECTED_CLSID = bytes.fromhex(
    "01140200"   # Data1 (little‑endian)
    "0000"       # Data2
    "0000"       # Data3
    "C0000000000046"  # Data4
)

# LinkFlag bits
HAS_LINK_TARGET_ID_LIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080


def filetime_to_iso(ft):
    """Convert Windows FILETIME to ISO‑8601 with UTC offset."""
    if ft == 0:
        return None
    # FILETIME is number of 100‑ns intervals since 1601‑01‑01 UTC
    us = ft // 10  # convert to microseconds
    dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
    return dt.isoformat()


def read_uint16(data, offset):
    return struct.unpack_from("<H", data, offset)[0], offset + 2


def read_uint32(data, offset):
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def read_uint64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0], offset + 8


def read_string(data, offset, is_unicode):
    """Read a length‑prefixed string (Unicode or ANSI)."""
    length, offset = read_uint16(data, offset)
    if is_unicode:
        byte_len = length * 2
        raw = data[offset: offset + byte_len]
        try:
            s = raw.decode("utf-16le", errors="replace")
        except Exception:
            raise ValueError("cannot decode Unicode string")
    else:
        raw = data[offset: offset + length]
        try:
            s = raw.decode("utf-8", errors="replace")
        except Exception:
            raise ValueError("cannot decode ANSI string")
    offset += byte_len if is_unicode else length
    return s, offset


def parse_lnk(data):
    if len(data) < HEADER_SIZE:
        raise ValueError("file too short for header")

    # Header
    (
        hdr_size,
        link_clsid,
        link_flags,
        file_attrs,
        creation_time,
        access_time,
        write_time,
        file_size,
        icon_index,
        show_cmd,
        hot_key,
        reserved1,
        reserved2,
        reserved3,
    ) = struct.unpack_from("<I16sI I Q Q Q I I I H H I I", data, 0)

    if hdr_size != HEADER_SIZE:
        raise ValueError("invalid header size")
    if link_clsid[:16] != EXPECTED_CLSID:
        raise ValueError("invalid LinkCLSID")

    offset = HEADER_SIZE
    is_unicode = bool(link_flags & IS_UNICODE)

    # Optional LinkTargetIDList
    if link_flags & HAS_LINK_TARGET_ID_LIST:
        if offset + 2 > len(data):
            raise ValueError("truncated IDList size")
        idlist_size, offset = read_uint16(data, offset)
        if offset + idlist_size > len(data):
            raise ValueError("truncated IDList")
        offset += idlist_size

    # Optional LinkInfo
    if link_flags & HAS_LINK_INFO:
        if offset + 4 > len(data):
            raise ValueError("truncated LinkInfo size")
        linkinfo_size, offset = read_uint32(data, offset)
        if offset - 4 + linkinfo_size > len(data):
            raise ValueError("truncated LinkInfo")
        offset += linkinfo_size - 4  # size includes the 4 bytes we already read

    # Strings in fixed order
    def maybe_read(flag):
        nonlocal offset
        if link_flags & flag:
            s, offset = read_string(data, offset, is_unicode)
            return s
        return None

    name_string = maybe_read(HAS_NAME)
    relative_path = maybe_read(HAS_RELATIVE_PATH)
    working_dir = maybe_read(HAS_WORKING_DIR)
    command_line_arguments = maybe_read(HAS_ARGUMENTS)
    icon_location = maybe_read(HAS_ICON_LOCATION)

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_time),
        "access_time": filetime_to_iso(access_time),
        "write_time": filetime_to_iso(write_time),
    }
    return result


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        err = {"error": f"cannot read file: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

    try:
        parsed = parse_lnk(data)
    except Exception as e:
        err = {"error": str(e)}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

    # Ensure JSON nulls are emitted for Python None
    print(json.dumps(parsed, ensure_ascii=False))


if __name__ == "__main__":
    main()