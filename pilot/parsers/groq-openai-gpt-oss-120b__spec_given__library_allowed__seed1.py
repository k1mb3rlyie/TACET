#!/usr/bin/env python3
import sys
import struct
import json
from datetime import datetime, timezone, timedelta

# LinkFlags bits we care about
HAS_LINK_TARGET_IDLIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080

EXPECTED_HEADER_SIZE = 0x4C
EXPECTED_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'  # little‑endian GUID


class ParseError(Exception):
    pass


def read_bytes(data, offset, size):
    if offset + size > len(data):
        raise ParseError("Unexpected end of file while reading")
    return data[offset:offset + size], offset + size


def read_struct(fmt, data, offset):
    size = struct.calcsize(fmt)
    chunk, new_offset = read_bytes(data, offset, size)
    return struct.unpack(fmt, chunk), new_offset


def filetime_to_iso(ft):
    # ft is unsigned 64‑bit number of 100‑ns intervals since 1601‑01‑01 UTC
    try:
        base = datetime(1601, 1, 1, tzinfo=timezone.utc)
        microseconds = ft // 10  # 100‑ns -> µs
        dt = base + timedelta(microseconds=microseconds)
        return dt.isoformat()
    except Exception:
        raise ParseError("Invalid FILETIME value")


def parse_string(data, offset, unicode):
    (count,), offset = read_struct("<H", data, offset)  # CountCharacters
    byte_len = count * (2 if unicode else 1)
    raw, offset = read_bytes(data, offset, byte_len)
    try:
        if unicode:
            s = raw.decode('utf-16le')
        else:
            s = raw.decode('cp1252')  # best‑effort ANSI decoding
    except Exception:
        raise ParseError("String decoding failed")
    return s, offset


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
        offset = 0

        # ---- ShellLinkHeader ----
        (header_size,), offset = read_struct("<I", data, offset)
        if header_size != EXPECTED_HEADER_SIZE:
            raise ParseError("HeaderSize is not 0x4C")

        link_clsid, offset = read_bytes(data, offset, 16)
        if link_clsid != EXPECTED_CLSID:
            raise ParseError("LinkCLSID does not match expected value")

        (link_flags,), offset = read_struct("<I", data, offset)
        (file_attrs,), offset = read_struct("<I", data, offset)

        (creation_ft,), offset = read_struct("<Q", data, offset)
        (access_ft,), offset = read_struct("<Q", data, offset)
        (write_ft,), offset = read_struct("<Q", data, offset)

        (file_size,), offset = read_struct("<I", data, offset)
        (icon_index,), offset = read_struct("<i", data, offset)  # signed
        (show_cmd,), offset = read_struct("<I", data, offset)
        (hotkey,), offset = read_struct("<H", data, offset)

        # Reserved fields (must be zero)
        offset += 2  # Reserved1
        offset += 4  # Reserved2
        offset += 4  # Reserved3

        # ---- Optional IDList ----
        if link_flags & HAS_LINK_TARGET_IDLIST:
            (idlist_size,), offset = read_struct("<H", data, offset)
            _, offset = read_bytes(data, offset, idlist_size)

        # ---- Optional LinkInfo ----
        if link_flags & HAS_LINK_INFO:
            (linkinfo_size,), offset = read_struct("<I", data, offset)
            if linkinfo_size < 4:
                raise ParseError("LinkInfoSize too small")
            _, offset = read_bytes(data, offset, linkinfo_size - 4)

        unicode = bool(link_flags & IS_UNICODE)

        # ---- StringData (in fixed order) ----
        name_string = None
        relative_path = None
        working_dir = None
        command_line_arguments = None
        icon_location = None

        if link_flags & HAS_NAME:
            name_string, offset = parse_string(data, offset, unicode)
        if link_flags & HAS_RELATIVE_PATH:
            relative_path, offset = parse_string(data, offset, unicode)
        if link_flags & HAS_WORKING_DIR:
            working_dir, offset = parse_string(data, offset, unicode)
        if link_flags & HAS_ARGUMENTS:
            command_line_arguments, offset = parse_string(data, offset, unicode)
        if link_flags & HAS_ICON_LOCATION:
            icon_location, offset = parse_string(data, offset, unicode)

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
            "write_time": filetime_to_iso(write_ft)
        }

        json.dump(result, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)

    except ParseError as pe:
        err_obj = {"error": str(pe)}
        json.dump(err_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)
    except Exception as e:
        err_obj = {"error": "Unexpected parsing error"}
        json.dump(err_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()