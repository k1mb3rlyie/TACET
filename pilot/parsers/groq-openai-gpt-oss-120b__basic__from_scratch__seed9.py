#!/usr/bin/env python3
import sys
import struct
import json
import datetime

# Constants
HEADER_SIZE = 0x4C
LINK_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'

# LinkFlags bits
HAS_LINK_TARGET_ID_LIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080


def filetime_to_iso(ft):
    """Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01) to ISO 8601 with UTC offset."""
    if ft == 0:
        # Zero is a valid FILETIME; still convert to a sensible representation
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    else:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = epoch + datetime.timedelta(microseconds=ft // 10)
    return dt.isoformat()


def parse_lnk(data):
    if len(data) < HEADER_SIZE:
        raise ValueError("File too short for Shell Link Header")

    # Shell Link Header
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
    ) = struct.unpack_from("<I16sI I Q Q Q I i I H H I I", data, 0)

    if hdr_size != HEADER_SIZE:
        raise ValueError("Invalid Shell Link Header size")
    if link_clsid != LINK_CLSID:
        raise ValueError("Invalid LinkCLSID")

    offset = HEADER_SIZE

    # Optional LinkTargetIDList
    if link_flags & HAS_LINK_TARGET_ID_LIST:
        if offset + 2 > len(data):
            raise ValueError("Truncated IDList size")
        idlist_size = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        if offset + idlist_size > len(data):
            raise ValueError("Truncated IDList")
        offset += idlist_size

    # Optional LinkInfo
    if link_flags & HAS_LINK_INFO:
        if offset + 4 > len(data):
            raise ValueError("Truncated LinkInfo size")
        linkinfo_size = struct.unpack_from("<I", data, offset)[0]
        if linkinfo_size < 0x0000001C:  # minimum size per spec
            raise ValueError("Invalid LinkInfo size")
        if offset + linkinfo_size > len(data):
            raise ValueError("Truncated LinkInfo")
        offset += linkinfo_size

    # StringData
    unicode = bool(link_flags & IS_UNICODE)

    def read_string(flag):
        nonlocal offset
        if not (link_flags & flag):
            return None
        if offset + 2 > len(data):
            raise ValueError("Truncated string length")
        length = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        byte_len = length * (2 if unicode else 1)
        if offset + byte_len > len(data):
            raise ValueError("Truncated string data")
        raw = data[offset:offset + byte_len]
        offset += byte_len
        try:
            if unicode:
                return raw.decode('utf-16le')
            else:
                return raw.decode('mbcs')  # best effort for ANSI
        except Exception as e:
            raise ValueError(f"String decode error: {e}")

    name_string = read_string(HAS_NAME)
    relative_path = read_string(HAS_RELATIVE_PATH)
    working_dir = read_string(HAS_WORKING_DIR)
    command_line_arguments = read_string(HAS_ARGUMENTS)
    icon_location = read_string(HAS_ICON_LOCATION)

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
        parsed = parse_lnk(data)
        json.dump(parsed, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as exc:
        err_obj = {"error": str(exc)}
        json.dump(err_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()