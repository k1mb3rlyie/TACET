#!/usr/bin/env python3
import sys
import json
import struct
from datetime import datetime, timezone, timedelta

ERROR_OUTPUT = {"error": "Unable to parse .lnk file"}

def filetime_to_iso(ft):
    if ft == 0:
        return None
    # FILETIME is number of 100‑ns intervals since 1601‑01‑01 UTC
    us = ft // 10
    dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
    return dt.isoformat()

def read_uint16(data, off):
    if off + 2 > len(data):
        raise ValueError("truncated")
    return struct.unpack_from("<H", data, off)[0], off + 2

def read_uint32(data, off):
    if off + 4 > len(data):
        raise ValueError("truncated")
    return struct.unpack_from("<I", data, off)[0], off + 4

def read_uint64(data, off):
    if off + 8 > len(data):
        raise ValueError("truncated")
    return struct.unpack_from("<Q", data, off)[0], off + 8

def read_string(data, off, unicode):
    count, off = read_uint16(data, off)
    byte_len = count * (2 if unicode else 1)
    if off + byte_len > len(data):
        raise ValueError("truncated string")
    raw = data[off:off + byte_len]
    off += byte_len
    if unicode:
        s = raw.decode("utf-16le", errors="replace")
    else:
        s = raw.decode("utf-8", errors="replace")
    s = s.rstrip("\x00")
    return s, off

def parse_lnk(data: bytes):
    if len(data) < 76:
        raise ValueError("header too short")
    # ShellLinkHeader (76 bytes)
    (
        header_size,
        link_clsid,
        link_flags,
        file_attrs,
        creation_ft,
        access_ft,
        write_ft,
        file_size,
        icon_index,
        show_cmd,
        hotkey,
        reserved1,
        reserved2,
        reserved3,
    ) = struct.unpack_from("<I16sIIQQQIIIHHII", data, 0)

    if header_size != 0x4C:
        raise ValueError("invalid header size")

    off = 76
    is_unicode = bool(link_flags & 0x80)

    # Optional LinkTargetIDList
    if link_flags & 0x01:
        idlist_size, off = read_uint16(data, off)
        if off + idlist_size > len(data):
            raise ValueError("truncated IDList")
        off += idlist_size

    # Optional LinkInfo
    if link_flags & 0x02:
        linkinfo_size, off = read_uint32(data, off)
        if linkinfo_size < 4:
            raise ValueError("invalid LinkInfo size")
        if off - 4 + linkinfo_size > len(data):
            raise ValueError("truncated LinkInfo")
        off = off - 4 + linkinfo_size  # skip whole structure

    # StringData (order matters)
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if link_flags & 0x04:  # HasName
        name_string, off = read_string(data, off, is_unicode)
    if link_flags & 0x08:  # HasRelativePath
        relative_path, off = read_string(data, off, is_unicode)
    if link_flags & 0x10:  # HasWorkingDir
        working_dir, off = read_string(data, off, is_unicode)
    if link_flags & 0x20:  # HasArguments
        command_line_arguments, off = read_string(data, off, is_unicode)
    if link_flags & 0x40:  # HasIconLocation
        icon_location, off = read_string(data, off, is_unicode)

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

    # Convert any None timestamps to null (JSON will handle)
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
    except Exception as e:
        # Output error JSON as required
        json.dump(ERROR_OUTPUT, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)

if __name__ == "__main__":
    main()