#!/usr/bin/env python3
import sys
import struct
import json
from datetime import datetime, timezone, timedelta

def filetime_to_iso(ft):
    """Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01 UTC) to ISO‑8601."""
    try:
        us = ft // 10  # to microseconds
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
        return dt.isoformat()
    except Exception:
        return None

def read_uint16(data, off):
    if off + 2 > len(data):
        raise ValueError("Unexpected end of data while reading uint16")
    return struct.unpack_from('<H', data, off)[0], off + 2

def read_uint32(data, off):
    if off + 4 > len(data):
        raise ValueError("Unexpected end of data while reading uint32")
    return struct.unpack_from('<I', data, off)[0], off + 4

def read_uint64(data, off):
    if off + 8 > len(data):
        raise ValueError("Unexpected end of data while reading uint64")
    return struct.unpack_from('<Q', data, off)[0], off + 8

def read_string(data, off, is_unicode):
    """Read a counted string. Returns (string, new_offset)."""
    count, off = read_uint16(data, off)          # character count
    byte_len = count * (2 if is_unicode else 1)
    if off + byte_len > len(data):
        raise ValueError("String exceeds data length")
    raw = data[off:off + byte_len]
    off += byte_len
    if is_unicode:
        try:
            s = raw.decode('utf-16le')
        except Exception:
            s = raw.decode('utf-16le', errors='replace')
    else:
        try:
            s = raw.decode('utf-8')
        except Exception:
            s = raw.decode('utf-8', errors='replace')
    return s, off

def parse_lnk(data):
    if len(data) < 76:
        raise ValueError("File too short for LNK header")
    hdr = struct.unpack_from('<I16sIIQQQIIIHHII', data, 0)
    (header_size, link_clsid, link_flags, file_attrs,
     creation_ft, access_ft, write_ft,
     file_size, icon_index, show_cmd,
     hot_key, reserved1, reserved2, reserved3) = hdr

    if header_size != 0x4C:
        raise ValueError("Invalid header size")
    # GUID check (optional, ignore if not matching)
    expected_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    if link_clsid != expected_clsid:
        # Not a fatal error, continue parsing as best we can
        pass

    is_unicode = bool(link_flags & 0x00000080)

    offset = 76

    # Optional LinkTargetIDList
    if link_flags & 0x00000001:
        idlist_size, offset = read_uint16(data, offset)
        if offset + idlist_size > len(data):
            raise ValueError("IDList exceeds file size")
        offset += idlist_size

    # Optional LinkInfo
    if link_flags & 0x00000002:
        if offset + 4 > len(data):
            raise ValueError("Cannot read LinkInfo size")
        linkinfo_size, = struct.unpack_from('<I', data, offset)
        if linkinfo_size == 0:
            raise ValueError("LinkInfo size zero")
        if offset + linkinfo_size > len(data):
            raise ValueError("LinkInfo exceeds file size")
        offset += linkinfo_size

    # StringData fields
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if link_flags & 0x00000004:  # HasName
        name_string, offset = read_string(data, offset, is_unicode)
    if link_flags & 0x00000008:  # HasRelativePath
        relative_path, offset = read_string(data, offset, is_unicode)
    if link_flags & 0x00000010:  # HasWorkingDir
        working_dir, offset = read_string(data, offset, is_unicode)
    if link_flags & 0x00000020:  # HasArguments
        command_line_arguments, offset = read_string(data, offset, is_unicode)
    if link_flags & 0x00000040:  # HasIconLocation
        icon_location, offset = read_string(data, offset, is_unicode)

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
    return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        err = {"error": f"Cannot read file: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

    try:
        parsed = parse_lnk(data)
        print(json.dumps(parsed, ensure_ascii=False))
        sys.exit(0)
    except Exception as e:
        err = {"error": f"Failed to parse LNK: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

if __name__ == "__main__":
    main()