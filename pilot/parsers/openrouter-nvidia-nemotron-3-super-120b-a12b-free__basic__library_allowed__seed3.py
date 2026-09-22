#!/usr/bin/env python3
import sys
import json
import struct
from datetime import datetime, timezone

def _u8(b, off):
    return struct.unpack_from('<B', b, off)[0]

def _u16(b, off):
    return struct.unpack_from('<H', b, off)[0]

def _u32(b, off):
    return struct.unpack_from('<I', b, off)[0]

def _u64(b, off):
    return struct.unpack_from('<Q', b, off)[0]

def _filetime_to_dt(b, off):
    if off + 8 > len(b):
        raise ValueError("Incomplete FILETIME")
    v = _u64(b, off)
    # FILETIME to Unix epoch (seconds)
    if v < 116444736000000000:
        raise ValueError("FILETIME before Unix epoch")
    seconds = (v - 116444736000000000) / 10000000.0
    try:
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OSError, ValueError) as e:
        raise ValueError("Invalid FILETIME value") from e
    return dt

def _get_string(b, start, is_unicode):
    if start >= len(b):
        raise ValueError("String offset beyond file")
    if is_unicode:
        i = start
        while i + 1 < len(b):
            if b[i] == 0 and b[i+1] == 0:
                break
            i += 2
        else:
            raise ValueError("Missing Unicode null terminator")
        raw = b[start:i]
        try:
            return raw.decode('utf-16le')
        except UnicodeDecodeError as e:
            raise ValueError("Invalid UTF-16LE string") from e
    else:
        i = start
        while i < len(b) and b[i] != 0:
            i += 1
        if i >= len(b):
            raise ValueError("Missing ANSI null terminator")
        raw = b[start:i]
        try:
            return raw.decode('latin-1')
        except UnicodeDecodeError as e:
            raise ValueError("Invalid ANSI string") from e

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python parser.py <path-to-lnk-file>"}))
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        print(json.dumps({"error": f"Cannot read file: {e}"}))
        sys.exit(1)

    if len(data) < 0x4C:
        print(json.dumps({"error": "File too small to be a .lnk"}))
        sys.exit(1)

    off = 0
    # Skip CLSID (16 bytes)
    off += 16
    try:
        link_flags = _u32(data, off); off += 4
        _ = _u32(data, off); off += 4  # FileAttributes (unused)
        creation_time = _filetime_to_dt(data, off); off += 8
        access_time = _filetime_to_dt(data, off); off += 8
        write_time = _filetime_to_dt(data, off); off += 8
        file_size = _u32(data, off); off += 4
        icon_index = _u32(data, off); off += 4
        _ = _u32(data, off); off += 4  # ShowCommand
        _ = _u16(data, off); off += 2  # HotKey
        _ = _u16(data, off); off += 2  # Reserved1
        _ = _u32(data, off); off += 4  # Reserved2
        _ = _u32(data, off); off += 4  # Reserved3
    except ValueError as e:
        print(json.dumps({"error": f"Failed to parse header: {e}"}))
        sys.exit(1)

    # After header, optional IDList
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        if off + 2 > len(data):
            print(json.dumps({"error": "Truncated IDList size"}))
            sys.exit(1)
        idlist_len = _u16(data, off); off += 2
        if off + idlist_len > len(data):
            print(json.dumps({"error": "IDList exceeds file size"}))
            sys.exit(1)
        off += idlist_len

    # Optional LinkInfo
    if link_flags & 0x00000002:  # HasLinkInfo
        if off + 4 > len(data):
            print(json.dumps({"error": "Truncated LinkInfo size"}))
            sys.exit(1)
        linkinfo_size = _u32(data, off); off += 4
        if linkinfo_size < 0x14:
            print(json.dumps({"error": "Invalid LinkInfo size"}))
            sys.exit(1)
        if off + linkinfo_size > len(data):
            print(json.dumps({"error": "LinkInfo exceeds file size"}))
            sys.exit(1)
        off += linkinfo_size  # skip entire LinkInfo block

    string_data_start = off
    is_unicode = bool(link_flags & 0x00000080)

    # String offsets (order: name, relative path, working dir, command line, icon location)
    str_flags = [
        (link_flags & 0x00000004, "name_string"),
        (link_flags & 0x00000008, "relative_path"),
        (link_flags & 0x00000010, "working_dir"),
        (link_flags & 0x00000020, "command_line_arguments"),
        (link_flags & 0x00000040, "icon_location")
    ]

    result = {
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time.isoformat(),
        "access_time": access_time.isoformat(),
        "write_time": write_time.isoformat()
    }

    for flag, key in str_flags:
        if not flag:
            result[key] = None
            continue
        if off + 4 > len(data):
            print(json.dumps({"error": f"Truncated string offset for {key}"}))
            sys.exit(1)
        str_offset = _u32(data, off); off += 4
        if str_offset == 0:
            result[key] = None
            continue
        str_pos = string_data_start + str_offset
        try:
            s = _get_string(data, str_pos, is_unicode)
        except ValueError as e:
            print(json.dumps({"error": f"Failed to read {key}: {e}"}))
            sys.exit(1)
        result[key] = s

    # Output JSON
    print(json.dumps(result, separators=(',', ':')))
    sys.exit(0)

if __name__ == "__main__":
    main()