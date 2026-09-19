#!/usr/bin/env python3
import struct
import sys
import json
from datetime import datetime, timezone

def parse_lnk(data):
    if len(data) < 0x4C:
        raise ValueError("File too small to be a .lnk file")
    offset = 0

    # Skip CLSID (16 bytes)
    offset += 16

    # LinkFlags
    link_flags = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    # FileAttributes (skip)
    offset += 4

    # Timestamps
    creation_time_ft = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    access_time_ft = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    write_time_ft = struct.unpack_from('<Q', data, offset)[0]
    offset += 8

    # FileSize and IconIndex
    file_size = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    icon_index = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    # Skip ShowCommand, HotKey, Reserved fields to reach end of header
    offset += 4  # ShowCommand
    offset += 2  # HotKey
    offset += 2  # Reserved1
    offset += 4  # Reserved2
    offset += 4  # Reserved3
    offset += 4  # Reserved4  # now offset == 0x4C

    # Determine presence of optional fields
    has_target_idlist = bool(link_flags & 0x00000001)
    has_linkinfo = bool(link_flags & 0x00000002)
    has_name = bool(link_flags & 0x00000004)
    has_relative_path = bool(link_flags & 0x00000008)
    has_working_dir = bool(link_flags & 0x00000010)
    has_command_line_args = bool(link_flags & 0x00000020)
    has_icon_location = bool(link_flags & 0x00000040)
    is_unicode = bool(link_flags & 0x00000080)

    # Skip LinkTargetIDList
    if has_target_idlist:
        if offset + 2 > len(data):
            raise ValueError("Truncated IDList size")
        idlist_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if offset + idlist_size > len(data):
            raise ValueError("Truncated IDList")
        offset += idlist_size

    # Skip LinkInfo
    if has_linkinfo:
        if offset + 4 > len(data):
            raise ValueError("Truncated LinkInfo size")
        linkinfo_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if linkinfo_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if offset + linkinfo_size - 4 > len(data):
            raise ValueError("Truncated LinkInfo")
        offset += linkinfo_size - 4

    # Helper to read a string if present
    def read_string_present(present):
        nonlocal offset
        if not present:
            return None
        if offset + 2 > len(data):
            raise ValueError("Truncated string length")
        length = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if is_unicode:
            byte_len = length * 2
        else:
            byte_len = length
        if offset + byte_len > len(data):
            raise ValueError("Truncated string data")
        raw = data[offset:offset + byte_len]
        offset += byte_len
        try:
            if is_unicode:
                s = raw.decode('utf-16-le')
            else:
                # Use latin-1 to map bytes 1:1 to Unicode characters without errors
                s = raw.decode('latin-1')
        except UnicodeDecodeError:
            raise ValueError("Failed to decode string")
        # Padding to 4-byte boundary
        pad = (4 - ((2 + byte_len) % 4)) % 4
        if offset + pad > len(data):
            raise ValueError("Truncated padding")
        offset += pad
        return s

    name_string = read_string_present(has_name)
    relative_path = read_string_present(has_relative_path)
    working_dir = read_string_present(has_working_dir)
    command_line_arguments = read_string_present(has_command_line_args)
    icon_location = read_string_present(has_icon_location)

    # Convert FILETIME to ISO 8601 with UTC offset
    def ft_to_iso(ft):
        # ft: 100-nanosecond intervals since 1601-01-01 UTC
        # Convert to seconds since 1970-01-01 UTC
        seconds = ft / 10000000.0 - 11644473600.0
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        return dt.isoformat()

    creation_time_iso = ft_to_iso(creation_time_ft)
    access_time_iso = ft_to_iso(access_time_ft)
    write_time_iso = ft_to_iso(write_time_ft)

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time_iso,
        "access_time": access_time_iso,
        "write_time": write_time_iso,
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
        result = parse_lnk(data)
        # Ensure null values are serialized as None -> JSON null
        print(json.dumps(result, ensure_ascii=False))
    except Exception as e:
        sys.stderr.write(f"Error parsing .lnk file: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()