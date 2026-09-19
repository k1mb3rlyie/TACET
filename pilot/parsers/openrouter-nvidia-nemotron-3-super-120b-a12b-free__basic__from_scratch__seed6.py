#!/usr/bin/env python3
import sys
import struct
import datetime
import json

def filetime_to_iso(ft: int) -> str:
    """Convert Windows FILETIME to ISO 8601 string with UTC offset."""
    if ft < 0:
        raise ValueError("Invalid FILETIME")
    # 100-nanoseconds since 1601-01-01 UTC to seconds since epoch
    unix_time = ft // 10_000_000 - 11644473600
    dt = datetime.datetime.fromtimestamp(unix_time, tz=datetime.timezone.utc)
    return dt.isoformat()

def parse_lnk(data: bytes):
    if len(data) < 0x4C:
        raise ValueError("File too small for LNK header")

    header = data[0:0x4C]

    # LinkFlags at offset 0x10
    link_flags = struct.unpack_from('<I', header, 0x10)[0]

    has_link_info = bool(link_flags & 0x00000001)
    has_name = bool(link_flags & 0x00000002)
    has_relative = bool(link_flags & 0x00000004)
    has_working_dir = bool(link_flags & 0x00000008)
    has_args = bool(link_flags & 0x00000010)
    has_icon = bool(link_flags & 0x00000020)
    is_unicode = bool(link_flags & 0x00000040)

    # LinkInfo size
    linkinfo_size = 0
    if has_link_info:
        if len(data) < 0x4C + 4:
            raise ValueError("File too small for LinkInfo size")
        linkinfo_size = struct.unpack_from('<I', data, 0x4C)[0]
        if linkinfo_size < 0x18:  # minimum fixed part size
            raise ValueError("LinkInfo size too small")
        if 0x4C + linkinfo_size > len(data):
            raise ValueError("LinkInfo exceeds file size")

    # Start of string data block
    offset = 0x4C + linkinfo_size

    def read_string(current_offset):
        if current_offset + 2 > len(data):
            raise ValueError("String length exceeds file")
        length = struct.unpack_from('<H', data, current_offset)[0]
        current_offset += 2
        if is_unicode:
            byte_len = length * 2
        else:
            byte_len = length
        if current_offset + byte_len > len(data):
            raise ValueError("String data exceeds file")
        if byte_len == 0:
            s = ''
        else:
            raw = data[current_offset:current_offset + byte_len]
            current_offset += byte_len
            if is_unicode:
                s = raw.decode('utf-16-le')
            else:
                # Use Windows ANSI code page 1252 as a reasonable fallback
                s = raw.decode('cp1252')
        return s, current_offset

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if has_name:
        name_string, offset = read_string(offset)
    if has_relative:
        relative_path, offset = read_string(offset)
    if has_working_dir:
        working_dir, offset = read_string(offset)
    if has_args:
        command_line_arguments, offset = read_string(offset)
    if has_icon:
        icon_location, offset = read_string(offset)

    # Times from header
    creation_time = struct.unpack_from('<Q', header, 0x18)[0]
    access_time = struct.unpack_from('<Q', header, 0x20)[0]
    write_time = struct.unpack_from('<Q', header, 0x28)[0]

    file_size = struct.unpack_from('<I', header, 0x30)[0]
    icon_index = struct.unpack_from('<i', header, 0x34)[0]

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
        err = {"error": "Usage: python parser.py <path-to-lnk-file>"}
        print(json.dumps(err))
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
        result = parse_lnk(data)
        print(json.dumps(result))
        sys.exit(0)
    except Exception as e:
        err = {"error": str(e)}
        print(json.dumps(err))
        sys.exit(1)

if __name__ == "__main__":
    main()