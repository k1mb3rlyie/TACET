#!/usr/bin/env python3
import sys
import json
import struct
import datetime
import locale

def filetime_to_iso(ft: int) -> str:
    """Convert Windows FILETIME to ISO 8601 string with UTC offset."""
    # FILETIME: 100-nanosecond intervals since 1601-01-01 UTC
    # Convert to seconds since 1970-01-01 UTC
    seconds = ft / 10000000.0 - 11644473600.0
    dt = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    return dt.isoformat()

def parse_lnk(data: bytes) -> dict:
    if len(data) < 76:
        raise ValueError("File too small for LNK header")
    header_size = struct.unpack_from('<I', data, 0)[0]
    if header_size < 76:
        raise ValueError("Invalid HeaderSize")
    if len(data) < header_size:
        raise ValueError("File truncated, header incomplete")

    # Fixed part (first 76 bytes)
    link_flags = struct.unpack_from('<I', data, 20)[0]
    is_unicode = bool(link_flags & 0x0001)
    has_name = bool(link_flags & 0x0008)
    has_relative_path = bool(link_flags & 0x0010)
    has_working_dir = bool(link_flags & 0x0020)
    has_arguments = bool(link_flags & 0x0040)
    has_icon_location = bool(link_flags & 0x0080)
    has_idlist = bool(link_flags & 0x0002)
    has_linkinfo = bool(link_flags & 0x0004)

    # Timestamps
    try:
        creation_raw = struct.unpack_from('<Q', data, 28)[0]
        access_raw = struct.unpack_from('<Q', data, 36)[0]
        write_raw = struct.unpack_from('<Q', data, 44)[0]
    except struct.error as e:
        raise ValueError(f"Cannot read timestamps: {e}")

    creation_iso = filetime_to_iso(creation_raw)
    access_iso = filetime_to_iso(access_raw)
    write_iso = filetime_to_iso(write_raw)

    # File size and icon index
    try:
        file_size = struct.unpack_from('<I', data, 52)[0]
        icon_index = struct.unpack_from('<I', data, 56)[0]
    except struct.error as e:
        raise ValueError(f"Cannot read file size or icon index: {e}")

    offset = header_size

    # Skip IDList if present
    if has_idlist:
        while True:
            if offset + 2 > len(data):
                raise ValueError("Truncated IDList")
            id_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if id_size == 0:
                break
            if id_size < 2:
                raise ValueError("Invalid IDList size")
            if offset + (id_size - 2) > len(data):
                raise ValueError("Truncated IDList item")
            offset += id_size - 2

    # Skip LinkInfo if present
    if has_linkinfo:
        if offset + 4 > len(data):
            raise ValueError("Truncated LinkInfo size")
        link_info_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if link_info_size < 0x1C:
            raise ValueError("LinkInfo too small")
        if offset + link_info_size > len(data):
            raise ValueError("Truncated LinkInfo")
        offset += link_info_size

    def read_string(present):
        nonlocal offset
        if not present:
            return None
        if offset + 2 > len(data):
            raise ValueError("Truncated string size")
        str_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if str_size == 0:
            return ""
        if offset + str_size > len(data):
            raise ValueError("Truncated string data")
        raw = data[offset:offset + str_size]
        offset += str_size
        if is_unicode:
            try:
                s = raw.decode('utf-16-le')
            except UnicodeDecodeError as e:
                raise ValueError(f"Failed to decode Unicode string: {e}")
        else:
            try:
                encoding = locale.getpreferredencoding(False)
                s = raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                s = raw.decode('latin-1')
        # Strip terminating null(s)
        if is_unicode:
            s = s.rstrip('\x00')
        else:
            s = s.rstrip('\x00')
        return s

    name_string = read_string(has_name)
    relative_path = read_string(has_relative_path)
    working_dir = read_string(has_working_dir)
    command_line_arguments = read_string(has_arguments)
    icon_location = read_string(has_icon_location)

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_iso,
        "access_time": access_iso,
        "write_time": write_iso
    }
    return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Cannot open file: {e}\n")
        sys.exit(1)

    try:
        result = parse_lnk(data)
        # Ensure ASCII non‑ensure for proper Unicode output
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Error parsing LNK file: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()