#!/usr/bin/env python3
import struct
import datetime
import json
import sys

EXPECTED_CLSID = bytes.fromhex('0114020000000000C000000000000046')
TERMINAL_MAX_SIZE = 3  # blockSize < 4 indicates terminal block

def filetime_to_dt(ft: int) -> datetime.datetime:
    # FILETIME: 100-ns intervals since 1601-01-01 UTC
    # Convert to microseconds (discard sub-microsecond)
    us = ft // 10
    return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)

def parse_lnk(data: bytes):
    if len(data) < 76:
        raise ValueError("File too short for ShellLinkHeader")
    off = 0
    (header_size, clsid, link_flags, file_attrs,
     creation_time, access_time, write_time,
     file_size, icon_index, show_command,
     hot_key, reserved1, reserved2, reserved3) = struct.unpack_from(
        '<I 16s I I Q Q Q I i H H I I I', data, off)
    off += 76

    if header_size != 0x4C:
        raise ValueError(f"Invalid HeaderSize: 0x{header_size:08X}")
    if clsid != EXPECTED_CLSID:
        raise ValueError(f"Invalid LinkCLSID")

    # Parse optional IDList
    if link_flags & 0x00000001:
        while True:
            if off + 2 > len(data):
                raise ValueError("Truncated IDList size field")
            id_size = struct.unpack_from('<H', data, off)[0]
            off += 2
            if id_size == 0:
                break
            if id_size < 2:
                raise ValueError("Invalid IDList item size")
            if off + (id_size - 2) > len(data):
                raise ValueError("Truncated IDList item data")
            off += id_size - 2

    # Parse optional LinkInfo
    if link_flags & 0x00000002:
        if off + 4 > len(data):
            raise ValueError("Truncated LinkInfo size")
        link_info_size = struct.unpack_from('<I', data, off)[0]
        off += 4
        if link_info_size < 4:
            raise ValueError("LinkInfo size too small")
        if off + (link_info_size - 4) > len(data):
            raise ValueError("Truncated LinkInfo structure")
        off += link_info_size - 4

    # Helper to read a string section if flag is set
    def read_string(flag, is_unicode):
        nonlocal off
        if not (link_flags & flag):
            return None
        if off + 2 > len(data):
            raise ValueError("Truncated string length")
        chars = struct.unpack_from('<H', data, off)[0]
        off += 2
        byte_len = chars * (2 if is_unicode else 1)
        if off + byte_len > len(data):
            raise ValueError("Truncated string data")
        raw = data[off:off + byte_len]
        off += byte_len
        if is_unicode:
            try:
                return raw.decode('utf-16-le')
            except UnicodeDecodeError as e:
                raise ValueError(f"Invalid UTF-16LE string: {e}")
        else:
            # Latin-1 losslessly maps bytes to Unicode code points
            return raw.decode('latin-1')

    is_unicode = bool(link_flags & 0x00000080)
    name_string = read_string(0x00000004, is_unicode)
    relative_path = read_string(0x00000008, is_unicode)
    working_dir = read_string(0x00000010, is_unicode)
    command_line_arguments = read_string(0x00000020, is_unicode)
    icon_location = read_string(0x00000040, is_unicode)

    # Parse extra data blocks
    while off + 4 <= len(data):
        block_size = struct.unpack_from('<I', data, off)[0]
        if block_size < TERMINAL_MAX_SIZE + 1:  # < 4
            break
        if off + block_size > len(data):
            raise ValueError("Extra data block exceeds file size")
        off += block_size
    if off != len(data):
        raise ValueError("Trailing data after terminal block")

    # Build result
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_dt(creation_time).isoformat(),
        "access_time": filetime_to_dt(access_time).isoformat(),
        "write_time": filetime_to_dt(write_time).isoformat(),
    }
    return result

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python parser.py <path-to-lnk-file>"}), file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
        result = parse_lnk(data)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stdout)
        sys.exit(0)

if __name__ == "__main__":
    main()