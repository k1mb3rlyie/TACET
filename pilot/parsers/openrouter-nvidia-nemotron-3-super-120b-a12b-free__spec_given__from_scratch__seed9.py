#!/usr/bin/env python3
import struct
import sys
import datetime
import json

def filetime_to_iso(ft):
    """Convert FILETIME (100-ns since 1601-01-01 UTC) to ISO 8601 string with UTC offset."""
    try:
        # seconds since 1601-01-01
        seconds = ft / 10_000_000.0
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=seconds)
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.isoformat()
    except Exception:
        raise ValueError("Invalid FILETIME value")

def parse_lnk(data):
    if len(data) < 0x4C:
        raise ValueError("File too short for ShellLinkHeader")
    off = 0

    # Header
    (header_size,
     link_clsid,
     link_flags,
     file_attributes,
     creation_time,
     access_time,
     write_time,
     file_size,
     icon_index,
     show_command,
     hot_key,
     reserved1,
     reserved2,
     reserved3) = struct.unpack_from('<I 16s I I Q Q Q Q I i H H 2s 4s 4s', data, off)
    off += 0x4C

    if header_size != 0x0000004C:
        raise ValueError("Invalid HeaderSize")
    expected_clsid = bytes.fromhex('0104020000000000C000000000000046')
    if link_clsid != expected_clsid:
        raise ValueError("Invalid LinkCLSID")
    if reserved1 != b'\x00\x00' or reserved2 != b'\x00\x00\x00\x00' or reserved3 != b'\x00\x00\x00\x00':
        raise ValueError("Reserved fields not zero")

    is_unicode = bool(link_flags & 0x00000080)

    # Helper to skip IDList
    def skip_idlist():
        nonlocal off
        while True:
            if off + 2 > len(data):
                raise ValueError("Truncated IDList")
            id_size = struct.unpack_from('<H', data, off)[0]
            off += 2
            if id_size == 0:
                break
            if id_size < 2:
                raise ValueError("Invalid IDList size")
            if off + (id_size - 2) > len(data):
                raise ValueError("Truncated IDList item")
            off += id_size - 2

    # Helper to skip LinkInfo
    def skip_linkinfo():
        nonlocal off
        if off + 4 > len(data):
            raise ValueError("Truncated LinkInfo size")
        li_size = struct.unpack_from('<I', data, off)[0]
        off += 4
        if li_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if off + (li_size - 4) > len(data):
            raise ValueError("Truncated LinkInfo")
        off += li_size - 4

    # Optional IDList
    if link_flags & 0x00000001:
        skip_idlist()

    # Optional LinkInfo
    if link_flags & 0x00000002:
        skip_linkinfo()

    # String sections in fixed order
    def read_string(flag):
        nonlocal off
        if not (link_flags & flag):
            return None
        if off + 2 > len(data):
            raise ValueError("Truncated string length")
        char_count = struct.unpack_from('<H', data, off)[0]
        off += 2
        byte_len = char_count * (2 if is_unicode else 1)
        if off + byte_len > len(data):
            raise ValueError("Truncated string data")
        raw = data[off:off+byte_len]
        off += byte_len
        try:
            encoding = 'utf-16-le' if is_unicode else 'utf-8'
            return raw.decode(encoding)
        except UnicodeDecodeError as e:
            raise ValueError(f"String decoding failed: {e}")

    name_string = read_string(0x00000004)          # HasName
    relative_path = read_string(0x00000008)       # HasRelativePath
    working_dir = read_string(0x00000010)         # HasWorkingDir
    command_line_arguments = read_string(0x00000020)  # HasArguments
    icon_location = read_string(0x00000040)       # HasIconLocation

    # Extra data blocks (skip until terminal block)
    while True:
        if off + 4 > len(data):
            raise ValueError("Truncated extra data")
        block_size = struct.unpack_from('<I', data, off)[0]
        off += 4
        if block_size < 4:
            # Terminal block
            break
        if off + (block_size - 4) > len(data):
            raise ValueError("Truncated extra data block")
        off += block_size - 4

    if off != len(data):
        raise ValueError("Extra data after terminal block")

    # Convert timestamps
    creation_iso = filetime_to_iso(creation_time)
    access_iso = filetime_to_iso(access_time)
    write_iso = filetime_to_iso(write_time)

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
        print(json.dumps({"error": "Usage: python parser.py <path-to-lnk-file>"}), file=sys.stderr)
        sys.exit(2)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
        result = parse_lnk(data)
        print(json.dumps(result))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()