#!/usr/bin/env python3
import sys
import struct
import json
from datetime import datetime, timezone, timedelta

def read_le(fmt, data, offset):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError("Insufficient data for {}".format(fmt))
    return struct.unpack_from(fmt, data, offset)[0], offset + size

def parse_idlist(data, offset):
    while True:
        if offset + 2 > len(data):
            raise ValueError("IDList size field missing")
        id_size, offset = read_le('<H', data, offset)
        if offset + id_size > len(data):
            raise ValueError("IDList item exceeds file size")
        offset += id_size
        if id_size == 0:
            break
    return offset

def parse_linkinfo(data, offset):
    if offset + 4 > len(data):
        raise ValueError("LinkInfo size missing")
    link_info_size, offset = read_le('<I', data, offset)
    if link_info_size < 0x1c:
        raise ValueError("LinkInfo size too small")
    if offset + link_info_size > len(data):
        raise ValueError("LinkInfo exceeds file size")
    offset += link_info_size
    return offset

def filetime_to_iso(ft):
    try:
        # FILETIME: 100-nanosecond intervals since 1601-01-01 UTC
        dt = datetime(1601, 1, 1) + timedelta(microseconds=ft // 10)
    except OverflowError:
        raise ValueError("FILETIME out of range")
    dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        print(json.dumps({"error": "Invalid arguments"}))
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Cannot open file: {e}\n")
        print(json.dumps({"error": "Cannot open file"}))
        sys.exit(1)

    try:
        if len(data) < 0x4c:
            raise ValueError("File too small for ShellLink header")

        # Header
        headersize, offset = read_le('<I', data, 0x00)
        if headersize != 0x4c:
            raise ValueError("Invalid HeaderSize")
        linkclsid, offset = read_le('<16s', data, offset)
        expected_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'
        if linkclsid != expected_clsid:
            raise ValueError("Invalid LinkCLSID")
        linkflags, offset = read_le('<I', data, offset)
        fileattributes, offset = read_le('<I', data, offset)
        creationtime, offset = read_le('<Q', data, offset)
        accesstime, offset = read_le('<Q', data, offset)
        writetime, offset = read_le('<Q', data, offset)
        filesize, offset = read_le('<I', data, offset)  # unsigned
        iconindex, offset = read_le('<i', data, offset)  # signed
        showcommand, offset = read_le('<I', data, offset)
        hotkey, offset = read_le('<H', data, offset)
        reserved1, offset = read_le('<H', data, offset)
        reserved2, offset = read_le('<I', data, offset)
        reserved3, offset = read_le('<I', data, offset)

        if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
            # Not treating as fatal per spec, but we note it.
            pass

        is_unicode = bool(linkflags & 0x00000080)

        # Optional IDList
        if linkflags & 0x00000001:
            offset = parse_idlist(data, offset)

        # Optional LinkInfo
        if linkflags & 0x00000002:
            offset = parse_linkinfo(data, offset)

        # String sections in order
        sections = [
            (0x00000004, "name_string"),
            (0x00000008, "relative_path"),
            (0x00000010, "working_dir"),
            (0x00000020, "command_line_arguments"),
            (0x00000040, "icon_location"),
        ]

        result = {}
        for flag, key in sections:
            if linkflags & flag:
                if offset + 2 > len(data):
                    raise ValueError(f"Missing size for {key}")
                count, offset = read_le('<H', data, offset)
                byte_len = count * 2 if is_unicode else count
                if offset + byte_len > len(data):
                    raise ValueError(f"String data for {key} exceeds file size")
                raw = data[offset:offset + byte_len]
                offset += byte_len
                try:
                    if is_unicode:
                        s = raw.decode('utf-16-le')
                    else:
                        s = raw.decode('latin-1')
                except UnicodeDecodeError as e:
                    raise ValueError(f"Failed to decode {key}: {e}")
                result[key] = s
            else:
                result[key] = None

        # Timestamps
        result["creation_time"] = filetime_to_iso(creationtime)
        result["access_time"] = filetime_to_iso(accesstime)
        result["write_time"] = filetime_to_iso(writetime)

        # Integers
        result["file_size"] = filesize
        result["icon_index"] = iconindex

        # Output JSON
        print(json.dumps(result, separators=(',', ':')))
        sys.exit(0)

    except Exception as e:
        sys.stderr.write(f"Error parsing LNK file: {e}\n")
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()