#!/usr/bin/env python3
import sys
import struct
import datetime
import json

def error_exit(msg):
    print(json.dumps({"error": msg}))
    sys.exit(1)

def parse_lnk(data):
    if len(data) < 0x4C:
        error_exit("File too small for header")
    off = 0
    (header_size,) = struct.unpack_from('<I', data, off); off += 4
    if header_size != 0x4C:
        error_exit(f"Invalid HeaderSize {header_size:#x}")
    link_clsid = data[off:off+16]; off += 16
    expected_clsid = bytes.fromhex('0114020000000000C000000000000046')
    if link_clsid != expected_clsid:
        error_exit("Invalid LinkCLSID")
    (link_flags,) = struct.unpack_from('<I', data, off); off += 4
    (file_attributes,) = struct.unpack_from('<I', data, off); off += 4
    (creation_time_raw,) = struct.unpack_from('<Q', data, off); off += 8
    (access_time_raw,) = struct.unpack_from('<Q', data, off); off += 8
    (write_time_raw,) = struct.unpack_from('<Q', data, off); off += 8
    (file_size,) = struct.unpack_from('<I', data, off); off += 4
    (icon_index,) = struct.unpack_from('<i', data, off); off += 4
    (show_command,) = struct.unpack_from('<I', data, off); off += 4
    (hot_key,) = struct.unpack_from('<H', data, off); off += 2
    (reserved1,) = struct.unpack_from('<H', data, off); off += 2
    (reserved2,) = struct.unpack_from('<I', data, off); off += 4
    (reserved3,) = struct.unpack_from('<I', data, off); off += 4

    # Validate reserved fields (should be zero)
    if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
        error_exit("Non-zero reserved fields")

    is_unicode = bool(link_flags & 0x00000080)
    has_idlist = bool(link_flags & 0x00000001)
    has_linkinfo = bool(link_flags & 0x00000002)
    has_name = bool(link_flags & 0x00000004)
    has_relpath = bool(link_flags & 0x00000008)
    has_workdir = bool(link_flags & 0x00000010)
    has_args = bool(link_flags & 0x00000020)
    has_iconloc = bool(link_flags & 0x00000040)

    # Skip IDList
    if has_idlist:
        while True:
            if off + 2 > len(data):
                error_exit("Truncated IDList")
            cb = struct.unpack_from('<H', data, off)[0]; off += 2
            if cb == 0:
                break
            if off + cb > len(data):
                error_exit("IDList exceeds file size")
            off += cb

    # Skip LinkInfo
    if has_linkinfo:
        if off + 4 > len(data):
            error_exit("Truncated LinkInfo size")
        link_info_size = struct.unpack_from('<I', data, off)[0]; off += 4
        if link_info_size < 0:
            error_exit("Invalid LinkInfo size")
        if off + link_info_size > len(data):
            error_exit("LinkInfo exceeds file size")
        off += link_info_size

    # Helper to read a string
    def read_string(unicode_flag):
        nonlocal off
        if off + 2 > len(data):
            error_exit("Truncated string length")
        count = struct.unpack_from('<H', data, off)[0]; off += 2
        byte_len = count * (2 if unicode_flag else 1)
        if off + byte_len > len(data):
            error_exit("Truncated string data")
        raw = data[off:off+byte_len]; off += byte_len
        try:
            if unicode_flag:
                return raw.decode('utf-16-le')
            else:
                # ANSI: we cannot guarantee correct code page; treat as error
                raise UnicodeDecodeError('ansi', b'', 0, 1, "ANSI strings not supported")
        except UnicodeDecodeError as e:
            error_exit(f"Failed to decode string: {e}")

    # Extract strings (only if Unicode, else error)
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if is_unicode:
        if has_name:
            name_string = read_string(True)
        if has_relpath:
            relative_path = read_string(True)
        if has_workdir:
            working_dir = read_string(True)
        if has_args:
            command_line_arguments = read_string(True)
        if has_iconloc:
            icon_location = read_string(True)
    else:
        # If any string present, we cannot decode correctly -> error
        if has_name or has_relpath or has_workdir or has_args or has_iconloc:
            error_exit("ANSI strings present but decoding not supported")
        # else all remain None

    # Parse extra data blocks
    while off + 4 <= len(data):
        block_size = struct.unpack_from('<I', data, off)[0]; off += 4
        if block_size < 4:
            # Terminal block
            break
        if off + 4 > len(data):
            error_exit("Truncated extra block signature")
        # signature = struct.unpack_from('<I', data, off)[0]; off += 4  # signature not needed
        off += 4
        remaining = block_size - 4
        if off + remaining > len(data):
            error_exit("Extra block exceeds file size")
        off += remaining
    else:
        # Ran out of data before finding terminal block
        error_exit("Missing terminal block in extra data")

    if off != len(data):
        error_exit("Trailing data after terminal block")

    # Convert FILETIME to ISO 8601 UTC
    def filetime_to_iso(ft):
        # ft is 100-ns intervals since 1601-01-01 UTC
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ft // 10)
        return dt.isoformat()

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_time_raw),
        "access_time": filetime_to_iso(access_time_raw),
        "write_time": filetime_to_iso(write_time_raw),
    }
    return result

def main():
    if len(sys.argv) != 2:
        error_exit("Usage: python parser.py <path-to-lnk-file>")
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        error_exit(f"Cannot read file: {e}")
    try:
        result = parse_lnk(data)
        print(json.dumps(result))
    except Exception as e:
        error_exit(str(e))

if __name__ == "__main__":
    main()