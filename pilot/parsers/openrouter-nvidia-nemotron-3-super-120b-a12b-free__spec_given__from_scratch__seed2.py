#!/usr/bin/env python3
import sys
import struct
import datetime
import json

def filetime_to_iso(ft):
    """Convert FILETIME (100-ns since 1601-01-01 UTC) to ISO 8601 string with UTC offset."""
    # Seconds since 1601-01-01
    try:
        secs = ft // 10_000_000
        rem = ft % 10_000_000          # remaining 100-ns units
        micros = rem // 10             # convert to microseconds
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = base + datetime.timedelta(seconds=secs, microseconds=microseconds)
        return dt.isoformat()
    except Exception:
        raise ValueError("Invalid FILETIME value")

def parse_lnk(data):
    offset = 0
    n = len(data)

    # ---- ShellLinkHeader (76 bytes) ----
    if n < 76:
        raise ValueError("File too small for header")
    header = data[offset:offset+76]
    offset += 76
    try:
        (header_size,
         clsid,
         link_flags,
         file_attrs,
         creation_time,
         access_time,
         write_time,
         file_size,
         icon_index,
         show_command,
         hot_key,
         reserved1,
         reserved2,
         reserved3) = struct.unpack('<I16sIIQQQIiIHHI I I I', header)
    except struct.error:
        raise ValueError("Failed to unpack header")

    if header_size != 0x4C:
        raise ValueError(f"Invalid HeaderSize: 0x{header_size:X}")
    expected_clsid = bytes.fromhex('0114020000000000C000000000000046')
    if clsid != expected_clsid:
        raise ValueError("Invalid LinkCLSID")

    # ---- IDList (if present) ----
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        while offset + 2 <= n:
            id_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if id_size == 0:
                break
            if id_size < 2:
                raise ValueError("Invalid IDList size")
            if offset + id_size - 2 > n:
                raise ValueError("IDList exceeds file size")
            offset += id_size - 2
        else:
            raise ValueError("IDList not properly terminated")

    # ---- LinkInfo (if present) ----
    if link_flags & 0x00000002:  # HasLinkInfo
        if offset + 4 > n:
            raise ValueError("LinkInfo size missing")
        link_info_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if link_info_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if offset + link_info_size - 4 > n:
            raise ValueError("LinkInfo exceeds file size")
        offset += link_info_size - 4

    # ---- String sections ----
    is_unicode = bool(link_flags & 0x00000080)
    def read_string(flag):
        nonlocal offset
        if not (link_flags & flag):
            return None
        if offset + 2 > n:
            raise ValueError("String size missing")
        count_chars = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if is_unicode:
            byte_len = count_chars * 2
        else:
            byte_len = count_chars  # ANSI, one byte per char
        if offset + byte_len > n:
            raise ValueError("String data exceeds file size")
        raw = data[offset:offset+byte_len]
        offset += byte_len
        try:
            if is_unicode:
                return raw.decode('utf-16-le')
            else:
                # Use latin-1 as a safe fallback; preserves byte values
                return raw.decode('latin-1')
        except Exception:
            raise ValueError("Failed to decode string")

    name_string = read_string(0x00000004)   # HasName
    relative_path = read_string(0x00000008) # HasRelativePath
    working_dir = read_string(0x00000010)   # HasWorkingDir
    command_line_arguments = read_string(0x00000020) # HasArguments
    icon_location = read_string(0x00000040) # HasIconLocation

    # ---- Extra Data (skip until terminal block) ----
    while offset + 4 <= n:
        block_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if block_size < 4:
            # Terminal block
            break
        if block_size > n - offset:
            raise ValueError("Extra data block exceeds file size")
        offset += block_size
    else:
        raise ValueError("Unexpected end of file while reading extra data")

    if offset != n:
        raise ValueError("Trailing data after terminal block")

    # ---- Build result ----
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
        print(json.dumps({"error": "Usage: python parser.py <path-to-lnk-file>"}), file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        print(json.dumps({"error": f"Cannot read file: {e}"}), file=sys.stderr)
        sys.exit(1)

    try:
        result = parse_lnk(data)
    except ValueError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {e}"}), file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()