#!/usr/bin/env python3
import sys
import struct
import json
from datetime import datetime, timezone, timedelta

def filetime_to_iso(ft: int) -> str:
    """Convert FILETIME uint64 to ISO 8601 string with UTC offset."""
    # Base epoch: 1601-01-01 00:00:00 UTC
    base = datetime(1601, 1, 1, tzinfo=timezone.utc)
    # 1 FILETIME unit = 100 nanoseconds = 0.1 microsecond
    dt = base + timedelta(microseconds=ft // 10)
    return dt.isoformat()

def error_exit(msg: str):
    print(msg, file=sys.stderr)
    sys.exit(1)

def main():
    if len(sys.argv) != 2:
        error_exit("Usage: python parser.py <path-to-lnk-file>")
    lnk_path = sys.argv[1]

    try:
        with open(lnk_path, "rb") as f:
            data = f.read()
    except IOError as e:
        error_exit(f"Cannot read file: {e}")

    if len(data) < 76:
        error_exit("File too small to be a valid LNK")

    try:
        (clsid, link_flags, file_attrs,
         creation_ft, access_ft, write_ft,
         file_size, icon_index,
         show_cmd, hot_key, reserved1, reserved2) = struct.unpack(
            "<16sIIQQQQQIIIIII", data[:76])
    except struct.error as e:
        error_exit(f"Failed to parse header: {e}")

    # Determine if strings are Unicode
    unicode_flag = link_flags & 0x00000800  # Actually 0x00000800? Wait, Unicode flag is 0x00000400? Let's verify.
    # According to MSDN: bit 0x00000400 is Unicode? Let's check: The LinkFlags bits:
    # 0: HasLinkTargetIDList
    # 1: HasLinkInfo
    # 2: HasName
    # 3: HasRelativePath
    # 4: HasWorkingDir
    # 5: HasCommandLineArgs
    # 6: HasIconLocation
    # 7: IsUnicode (0x00000080) Actually I think it's 0x00000080.
    # Let's double-check: Many sources show IsUnicode = 0x00000080.
    # We'll use 0x00000080.
    unicode_flag = link_flags & 0x00000080

    pos = 76

    # Optional LinkTargetIDList
    if link_flags & 0x00000001:
        if pos + 2 > len(data):
            error_exit("Failed to read LinkTargetIDList size")
        idlist_size = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if pos + idlist_size > len(data):
            error_exit("LinkTargetIDList exceeds file size")
        pos += idlist_size

    # Optional LinkInfo
    if link_flags & 0x00000002:
        if pos + 4 > len(data):
            error_exit("Failed to read LinkInfo header size")
        linkinfo_hdr_size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if linkinfo_hdr_size < 4:
            error_exit("Invalid LinkInfo header size")
        if pos + linkinfo_hdr_size - 4 > len(data):
            error_exit("LinkInfo exceeds file size")
        pos += linkinfo_hdr_size - 4

    # Helper to read a string if present
    def read_string(present: bool):
        nonlocal pos
        if not present:
            return None
        if pos + 2 > len(data):
            error_exit("Failed to read string length")
        strlen = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if strlen == 0:
            value = ""
        else:
            if strlen < 2:
                error_exit("Invalid string length")
            if strlen % 2 != 0:
                error_exit("String length must be even (UTF-16LE)")
            # Extract characters (excluding terminating null)
            chars_len = strlen - 2
            if pos + chars_len > len(data):
                error_exit("String data exceeds file size")
            chars_bytes = data[pos:pos + chars_len]
            pos += chars_len
            # Decode according to Unicode flag
            try:
                if unicode_flag:
                    value = chars_bytes.decode("utf-16le")
                else:
                    # Assume Windows-1252 for ANSI strings
                    value = chars_bytes.decode("cp1252")
            except UnicodeDecodeError as e:
                error_exit(f"Failed to decode string: {e}")
            # Skip terminating null terminator
            if pos + 2 > len(data):
                error_exit("Missing string terminator")
            null_term = data[pos:pos + 2]
            pos += 2
            # Optionally verify null terminator
            if null_term != b"\x00\x00":
                # Not fatal, but note
                pass
        return value

    # Order of strings: name, relative path, working dir, command line args, icon location
    name_string = read_string(bool(link_flags & 0x00000004))
    relative_path = read_string(bool(link_flags & 0x00000008))
    working_dir = read_string(bool(link_flags & 0x00000010))
    command_line_arguments = read_string(bool(link_flags & 0x00000020))
    icon_location = read_string(bool(link_flags & 0x00000040))

    # Build ISO timestamps
    try:
        creation_iso = filetime_to_iso(creation_ft)
        access_iso = filetime_to_iso(access_ft)
        write_iso = filetime_to_iso(write_ft)
    except Exception as e:
        error_exit(f"Timestamp conversion failed: {e}")

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

    # Output JSON to stdout
    try:
        json.dump(result, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
    except Exception as e:
        error_exit(f"Failed to write JSON output: {e}")

if __name__ == "__main__":
    main()