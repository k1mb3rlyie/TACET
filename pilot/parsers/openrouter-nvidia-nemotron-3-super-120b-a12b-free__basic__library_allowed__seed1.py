#!/usr/bin/env python3
import sys
import json
import struct
import datetime

# Shell Link constants
SHELL_LINK_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
FLAG_HAS_LINK_TARGET_IDLIST = 0x00000001
FLAG_HAS_LINKINFO = 0x00000002
FLAG_HAS_NAME = 0x00000004
FLAG_HAS_RELATIVE_PATH = 0x00000008
FLAG_HAS_WORKING_DIR = 0x00000010
FLAG_HAS_ARGUMENTS = 0x00000020
FLAG_HAS_ICON_LOCATION = 0x00000040
FLAG_IS_UNICODE = 0x00000080

def filetime_to_iso(ft):
    """Convert FILETIME (100-ns since 1601-01-01 UTC) to ISO 8601 with UTC offset."""
    # Unix epoch start in FILETIME
    EPOCH_AS_FILETIME = 116444736000000000
    if ft < EPOCH_AS_FILETIME:
        # Before epoch, still handle (should not happen for normal files)
        ts = (ft - EPOCH_AS_FILETIME) / 10000000.0
    else:
        ts = (ft - EPOCH_AS_FILETIME) / 10000000.0
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    return dt.isoformat()

def parse_item_id_list(data, offset):
    """Parse the ID list, returning new offset after the terminating 0 size."""
    while True:
        if offset + 2 > len(data):
            raise ValueError("Truncated ID list")
        cb = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if cb == 0:
            break
        if cb < 2:
            raise ValueError("Invalid ID list size")
        if offset + cb - 2 > len(data):
            raise ValueError("Truncated ID list entry")
        offset += cb - 2
    return offset

def parse_lnk_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) < 76:
        raise ValueError("File too small to be a .lnk")
    # Read header (76 bytes)
    header = data[:76]
    clsid = header[0:16]
    if clsid != SHELL_LINK_CLSID:
        raise ValueError("Invalid CLSID, not a .lnk file")
    # Unpack the rest of the header (bytes 16-72)
    try:
        (link_flags, file_attributes,
         creation_time, access_time, write_time,
         file_size, icon_index, show_command,
         hot_key, reserved1, reserved2, reserved3) = struct.unpack_from('<IIQQQIIHHIII', header, 16)
    except struct.error as e:
        raise ValueError(f"Failed to unpack header: {e}")

    # Determine if strings are Unicode
    if not (link_flags & FLAG_IS_UNICODE):
        raise ValueError("Non-Unicode strings are not supported")

    offset = 76  # start after header

    # Optional ID list
    if link_flags & FLAG_HAS_LINK_TARGET_IDLIST:
        offset = parse_item_id_list(data, offset)

    # Optional LinkInfo
    if link_flags & FLAG_HAS_LINKINFO:
        if offset + 4 > len(data):
            raise ValueError("Truncated LinkInfo size")
        link_info_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if link_info_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if offset + link_info_size - 4 > len(data):
            raise ValueError("Truncated LinkInfo")
        offset += link_info_size - 4

    # Helper to read a Unicode null-terminated string
    def read_unicode_string():
        nonlocal offset
        start = offset
        while True:
            if offset + 2 > len(data):
                raise ValueError("Truncated string")
            w = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if w == 0:
                break
        string_bytes = data[start:offset-2]
        try:
            return string_bytes.decode('utf-16le')
        except UnicodeDecodeError:
            raise ValueError("Failed to decode Unicode string")

    # Parse strings in order
    name_string = None
    if link_flags & FLAG_HAS_NAME:
        name_string = read_unicode_string()

    relative_path = None
    if link_flags & FLAG_HAS_RELATIVE_PATH:
        relative_path = read_unicode_string()

    working_dir = None
    if link_flags & FLAG_HAS_WORKING_DIR:
        working_dir = read_unicode_string()

    command_line_arguments = None
    if link_flags & FLAG_HAS_ARGUMENTS:
        command_line_arguments = read_unicode_string()

    icon_location = None
    if link_flags & FLAG_HAS_ICON_LOCATION:
        icon_location = read_unicode_string()

    # Times
    creation_time_iso = filetime_to_iso(creation_time)
    access_time_iso = filetime_to_iso(access_time)
    write_time_iso = filetime_to_iso(write_time)

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
        "write_time": write_time_iso
    }
    return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)
    path = sys.argv[1]
    try:
        result = parse_lnk_file(path)
        json.dump(result, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as e:
        err = {"error": str(e)}
        json.dump(err, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)

if __name__ == "__main__":
    main()