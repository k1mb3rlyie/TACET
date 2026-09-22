#!/usr/bin/env python3
import struct
import sys
import json
from datetime import datetime, timezone, timedelta


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)


def parse_filetime(value):
    """Convert a FILETIME (100ns intervals since 1601-01-01 UTC) to an ISO 8601 string with UTC offset."""
    # FILETIME is unsigned 64-bit. If it's 0, it could mean "unset" but per spec we treat it as a valid time (1601-01-01).
    # However, in practice, 0 often means no time. But the spec says it's a FILETIME value.
    # Let's convert it.
    # 1601-01-01 00:00:00 UTC in Unix timestamp is -11644473600
    unix_timestamp = (value / 10000000) - 11644473600
    # Check if it's a reasonable date
    if unix_timestamp < 0:
        # Before 1970, still valid but let's handle it
        pass
    try:
        dt = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        fail("Invalid FILETIME value")
    return dt.isoformat()


def read_string(data, offset, is_unicode):
    """Read a StringData section. Returns (string, new_offset)."""
    if offset + 2 > len(data):
        fail("Truncated StringData: missing character count")
    count = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if is_unicode:
        byte_count = count * 2
    else:
        byte_count = count
    if offset + byte_count > len(data):
        fail("Truncated StringData: string exceeds file boundary")
    raw = data[offset:offset + byte_count]
    offset += byte_count
    if is_unicode:
        try:
            s = raw.decode('utf-16-le')
        except UnicodeDecodeError:
            fail("Invalid UTF-16LE encoding in string")
    else:
        try:
            s = raw.decode('cp1252')
        except UnicodeDecodeError:
            fail("Invalid encoding in string")
    return s, offset


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: parser.py <path-to-lnk-file>"}))
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(json.dumps({"error": f"Cannot read file: {e}"}))
        sys.exit(1)

    # Check minimum size for header
    if len(data) < 0x4C:
        fail("File too short for ShellLinkHeader")

    # Parse header
    header_size = struct.unpack_from('<I', data, 0x00)[0]
    if header_size != 0x4C:
        fail(f"Invalid HeaderSize: {header_size:#x}, expected 0x4C")

    # LinkCLSID
    expected_clsid = bytes([
        0x00, 0x02, 0x14, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0xC0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    ])
    actual_clsid = data[0x04:0x14]
    if actual_clsid != expected_clsid:
        fail("Invalid LinkCLSID")

    link_flags = struct.unpack_from('<I', data, 0x14)[0]
    file_attributes = struct.unpack_from('<I', data, 0x18)[0]
    creation_time = struct.unpack_from('<Q', data, 0x1C)[0]
    access_time = struct.unpack_from('<Q', data, 0x24)[0]
    write_time = struct.unpack_from('<Q', data, 0x2C)[0]
    file_size = struct.unpack_from('<I', data, 0x34)[0]  # unsigned
    icon_index = struct.unpack_from('<i', data, 0x38)[0]  # signed
    show_command = struct.unpack_from('<I', data, 0x3C)[0]
    hot_key = struct.unpack_from('<H', data, 0x40)[0]
    reserved1 = struct.unpack_from('<H', data, 0x42)[0]
    reserved2 = struct.unpack_from('<I', data, 0x44)[0]
    reserved3 = struct.unpack_from('<I', data, 0x48)[0]

    # Check reserved fields must be zero
    if reserved1 != 0:
        fail("Reserved1 is not zero")
    if reserved2 != 0:
        fail("Reserved2 is not zero")
    if reserved3 != 0:
        fail("Reserved3 is not zero")

    is_unicode = bool(link_flags & 0x00000080)

    # Determine which string sections are present
    has_name = bool(link_flags & 0x00000004)
    has_relative_path = bool(link_flags & 0x00000008)
    has_working_dir = bool(link_flags & 0x00000010)
    has_arguments = bool(link_flags & 0x00000020)
    has_icon_location = bool(link_flags & 0x00000040)

    has_idlist = bool(link_flags & 0x00000001)
    has_linkinfo = bool(link_flags & 0x00000002)

    # We don't need to fully parse IDList and LinkInfo for the output,
    # but we need to skip over them to reach the StringData sections.
    # The specification says StringData follows after IDList and LinkInfo.
    # However, the exact size of IDList and LinkInfo is variable.
    # IDList: a series of IDListEntry, terminated by a 2-byte zero.
    #   Each IDListEntry: 2-byte offset, 2-byte size, then the bytes.
    # LinkInfo: starts with a 4-byte size field (size of the remaining LinkInfo structure, not including the size field itself? Actually, per spec, it's the size of the LinkInfo structure).
    #   Actually, LinkInfo has a 4-byte header (size of the whole LinkInfo struct), then common data, then link target ID list, then local base path, then common path, then relative path, then command line, then icon.
    #   This is complex. For a forensics tool that only extracts the named fields, we might be able to avoid parsing LinkInfo fully if we can find the StringData sections.
    #   But the StringData sections come *after* LinkInfo. So we must skip LinkInfo.
    #   Let's try to parse it.

    offset = 0x4C  # Start after header

    # Parse IDList if present
    if has_idlist:
        # IDList is a sequence of IDListEntry, each: 2-byte offset, 2-byte size
        # Terminated by 2-byte zero (offset=0, size=0)
        while True:
            if offset + 4 > len(data):
                fail("Truncated IDList")
            entry_offset = struct.unpack_from('<H', data, offset)[0]
            entry_size = struct.unpack_from('<H', data, offset + 2)[0]
            # The next entry starts at offset + 4 + entry_size
            if entry_offset == 0 and entry_size == 0:
                offset += 4  # skip the terminator
                break
            offset += 4 + entry_size
            if offset > len(data):
                fail("IDList extends beyond file")

    # Parse LinkInfo if present
    if has_linkinfo:
        if offset + 4 > len(data):
            fail("Truncated LinkInfo: missing size field")
        linkinfo_size = struct.unpack_from('<I', data, offset)[0]
        # linkinfo_size is the size of the LinkInfo structure (including the 4-byte size field? or not?)
        # Per MS-SHLLINK: "This field specifies the size, in bytes, of the LinkInfo structure."
        # So it includes the 4-byte size field.
        offset += linkinfo_size
        if offset > len(data):
            fail("LinkInfo extends beyond file")

    # Now we should be at the start of StringData sections
    # Parse StringData sections in order: NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if has_name:
        name_string, offset = read_string(data, offset, is_unicode)
    if has_relative_path:
        relative_path, offset = read_string(data, offset, is_unicode)
    if has_working_dir:
        working_dir, offset = read_string(data, offset, is_unicode)
    if has_arguments:
        command_line_arguments, offset = read_string(data, offset, is_unicode)
    if has_icon_location:
        icon_location, offset = read_string(data, offset, is_unicode)

    # After StringData, there may be EXTRA_DATA blocks.
    # We don't need to parse them for the output, but we should ensure the file is well-formed.
    # The spec says: "the file ends with a sequence of extra data blocks terminated by a TerminalBlock: a 32-bit value less than 0x00000004."
    # We'll just verify that if there's more data, it looks like extra data blocks.
    # For simplicity, and since we don't need to extract extra data, we can stop here.
    # But to be safe, let's just make sure we haven't gone past the file.
    if offset > len(data):
        fail("Offset exceeds file size after parsing StringData")

    # Convert timestamps
    creation_time_iso = parse_filetime(creation_time)
    access_time_iso = parse_filetime(access_time)
    write_time_iso = parse_filetime(write_time)

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

    print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()