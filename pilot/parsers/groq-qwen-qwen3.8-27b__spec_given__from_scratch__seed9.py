#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files following MS-SHLLINK specification.
Designed for digital forensics: handles damaged, incomplete, or tampered files.
"""

import json
import struct
import sys
import uuid
from datetime import datetime, timezone, timedelta

# Constants
HEADER_SIZE = 0x4C  # 76 bytes
EXPECTED_CLSID = uuid.UUID('00021401-0000-0000-C000-000000000046')

# LinkFlags bits
LF_HAS_LINK_TARGET_ID_LIST = 0x00000001
LF_HAS_LINK_INFO = 0x00000002
LF_HAS_NAME = 0x00000004
LF_HAS_RELATIVE_PATH = 0x00000008
LF_HAS_WORKING_DIR = 0x00000010
LF_HAS_ARGUMENTS = 0x00000020
LF_HAS_ICON_LOCATION = 0x00000040
LF_IS_UNICODE = 0x00000080

# FILETIME epoch: 1601-01-01 00:00:00 UTC
FILETIME_EPOCH = datetime(1601, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
HUNDRED_NANOSEC_PER_SEC = 10_000_000


def fail(msg):
    """Print error JSON to stdout and exit with code 1."""
    print(json.dumps({"error": msg}))
    sys.exit(1)


def read_bytes(data, offset, size, field_name):
    """Read exactly `size` bytes from `data` at `offset`. Fail if not enough data."""
    if offset < 0 or offset + size > len(data):
        fail(f"truncated file: cannot read {field_name} at offset {offset}")
    return data[offset:offset + size]


def read_uint16(data, offset, field_name):
    raw = read_bytes(data, offset, 2, field_name)
    return struct.unpack('<H', raw)[0]


def read_uint32(data, offset, field_name):
    raw = read_bytes(data, offset, 4, field_name)
    return struct.unpack('<I', raw)[0]


def read_int32(data, offset, field_name):
    raw = read_bytes(data, offset, 4, field_name)
    return struct.unpack('<i', raw)[0]


def read_uint64(data, offset, field_name):
    raw = read_bytes(data, offset, 8, field_name)
    return struct.unpack('<Q', raw)[0]


def read_guid(data, offset, field_name):
    raw = read_bytes(data, offset, 16, field_name)
    # GUID layout in .lnk files:
    # Data1 (4 bytes LE), Data2 (2 bytes LE), Data3 (2 bytes LE),
    # Data4 (8 bytes, first 2 bytes LE, remaining 6 bytes as-is)
    d1, d2, d3 = struct.unpack('<IHH', raw[:8])
    d4 = raw[8:16]
    d4_le = struct.unpack('<I', d4[:4])[0]
    d4_rest = d4[4:]
    guid = uuid.UUID(fields=(d1, d2, d3, d4_le >> 8, d4_le & 0xFF, d4_rest.hex()))
    # Actually, let's use the proper way:
    # The standard way to parse a GUID from bytes in .lnk format:
    # The bytes are stored in mixed endianness.
    # struct.unpack from the raw 16 bytes with proper format:
    # '<IHH6s' won't work directly. Let's use uuid.UUID(bytes) which expects big-endian network order.
    # But .lnk stores Data1, Data2, Data3 in little-endian, and Data4 in mixed.
    # The correct approach:
    # data1 = struct.unpack('<I', raw[0:4])[0]
    # data2 = struct.unpack('<H', raw[4:6])[0]
    # data3 = struct.unpack('<H', raw[6:8])[0]
    # data4 = raw[8:16]
    # Then construct UUID with fields.
    # uuid.UUID(fields=(data1, data2, data3, d4[0], d4[1], d4[2:]))
    # But uuid.UUID expects the last field as a tuple of 8 bytes or similar.
    # Let me just use uuid.UUID(bytes=...) after converting to big-endian form.
    
    # Simpler: construct the UUID bytes in network (big-endian) order
    be_bytes = struct.pack('>IHH', d1, d2, d3) + d4
    return uuid.UUID(bytes=be_bytes)


def filetime_to_iso(ft_value):
    """Convert a FILETIME (100ns intervals since 1601) to ISO 8601 with UTC offset.
    Returns None if the value is not representable."""
    if ft_value == 0:
        # 0 is a valid FILETIME (1601-01-01), but in practice, 0 often means "unspecified"
        # However, the spec says it's a count of intervals. 0 = 1601-01-01 00:00:00 UTC.
        # We'll treat it as valid.
        pass
    
    # Max representable FILETIME: 2^64 - 1
    # That corresponds to a very distant future date.
    # datetime can handle dates from year 1 to 9999.
    # 1601 + ~3400 years is too far. Let's check bounds.
    
    ticks = ft_value
    if ticks > 2**64 - 1:
        return None
    
    # Convert to seconds and microseconds
    total_seconds = ticks / 10_000_000.0
    
    # We need to be careful with floating point. Let's use integer arithmetic.
    seconds, remainder_ns = divmod(ticks, 10_000_000)
    microseconds = (remainder_ns * 1000) // 1  # 100ns * 1000 = 100,000 ns = 100 us? No.
    # 1 second = 10,000,000 * 100 ns
    # remainder_ns is in 100ns units
    # microseconds = remainder_ns * 100 // 1000 = remainder_ns // 10
    microseconds = remainder_ns // 10
    
    try:
        dt = FILETIME_EPOCH + timedelta(seconds=seconds, microseconds=microseconds)
    except (OverflowError, ValueError):
        return None
    
    # Check if the resulting datetime is representable
    if dt.year < 1 or dt.year > 9999:
        return None
    
    return dt.isoformat()


def parse_string_data(data, offset, count_chars, is_unicode, field_name):
    """Parse a StringData section. Returns (string_value, new_offset)."""
    if is_unicode:
        byte_len = count_chars * 2
    else:
        byte_len = count_chars
    
    raw = read_bytes(data, offset, byte_len, f"{field_name} string")
    
    if is_unicode:
        try:
            s = raw.decode('utf-16-le')
        except UnicodeDecodeError:
            fail(f"invalid UTF-16LE in {field_name}")
    else:
        # ANSI/ASCII - use latin-1 for byte-per-byte mapping, or try utf-8?
        # Windows ANSI strings are typically in the system code page.
        # For simplicity, use latin-1 which never fails, or try utf-8 with fallback.
        # In forensics, we should preserve bytes. Let's use latin-1 to avoid failures.
        s = raw.decode('latin-1')
    
    return s, offset + byte_len


def skip_idlist(data, offset):
    """Skip over the LinkTargetIDList. Returns new offset."""
    # IDList is a sequence of items, each:
    #   Count (2 bytes, little-endian) - number of bytes in the item including the null terminator
    #   Item bytes (Count bytes, including a trailing null byte)
    # Terminated by a 2-byte zero (Count = 0).
    
    while True:
        if offset + 2 > len(data):
            fail("truncated file: incomplete IDList")
        count = read_uint16(data, offset, "IDList item count")
        offset += 2
        if count == 0:
            break
        if offset + count > len(data):
            fail("truncated file: incomplete IDList item")
        offset += count
    
    return offset


def parse_link_info(data, offset):
    """Parse and skip the LinkInfo structure. Returns new offset."""
    # LinkInfo structure:
    #   LinkInfoSize (4 bytes) - total size of the LinkInfo block
    #   LinkInfoFlags (4 bytes)
    #   ... additional fields
    
    if offset + 8 > len(data):
        fail("truncated file: incomplete LinkInfo header")
    
    link_info_size = read_uint32(data, offset, "LinkInfoSize")
    link_info_flags = read_uint32(data, offset + 4, "LinkInfoFlags")
    
    # The LinkInfoSize should be at least 8 (the header itself)
    if link_info_size < 8:
        fail("invalid LinkInfoSize")
    
    # We need to make sure we don't go past the end of the data
    if offset + link_info_size > len(data):
        fail("truncated file: LinkInfo extends beyond file")
    
    # For our purposes, we just need to skip over the LinkInfo structure.
    # There are optional sub-structures (LocalBasePath, CommonPathSuffix, etc.)
    # but we don't need to parse them for the required output fields.
    # We just skip the entire LinkInfo block.
    
    return offset + link_info_size


def main():
    if len(sys.argv) != 2:
        fail("usage: parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except (IOError, OSError) as e:
        fail(f"cannot read file: {e}")
    
    # Check minimum size for header
    if len(data) < HEADER_SIZE:
        fail("file too small for ShellLinkHeader")
    
    # Parse ShellLinkHeader
    header_size = read_uint32(data, 0x00, "HeaderSize")
    if header_size != HEADER_SIZE:
        fail(f"invalid HeaderSize: {header_size:#x}, expected {HEADER_SIZE:#x}")
    
    clsid = read_guid(data, 0x04, "LinkCLSID")
    if clsid != EXPECTED_CLSID:
        fail(f"invalid LinkCLSID: {clsid}, expected {EXPECTED_CLSID}")
    
    link_flags = read_uint32(data, 0x14, "LinkFlags")
    file_attributes = read_uint32(data, 0x18, "FileAttributes")
    creation_time_ft = read_uint64(data, 0x1C, "CreationTime")
    access_time_ft = read_uint64(data, 0x24, "AccessTime")
    write_time_ft = read_uint64(data, 0x2C, "WriteTime")
    file_size = read_uint32(data, 0x34, "FileSize")  # unsigned
    icon_index = read_int32(data, 0x38, "IconIndex")  # signed
    show_command = read_uint32(data, 0x3C, "ShowCommand")
    hot_key = read_uint16(data, 0x40, "HotKey")
    reserved1 = read_uint16(data, 0x42, "Reserved1")
    reserved2 = read_uint32(data, 0x44, "Reserved2")
    reserved3 = read_uint32(data, 0x48, "Reserved3")
    
    # Reserved fields must be zero
    if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
        fail("non-zero reserved fields in header")
    
    # Determine if strings are unicode
    is_unicode = bool(link_flags & LF_IS_UNICODE)
    
    # Parse the body after the header
    offset = HEADER_SIZE
    
    # Skip IDList if present
    if link_flags & LF_HAS_LINK_TARGET_ID_LIST:
        offset = skip_idlist(data, offset)
    
    # Skip LinkInfo if present
    if link_flags & LF_HAS_LINK_INFO:
        offset = parse_link_info(data, offset)
    
    # Parse StringData sections in order:
    # NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
    # Only sections whose flag is set are present.
    
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    if link_flags & LF_HAS_NAME:
        if offset + 2 > len(data):
            fail("truncated file: incomplete NAME_STRING")
        count = read_uint16(data, offset, "NAME_STRING count")
        offset += 2
        name_string, offset = parse_string_data(data, offset, count, is_unicode, "NAME_STRING")
    
    if link_flags & LF_HAS_RELATIVE_PATH:
        if offset + 2 > len(data):
            fail("truncated file: incomplete RELATIVE_PATH")
        count = read_uint16(data, offset, "RELATIVE_PATH count")
        offset += 2
        relative_path, offset = parse_string_data(data, offset, count, is_unicode, "RELATIVE_PATH")
    
    if link_flags & LF_HAS_WORKING_DIR:
        if offset + 2 > len(data):
            fail("truncated file: incomplete WORKING_DIR")
        count = read_uint16(data, offset, "WORKING_DIR count")
        offset += 2
        working_dir, offset = parse_string_data(data, offset, count, is_unicode, "WORKING_DIR")
    
    if link_flags & LF_HAS_ARGUMENTS:
        if offset + 2 > len(data):
            fail("truncated file: incomplete COMMAND_LINE_ARGUMENTS")
        count = read_uint16(data, offset, "COMMAND_LINE_ARGUMENTS count")
        offset += 2
        command_line_arguments, offset = parse_string_data(data, offset, count, is_unicode, "COMMAND_LINE_ARGUMENTS")
    
    if link_flags & LF_HAS_ICON_LOCATION:
        if offset + 2 > len(data):
            fail("truncated file: incomplete ICON_LOCATION")
        count = read_uint16(data, offset, "ICON_LOCATION count")
        offset += 2
        icon_location, offset = parse_string_data(data, offset, count, is_unicode, "ICON_LOCATION")
    
    # After StringData, there may be EXTRA_DATA blocks.
    # We don't need to parse them for the output, but we should verify the file
    # ends properly with a TerminalBlock (32-bit value < 4).
    # However, the spec says "the file ends with a sequence of extra data blocks
    # terminated by a TerminalBlock". We don't strictly need to validate this
    # for the required output fields, but let's do a basic sanity check.
    # Actually, the requirement is to parse correctly. If there's extra data,
    # we can ignore it as long as the required fields are parsed correctly.
    # But we should ensure we haven't misread offsets.
    
    # Convert FILETIMEs to ISO 8601
    creation_time = filetime_to_iso(creation_time_ft)
    access_time = filetime_to_iso(access_time_ft)
    write_time = filetime_to_iso(write_time_ft)
    
    if creation_time is None:
        fail("invalid CreationTime")
    if access_time is None:
        fail("invalid AccessTime")
    if write_time is None:
        fail("invalid WriteTime")
    
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time,
        "access_time": access_time,
        "write_time": write_time,
    }
    
    print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()