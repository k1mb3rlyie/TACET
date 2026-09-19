#!/usr/bin/env python3
import sys
import json
import struct
import os
from datetime import datetime, timezone, timedelta

def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)

def parse_filetime(ft):
    """Convert FILETIME (100-ns intervals since 1601-01-01 UTC) to ISO 8601 string."""
    if ft == 0:
        return "1601-01-01T00:00:00+00:00"
    
    # 100-ns intervals to seconds
    total_100ns = ft
    seconds = total_100ns // 10_000_000
    remaining_100ns = total_100ns % 10_000_000
    microseconds = remaining_100ns * 100  # 100ns * 100 = microseconds
    
    # FILETIME epoch is 1601-01-01
    # Unix epoch is 1970-01-01
    # Difference: 11644473600 seconds
    UNIX_EPOCH_OFFSET = 11644473600
    
    unix_seconds = seconds - UNIX_EPOCH_OFFSET
    
    # Check if the timestamp is representable
    # Python's datetime has range from 1 AD to 9999 AD
    # Unix timestamp range for that: roughly -62135596800 to 253402300799
    try:
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        # Try to construct manually or fail
        # If it's out of range, we can't represent it
        # Let's try a different approach: construct from the 1601 epoch directly
        try:
            # 1601-01-01T00:00:00+00:00
            base = datetime(1601, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
            delta = timedelta(microseconds=total_100ns * 100)
            dt = base + delta
        except (OverflowError, OSError, ValueError):
            return None
    
    return dt.isoformat()

def read_string(data, offset, is_unicode):
    """
    Read a StringData section.
    Returns (string, new_offset) or raises exception.
    """
    if offset + 2 > len(data):
        raise ValueError("Truncated: cannot read CountCharacters")
    
    count_chars = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    if is_unicode:
        str_len_bytes = count_chars * 2
        if offset + str_len_bytes > len(data):
            raise ValueError("Truncated: string data exceeds file size")
        raw = data[offset:offset + str_len_bytes]
        try:
            s = raw.decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16LE string")
        offset += str_len_bytes
    else:
        str_len_bytes = count_chars
        if offset + str_len_bytes > len(data):
            raise ValueError("Truncated: string data exceeds file size")
        raw = data[offset:offset + str_len_bytes]
        try:
            s = raw.decode('cp1252')
        except UnicodeDecodeError:
            raise ValueError("Invalid CP1252 string")
        offset += str_len_bytes
    
    return s, offset

def parse_idlist(data, offset):
    """
    Skip the IDList. It's a sequence of ITEMID structures terminated by a 2-byte zero.
    Each ITEMID: 2-byte size (including the size field), then (size-2) bytes of ID.
    The list is terminated by a 2-byte 0x0000.
    """
    while offset + 2 <= len(data):
        size = struct.unpack_from('<H', data, offset)[0]
        if size == 0:
            offset += 2
            return offset
        if size < 2:
            raise ValueError("Invalid IDList item size")
        if offset + size > len(data):
            raise ValueError("Truncated IDList")
        offset += size
    
    raise ValueError("Truncated IDList: no terminator found")

def parse_linkinfo(data, offset):
    """
    Skip the LinkInfo structure.
    LinkInfo:
    - 4 bytes: LinkInfoSize
    - 4 bytes: LinkInfoHeaderSize
    - 4 bytes: LinkInfoFlags
    - 4 bytes: CommonFlags
    - 4 bytes: Reserved
    - Common data block follows
    """
    if offset + 20 > len(data):
        raise ValueError("Truncated LinkInfo")
    
    linkinfo_size = struct.unpack_from('<I', data, offset)[0]
    linkinfo_header_size = struct.unpack_from('<I', data, offset + 4)[0]
    linkinfo_flags = struct.unpack_from('<I', data, offset + 8)[0]
    
    # The total LinkInfo size includes the header and the common data
    if offset + linkinfo_size > len(data):
        raise ValueError("Truncated LinkInfo: size exceeds file")
    
    # Skip the entire LinkInfo block
    offset += linkinfo_size
    return offset

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: parser.py <path-to-lnk-file>"}))
        sys.exit(1)
    
    path = sys.argv[1]
    
    if not os.path.isfile(path):
        fail("File not found")
    
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        fail(f"Cannot read file: {e}")
    
    # Minimum size is header (76 bytes)
    if len(data) < 76:
        fail("File too small for ShellLinkHeader")
    
    # Parse header
    header_size = struct.unpack_from('<I', data, 0x00)[0]
    if header_size != 0x4C:
        fail(f"Invalid HeaderSize: {header_size:#x}, expected 0x4C")
    
    # Check CLSID
    expected_clsid = bytes.fromhex('0002140100000000C000000000000046')
    actual_clsid = data[0x04:0x14]
    if actual_clsid != expected_clsid:
        fail("Invalid LinkCLSID")
    
    linkflags = struct.unpack_from('<I', data, 0x14)[0]
    file_attributes = struct.unpack_from('<I', data, 0x18)[0]
    
    creation_time_raw = struct.unpack_from('<Q', data, 0x1C)[0]
    access_time_raw = struct.unpack_from('<Q', data, 0x24)[0]
    write_time_raw = struct.unpack_from('<Q', data, 0x2C)[0]
    
    file_size = struct.unpack_from('<I', data, 0x34)[0]
    icon_index = struct.unpack_from('<i', data, 0x38)[0]
    show_command = struct.unpack_from('<I', data, 0x3C)[0]
    hotkey = struct.unpack_from('<H', data, 0x40)[0]
    
    # Reserved fields check
    reserved1 = struct.unpack_from('<H', data, 0x42)[0]
    reserved2 = struct.unpack_from('<I', data, 0x44)[0]
    reserved3 = struct.unpack_from('<I', data, 0x48)[0]
    # We don't strictly need to fail on non-zero reserved, but let's be lenient
    
    # Parse timestamps
    creation_time = parse_filetime(creation_time_raw)
    access_time = parse_filetime(access_time_raw)
    write_time = parse_filetime(write_time_raw)
    
    if creation_time is None:
        fail("Invalid creation_time")
    if access_time is None:
        fail("Invalid access_time")
    if write_time is None:
        fail("Invalid write_time")
    
    # Determine flags
    has_link_target_id_list = bool(linkflags & 0x00000001)
    has_link_info = bool(linkflags & 0x00000002)
    has_name = bool(linkflags & 0x00000004)
    has_relative_path = bool(linkflags & 0x00000008)
    has_working_dir = bool(linkflags & 0x00000010)
    has_arguments = bool(linkflags & 0x00000020)
    has_icon_location = bool(linkflags & 0x00000040)
    is_unicode = bool(linkflags & 0x00000080)
    
    # Parse optional structures after header
    offset = 76
    
    if has_link_target_id_list:
        offset = parse_idlist(data, offset)
    
    if has_link_info:
        offset = parse_linkinfo(data, offset)
    
    # Parse StringData sections in order
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
    
    # EXTRA_DATA: should start after StringData
    # We could validate the extra data blocks, but the spec says the file ends with them.
    # For our output contract, we don't need to parse extra data, but we should ensure
    # the remaining data is valid if we want to be strict. However, the task doesn't
    # require us to parse extra data, just to extract the listed fields.
    
    # Check that we haven't gone past the end
    if offset > len(data):
        fail("Offset exceeded file size")
    
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
        "write_time": write_time
    }
    
    print(json.dumps(result))
    sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(0)