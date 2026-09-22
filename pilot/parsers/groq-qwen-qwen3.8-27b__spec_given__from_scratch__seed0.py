#!/usr/bin/env python3
import sys
import struct
import json
import os
from datetime import datetime, timezone, timedelta

def fail(msg):
    """Exit with error, printing to stderr and a JSON error to stdout."""
    print(json.dumps({"error": msg}))
    sys.exit(0)

def read_file(path):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        fail(f"Cannot read file: {str(e)}")

def parse_filetime(ft_value):
    """Convert FILETIME (100ns intervals since 1601-01-01 UTC) to ISO 8601 string.
    Return None if the value is invalid (e.g., negative or too large)."""
    if ft_value == 0:
        return None
    # FILETIME is unsigned 64-bit. If it's 0, it's "no time" - treat as absent?
    # Actually, FILETIME value 0 means 1601-01-01T00:00:00Z. But in practice,
    # 0 often means "not set". The spec says it's a count since 1601.
    # Let's convert: 1601-01-01 to 1970-01-01 is 11644473600 seconds.
    # 11644473600 * 10000000 = 116444736000000000
    EPOCH_DIFF = 116444736000000000  # 100ns intervals from 1601 to 1970
    
    if ft_value < EPOCH_DIFF:
        # Before 1970, let's still try to convert
        delta_100ns = ft_value - EPOCH_DIFF
        # This would be a negative number of seconds from epoch
        total_seconds = delta_100ns / 10000000.0
        try:
            dt = datetime.fromtimestamp(0, tz=timezone.utc) + timedelta(seconds=total_seconds)
            return dt.isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    
    delta_100ns = ft_value - EPOCH_DIFF
    total_seconds = delta_100ns / 10000000.0
    try:
        dt = datetime.fromtimestamp(0, tz=timezone.utc) + timedelta(seconds=total_seconds)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return None

def main():
    if len(sys.argv) != 2:
        fail("Usage: parser.py <path-to-lnk-file>")
    
    path = sys.argv[1]
    data = read_file(path)
    
    # Minimum size for header
    if len(data) < 76:
        fail("File too small for ShellLinkHeader")
    
    # Parse header
    header_size = struct.unpack_from('<I', data, 0x00)[0]
    if header_size != 0x0000004C:
        fail(f"Invalid HeaderSize: {header_size:#x}, expected 0x4C")
    
    # LinkCLSID check
    # 00021401-0000-0000-C000-000000000046
    # In little-endian bytes:
    # 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
    expected_clsid = bytes([
        0x01, 0x14, 0x02, 0x00,
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
    creation_time_ft = struct.unpack_from('<Q', data, 0x1C)[0]
    access_time_ft = struct.unpack_from('<Q', data, 0x24)[0]
    write_time_ft = struct.unpack_from('<Q', data, 0x2C)[0]
    file_size = struct.unpack_from('<I', data, 0x34)[0]  # unsigned
    icon_index = struct.unpack_from('<i', data, 0x38)[0]  # signed
    show_command = struct.unpack_from('<I', data, 0x3C)[0]
    hotkey = struct.unpack_from('<H', data, 0x40)[0]
    
    # Reserved fields must be zero
    reserved1 = struct.unpack_from('<H', data, 0x42)[0]
    reserved2 = struct.unpack_from('<I', data, 0x44)[0]
    reserved3 = struct.unpack_from('<I', data, 0x48)[0]
    if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
        fail("Reserved fields are not zero")
    
    # Determine if strings are Unicode
    is_unicode = bool(link_flags & 0x00000080)
    
    # Flags
    has_link_target_id_list = bool(link_flags & 0x00000001)
    has_link_info = bool(link_flags & 0x00000002)
    has_name = bool(link_flags & 0x00000004)
    has_relative_path = bool(link_flags & 0x00000008)
    has_working_dir = bool(link_flags & 0x00000010)
    has_arguments = bool(link_flags & 0x00000020)
    has_icon_location = bool(link_flags & 0x00000040)
    
    pos = 76  # Start of variable data
    
    # Skip LinkTargetIDList if present
    if has_link_target_id_list:
        if pos + 2 > len(data):
            fail("Truncated: cannot read IDList size")
        idlist_size = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        if pos + idlist_size > len(data):
            fail("Truncated: IDList extends beyond file")
        pos += idlist_size
    
    # Skip LinkInfo if present
    if has_link_info:
        if pos + 4 > len(data):
            fail("Truncated: cannot read LinkInfo size")
        linkinfo_size = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if pos + linkinfo_size > len(data):
            fail("Truncated: LinkInfo extends beyond file")
        pos += linkinfo_size
    
    # Now parse StringData sections in order:
    # NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
    
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    def read_string(pos):
        """Read a StringData section. Returns (string, new_pos)."""
        nonlocal is_unicode
        if pos + 2 > len(data):
            fail("Truncated: cannot read string character count")
        count = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        if is_unicode:
            byte_len = count * 2
        else:
            byte_len = count
        if pos + byte_len > len(data):
            fail("Truncated: string data extends beyond file")
        raw = data[pos:pos + byte_len]
        pos += byte_len
        if is_unicode:
            try:
                s = raw.decode('utf-16-le')
            except UnicodeDecodeError:
                fail("Invalid UTF-16LE string")
        else:
            try:
                s = raw.decode('cp1252')
            except UnicodeDecodeError:
                fail("Invalid string encoding")
        return s, pos
    
    if has_name:
        name_string, pos = read_string(pos)
    if has_relative_path:
        relative_path, pos = read_string(pos)
    if has_working_dir:
        working_dir, pos = read_string(pos)
    if has_arguments:
        command_line_arguments, pos = read_string(pos)
    if has_icon_location:
        icon_location, pos = read_string(pos)
    
    # Parse EXTRA_DATA blocks
    # We need to parse through the extra data to reach the TerminalBlock.
    # The spec says extra data blocks are terminated by a TerminalBlock:
    # a 32-bit value less than 0x00000004.
    
    while pos < len(data):
        if pos + 4 > len(data):
            fail("Truncated: cannot read extra data block header")
        extra_id = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        
        # TerminalBlock: value less than 4
        if extra_id < 0x00000004:
            break
        
        # If not terminal, we need to read the size of this block
        # According to MS-SHLLINK, extra data blocks have:
        # ExtraData (variable)
        # The structure is:
        #   ExtraDataType (4 bytes)
        #   [ExtraDataSize (4 bytes) - only if ExtraDataType >= 4]
        #   [Data]
        
        if pos + 4 > len(data):
            fail("Truncated: cannot read extra data block size")
        extra_size = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        
        if pos + extra_size > len(data):
            fail("Truncated: extra data block extends beyond file")
        pos += extra_size
    
    # Now parse timestamps
    creation_time = parse_filetime(creation_time_ft)
    access_time = parse_filetime(access_time_ft)
    write_time = parse_filetime(write_time_ft)
    
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

if __name__ == "__main__":
    main()