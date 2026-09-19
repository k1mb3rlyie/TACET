#!/usr/bin/env python3
import sys
import json
import struct
from datetime import datetime, timezone

def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)

def parse_filetime(data, offset):
    """Parse a 64-bit FILETIME value at the given offset."""
    if offset + 8 > len(data):
        raise ValueError("Truncated FILETIME")
    val = struct.unpack_from('<Q', data, offset)[0]
    # Convert 100-nanosecond intervals since 1601-01-01 to datetime
    # 1601-01-01 00:00:00 UTC in seconds from epoch (1970-01-01) is -11644473600
    seconds_since_epoch = (val / 10000000.0) - 11644473600.0
    
    # Check if the value is reasonable (not before 1601 or too far in future)
    if val == 0:
        # This could be an unset time, but we still need to convert it
        # 0 means 1601-01-01 00:00:00 UTC
        dt = datetime(1601, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    else:
        try:
            dt = datetime.fromtimestamp(seconds_since_epoch, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            raise ValueError(f"FILETIME value {val} not representable")
    return dt

def parse_string(data, offset, is_unicode):
    """Parse a StringData section. Returns (string, new_offset)."""
    if offset + 2 > len(data):
        raise ValueError("Truncated string length")
    count = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    if is_unicode:
        byte_len = count * 2
        if offset + byte_len > len(data):
            raise ValueError("Truncated Unicode string")
        raw = data[offset:offset + byte_len]
        s = raw.decode('utf-16-le')
        offset += byte_len
    else:
        if offset + count > len(data):
            raise ValueError("Truncated ASCII string")
        raw = data[offset:offset + count]
        s = raw.decode('ascii', errors='replace')
        offset += count
    
    return s, offset

def parse_link_info(data, offset):
    """
    Parse the LinkInfo structure. We need to skip past it.
    LinkInfo:
      0x00: LinkInfoSize (4 bytes) - size of LinkInfo structure including this field
      0x04: HeaderSize (4 bytes) - size of the header (usually 0x0C)
      0x08: Flags (4 bytes)
      0x0C: ... additional fields depending on flags
    We just need to read LinkInfoSize to know how many bytes to skip.
    """
    if offset + 4 > len(data):
        raise ValueError("Truncated LinkInfo")
    link_info_size = struct.unpack_from('<I', data, offset)[0]
    if link_info_size < 4:
        raise ValueError("Invalid LinkInfo size")
    if offset + link_info_size > len(data):
        raise ValueError("Truncated LinkInfo data")
    return offset + link_info_size

def parse_idlist(data, offset):
    """
    Parse the LinkTargetIDList. It's a variable-length list of PIDLs.
    Each PIDL starts with a 1-byte cb (size of the PIDL including cb) and a 1-byte level.
    Then (cb - 2) bytes of data.
    The list is terminated by a 2-byte 0x0000 (or a cb of 0).
    Actually, the IDList is terminated by a 2-byte value of 0.
    Each entry: 1 byte cb, 1 byte level, then cb-2 bytes.
    The terminator is a 2-byte 0x00 0x00.
    """
    while offset < len(data):
        if offset + 1 > len(data):
            break
        cb = data[offset]
        if cb == 0:
            # Terminator
            if offset + 2 > len(data):
                raise ValueError("Truncated IDList terminator")
            # Check that the next byte is also 0
            if data[offset + 1] != 0:
                # This is unusual but let's just move past the 2 bytes
                offset += 2
                break
            offset += 2
            break
        if cb < 2:
            raise ValueError("Invalid IDList PIDL size")
        if offset + cb > len(data):
            raise ValueError("Truncated IDList PIDL")
        offset += cb
    
    return offset

def main():
    if len(sys.argv) != 2:
        fail("Usage: parser.py <path-to-lnk-file>")
    
    path = sys.argv[1]
    
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        fail(f"Cannot read file: {e}")
    
    # Minimum size is 76 bytes for the header
    if len(data) < 76:
        fail("File too small for ShellLinkHeader")
    
    # Parse header
    header_size = struct.unpack_from('<I', data, 0)[0]
    if header_size != 0x4C:
        fail(f"Invalid HeaderSize: {header_size:#x}, expected 0x4C")
    
    # LinkCLSID - 16 bytes at offset 0x04
    # Must equal 00021401-0000-0000-C000-000000000046
    # In little-endian bytes:
    expected_clsid = bytes([
        0x01, 0x14, 0x02, 0x00,  # 00021401 (little-endian)
        0x00, 0x00,  # 0000
        0x00, 0x00,  # 0000
        0xC0, 0x00,  # C000
        0x00, 0x00, 0x00, 0x00, 0x00, 0x46  # 000000000046
    ])
    actual_clsid = data[0x04:0x14]
    if actual_clsid != expected_clsid:
        fail("Invalid LinkCLSID")
    
    link_flags = struct.unpack_from('<I', data, 0x14)[0]
    file_attributes = struct.unpack_from('<I', data, 0x18)[0]
    
    # Parse times
    try:
        creation_time = parse_filetime(data, 0x1C)
        access_time = parse_filetime(data, 0x24)
        write_time = parse_filetime(data, 0x2C)
    except ValueError as e:
        fail(f"Invalid timestamp: {e}")
    
    file_size = struct.unpack_from('<I', data, 0x34)[0]
    icon_index = struct.unpack_from('<i', data, 0x38)[0]
    show_command = struct.unpack_from('<I', data, 0x3C)[0]
    hotkey = struct.unpack_from('<H', data, 0x40)[0]
    
    # Reserved fields should be zero, but we don't fail on those unless required
    # The spec says "must be zero" for Reserved1, Reserved2, Reserved3
    # Let's check them
    r1 = struct.unpack_from('<H', data, 0x42)[0]
    r2 = struct.unpack_from('<I', data, 0x44)[0]
    r3 = struct.unpack_from('<I', data, 0x48)[0]
    if r1 != 0 or r2 != 0 or r3 != 0:
        fail("Non-zero reserved fields")
    
    # Determine string encoding
    is_unicode = bool(link_flags & 0x00000080)
    
    # Parse the rest of the file
    offset = 76  # 0x4C
    
    # If HasLinkTargetIDList, parse and skip the IDList
    if link_flags & 0x00000001:
        try:
            offset = parse_idlist(data, offset)
        except ValueError as e:
            fail(f"Error parsing IDList: {e}")
    
    # If HasLinkInfo, parse and skip the LinkInfo
    if link_flags & 0x00000002:
        try:
            offset = parse_link_info(data, offset)
        except ValueError as e:
            fail(f"Error parsing LinkInfo: {e}")
    
    # Now parse StringData sections in order:
    # NAME_STRING (0x00000004)
    # RELATIVE_PATH (0x00000008)
    # WORKING_DIR (0x00000010)
    # COMMAND_LINE_ARGUMENTS (0x00000020)
    # ICON_LOCATION (0x00000040)
    
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    # NAME_STRING
    if link_flags & 0x00000004:
        try:
            name_string, offset = parse_string(data, offset, is_unicode)
        except ValueError as e:
            fail(f"Error parsing NAME_STRING: {e}")
    
    # RELATIVE_PATH
    if link_flags & 0x00000008:
        try:
            relative_path, offset = parse_string(data, offset, is_unicode)
        except ValueError as e:
            fail(f"Error parsing RELATIVE_PATH: {e}")
    
    # WORKING_DIR
    if link_flags & 0x00000010:
        try:
            working_dir, offset = parse_string(data, offset, is_unicode)
        except ValueError as e:
            fail(f"Error parsing WORKING_DIR: {e}")
    
    # COMMAND_LINE_ARGUMENTS
    if link_flags & 0x00000020:
        try:
            command_line_arguments, offset = parse_string(data, offset, is_unicode)
        except ValueError as e:
            fail(f"Error parsing COMMAND_LINE_ARGUMENTS: {e}")
    
    # ICON_LOCATION
    if link_flags & 0x00000040:
        try:
            icon_location, offset = parse_string(data, offset, is_unicode)
        except ValueError as e:
            fail(f"Error parsing ICON_LOCATION: {e}")
    
    # After StringData, there may be EXTRA_DATA blocks
    # We don't need to parse them for the output, but we should verify
    # that the file is well-formed. The extra data is terminated by a TerminalBlock:
    # a 32-bit value less than 0x00000004.
    # However, for our purposes, we just need to make sure we haven't gone past the end.
    # If offset > len(data), that's an error.
    if offset > len(data):
        fail("File truncated after StringData")
    
    # Format timestamps as ISO 8601 with UTC offset
    def format_dt(dt):
        if dt is None:
            return None
        # Ensure timezone awareness
        return dt.isoformat()
    
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": format_dt(creation_time),
        "access_time": format_dt(access_time),
        "write_time": format_dt(write_time)
    }
    
    print(json.dumps(result))
    sys.exit(0)

if __name__ == "__main__":
    main()