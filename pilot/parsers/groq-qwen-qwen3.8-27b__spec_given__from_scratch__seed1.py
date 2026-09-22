import sys
import json
import struct
import os
from datetime import datetime, timezone

def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)

def parse_filetime(val):
    """Convert FILETIME (100ns intervals since 1601-01-01 UTC) to ISO 8601 with UTC offset."""
    if val == 0:
        return "1601-01-01T00:00:00+00:00"
    # Convert to seconds since epoch
    # 1601-01-01 to 1970-01-01 is 11644473600 seconds
    seconds_since_1601 = val / 10000000.0
    seconds_since_1970 = seconds_since_1601 - 11644473600.0
    
    try:
        dt = datetime.fromtimestamp(seconds_since_1970, tz=timezone.utc)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        raise ValueError("Invalid FILETIME value")

def parse_string(data, offset, is_unicode):
    """Parse a StringData section. Returns (string, new_offset) or raises."""
    if offset + 2 > len(data):
        raise ValueError("Truncated: not enough bytes for CountCharacters")
    
    count_chars = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    char_size = 2 if is_unicode else 1
    byte_len = count_chars * char_size
    
    if offset + byte_len > len(data):
        raise ValueError("Truncated: not enough bytes for string data")
    
    raw = data[offset:offset + byte_len]
    offset += byte_len
    
    if is_unicode:
        try:
            s = raw.decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16 string")
    else:
        try:
            s = raw.decode('latin-1')
        except UnicodeDecodeError:
            raise ValueError("Invalid string")
    
    return s, offset

def main():
    if len(sys.argv) != 2:
        fail("Usage: parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    if not os.path.isfile(filepath):
        fail(f"File not found: {filepath}")
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        fail(f"Cannot read file: {e}")
    
    # Check minimum size for header
    if len(data) < 0x4C:
        fail("File too small for ShellLinkHeader")
    
    # Parse header
    header_size = struct.unpack_from('<I', data, 0x00)[0]
    if header_size != 0x4C:
        fail(f"Invalid HeaderSize: expected 0x4C, got 0x{header_size:X}")
    
    link_clsid = data[0x04:0x14]
    expected_clsid = bytes([
        0x00, 0x02, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    ])
    if link_clsid != expected_clsid:
        fail("Invalid LinkCLSID")
    
    link_flags = struct.unpack_from('<I', data, 0x14)[0]
    file_attributes = struct.unpack_from('<I', data, 0x18)[0]
    creation_time = struct.unpack_from('<Q', data, 0x1C)[0]
    access_time = struct.unpack_from('<Q', data, 0x24)[0]
    write_time = struct.unpack_from('<Q', data, 0x2C)[0]
    file_size = struct.unpack_from('<I', data, 0x34)[0]
    icon_index = struct.unpack_from('<i', data, 0x38)[0]
    show_command = struct.unpack_from('<I', data, 0x3C)[0]
    hot_key = struct.unpack_from('<H', data, 0x40)[0]
    reserved1 = struct.unpack_from('<H', data, 0x42)[0]
    reserved2 = struct.unpack_from('<I', data, 0x44)[0]
    reserved3 = struct.unpack_from('<I', data, 0x48)[0]
    
    # Reserved fields must be zero
    if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
        fail("Reserved fields are not zero")
    
    is_unicode = bool(link_flags & 0x00000080)
    
    # Determine which string sections are present
    has_name = bool(link_flags & 0x00000004)
    has_relative_path = bool(link_flags & 0x00000008)
    has_working_dir = bool(link_flags & 0x00000010)
    has_arguments = bool(link_flags & 0x00000020)
    has_icon_location = bool(link_flags & 0x00000040)
    has_idlist = bool(link_flags & 0x00000001)
    has_linkinfo = bool(link_flags & 0x00000002)
    
    # Parse IDList if present
    offset = 0x4C
    if has_idlist:
        # IDList: sequence of IDListEntries, terminated by two zero bytes
        # Each entry: 2-byte length (including the 2 bytes), then that many bytes
        while True:
            if offset + 2 > len(data):
                fail("Truncated: not enough bytes for IDList entry length")
            entry_len = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if entry_len == 0:
                break
            if offset + entry_len > len(data):
                fail("Truncated: not enough bytes for IDList entry")
            offset += entry_len
    
    # Parse LinkInfo if present
    if has_linkinfo:
        if offset + 4 > len(data):
            fail("Truncated: not enough bytes for LinkInfo size")
        linkinfo_size = struct.unpack_from('<I', data, offset)[0]
        if offset + linkinfo_size > len(data):
            fail("Truncated: LinkInfo extends beyond file")
        offset += linkinfo_size
    
    # Parse StringData sections
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    try:
        if has_name:
            name_string, offset = parse_string(data, offset, is_unicode)
        if has_relative_path:
            relative_path, offset = parse_string(data, offset, is_unicode)
        if has_working_dir:
            working_dir, offset = parse_string(data, offset, is_unicode)
        if has_arguments:
            command_line_arguments, offset = parse_string(data, offset, is_unicode)
        if has_icon_location:
            icon_location, offset = parse_string(data, offset, is_unicode)
    except ValueError as e:
        fail(str(e))
    
    # Parse timestamps
    try:
        creation_time_iso = parse_filetime(creation_time)
    except ValueError:
        fail("Invalid creation time")
    
    try:
        access_time_iso = parse_filetime(access_time)
    except ValueError:
        fail("Invalid access time")
    
    try:
        write_time_iso = parse_filetime(write_time)
    except ValueError:
        fail("Invalid write time")
    
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