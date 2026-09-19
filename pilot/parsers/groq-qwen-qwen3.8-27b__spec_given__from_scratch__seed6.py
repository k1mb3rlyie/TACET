#!/usr/bin/env python3
import struct
import sys
import json
import datetime

def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)

def parse_filetime(value):
    """Parse a FILETIME (100-nanosecond intervals since 1601-01-01 UTC) to ISO 8601 string."""
    if value == 0:
        return "1601-01-01T00:00:00+00:00"
    # Max representable: 3000-01-01T00:00:00+00:00
    # FILETIME max is 0x7FFFFFFFFFFFFFFF
    if value > 0x7FFFFFFFFFFFFFFF:
        return None
    # Convert to seconds and microseconds
    total_seconds = value / 10000000.0
    # Use datetime arithmetic from epoch 1601
    epoch = datetime.datetime(1601, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    try:
        dt = epoch + datetime.timedelta(microseconds=int(value))
        # Ensure it's within valid range
        if dt.year < 1601 or dt.year > 3000:
            return None
        return dt.isoformat()
    except (OverflowError, ValueError, OSError):
        return None

def read_string(data, offset, is_unicode, max_len):
    """Read a StringData section. Returns (string, new_offset) or raises ValueError."""
    if offset + 2 > len(data):
        raise ValueError("Truncated: cannot read string length")
    count_chars = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    if is_unicode:
        byte_len = count_chars * 2
    else:
        byte_len = count_chars
    
    if offset + byte_len > len(data):
        raise ValueError("Truncated: string data exceeds file")
    
    raw = data[offset:offset + byte_len]
    offset += byte_len
    
    if is_unicode:
        s = raw.decode('utf-16-le', errors='strict')
    else:
        s = raw.decode('cp1252', errors='strict')
    
    return s, offset

def read_idlist(data, offset):
    """Skip the IDList structure. Returns new offset."""
    if offset + 2 > len(data):
        raise ValueError("Truncated: cannot read IDList length")
    idlist_len = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    if idlist_len < 2 or idlist_len % 2 != 0:
        raise ValueError("Invalid IDList length")
    
    if offset + idlist_len > len(data):
        raise ValueError("Truncated: IDList data exceeds file")
    
    offset += idlist_len
    return offset

def read_linkinfo(data, offset):
    """Skip the LinkInfo structure. Returns new offset."""
    if offset + 4 > len(data):
        raise ValueError("Truncated: cannot read LinkInfo size")
    linkinfo_size = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    
    if linkinfo_size < 4:
        raise ValueError("Invalid LinkInfo size")
    
    if offset + (linkinfo_size - 4) > len(data):
        raise ValueError("Truncated: LinkInfo data exceeds file")
    
    offset += (linkinfo_size - 4)
    return offset

def main():
    if len(sys.argv) != 2:
        fail("Usage: parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except (IOError, OSError) as e:
        fail(f"Cannot read file: {e}")
    
    # Minimum size for header
    if len(data) < 0x4C:
        fail("File too small for ShellLinkHeader")
    
    # Parse ShellLinkHeader
    header_size = struct.unpack_from('<I', data, 0)[0]
    if header_size != 0x4C:
        fail(f"Invalid HeaderSize: {header_size:#x}, expected 0x4C")
    
    # Check CLSID
    expected_clsid = bytes([
        0x00, 0x02, 0x14, 0x01,  # first part (little endian)
        0x00, 0x00,  # second part
        0x00, 0x00,  # third part
        0xC0, 0x00,  # fourth part (first two bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x46  # rest
    ])
    
    actual_clsid = data[4:20]
    # CLSID is stored in mixed-endian format in the LNK file
    # The standard representation: 00021401-0000-0000-C000-000000000046
    # In the file, the first 4 bytes are little-endian, next 2 bytes little-endian,
    # next 2 bytes little-endian, remaining 8 bytes big-endian
    # Let's verify by comparing with expected bytes
    # Actually, the CLSID in the file is stored as:
    # Data1 (4 bytes LE), Data2 (2 bytes LE), Data3 (2 bytes LE), Data4 (8 bytes BE)
    # 00021401 -> LE bytes: 01 14 02 00
    # 0000 -> LE bytes: 00 00
    # 0000 -> LE bytes: 00 00
    # C000-000000000046 -> BE bytes: C0 00 00 00 00 00 00 46
    expected_bytes = bytes([
        0x01, 0x14, 0x02, 0x00,  # Data1 LE
        0x00, 0x00,  # Data2 LE
        0x00, 0x00,  # Data3 LE
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46  # Data4 BE
    ])
    
    if actual_clsid != expected_bytes:
        fail("Invalid LinkCLSID")
    
    link_flags = struct.unpack_from('<I', data, 0x14)[0]
    file_attributes = struct.unpack_from('<I', data, 0x18)[0]
    creation_time_raw = struct.unpack_from('<Q', data, 0x1C)[0]
    access_time_raw = struct.unpack_from('<Q', data, 0x24)[0]
    write_time_raw = struct.unpack_from('<Q', data, 0x2C)[0]
    file_size = struct.unpack_from('<I', data, 0x34)[0]  # unsigned
    icon_index = struct.unpack_from('<i', data, 0x38)[0]  # signed
    show_command = struct.unpack_from('<I', data, 0x3C)[0]
    hot_key = struct.unpack_from('<H', data, 0x40)[0]
    reserved1 = struct.unpack_from('<H', data, 0x42)[0]
    reserved2 = struct.unpack_from('<I', data, 0x44)[0]
    reserved3 = struct.unpack_from('<I', data, 0x48)[0]
    
    # Check reserved fields
    if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
        fail("Reserved fields are not zero")
    
    # Parse timestamps
    creation_time = parse_filetime(creation_time_raw)
    access_time = parse_filetime(access_time_raw)
    write_time = parse_filetime(write_time_raw)
    
    if creation_time is None:
        fail("Invalid creation time")
    if access_time is None:
        fail("Invalid access time")
    if write_time is None:
        fail("Invalid write time")
    
    # Determine string encoding
    is_unicode = bool(link_flags & 0x00000080)
    
    # Skip IDList if present
    offset = 0x4C
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        offset = read_idlist(data, offset)
    
    # Skip LinkInfo if present
    if link_flags & 0x00000002:  # HasLinkInfo
        offset = read_linkinfo(data, offset)
    
    # Parse StringData sections in order
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    if link_flags & 0x00000004:  # HasName
        name_string, offset = read_string(data, offset, is_unicode, 0)
    
    if link_flags & 0x00000008:  # HasRelativePath
        relative_path, offset = read_string(data, offset, is_unicode, 0)
    
    if link_flags & 0x00000010:  # HasWorkingDir
        working_dir, offset = read_string(data, offset, is_unicode, 0)
    
    if link_flags & 0x00000020:  # HasArguments
        command_line_arguments, offset = read_string(data, offset, is_unicode, 0)
    
    if link_flags & 0x00000040:  # HasIconLocation
        icon_location, offset = read_string(data, offset, is_unicode, 0)
    
    # After StringData, there should be EXTRA_DATA blocks terminated by TerminalBlock
    # We don't need to parse them for the output, but we should verify the file structure
    # is valid. The spec says the file ends with extra data blocks.
    # We'll just check that we haven't read past the end, which is already handled above.
    
    # Build output
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
    try:
        main()
    except ValueError as e:
        fail(str(e))
    except Exception as e:
        fail(f"Unexpected error: {e}")