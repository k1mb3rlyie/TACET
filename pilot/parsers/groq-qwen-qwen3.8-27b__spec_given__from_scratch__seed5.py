import sys
import struct
import json
import os
from datetime import datetime, timedelta, timezone

HEADER_SIZE = 0x4C
LINK_CLSID = bytes.fromhex('0002140100000000c000000000000046')

# LinkFlags bits
FLAG_HAS_LINK_TARGET_ID_LIST = 0x00000001
FLAG_HAS_LINK_INFO = 0x00000002
FLAG_HAS_NAME = 0x00000004
FLAG_HAS_RELATIVE_PATH = 0x00000008
FLAG_HAS_WORKING_DIR = 0x00000010
FLAG_HAS_ARGUMENTS = 0x00000020
FLAG_HAS_ICON_LOCATION = 0x00000040
FLAG_IS_UNICODE = 0x00000080

# FILETIME epoch: 1601-01-01 00:00:00 UTC
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_iso(ft):
    """Convert a FILETIME (100-nanosecond intervals since 1601) to ISO 8601 with UTC offset."""
    if ft == 0:
        return None
    # Convert to seconds and microseconds
    # 100 ns = 1e-7 seconds
    # Python's datetime has microsecond precision (1e-6 seconds)
    # So we need to be careful: 100 ns intervals -> divide by 10 to get microseconds? No.
    # 1 interval = 100 ns = 0.1 microseconds. That's sub-microsecond.
    # But datetime only supports microsecond precision.
    # Let's compute: total microseconds = ft * 0.1
    # Since ft is integer, ft * 0.1 might not be integer.
    # We'll truncate to microseconds for datetime representation.
    
    # The maximum valid FILETIME for datetime:
    # datetime.max is year 9999. Let's just try and catch overflow.
    
    # Convert to seconds and remainder
    total_ns = ft * 100  # nanoseconds
    total_us = total_ns // 1000  # microseconds (truncating)
    
    try:
        dt = FILETIME_EPOCH + timedelta(microseconds=total_us)
        return dt.isoformat()
    except (OverflowError, ValueError, OSError):
        return None


def parse_string_data(data, offset, is_unicode):
    """Parse a StringData structure. Returns (string, new_offset) or raises ValueError."""
    if offset + 2 > len(data):
        raise ValueError("Truncated: cannot read CountCharacters")
    count_chars = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    if is_unicode:
        str_bytes = count_chars * 2
    else:
        str_bytes = count_chars * 1
    
    if offset + str_bytes > len(data):
        raise ValueError("Truncated: cannot read string data")
    
    raw_bytes = data[offset:offset + str_bytes]
    offset += str_bytes
    
    if is_unicode:
        try:
            s = raw_bytes.decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16LE string")
    else:
        try:
            s = raw_bytes.decode('latin-1')
        except UnicodeDecodeError:
            raise ValueError("Invalid string encoding")
    
    return s, offset


def parse_idlist(data, offset):
    """Parse IDList. Returns new_offset."""
    while True:
        if offset + 2 > len(data):
            raise ValueError("Truncated: cannot read IDList size")
        size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if size == 0:
            break
        if offset + size > len(data):
            raise ValueError("Truncated: IDList entry exceeds data")
        offset += size
    return offset


def parse_link_info(data, offset):
    """Parse LinkInfo structure. Returns new_offset."""
    if offset + 4 > len(data):
        raise ValueError("Truncated: cannot read LinkInfo size")
    link_info_size = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    
    if link_info_size == 0:
        raise ValueError("Invalid LinkInfo size")
    
    if offset + link_info_size > len(data):
        raise ValueError("Truncated: LinkInfo exceeds data")
    
    # Just skip the entire LinkInfo structure
    offset += link_info_size
    return offset


def parse_extra_data(data, offset):
    """Parse extra data blocks until TerminalBlock. Returns new_offset or raises."""
    while True:
        if offset + 4 > len(data):
            raise ValueError("Truncated: cannot read extra data block ID")
        block_id = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        
        if block_id < 0x00000004:
            # TerminalBlock
            break
        
        if offset + 4 > len(data):
            raise ValueError("Truncated: cannot read extra data block size")
        block_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        
        if block_size == 0:
            raise ValueError("Invalid extra data block size")
        
        if offset + block_size > len(data):
            raise ValueError("Truncated: extra data block exceeds data")
        
        offset += block_size
    
    return offset


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python parser.py <path-to-lnk-file>"}))
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        if not os.path.isfile(filepath):
            print(json.dumps({"error": "File not found"}))
            sys.exit(1)
        
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(json.dumps({"error": f"Cannot read file: {str(e)}"}))
        sys.exit(1)
    
    try:
        # Check minimum size for header
        if len(data) < HEADER_SIZE:
            print(json.dumps({"error": "File too small for ShellLinkHeader"}))
            sys.exit(1)
        
        # Parse header
        header_size = struct.unpack_from('<I', data, 0x00)[0]
        if header_size != HEADER_SIZE:
            print(json.dumps({"error": f"Invalid HeaderSize: {header_size:#x}, expected {HEADER_SIZE:#x}"}))
            sys.exit(1)
        
        link_clsid = data[0x04:0x14]
        if link_clsid != LINK_CLSID:
            print(json.dumps({"error": "Invalid LinkCLSID"}))
            sys.exit(1)
        
        link_flags = struct.unpack_from('<I', data, 0x14)[0]
        file_attributes = struct.unpack_from('<I', data, 0x18)[0]
        creation_time_ft = struct.unpack_from('<Q', data, 0x1C)[0]
        access_time_ft = struct.unpack_from('<Q', data, 0x24)[0]
        write_time_ft = struct.unpack_from('<Q', data, 0x2C)[0]
        file_size = struct.unpack_from('<I', data, 0x34)[0]  # unsigned
        icon_index = struct.unpack_from('<i', data, 0x38)[0]  # signed
        show_command = struct.unpack_from('<I', data, 0x3C)[0]
        hotkey = struct.unpack_from('<H', data, 0x40)[0]
        reserved1 = struct.unpack_from('<H', data, 0x42)[0]
        reserved2 = struct.unpack_from('<I', data, 0x44)[0]
        reserved3 = struct.unpack_from('<I', data, 0x48)[0]
        
        if reserved1 != 0:
            print(json.dumps({"error": "Reserved1 is not zero"}))
            sys.exit(1)
        if reserved2 != 0:
            print(json.dumps({"error": "Reserved2 is not zero"}))
            sys.exit(1)
        if reserved3 != 0:
            print(json.dumps({"error": "Reserved3 is not zero"}))
            sys.exit(1)
        
        is_unicode = bool(link_flags & FLAG_IS_UNICODE)
        
        offset = HEADER_SIZE
        
        # Parse optional structures before StringData
        if link_flags & FLAG_HAS_LINK_TARGET_ID_LIST:
            offset = parse_idlist(data, offset)
        
        if link_flags & FLAG_HAS_LINK_INFO:
            offset = parse_link_info(data, offset)
        
        # Parse StringData sections in order
        name_string = None
        relative_path = None
        working_dir = None
        command_line_arguments = None
        icon_location = None
        
        if link_flags & FLAG_HAS_NAME:
            name_string, offset = parse_string_data(data, offset, is_unicode)
        
        if link_flags & FLAG_HAS_RELATIVE_PATH:
            relative_path, offset = parse_string_data(data, offset, is_unicode)
        
        if link_flags & FLAG_HAS_WORKING_DIR:
            working_dir, offset = parse_string_data(data, offset, is_unicode)
        
        if link_flags & FLAG_HAS_ARGUMENTS:
            command_line_arguments, offset = parse_string_data(data, offset, is_unicode)
        
        if link_flags & FLAG_HAS_ICON_LOCATION:
            icon_location, offset = parse_string_data(data, offset, is_unicode)
        
        # Parse extra data
        if offset < len(data):
            offset = parse_extra_data(data, offset)
        
        # Convert FILETIMEs to ISO 8601
        creation_time = filetime_to_iso(creation_time_ft)
        access_time = filetime_to_iso(access_time_ft)
        write_time = filetime_to_iso(write_time_ft)
        
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
        
    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {str(e)}"}))
        sys.exit(1)


if __name__ == '__main__':
    main()