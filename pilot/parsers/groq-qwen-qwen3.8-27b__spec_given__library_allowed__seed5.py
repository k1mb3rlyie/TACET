#!/usr/bin/env python3
"""Parse a Windows Shortcut (.lnk) file and extract metadata per MS-SHLLINK."""

import sys
import json
import struct
from datetime import datetime, timezone, timedelta

# Constants
HEADER_SIZE = 0x4C
EXPECTED_CLSID = bytes.fromhex('0002140100000000C000000000000046')

# LinkFlags bits
LF_HAS_LINK_TARGET_ID_LIST = 0x00000001
LF_HAS_LINK_INFO = 0x00000002
LF_HAS_NAME = 0x00000004
LF_HAS_RELATIVE_PATH = 0x00000008
LF_HAS_WORKING_DIR = 0x00000010
LF_HAS_ARGUMENTS = 0x00000020
LF_HAS_ICON_LOCATION = 0x00000040
LF_IS_UNICODE = 0x00000080

# FILETIME constants
FILETIME_EPOCH_DELTA = datetime(1601, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def filetime_to_iso8601(ft_value):
    """Convert a 64-bit FILETIME value to an ISO 8601 string with UTC offset.
    
    Returns None if the value is not representable.
    """
    if ft_value < 0:
        return None
    # 100-nanosecond intervals since 1601-01-01
    try:
        dt = FILETIME_EPOCH_DELTA + timedelta(microseconds=(ft_value // 10))
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def parse_lnk(data):
    """Parse LNK file data and return a dict of fields or raise ValueError."""
    if len(data) < HEADER_SIZE:
        raise ValueError("File too short to contain ShellLinkHeader")

    # Parse header fields
    header_size = struct.unpack_from('<I', data, 0x00)[0]
    if header_size != HEADER_SIZE:
        raise ValueError(f"Invalid HeaderSize: {header_size:#x}, expected {HEADER_SIZE:#x}")

    link_clsid = data[0x04:0x14]
    if link_clsid != EXPECTED_CLSID:
        raise ValueError("Invalid LinkCLSID")

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

    # Check reserved fields are zero
    if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
        raise ValueError("Reserved fields are non-zero")

    # Convert timestamps
    creation_iso = filetime_to_iso8601(creation_time)
    access_iso = filetime_to_iso8601(access_time)
    write_iso = filetime_to_iso8601(write_time)

    if creation_iso is None:
        raise ValueError("CreationTime is not representable")
    if access_iso is None:
        raise ValueError("AccessTime is not representable")
    if write_iso is None:
        raise ValueError("WriteTime is not representable")

    is_unicode = bool(link_flags & LF_IS_UNICODE)
    char_size = 2 if is_unicode else 1

    offset = HEADER_SIZE

    # Skip LinkTargetIDList if present
    if link_flags & LF_HAS_LINK_TARGET_ID_LIST:
        if offset + 2 > len(data):
            raise ValueError("Truncated: cannot read IDList size")
        id_list_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2 + id_list_size
        if offset > len(data):
            raise ValueError("Truncated: IDList extends beyond file")

    # Skip LinkInfo if present
    if link_flags & LF_HAS_LINK_INFO:
        if offset + 4 > len(data):
            raise ValueError("Truncated: cannot read LinkInfo size")
        link_info_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4 + link_info_size
        if offset > len(data):
            raise ValueError("Truncated: LinkInfo extends beyond file")

    # Helper to read a StringData section
    def read_string_data():
        nonlocal offset
        if offset + 2 > len(data):
            raise ValueError("Truncated: cannot read string character count")
        count_chars = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        byte_len = count_chars * char_size
        if offset + byte_len > len(data):
            raise ValueError(f"Truncated: string data extends beyond file")
        raw = data[offset:offset + byte_len]
        offset += byte_len
        if is_unicode:
            try:
                return raw.decode('utf-16-le')
            except UnicodeDecodeError:
                raise ValueError("Invalid UTF-16LE encoding in string")
        else:
            # For non-Unicode, we'll use latin-1 to avoid decode errors,
            # but this is a best-effort for legacy strings
            return raw.decode('latin-1')

    # Parse StringData sections in order
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if link_flags & LF_HAS_NAME:
        name_string = read_string_data()
    if link_flags & LF_HAS_RELATIVE_PATH:
        relative_path = read_string_data()
    if link_flags & LF_HAS_WORKING_DIR:
        working_dir = read_string_data()
    if link_flags & LF_HAS_ARGUMENTS:
        command_line_arguments = read_string_data()
    if link_flags & LF_HAS_ICON_LOCATION:
        icon_location = read_string_data()

    # Parse EXTRA_DATA blocks
    # Extra data blocks: each starts with a 16-bit signature, 16-bit size, data
    # Terminated by a 32-bit value < 0x00000004
    while offset < len(data):
        if offset + 4 > len(data):
            # Check if remaining bytes form a terminal block
            if len(data) - offset == 4:
                term_val = struct.unpack_from('<I', data, offset)[0]
                if term_val < 0x00000004:
                    break
            raise ValueError("Truncated: cannot read extra data terminal block")
        
        term_val = struct.unpack_from('<I', data, offset)[0]
        if term_val < 0x00000004:
            break
        
        # This is an extra data block
        if offset + 4 > len(data):
            raise ValueError("Truncated: cannot read extra data block header")
        # The first 16 bits are signature, next 16 bits are header size
        sig = term_val & 0xFFFF
        header_size = (term_val >> 16) & 0xFFFF
        
        if header_size < 4:
            raise ValueError("Invalid extra data block header size")
        
        # Read the full block header
        if offset + header_size > len(data):
            raise ValueError("Truncated: extra data block header extends beyond file")
        
        # The data size is in the first 16 bits of the data portion (after the 4-byte header)
        if offset + 4 + 2 > len(data):
            raise ValueError("Truncated: cannot read extra data block data size")
        data_size = struct.unpack_from('<H', data, offset + 4)[0]
        
        total_block_size = header_size + data_size
        if offset + total_block_size > len(data):
            raise ValueError("Truncated: extra data block extends beyond file")
        
        offset += total_block_size
    
    return {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_iso,
        "access_time": access_iso,
        "write_time": write_iso,
    }


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python parser.py <path-to-lnk-file>"}))
        sys.exit(1)

    path = sys.argv[1]

    try:
        with open(path, 'rb') as f:
            data = f.read()
    except (IOError, OSError) as e:
        print(json.dumps({"error": f"Cannot read file: {e}"}))
        sys.exit(1)

    try:
        result = parse_lnk(data)
    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": f"Parse error: {e}"}))
        sys.exit(0)

    print(json.dumps(result))
    sys.exit(0)


if __name__ == '__main__':
    main()