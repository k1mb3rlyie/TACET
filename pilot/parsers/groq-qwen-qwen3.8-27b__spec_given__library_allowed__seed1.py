#!/usr/bin/env python3
import sys
import json
import struct
import uuid
from datetime import datetime, timezone, timedelta

# The specified CLSID for a .lnk file
EXPECTED_CLSID = uuid.UUID('00021401-0000-0000-C000-000000000046')


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)


def try_fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)


def parse_filetime(value):
    """Convert a FILETIME (100ns intervals since 1601-01-01 UTC) to an ISO 8601 string with UTC offset.
    Returns None if the value is invalid (0 or out of reasonable range).
    """
    if value == 0:
        return None
    
    # FILETIME is 100-nanosecond intervals since 1601-01-01 00:00:00 UTC
    # Convert to seconds and nanoseconds
    total_100ns = value
    seconds = total_100ns // 10_000_000
    remainder_100ns = total_100ns % 10_000_000
    
    # The epoch for Python's datetime is 1970-01-01. 
    # 1601-01-01 to 1970-01-01 is a known offset in seconds.
    # Number of days between 1601-01-01 and 1970-01-01:
    # From 1601 to 1970 is 369 years.
    # Let's compute it precisely or use a known constant.
    # Known: 11644473600 seconds between 1601-01-01 and 1970-01-01.
    EPOCH_1601_TO_1970_SECONDS = 11644473600
    
    unix_seconds = seconds - EPOCH_1601_TO_1970_SECONDS
    
    # Check if this is a reasonable date
    # FILETIME can represent dates from 1601 to 3000 AD roughly
    # Let's check if unix_seconds is within a reasonable range
    # Min: 1601-01-01 -> -11644473600
    # Max: ~3000-01-01 -> around 32503680000
    if unix_seconds < -11644473600 or unix_seconds > 32503680000:
        return None
    
    # Create datetime in UTC
    try:
        # Python's datetime supports microseconds, so we convert 100ns remainder to microseconds
        # 100ns = 0.1 microseconds, so we need to round
        remainder_microseconds = int(remainder_100ns * 0.1)
        # Clamp to valid range for microseconds (0-999999)
        if remainder_microseconds >= 1000000:
            unix_seconds += 1
            remainder_microseconds -= 1000000
        
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        # Add microseconds
        dt = dt.replace(microsecond=remainder_microseconds)
        return dt.isoformat()
    except (OSError, ValueError, OverflowError):
        return None


def parse_idlist(data, offset):
    """Parse an IDList (ShellLinkItemIDListData). Returns the new offset after the IDList.
    The IDList consists of one or more IDList entries, each with:
      - 2 bytes: size of the item ID (in bytes)
      - size bytes of item ID
      Terminated by a 2-byte value of 0.
    """
    start = offset
    while offset + 2 <= len(data):
        item_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if item_size == 0:
            # Terminal entry
            return offset
        if offset + item_size > len(data):
            raise ValueError("Truncated IDList")
        offset += item_size
    
    # If we run out of data without hitting the terminal, it's malformed
    raise ValueError("Malformed IDList: missing terminal entry")


def parse_linkinfo(data, offset):
    """Parse a LinkInfo structure. Returns the new offset after LinkInfo.
    LinkInfo structure:
    - 4 bytes: LinkInfoSize (total size including this field)
    - 4 bytes: LinkInfoFlags
    - 12 bytes: Hotkey (if flag set)
    - 4 bytes: ShowCmd (if flag set)
    - 4 bytes: Reserved (if flag set)
    - 4 bytes: RelativePathOffset
    - 4 bytes: CommonNetworkRelPathOffset
    - 4 bytes: IconLocationOffset
    - 4 bytes: IconFileOffset
    - 4 bytes: NameOffset
    - 4 bytes: Name
    - Then variable length data at the specified offsets
    
    For our purposes, we just need to advance past the LinkInfo structure.
    The LinkInfoSize tells us the total size.
    """
    if offset + 4 > len(data):
        raise ValueError("Truncated LinkInfo")
    
    linkinfo_size = struct.unpack_from('<I', data, offset)[0]
    if linkinfo_size < 4:
        raise ValueError("Invalid LinkInfo size")
    
    # The LinkInfoSize includes the first 4 bytes
    if offset + linkinfo_size > len(data):
        raise ValueError("LinkInfo extends beyond file")
    
    return offset + linkinfo_size


def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        fail(f"Cannot read file: {e}")
    
    # Minimum size for header
    if len(data) < 0x4C:
        fail("File too small to contain ShellLinkHeader")
    
    # Parse ShellLinkHeader
    try:
        header_size = struct.unpack_from('<I', data, 0x00)[0]
        if header_size != 0x4C:
            fail(f"Invalid HeaderSize: expected 0x4C, got 0x{header_size:08X}")
        
        # Parse CLSID
        clsid_bytes = data[0x04:0x14]
        try:
            clsid = uuid.UUID(bytes=clsid_bytes, little_endian=True)
        except Exception:
            fail("Invalid CLSID")
        
        if clsid != EXPECTED_CLSID:
            fail(f"Invalid CLSID: expected {EXPECTED_CLSID}, got {clsid}")
        
        link_flags = struct.unpack_from('<I', data, 0x14)[0]
        file_attributes = struct.unpack_from('<I', data, 0x18)[0]
        creation_time = struct.unpack_from('<Q', data, 0x1C)[0]
        access_time = struct.unpack_from('<Q', data, 0x24)[0]
        write_time = struct.unpack_from('<Q', data, 0x2C)[0]
        file_size = struct.unpack_from('<I', data, 0x34)[0]  # unsigned
        icon_index = struct.unpack_from('<i', data, 0x38)[0]  # signed
        show_command = struct.unpack_from('<I', data, 0x3C)[0]
        hotkey = struct.unpack_from('<H', data, 0x40)[0]
        reserved1 = struct.unpack_from('<H', data, 0x42)[0]
        reserved2 = struct.unpack_from('<I', data, 0x44)[0]
        reserved3 = struct.unpack_from('<I', data, 0x48)[0]
        
        # Check reserved fields
        if reserved1 != 0:
            fail("Reserved1 is not zero")
        if reserved2 != 0:
            fail("Reserved2 is not zero")
        if reserved3 != 0:
            fail("Reserved3 is not zero")
        
    except struct.error as e:
        fail(f"Error parsing header: {e}")
    
    # Determine which string sections are present
    has_link_target_id_list = bool(link_flags & 0x00000001)
    has_link_info = bool(link_flags & 0x00000002)
    has_name = bool(link_flags & 0x00000004)
    has_relative_path = bool(link_flags & 0x00000008)
    has_working_dir = bool(link_flags & 0x00000010)
    has_arguments = bool(link_flags & 0x00000020)
    has_icon_location = bool(link_flags & 0x00000040)
    is_unicode = bool(link_flags & 0x00000080)
    
    offset = 0x4C  # After the header
    
    # Parse IDList if present
    if has_link_target_id_list:
        try:
            offset = parse_idlist(data, offset)
        except ValueError as e:
            fail(f"Error parsing IDList: {e}")
    
    # Parse LinkInfo if present
    if has_link_info:
        try:
            offset = parse_linkinfo(data, offset)
        except ValueError as e:
            fail(f"Error parsing LinkInfo: {e}")
    
    # Parse StringData sections in order:
    # NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
    # Only sections whose flag is set are present
    
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    try:
        # NAME_STRING
        if has_name:
            if offset + 2 > len(data):
                fail("Truncated: cannot read NAME_STRING count")
            count_chars = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if is_unicode:
                byte_len = count_chars * 2
            else:
                byte_len = count_chars
            if offset + byte_len > len(data):
                fail("Truncated: NAME_STRING extends beyond file")
            raw = data[offset:offset + byte_len]
            offset += byte_len
            if is_unicode:
                name_string = raw.decode('utf-16-le', errors='strict')
            else:
                name_string = raw.decode('cp1252', errors='strict')
        
        # RELATIVE_PATH
        if has_relative_path:
            if offset + 2 > len(data):
                fail("Truncated: cannot read RELATIVE_PATH count")
            count_chars = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if is_unicode:
                byte_len = count_chars * 2
            else:
                byte_len = count_chars
            if offset + byte_len > len(data):
                fail("Truncated: RELATIVE_PATH extends beyond file")
            raw = data[offset:offset + byte_len]
            offset += byte_len
            if is_unicode:
                relative_path = raw.decode('utf-16-le', errors='strict')
            else:
                relative_path = raw.decode('cp1252', errors='strict')
        
        # WORKING_DIR
        if has_working_dir:
            if offset + 2 > len(data):
                fail("Truncated: cannot read WORKING_DIR count")
            count_chars = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if is_unicode:
                byte_len = count_chars * 2
            else:
                byte_len = count_chars
            if offset + byte_len > len(data):
                fail("Truncated: WORKING_DIR extends beyond file")
            raw = data[offset:offset + byte_len]
            offset += byte_len
            if is_unicode:
                working_dir = raw.decode('utf-16-le', errors='strict')
            else:
                working_dir = raw.decode('cp1252', errors='strict')
        
        # COMMAND_LINE_ARGUMENTS
        if has_arguments:
            if offset + 2 > len(data):
                fail("Truncated: cannot read COMMAND_LINE_ARGUMENTS count")
            count_chars = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if is_unicode:
                byte_len = count_chars * 2
            else:
                byte_len = count_chars
            if offset + byte_len > len(data):
                fail("Truncated: COMMAND_LINE_ARGUMENTS extends beyond file")
            raw = data[offset:offset + byte_len]
            offset += byte_len
            if is_unicode:
                command_line_arguments = raw.decode('utf-16-le', errors='strict')
            else:
                command_line_arguments = raw.decode('cp1252', errors='strict')
        
        # ICON_LOCATION
        if has_icon_location:
            if offset + 2 > len(data):
                fail("Truncated: cannot read ICON_LOCATION count")
            count_chars = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if is_unicode:
                byte_len = count_chars * 2
            else:
                byte_len = count_chars
            if offset + byte_len > len(data):
                fail("Truncated: ICON_LOCATION extends beyond file")
            raw = data[offset:offset + byte_len]
            offset += byte_len
            if is_unicode:
                icon_location = raw.decode('utf-16-le', errors='strict')
            else:
                icon_location = raw.decode('cp1252', errors='strict')
    
    except (UnicodeDecodeError, struct.error) as e:
        fail(f"Error parsing string data: {e}")
    
    # Now we should be at the EXTRA_DATA section
    # The EXTRA_DATA section consists of blocks, terminated by a TerminalBlock:
    # a 32-bit value less than 0x00000004.
    # We don't need to parse the extra data blocks for the output, but we should
    # verify that the file ends properly with a terminal block.
    
    if offset + 4 > len(data):
        # No space for extra data terminal block - this might be okay if there's no extra data
        # But per spec, there should be a terminal block. Let's check if offset == len(data)
        if offset == len(data):
            # No extra data at all, which might be acceptable, but let's be strict
            # Actually, the spec says the file ends with extra data blocks terminated by TerminalBlock.
            # If there's no extra data, there should still be a terminal block (value < 4).
            fail("Missing EXTRA_DATA terminal block")
        else:
            fail("Truncated: cannot read EXTRA_DATA")
    
    # Check for terminal block
    terminal_block = struct.unpack_from('<I', data, offset)[0]
    if terminal_block >= 0x00000004:
        # Not a terminal block, so there might be extra data blocks we need to skip
        # Let's try to skip through extra data blocks
        current_offset = offset
        while current_offset + 4 <= len(data):
            block_id = struct.unpack_from('<I', data, current_offset)[0]
            if block_id < 0x00000004:
                # Terminal block found
                break
            if current_offset + 8 > len(data):
                fail("Truncated: cannot read extra data block size")
            block_size = struct.unpack_from('<I', data, current_offset + 4)[0]
            if block_size < 8:
                fail("Invalid extra data block size")
            current_offset += block_size
        else:
            fail("No terminal block found in EXTRA_DATA")
        
        if current_offset + 4 > len(data):
            fail("Truncated: cannot read terminal block")
        
        terminal_block = struct.unpack_from('<I', data, current_offset)[0]
        if terminal_block >= 0x00000004:
            fail("No terminal block found in EXTRA_DATA")
    
    # Convert timestamps
    creation_time_iso = parse_filetime(creation_time)
    access_time_iso = parse_filetime(access_time)
    write_time_iso = parse_filetime(write_time)
    
    # Build output
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


if __name__ == '__main__':
    main()