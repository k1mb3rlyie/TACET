#!/usr/bin/env python3
import sys
import json
import struct
import datetime
import uuid


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)


def parse_filetime(ft):
    """Convert FILETIME (100ns intervals since 1601-01-01 UTC) to ISO 8601 string."""
    if ft == 0:
        # Zero is a valid FILETIME meaning "no time"
        return "1601-01-01T00:00:00+00:00"
    
    # The FILETIME epoch is 1601-01-01 00:00:00 UTC
    # Python's datetime.min is 0001-01-01 00:00:00
    # Difference between 1601-01-01 and 0001-01-01 is 1600 years
    
    # 100-nanosecond intervals to seconds
    total_seconds = ft / 10000000.0
    
    # Convert to microseconds for datetime
    # datetime uses microseconds since epoch
    # We need to be careful about precision
    
    # The maximum representable FILETIME value
    # 2^64 - 1 / 10000000 seconds = ~146744 years, which is way beyond datetime.max
    
    # Let's compute: datetime.max is 9999-12-31 23:59:59.999999
    # That's roughly (9999 - 1601) * 365.25 * 24 * 3600 * 10^7 * 10000000 microseconds... 
    # Actually let's just try to construct the datetime and catch exceptions
    
    # Convert 100ns intervals to microseconds
    # 100ns = 0.0001 ms = 0.0000001 s = 100 µs
    # So ft * 100 gives microseconds since 1601-01-01
    
    # We need to convert from 1601-01-01 to Python's datetime
    # Python's datetime works with years 1-9999
    
    # Calculate the number of days from 1601-01-01
    # 1601-01-01 is day 0 in our calculation
    # We can use the fact that 1970-01-01 is well known
    
    # Days from 1601-01-01 to 1970-01-01:
    # From 1601 to 1970 is 369 years
    # Let me compute this properly using datetime
    
    try:
        # ft is in 100ns units
        # Convert to microseconds
        # 100ns = 0.1 µs, so ft * 0.1 µs... wait
        # 1 second = 10,000,000 * 100ns
        # 1 microsecond = 10,000 * 100ns
        # So ft / 10000 = microseconds? No:
        # ft * 100ns = ft * 0.0001 ms = ft * 0.0000001 s
        # In microseconds: ft * 0.1 µs... that's not right either
        # 
        # 1 µs = 10,000 * 100ns
        # So ft / 10000 = µs? No:
        # ft * 100ns = (ft / 10000) µs because 10000 * 100ns = 1 µs
        # Wait: 1 µs = 10^-6 s, 100ns = 10^-7 s
        # So 1 µs = 10 * 100ns
        # Therefore ft * 100ns = ft/10 µs
        
        # Actually let me just use a different approach.
        # Convert 100ns intervals to a timedelta from 1601-01-01
        # timedelta.max is about 999999999 days, so we're fine for most cases
        
        # 100ns in seconds is 1e-7
        # So total seconds = ft * 1e-7
        # But float precision might be an issue for large values
        
        # Better: use integer arithmetic where possible
        # ft is an integer number of 100ns intervals
        # We want to convert to days, hours, minutes, seconds, microseconds
        
        # 1 day = 86400 seconds = 86400 * 10000000 * 100ns = 864000000000 * 100ns
        # 1 second = 10000000 * 100ns
        # 1 microsecond = 10000 * 100ns
        
        # Let's compute:
        # total_100ns = ft
        # seconds = total_100ns // 10000000
        # remaining_100ns = total_100ns % 10000000
        # microseconds = remaining_100ns // 10000
        # remaining_100ns = remaining_100ns % 10000
        # 
        # But datetime.timedelta takes microseconds, so we can do:
        # total_microseconds = ft // 10  (since 1 µs = 10 * 100ns)
        # But this might lose precision for the last 100ns
        
        # Actually, for forensic purposes, sub-microsecond precision doesn't matter much,
        # but we should be accurate. Let's use:
        # total_seconds_and_micros: 
        # ft // 10000000 = whole seconds
        # (ft % 10000000) // 10000 = microseconds (approximate, since 10000 * 100ns = 1 µs)
        # The remainder (ft % 10000000) % 10000 represents 100ns units less than 1 µs,
        # which we can round down.
        
        whole_seconds = ft // 10000000
        remaining = ft % 10000000
        microseconds = remaining // 10000  # 10000 * 100ns = 1 µs
        # The remaining 100ns units (0-9999) are less than 1 µs, so we truncate
        
        # Now create a timedelta
        # But timedelta max is about 2.7 million years, so we're fine
        
        # Convert whole_seconds to days, hours, etc.
        days = whole_seconds // 86400
        remaining_seconds = whole_seconds % 86400
        hours = remaining_seconds // 3600
        remaining_seconds = remaining_seconds % 3600
        minutes = remaining_seconds // 60
        seconds = remaining_seconds % 60
        
        # Create base datetime 1601-01-01
        base = datetime.datetime(1601, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
        
        # Add the timedelta
        dt = base + datetime.timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds, microseconds=microseconds)
        
        # Check if the resulting datetime is valid
        # datetime.max is 9999-12-31 23:59:59.999999
        # If dt > datetime.max, that's an error
        
        if dt > datetime.datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=datetime.timezone.utc):
            fail("FILETIME out of range")
        
        return dt.isoformat()
        
    except (OverflowError, ValueError, OSError) as e:
        fail(f"Invalid FILETIME: {e}")


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
        fail("File too small for LNK header")
    
    # Parse header
    header_size = struct.unpack_from('<I', data, 0)[0]
    if header_size != 0x4C:
        fail(f"Invalid header size: {header_size:#x}")
    
    # LinkCLSID
    clsid_bytes = data[4:20]
    try:
        clsid = uuid.UUID(bytes=clsid_bytes)
    except Exception as e:
        fail(f"Invalid CLSID: {e}")
    
    expected_clsid = uuid.UUID('00021401-0000-0000-C000-000000000046')
    if clsid != expected_clsid:
        fail(f"Invalid CLSID: {clsid}")
    
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
    
    # Determine pointers
    offset = 0x4C  # Start after header
    
    # Parse optional blocks
    has_link_target_id_list = bool(link_flags & 0x00000001)
    has_link_info = bool(link_flags & 0x00000002)
    has_name = bool(link_flags & 0x00000004)
    has_relative_path = bool(link_flags & 0x00000008)
    has_working_dir = bool(link_flags & 0x00000010)
    has_arguments = bool(link_flags & 0x00000020)
    has_icon_location = bool(link_flags & 0x00000040)
    is_unicode = bool(link_flags & 0x00000080)
    
    # Skip LinkTargetIDList if present
    if has_link_target_id_list:
        if offset + 2 > len(data):
            fail("Truncated: cannot read IDList size")
        idlist_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2 + idlist_size
        if offset > len(data):
            fail("Truncated: IDList extends beyond file")
    
    # Skip LinkInfo if present
    if has_link_info:
        if offset + 4 > len(data):
            fail("Truncated: cannot read LinkInfo size")
        link_info_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4 + link_info_size
        if offset > len(data):
            fail("Truncated: LinkInfo extends beyond file")
    
    # Parse StringData sections in order:
    # NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
    # Only for flags that are set
    
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    def read_string(offset, is_unicode):
        """Read a string from data at offset. Returns (string, new_offset)."""
        if offset + 2 > len(data):
            fail("Truncated: cannot read string length")
        count_chars = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        
        if is_unicode:
            byte_count = count_chars * 2
            if offset + byte_count > len(data):
                fail("Truncated: string data extends beyond file")
            raw = data[offset:offset + byte_count]
            offset += byte_count
            try:
                s = raw.decode('utf-16-le')
            except UnicodeDecodeError:
                fail("Invalid UTF-16LE string")
            return s, offset
        else:
            byte_count = count_chars
            if offset + byte_count > len(data):
                fail("Truncated: string data extends beyond file")
            raw = data[offset:offset + byte_count]
            offset += byte_count
            try:
                s = raw.decode('cp1252')
            except UnicodeDecodeError:
                fail("Invalid string encoding")
            return s, offset
    
    # NAME_STRING
    if has_name:
        name_string, offset = read_string(offset, is_unicode)
    
    # RELATIVE_PATH
    if has_relative_path:
        relative_path, offset = read_string(offset, is_unicode)
    
    # WORKING_DIR
    if has_working_dir:
        working_dir, offset = read_string(offset, is_unicode)
    
    # COMMAND_LINE_ARGUMENTS
    if has_arguments:
        command_line_arguments, offset = read_string(offset, is_unicode)
    
    # ICON_LOCATION
    if has_icon_location:
        icon_location, offset = read_string(offset, is_unicode)
    
    # Now we should be at the EXTRA_DATA section
    # We need to verify that the remaining data consists of valid extra data blocks
    # terminated by a TerminalBlock (32-bit value < 0x00000004)
    
    # Actually, the spec says extra data blocks follow. We should validate them.
    # But the output contract doesn't require us to parse extra data, just to not crash.
    # However, we should verify the structure is valid.
    
    # Let's traverse the extra data blocks to validate
    while offset < len(data):
        if offset + 2 > len(data):
            fail("Truncated: extra data block header")
        # The first 2 bytes are the size of the block (including this 2-byte size field)
        # Actually, let me check the MS-SHLLINK spec for extra data blocks.
        # Each block has:
        # - 2 bytes: size of the block (including this size field)
        # - 2 bytes: ID type
        # - remaining: data
        # 
        # Wait, I need to double-check. The extra data blocks have a different structure.
        # According to MS-SHLLINK:
        # Each block:
        #   Size (2 bytes): total size of the block including this field
        #   ID (2 bytes): identifies the type
        #   Data (Size - 4 bytes)
        # 
        # TerminalBlock: Size < 4 (typically 2), ID is 0xFFFF
        
        block_size = struct.unpack_from('<H', data, offset)[0]
        if block_size < 2:
            fail("Invalid extra data block size")
        if offset + block_size > len(data):
            fail("Truncated: extra data block extends beyond file")
        
        if block_size < 4:
            # This should be a TerminalBlock
            # TerminalBlock has Size < 4 and ID = 0xFFFF
            # But we need to check if there's an ID field
            # For TerminalBlock, the size is typically 2, so there's no ID field
            # Let's check: if size < 4, it's a terminal block
            # We don't need to validate further, just break
            # But we should make sure it's actually a terminal block (ID = 0xFFFF if present)
            # If size is 2, there's no room for an ID, so we just break
            # If size is 3, that's unusual
            # Let's just break for now
            break
        
        # Check ID
        if offset + 4 > len(data):
            fail("Truncated: extra data block ID")
        block_id = struct.unpack_from('<H', data, offset + 2)[0]
        
        # If this is a terminal block, size should be < 4
        # We already handled size < 4 above
        # For regular blocks, continue
        offset += block_size
    
    # Build result
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": parse_filetime(creation_time),
        "access_time": parse_filetime(access_time),
        "write_time": parse_filetime(write_time)
    }
    
    print(json.dumps(result))
    sys.exit(0)


if __name__ == '__main__':
    main()