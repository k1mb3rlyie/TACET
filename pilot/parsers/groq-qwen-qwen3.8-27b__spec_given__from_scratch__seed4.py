#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files following MS-SHLLINK specification.
Designed for digital forensics: strict validation, no guessing.
"""

import struct
import json
import sys
import uuid
from datetime import datetime, timezone, timedelta


def fail(msg):
    """Print error JSON and exit non-zero."""
    print(json.dumps({"error": msg}))
    sys.exit(1)


def read_exact(data, offset, size, field_name=""):
    """Read exactly `size` bytes from `data` at `offset`. Fail if not enough data."""
    if offset < 0 or offset + size > len(data):
        fail(f"Truncated file: cannot read {field_name} at offset {offset} (need {size} bytes, have {len(data) - offset if offset <= len(data) else 'negative'})")
    return data[offset:offset + size]


def parse_filetime(raw_8bytes):
    """Parse a FILETIME (8 bytes, unsigned 64-bit) to ISO 8601 UTC string.
    Returns None if the value is zero (which is a valid 'no time' in some contexts,
    but per spec we should still convert it). Actually, FILETIME of 0 is 1601-01-01.
    We'll convert any valid 64-bit value. If conversion fails (out of range for datetime), fail.
    """
    if len(raw_8bytes) != 8:
        fail("FILETIME must be 8 bytes")
    ft = struct.unpack("<Q", raw_8bytes)[0]
    # FILETIME: 100-nanosecond intervals since 1601-01-01 00:00:00 UTC
    # datetime supports years 1 to 9999
    # 1601-01-01 is datetime(1601,1,1)
    try:
        # Convert to seconds and microseconds
        # 100 ns = 0.1 microseconds
        total_microseconds = ft * 100  # since 100ns intervals -> *100 gives microseconds
        # But ft can be up to 2^64-1, which is way beyond datetime range
        # Let's check range:
        # datetime.min = 1-01-01 00:00:00
        # datetime.max = 9999-12-31 23:59:59.999999
        # 1601-01-01 is within range.
        # The max FILETIME that maps to datetime.max:
        # datetime.max - datetime(1601,1,1) in 100ns intervals
        epoch_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt_max = datetime.max.replace(tzinfo=timezone.utc)
        max_delta = dt_max - epoch_1601
        max_ft = int(max_delta.total_seconds() * 10_000_000)  # 100ns per second = 10,000,000
        
        if ft > max_ft:
            fail(f"FILETIME value {ft} out of representable datetime range")
        
        delta = timedelta(microseconds=total_microseconds)
        dt = epoch_1601 + delta
        return dt.isoformat()
    except (OverflowError, ValueError) as e:
        fail(f"Cannot convert FILETIME value {ft} to datetime: {e}")


def parse_lnk(data):
    """Parse LNK file bytes. Returns dict of extracted fields."""
    if len(data) < 0x4C:
        fail("File too small to contain ShellLinkHeader (need 76 bytes)")
    
    offset = 0
    
    # HeaderSize
    header_size = struct.unpack("<I", data[0:4])[0]
    if header_size != 0x0000004C:
        fail(f"Invalid HeaderSize: expected 0x4C, got 0x{header_size:08X}")
    
    # LinkCLSID
    clsid_bytes = data[4:20]
    # The CLSID is stored as: 
    # DWORD (little-endian)
    # WORD (little-endian)
    # WORD (little-endian)
    # 8 bytes (as-is)
    # We need to check against 00021401-0000-0000-C000-000000000046
    # Let's construct the expected bytes
    # 00021401 -> little endian: 01 14 02 00
    # 0000 -> 00 00
    # 0000 -> 00 00
    # C000-000000000046 -> C0 00 00 00 00 00 00 46
    
    expected_clsid = bytes([
        0x01, 0x14, 0x02, 0x00,  # 00021401 LE
        0x00, 0x00,              # 0000 LE
        0x00, 0x00,              # 0000 LE
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46  # C000000000000046
    ])
    
    if clsid_bytes != expected_clsid:
        actual_uuid = uuid.UUID(bytes_le=clsid_bytes)
        fail(f"Invalid LinkCLSID: expected 00021401-0000-0000-C000-000000000046, got {actual_uuid}")
    
    offset = 0x14
    link_flags = struct.unpack("<I", data[0x14:0x18])[0]
    file_attributes = struct.unpack("<I", data[0x18:0x1C])[0]
    
    # CreationTime
    creation_time_raw = data[0x1C:0x24]
    # AccessTime
    access_time_raw = data[0x24:0x2C]
    # WriteTime
    write_time_raw = data[0x2C:0x34]
    
    file_size = struct.unpack("<I", data[0x34:0x38])[0]
    icon_index = struct.unpack("<i", data[0x38:0x3C])[0]
    show_command = struct.unpack("<I", data[0x3C:0x40])[0]
    hot_key = struct.unpack("<H", data[0x40:0x42])[0]
    
    reserved1 = struct.unpack("<H", data[0x42:0x44])[0]
    reserved2 = struct.unpack("<I", data[0x44:0x48])[0]
    reserved3 = struct.unpack("<I", data[0x48:0x4C])[0]
    
    if reserved1 != 0:
        fail(f"Reserved1 is not zero: {reserved1}")
    if reserved2 != 0:
        fail(f"Reserved2 is not zero: {reserved2}")
    if reserved3 != 0:
        fail(f"Reserved3 is not zero: {reserved3}")
    
    offset = 0x4C
    
    # Parse IDList if present
    if link_flags & 0x00000001:
        # IDList: sequence of SID structures, terminated by two null bytes (0x0000)
        # Each SID: 2-byte count, then count bytes of data
        while True:
            if offset + 2 > len(data):
                fail("Truncated file in IDList: cannot read SID count")
            sid_count = struct.unpack("<H", data[offset:offset+2])[0]
            offset += 2
            if sid_count == 0:
                # End of IDList
                break
            if offset + sid_count > len(data):
                fail(f"Truncated file in IDList: cannot read SID data of length {sid_count}")
            offset += sid_count
    
    # Parse LinkInfo if present
    if link_flags & 0x00000002:
        # LinkInfo structure:
        # DWORD LinkInfoSize
        # DWORD LinkInfoHeaderSize
        # DWORD LinkInfoFlags
        # DWORD CommonNetworkRelaunchFlags
        # 
        # If LinkInfoFlags & 0x00000001: LocalBasePath follows
        # If LinkInfoFlags & 0x00000002: CommonNetworkRelaunchPath follows
        # If LinkInfoFlags & 0x00000004: UnicodeLocalBasePath follows (after the above)
        # If LinkInfoFlags & 0x00000008: UnicodeCommonNetworkRelaunchPath follows
        
        if offset + 16 > len(data):
            fail("Truncated file: cannot read LinkInfo header")
        
        link_info_size = struct.unpack("<I", data[offset:offset+4])[0]
        link_info_header_size = struct.unpack("<I", data[offset+4:offset+8])[0]
        link_info_flags = struct.unpack("<I", data[offset+8:offset+12])[0]
        common_network_relaunch_flags = struct.unpack("<I", data[offset+12:offset+16])[0]
        
        # Validate LinkInfoSize
        if link_info_size < 0x24:  # minimum size is 36 bytes (0x24)
            fail(f"Invalid LinkInfoSize: {link_info_size}")
        
        if offset + link_info_size > len(data):
            fail(f"Truncated file: LinkInfo extends beyond file end (size={link_info_size})")
        
        # We need to skip the entire LinkInfo. The strings inside are variable length.
        # Let's parse through them.
        li_offset = offset + 16  # after the 16-byte header
        
        # LocalBasePath (ANSI)
        if link_info_flags & 0x00000001:
            if li_offset + 4 > len(data):
                fail("Truncated file in LinkInfo: cannot read LocalBasePath length")
            local_base_path_len = struct.unpack("<I", data[li_offset:li_offset+4])[0]
            li_offset += 4
            if li_offset + local_base_path_len > len(data):
                fail("Truncated file in LinkInfo: LocalBasePath extends beyond file")
            li_offset += local_base_path_len
        
        # CommonNetworkRelaunchPath (ANSI)
        if link_info_flags & 0x00000002:
            if li_offset + 4 > len(data):
                fail("Truncated file in LinkInfo: cannot read CommonNetworkRelaunchPath length")
            common_net_path_len = struct.unpack("<I", data[li_offset:li_offset+4])[0]
            li_offset += 4
            if li_offset + common_net_path_len > len(data):
                fail("Truncated file in LinkInfo: CommonNetworkRelaunchPath extends beyond file")
            li_offset += common_net_path_len
        
        # UnicodeLocalBasePath
        if link_info_flags & 0x00000004:
            if li_offset + 4 > len(data):
                fail("Truncated file in LinkInfo: cannot read UnicodeLocalBasePath length")
            unicode_local_base_path_len = struct.unpack("<I", data[li_offset:li_offset+4])[0]
            li_offset += 4
            # Unicode string: length is in bytes
            if li_offset + unicode_local_base_path_len > len(data):
                fail("Truncated file in LinkInfo: UnicodeLocalBasePath extends beyond file")
            li_offset += unicode_local_base_path_len
        
        # UnicodeCommonNetworkRelaunchPath
        if link_info_flags & 0x00000008:
            if li_offset + 4 > len(data):
                fail("Truncated file in LinkInfo: cannot read UnicodeCommonNetworkRelaunchPath length")
            unicode_common_net_path_len = struct.unpack("<I", data[li_offset:li_offset+4])[0]
            li_offset += 4
            if li_offset + unicode_common_net_path_len > len(data):
                fail("Truncated file in LinkInfo: UnicodeCommonNetworkRelaunchPath extends beyond file")
            li_offset += unicode_common_net_path_len
        
        # The LinkInfo should end at offset + link_info_size
        # But we should verify that li_offset doesn't exceed the LinkInfo boundary
        if li_offset > offset + link_info_size:
            fail("LinkInfo internal structure exceeds declared size")
        
        offset += link_info_size
    
    # Now parse StringData sections
    # Order: NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
    # Only sections with their flag set are present.
    
    is_unicode = bool(link_flags & 0x00000080)
    
    def read_string_data(offset, flag, field_name):
        """Read a StringData section if its flag is set."""
        if not (link_flags & flag):
            return None, offset
        
        if offset + 2 > len(data):
            fail(f"Truncated file: cannot read {field_name} character count")
        
        char_count = struct.unpack("<H", data[offset:offset+2])[0]
        offset += 2
        
        if is_unicode:
            byte_count = char_count * 2
            if offset + byte_count > len(data):
                fail(f"Truncated file: {field_name} string extends beyond file (need {byte_count} bytes)")
            raw = data[offset:offset+byte_count]
            offset += byte_count
            try:
                s = raw.decode('utf-16-le')
            except UnicodeDecodeError as e:
                fail(f"Invalid UTF-16LE in {field_name}: {e}")
        else:
            byte_count = char_count
            if offset + byte_count > len(data):
                fail(f"Truncated file: {field_name} string extends beyond file (need {byte_count} bytes)")
            raw = data[offset:offset+byte_count]
            offset += byte_count
            try:
                s = raw.decode('cp1252')  # Windows default ANSI codepage
            except UnicodeDecodeError as e:
                fail(f"Invalid ANSI string in {field_name}: {e}")
        
        return s, offset
    
    name_string, offset = read_string_data(offset, 0x00000004, "NAME_STRING")
    relative_path, offset = read_string_data(offset, 0x00000008, "RELATIVE_PATH")
    working_dir, offset = read_string_data(offset, 0x00000010, "WORKING_DIR")
    command_line_arguments, offset = read_string_data(offset, 0x00000020, "COMMAND_LINE_ARGUMENTS")
    icon_location, offset = read_string_data(offset, 0x00000040, "ICON_LOCATION")
    
    # Now we should be at the EXTRA_DATA section
    # EXTRA_DATA: sequence of blocks, terminated by TerminalBlock (32-bit value < 0x00000004)
    # We don't need to parse extra data for the output, but we should validate that
    # the remaining data is well-formed or at least that we've consumed everything properly.
    # Actually, the spec says the file ends with EXTRA_DATA. We just need to ensure
    # that the remaining bytes form a valid sequence of extra data blocks ending with
    # a TerminalBlock.
    
    # Let's validate the extra data structure
    extra_offset = offset
    while extra_offset < len(data):
        if extra_offset + 4 > len(data):
            fail("Truncated file: cannot read EXTRA_DATA block header")
        
        block_id = struct.unpack("<I", data[extra_offset:extra_offset+4])[0]
        
        if block_id < 0x00000004:
            # TerminalBlock
            break
        
        # Regular block: next 4 bytes are the size of the data (excluding the 8-byte header)
        if extra_offset + 8 > len(data):
            fail("Truncated file: cannot read EXTRA_DATA block size")
        
        block_size = struct.unpack("<I", data[extra_offset+4:extra_offset+8])[0]
        
        # Total block size = 8 (header) + block_size
        if extra_offset + 8 + block_size > len(data):
            fail(f"Truncated file: EXTRA_DATA block extends beyond file end")
        
        extra_offset += 8 + block_size
    
    if extra_offset != len(data):
        # There's trailing data after the TerminalBlock
        fail(f"Trailing data after EXTRA_DATA: {len(data) - extra_offset} bytes remain")
    
    # Convert timestamps
    creation_time = parse_filetime(creation_time_raw)
    access_time = parse_filetime(access_time_raw)
    write_time = parse_filetime(write_time_raw)
    
    return {
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


def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")
    
    path = sys.argv[1]
    
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        fail(f"Cannot read file: {e}")
    
    try:
        result = parse_lnk(data)
        print(json.dumps(result))
    except SystemExit:
        raise
    except Exception as e:
        fail(f"Unexpected error during parsing: {e}")


if __name__ == "__main__":
    main()