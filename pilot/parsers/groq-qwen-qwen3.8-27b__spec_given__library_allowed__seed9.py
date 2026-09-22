#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files following MS-SHLLINK specification.
Designed for digital forensics: fails safely on malformed/truncated/corrupted input.
"""

import sys
import json
import struct
import os
from datetime import datetime, timezone, timedelta

# Constants
HEADER_SIZE = 0x4C  # 76 bytes
LINK_CLSID = bytes.fromhex('0002140100000000C00000000000000000000046')
# Actually the CLSID is 00021401-0000-0000-C000-000000000046
# In little-endian byte order for the first 4 bytes, and the rest follows GUID layout
# Let me think about GUID representation:
# GUID: 00021401-0000-0000-C000-000000000046
# Bytes in file (little-endian for first 3 fields, big-endian for rest? No, MS-SHLLINK stores it as raw bytes)
# The standard way: the first 4 bytes are little-endian uint32, next 2 bytes little-endian uint16, next 2 bytes little-endian uint16, then 8 bytes as-is
# 00021401 -> little-endian: 01 14 02 00
# 0000 -> 00 00
# 0000 -> 00 00
# C000 -> C0 00
# 000000000046 -> 00 00 00 00 00 00 00 46
# So the full 16 bytes: 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46

LINK_CLSID_BYTES = bytes([
    0x01, 0x14, 0x02, 0x00,  # 00021401 little-endian
    0x00, 0x00,               # 0000
    0x00, 0x00,               # 0000
    0xC0, 0x00,               # C000
    0x00, 0x00, 0x00, 0x00,   # 00000000
    0x00, 0x46                # 0046
])

# LinkFlags bits
FLAG_HAS_LINK_TARGET_ID_LIST = 0x00000001
FLAG_HAS_LINK_INFO = 0x00000002
FLAG_HAS_NAME = 0x00000004
FLAG_HAS_RELATIVE_PATH = 0x00000008
FLAG_HAS_WORKING_DIR = 0x00000010
FLAG_HAS_ARGUMENTS = 0x00000020
FLAG_HAS_ICON_LOCATION = 0x00000040
FLAG_IS_UNICODE = 0x00000080


class ParseError(Exception):
    pass


def filetime_to_iso8601(ft: int) -> str:
    """Convert FILETIME (100ns intervals since 1601-01-01 UTC) to ISO 8601 with UTC offset."""
    # FILETIME 0 = 1601-01-01T00:00:00Z
    # Python datetime min is 0001-01-01, but we need to handle the 1601 epoch.
    # 100ns per tick. 
    # Convert to seconds and microseconds
    total_ticks = ft
    if total_ticks < 0:
        raise ParseError(f"Negative FILETIME: {total_ticks}")
    
    # The FILETIME epoch is 1601-01-01. 
    # We can compute the datetime by adding ticks/10^7 seconds to 1601-01-01.
    # But Python's datetime has a maximum year of 9999.
    # Let's compute the number of seconds and microseconds.
    seconds = total_ticks // 10_000_000
    remainder_ticks = total_ticks % 10_000_000
    microseconds = remainder_ticks * 100  # 100ns * 100 = microseconds
    
    # Create a datetime starting from 1601-01-01T00:00:00Z
    # We'll use timedelta to add seconds
    base = datetime(1601, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    try:
        dt = base + timedelta(seconds=seconds, microseconds=microseconds)
    except (OverflowError, ValueError) as e:
        raise ParseError(f"FILETIME {ft} out of range: {e}")
    
    return dt.isoformat()


def read_string(data: bytes, offset: int, is_unicode: bool) -> tuple:
    """
    Read a StringData section.
    Returns (string_value, new_offset).
    Raises ParseError if truncated or invalid.
    """
    # CountCharacters: unsigned 16-bit
    if offset + 2 > len(data):
        raise ParseError("Truncated: cannot read CountCharacters")
    count_chars = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    if is_unicode:
        byte_len = count_chars * 2
    else:
        byte_len = count_chars
    
    if offset + byte_len > len(data):
        raise ParseError("Truncated: string data exceeds file size")
    
    raw = data[offset:offset + byte_len]
    offset += byte_len
    
    if is_unicode:
        try:
            s = raw.decode('utf-16-le')
        except UnicodeDecodeError as e:
            raise ParseError(f"Invalid UTF-16LE string: {e}")
    else:
        # ANSI/CP1252 or similar; use cp1252 as a reasonable default for Windows
        try:
            s = raw.decode('cp1252')
        except UnicodeDecodeError as e:
            # Fall back to latin-1 which never fails, but this indicates potential corruption
            s = raw.decode('latin-1')
    
    return s, offset


def parse_idlist(data: bytes, offset: int) -> int:
    """
    Parse IDList structure. Returns new offset.
    IDList is a sequence of IDListEntries, terminated by a 2-byte zero.
    Each IDListEntry: 
        - 2 bytes: item count (number of ID entries in this list)
        - For each item:
            - 2 bytes: length of the item (in bytes, includes the 2-byte length field? No, the length is the size of the item data)
            - Actually, per MS-SHLLINK, each IDListEntry has:
              - 2 bytes: ItemCount (number of items)
              - Then ItemCount items, each with:
                - 2 bytes: ItemSize (size of the item in bytes, not including the 2-byte size field)
                - ItemSize bytes of data
    Terminated by a 2-byte zero (ItemCount = 0).
    """
    while True:
        if offset + 2 > len(data):
            raise ParseError("Truncated: cannot read IDList entry count")
        item_count = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        
        if item_count == 0:
            # End of IDList
            return offset
        
        for _ in range(item_count):
            if offset + 2 > len(data):
                raise ParseError("Truncated: cannot read ID item size")
            item_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if offset + item_size > len(data):
                raise ParseError("Truncated: ID item data exceeds file size")
            offset += item_size


def parse_linkinfo(data: bytes, offset: int) -> int:
    """
    Parse LinkInfo structure. Returns new offset.
    LinkInfo:
        - 4 bytes: LinkInfoSize (total size of this structure including this field)
        - 4 bytes: LinkInfoFlags
        - 4 bytes: OffsetToLinkTargetIDList (offset from start of LinkInfo)
        - 4 bytes: CommonNetworkRelPathSize
        - 4 bytes: CommonNetworkRelPathOffset
        - 4 bytes: Hotkey
        - 4 bytes: ShowCmd
        - 4 bytes: Reserved1
        - 4 bytes: Reserved2
        - 4 bytes: Reserved3
        - Then: CommonNetworkRelPath (if size > 0)
        - Then: LocalBasePath
        - Then: CommonName
        - Then: RelativePath
        - Then: WorkingDir
        - Then: LocalBasePathUnicode
        - Then: CommonNameUnicode
        - Then: RelativePathUnicode
        - Then: WorkingDirUnicode
        
    For simplicity, we just need to skip the LinkInfo structure.
    The LinkInfoSize tells us the total size.
    """
    if offset + 4 > len(data):
        raise ParseError("Truncated: cannot read LinkInfoSize")
    linkinfo_size = struct.unpack_from('<I', data, offset)[0]
    
    # Sanity check: LinkInfoSize should be at least 0x24 (36 bytes for the fixed part)
    if linkinfo_size < 0x24:
        raise ParseError(f"Invalid LinkInfoSize: {linkinfo_size}")
    
    # The LinkInfo structure includes the LinkInfoSize field itself
    if offset + linkinfo_size > len(data):
        raise ParseError("Truncated: LinkInfo exceeds file size")
    
    return offset + linkinfo_size


def parse_extra_data(data: bytes, offset: int) -> int:
    """
    Parse EXTRA_DATA blocks. Returns new offset (should be end of file).
    Each block:
        - 4 bytes: Signature (0x00000001 to 0x00000003 for known types, < 0x00000004 for terminal)
        - 4 bytes: Size (size of the data following the signature and size fields)
        - Size bytes of data
    Terminal block: 4 bytes where value < 0x00000004 (typically 0x00000000)
    """
    while True:
        if offset + 4 > len(data):
            # Check if this is a terminal block (just 4 bytes)
            if offset + 4 == len(data):
                val = struct.unpack_from('<I', data, offset)[0]
                if val < 0x00000004:
                    return offset + 4
            raise ParseError("Truncated: cannot read extra data signature")
        
        sig = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        
        if sig < 0x00000004:
            # Terminal block
            return offset
        
        # Need to read the size
        if offset + 4 > len(data):
            raise ParseError("Truncated: cannot read extra data size")
        size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        
        if offset + size > len(data):
            raise ParseError("Truncated: extra data exceeds file size")
        offset += size


def parse_lnk(data: bytes) -> dict:
    """Parse a .lnk file and return the result dictionary."""
    if len(data) < HEADER_SIZE:
        raise ParseError(f"File too small: {len(data)} bytes, need at least {HEADER_SIZE}")
    
    # Parse header
    header_size = struct.unpack_from('<I', data, 0x00)[0]
    if header_size != HEADER_SIZE:
        raise ParseError(f"Invalid HeaderSize: 0x{header_size:08X}, expected 0x{HEADER_SIZE:08X}")
    
    link_clsid = data[0x04:0x14]
    if link_clsid != LINK_CLSID_BYTES:
        raise ParseError(f"Invalid LinkCLSID: {link_clsid.hex()}, expected {LINK_CLSID_BYTES.hex()}")
    
    link_flags = struct.unpack_from('<I', data, 0x14)[0]
    file_attributes = struct.unpack_from('<I', data, 0x18)[0]
    creation_time_ft = struct.unpack_from('<Q', data, 0x1C)[0]
    access_time_ft = struct.unpack_from('<Q', data, 0x24)[0]
    write_time_ft = struct.unpack_from('<Q', data, 0x2C)[0]
    file_size = struct.unpack_from('<I', data, 0x34)[0]  # unsigned
    icon_index = struct.unpack_from('<i', data, 0x38)[0]   # signed
    show_command = struct.unpack_from('<I', data, 0x3C)[0]
    hot_key = struct.unpack_from('<H', data, 0x40)[0]
    reserved1 = struct.unpack_from('<H', data, 0x42)[0]
    reserved2 = struct.unpack_from('<I', data, 0x44)[0]
    reserved3 = struct.unpack_from('<I', data, 0x48)[0]
    
    # Validate reserved fields
    if reserved1 != 0:
        raise ParseError(f"Reserved1 is non-zero: {reserved1}")
    if reserved2 != 0:
        raise ParseError(f"Reserved2 is non-zero: {reserved2}")
    if reserved3 != 0:
        raise ParseError(f"Reserved3 is non-zero: {reserved3}")
    
    is_unicode = bool(link_flags & FLAG_IS_UNICODE)
    
    offset = HEADER_SIZE
    
    # Parse IDList if present
    if link_flags & FLAG_HAS_LINK_TARGET_ID_LIST:
        offset = parse_idlist(data, offset)
    
    # Parse LinkInfo if present
    if link_flags & FLAG_HAS_LINK_INFO:
        offset = parse_linkinfo(data, offset)
    
    # Parse StringData sections in order
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    if link_flags & FLAG_HAS_NAME:
        name_string, offset = read_string(data, offset, is_unicode)
    
    if link_flags & FLAG_HAS_RELATIVE_PATH:
        relative_path, offset = read_string(data, offset, is_unicode)
    
    if link_flags & FLAG_HAS_WORKING_DIR:
        working_dir, offset = read_string(data, offset, is_unicode)
    
    if link_flags & FLAG_HAS_ARGUMENTS:
        command_line_arguments, offset = read_string(data, offset, is_unicode)
    
    if link_flags & FLAG_HAS_ICON_LOCATION:
        icon_location, offset = read_string(data, offset, is_unicode)
    
    # Parse EXTRA_DATA
    offset = parse_extra_data(data, offset)
    
    # Verify we've consumed the entire file
    if offset != len(data):
        raise ParseError(f"Unexpected data after EXTRA_DATA: expected end at {len(data)}, got {offset}")
    
    # Convert FILETIMEs to ISO 8601
    creation_time = filetime_to_iso8601(creation_time_ft)
    access_time = filetime_to_iso8601(access_time_ft)
    write_time = filetime_to_iso8601(write_time_ft)
    
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
        "write_time": write_time,
    }


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python parser.py <path-to-lnk-file>"}))
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        if not os.path.isfile(filepath):
            raise ParseError(f"File not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        result = parse_lnk(data)
        print(json.dumps(result))
        sys.exit(0)
    
    except ParseError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {str(e)}"}))
        sys.exit(1)


if __name__ == '__main__':
    main()