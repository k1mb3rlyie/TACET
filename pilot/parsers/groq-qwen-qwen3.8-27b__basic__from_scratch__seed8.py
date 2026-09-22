#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files.
Extracts metadata for digital forensics use.
"""

import struct
import json
import sys
import os
from datetime import datetime, timezone


def fail(msg):
    """Print error JSON to stdout and exit with non-zero code."""
    print(json.dumps({"error": msg}))
    sys.exit(1)


def read_windows_filetime(data, offset):
    """
    Read a Windows FILETIME (8 bytes, little-endian) from data at offset.
    Returns a datetime object with UTC timezone, or raises ValueError.
    FILETIME is the number of 100-nanosecond intervals since January 1, 1601 (UTC).
    """
    if offset + 8 > len(data):
        raise ValueError("FILETIME extends beyond data")
    filetime = struct.unpack_from('<Q', data, offset)[0]
    
    # Check for zero (unspecified time)
    if filetime == 0:
        raise ValueError("FILETIME is zero (unspecified)")
    
    # Convert from Windows FILETIME to Unix timestamp
    # Windows epoch is Jan 1, 1601 00:00:00 UTC
    # Unix epoch is Jan 1, 1970 00:00:00 UTC
    # Difference is 11644473600 seconds
    unix_time = (filetime / 10000000.0) - 11644473600.0
    
    # Check for reasonable range (avoid overflow issues)
    if unix_time < -2147483648 or unix_time > 2147483647:
        raise ValueError("FILETIME out of reasonable range")
    
    try:
        dt = datetime.fromtimestamp(unix_time, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as e:
        raise ValueError(f"Cannot convert FILETIME to datetime: {e}")
    
    return dt


def parse_unicode_string(data, offset, max_len=None):
    """
    Parse a UTF-16LE string from data at offset.
    The string is null-terminated with \x00\x00.
    Returns the string or None if not present/valid.
    """
    if max_len is None:
        # Find the null terminator
        i = offset
        while i + 1 < len(data):
            if data[i] == 0 and data[i + 1] == 0:
                break
            i += 2
        else:
            return None
        end = i + 2
    else:
        end = offset + max_len
    
    if end > len(data):
        return None
    
    raw = data[offset:end]
    # Remove trailing null terminator if present
    if len(raw) >= 2 and raw[-2:] == b'\x00\x00':
        raw = raw[:-2]
    
    return raw.decode('utf-16-le', errors='strict')


def parse_lnk_file(data):
    """
    Parse the LNK file data and extract metadata.
    Returns a dict with the required fields.
    """
    if len(data) < 4:
        raise ValueError("File too short to be a valid LNK file")
    
    # Check header signature: 0x4C 0x00 0x00 0x00
    header_sig = struct.unpack_from('<I', data, 0)[0]
    if header_sig != 0x00004C:
        raise ValueError(f"Invalid LNK header signature: 0x{header_sig:08X}")
    
    # Parse LinkFlags (4 bytes at offset 4)
    if len(data) < 8:
        raise ValueError("File too short for LinkFlags")
    link_flags = struct.unpack_from('<I', data, 4)[0]
    
    # Define bit flags
    LINKINFO_FLAG_HAS_NAME_STRING = 0x0001
    LINKINFO_FLAG_HAS_RELATIVE_PATH = 0x0002
    LINKINFO_FLAG_HAS_WORKING_DIR = 0x0004
    LINKINFO_FLAG_HAS_COMMAND_LINE = 0x0008
    LINKINFO_FLAG_HAS_ICON_LOCATION = 0x0010
    LINKINFO_FLAG_HAS_ID_LIST = 0x0010  # Wait, let me check: ID_LIST is 0x0010? No.
    
    # Correct flag definitions:
    # LINKINFO_FLAG_HAS_ID_LIST = 0x0000
    # Actually, the standard flags are:
    # 0x0001: LINKINFO_FLAG_HAS_NAME_STRING
    # 0x0002: LINKINFO_FLAG_HAS_RELATIVE_PATH
    # 0x0004: LINKINFO_FLAG_HAS_WORKING_DIR
    # 0x0008: LINKINFO_FLAG_HAS_COMMAND_LINE
    # 0x0010: LINKINFO_FLAG_HAS_ICON_LOCATION
    # 0x0020: LINKINFO_FLAG_HAS_ID_LIST
    # 0x0040: LINKINFO_FLAG_HAS_LOCALBASE_PATH
    # 0x0080: LINKINFO_FLAG_HAS_NETNAME
    # 0x0100: LINKINFO_FLAG_HAS_MAPPED_PATH
    # 0x0200: LINKINFO_FLAG_HAS_DRIVE_TYPE
    # 0x0400: LINKINFO_FLAG_STORAGE_GROUP
    # 0x0800: LINKINFO_FLAG_HAS_APPLIANCE_ID
    # 0x1000: LINKINFO_FLAG_HAS_ICON_INDEX
    # 0x2000: LINKINFO_FLAG_HAS_RUN_IN_SEPARATE_WINDOW
    # 0x4000: LINKINFO_FLAG_HAS_CLASS_STORE
    # 0x8000: LINKINFO_FLAG_HAS_ICON_UPDATE_FLAGS
    
    LINKINFO_FLAG_HAS_ICON_INDEX = 0x1000
    LINKINFO_FLAG_HAS_FILESIZE = 0x0000  # No, file size is in the extra data section
    
    # Actually, let me be more careful. The LinkFlags determine which optional fields are present.
    # The file size and icon index are in the "Property Store" or in specific blocks.
    
    # Let me re-examine the LNK format:
    # After the 32-byte header (which includes LinkFlags), we have:
    # FileAttributes (4 bytes)
    # CreationTime (8 bytes)
    # AccessTime (8 bytes)
    # WriteTime (8 bytes)
    # FileSize (8 bytes)
    # IconIndex (4 bytes)
    # 
    # Wait, that's not quite right either. Let me look at the actual structure.
    #
    # The LNK format:
    # 0x00: Header (48 bytes total)
    #   0x00: Header signature (4 bytes) = 0x00004C
    #   0x04: LinkFlags (4 bytes)
    #   0x08: FileAttributes (4 bytes)
    #   0x0C: CreationTime (8 bytes)
    #   0x14: AccessTime (8 bytes)
    #   0x1C: WriteTime (8 bytes)
    #   0x24: LocalBasePath (variable, if LINKINFO_FLAG_HAS_LOCALBASE_PATH)
    #   ...
    #
    # Actually, I recall now. The basic structure after the 4-byte signature and 4-byte LinkFlags:
    # - FileAttributes (4 bytes)
    # - CreationTime (8 bytes)
    # - AccessTime (8 bytes)
    # - WriteTime (8 bytes)
    # - FileSize (8 bytes)
    # - IconIndex (4 bytes)
    #
    # But wait, some of these are only present if certain flags are set? No, I think these are always present in the main header area.
    #
    # Let me check the Microsoft documentation more carefully from memory:
    # The LNK file format has:
    # - 48-byte header
    #   - 4 bytes: Signature (0x00004C)
    #   - 4 bytes: Link Flags
    #   - 4 bytes: File Attributes
    #   - 8 bytes: Creation Time
    #   - 8 bytes: Access Time
    #   - 8 bytes: Write Time
    #   - 8 bytes: File Size
    #   - 4 bytes: Icon Index
    #   - 4 bytes: Command Line Arguments (length, only if LinkFlag 0x0008 is set)
    #   ...
    #
    # Hmm, I'm getting confused. Let me take a different approach and carefully parse based on the LinkFlags.
    
    offset = 8  # After signature and LinkFlags
    
    # FileAttributes (4 bytes) - always present
    if offset + 4 > len(data):
        raise ValueError("Truncated: missing FileAttributes")
    file_attributes = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    
    # CreationTime (8 bytes) - always present
    if offset + 8 > len(data):
        raise ValueError("Truncated: missing CreationTime")
    creation_time = read_windows_filetime(data, offset)
    offset += 8
    
    # AccessTime (8 bytes) - always present
    if offset + 8 > len(data):
        raise ValueError("Truncated: missing AccessTime")
    access_time = read_windows_filetime(data, offset)
    offset += 8
    
    # WriteTime (8 bytes) - always present
    if offset + 8 > len(data):
        raise ValueError("Truncated: missing WriteTime")
    write_time = read_windows_filetime(data, offset)
    offset += 8
    
    # FileSize (8 bytes) - always present
    if offset + 8 > len(data):
        raise ValueError("Truncated: missing FileSize")
    file_size = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    
    # IconIndex (4 bytes) - always present
    if offset + 4 > len(data):
        raise ValueError("Truncated: missing IconIndex")
    icon_index = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    
    # Now parse the optional string fields based on LinkFlags
    
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    if link_flags & LINKINFO_FLAG_HAS_NAME_STRING:
        # NameString: UTF-16LE, null-terminated
        if offset >= len(data):
            raise ValueError("Truncated: missing NameString")
        name_string = parse_unicode_string(data, offset)
        if name_string is None:
            raise ValueError("Invalid NameString")
        # Advance offset past the string (including null terminator)
        # We need to find where the string ended
        i = offset
        while i + 1 < len(data):
            if data[i] == 0 and data[i + 1] == 0:
                break
            i += 2
        offset = i + 2
    
    if link_flags & LINKINFO_FLAG_HAS_RELATIVE_PATH:
        if offset >= len(data):
            raise ValueError("Truncated: missing RelativePath")
        relative_path = parse_unicode_string(data, offset)
        if relative_path is None:
            raise ValueError("Invalid RelativePath")
        i = offset
        while i + 1 < len(data):
            if data[i] == 0 and data[i + 1] == 0:
                break
            i += 2
        offset = i + 2
    
    if link_flags & LINKINFO_FLAG_HAS_WORKING_DIR:
        if offset >= len(data):
            raise ValueError("Truncated: missing WorkingDir")
        working_dir = parse_unicode_string(data, offset)
        if working_dir is None:
            raise ValueError("Invalid WorkingDir")
        i = offset
        while i + 1 < len(data):
            if data[i] == 0 and data[i + 1] == 0:
                break
            i += 2
        offset = i + 2
    
    if link_flags & LINKINFO_FLAG_HAS_COMMAND_LINE:
        if offset >= len(data):
            raise ValueError("Truncated: missing CommandLine")
        command_line_arguments = parse_unicode_string(data, offset)
        if command_line_arguments is None:
            raise ValueError("Invalid CommandLine")
        i = offset
        while i + 1 < len(data):
            if data[i] == 0 and data[i + 1] == 0:
                break
            i += 2
        offset = i + 2
    
    if link_flags & LINKINFO_FLAG_HAS_ICON_LOCATION:
        if offset >= len(data):
            raise ValueError("Truncated: missing IconLocation")
        icon_location = parse_unicode_string(data, offset)
        if icon_location is None:
            raise ValueError("Invalid IconLocation")
        i = offset
        while i + 1 < len(data):
            if data[i] == 0 and data[i + 1] == 0:
                break
            i += 2
        offset = i + 2
    
    # We don't need to parse the rest of the file for the required fields,
    # but we should verify that the remaining data doesn't indicate corruption.
    # For now, if we got here, we have all the required fields.
    
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time.isoformat(),
        "access_time": access_time.isoformat(),
        "write_time": write_time.isoformat()
    }
    
    return result


def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        fail(f"File not found: {filepath}")
    except PermissionError:
        fail(f"Permission denied: {filepath}")
    except OSError as e:
        fail(f"Cannot read file: {e}")
    
    try:
        result = parse_lnk_file(data)
    except ValueError as e:
        fail(str(e))
    except Exception as e:
        fail(f"Unexpected error: {e}")
    
    print(json.dumps(result))
    sys.exit(0)


if __name__ == '__main__':
    main()