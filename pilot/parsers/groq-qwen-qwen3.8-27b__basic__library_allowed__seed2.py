#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files in a digital forensics context.
Extracts metadata and signals errors for malformed/corrupted files.
"""

import sys
import json
import struct
from datetime import datetime, timezone


def fail(message: str) -> None:
    """Print error JSON to stdout and exit with non-zero code."""
    print(json.dumps({"error": message}))
    sys.exit(1)


def read_exact(data: bytes, offset: int, length: int) -> bytes:
    """Read exactly `length` bytes from `data` at `offset`. Raise if not enough data."""
    if offset < 0 or offset + length > len(data):
        raise ValueError(f"Not enough data: need {length} bytes at offset {offset}, have {len(data) - offset}")
    return data[offset:offset + length]


def parse_timestamp(data: bytes, offset: int) -> datetime:
    """
    Parse a Windows FILETIME (8 bytes, little-endian) into a datetime.
    Returns None if the timestamp is zero (uninitialized).
    """
    if offset + 8 > len(data):
        raise ValueError(f"FILETIME truncated at offset {offset}")
    filetime = struct.unpack_from('<Q', data, offset)[0]
    if filetime == 0:
        return None
    # Convert FILETIME to Python datetime
    # FILETIME is the number of 100-nanosecond intervals since January 1, 1601
    # Unix epoch is January 1, 1970
    # Difference: 11644473600 seconds
    unix_time = (filetime - 116444736000000000) / 10000000.0
    return datetime.fromtimestamp(unix_time, tz=timezone.utc)


def parse_string(data: bytes, offset: int) -> str:
    """
    Parse a null-terminated UTF-16LE string from `data` at `offset`.
    Returns None if the string is empty (just a null terminator).
    Raises ValueError if we run out of data before finding null terminator.
    """
    if offset + 2 > len(data):
        raise ValueError(f"String parsing: not enough data at offset {offset}")
    
    end = offset
    while end + 1 < len(data):
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    else:
        # Check if we reached the end without finding null terminator
        if end + 2 > len(data):
            raise ValueError(f"String parsing: no null terminator found starting at offset {offset}")
    
    # end is now at the position of the null terminator (or just after the last char)
    # The string bytes are from offset to end (not including the null)
    str_bytes = data[offset:end]
    if len(str_bytes) == 0:
        return None
    
    try:
        return str_bytes.decode('utf-16-le')
    except UnicodeDecodeError:
        raise ValueError(f"String parsing: invalid UTF-16LE data at offset {offset}")


def parse_link_flags(data: bytes, offset: int) -> int:
    """Parse the LinkFlags field (4 bytes, little-endian)."""
    if offset + 4 > len(data):
        raise ValueError("LinkFlags truncated")
    return struct.unpack_from('<I', data, offset)[0]


def parse_local_base_name(data: bytes, offset: int) -> str:
    """Parse LocalBaseName string (null-terminated UTF-16LE)."""
    return parse_string(data, offset)


def parse_relative_path(data: bytes, offset: int) -> str:
    """Parse RelativePath string (null-terminated UTF-16LE)."""
    return parse_string(data, offset)


def parse_working_dir(data: bytes, offset: int) -> str:
    """Parse WorkingDir string (null-terminated UTF-16LE)."""
    return parse_string(data, offset)


def parse_command_line(data: bytes, offset: int) -> str:
    """Parse CommandTail string (null-terminated UTF-16LE)."""
    return parse_string(data, offset)


def parse_icon_location(data: bytes, offset: int) -> str:
    """Parse IconLocation string (null-terminated UTF-16LE)."""
    return parse_string(data, offset)


def parse_icon_index(data: bytes, offset: int) -> int:
    """Parse IconIndex (4 bytes, little-endian)."""
    if offset + 4 > len(data):
        raise ValueError("IconIndex truncated")
    return struct.unpack_from('<i', data, offset)[0]


def parse_file_size(data: bytes, offset: int) -> int:
    """Parse FileSize (8 bytes, little-endian)."""
    if offset + 8 > len(data):
        raise ValueError("FileSize truncated")
    return struct.unpack_from('<Q', data, offset)[0]


def parse_creation_time(data: bytes, offset: int) -> datetime:
    """Parse CreationTime (8 bytes FILETIME)."""
    return parse_timestamp(data, offset)


def parse_access_time(data: bytes, offset: int) -> datetime:
    """Parse AccessTime (8 bytes FILETIME)."""
    return parse_timestamp(data, offset)


def parse_write_time(data: bytes, offset: int) -> datetime:
    """Parse WriteTime (8 bytes FILETIME)."""
    return parse_timestamp(data, offset)


def parse_link_file(data: bytes) -> dict:
    """
    Parse a .lnk file and extract the required metadata fields.
    Returns a dict with the required keys.
    Raises ValueError if the file is malformed.
    """
    if len(data) < 26:
        raise ValueError("File too small to be a valid .lnk file")
    
    # Header
    header_size = struct.unpack_from('<I', data, 0)[0]
    if header_size != 0x4C:  # 76 bytes is the standard header size
        # The header size field should be 0x4C (76) for standard .lnk files
        # But let's be a bit lenient - we'll still try to parse
        pass
    
    link_target_id_list_size = struct.unpack_from('<I', data, 4)[0]
    link_info_size = struct.unpack_from('<I', data, 8)[0]
    link_flags = struct.unpack_from('<I', data, 12)[0]
    link_target_id_list_offset = struct.unpack_from('<I', data, 16)[0]
    link_info_offset = struct.unpack_from('<I', data, 20)[0]
    # Bytes 24-27: Reserved (4 bytes)
    # Bytes 28-35: Reserved (8 bytes)
    # Bytes 36-43: Reserved (8 bytes)
    # Bytes 44-51: Reserved (8 bytes)
    # Bytes 52-59: Reserved (8 bytes)
    # Bytes 60-67: Reserved (8 bytes)
    # Bytes 68-75: Reserved (8 bytes)
    # Total header: 76 bytes
    
    # Flags:
    # Bit 0: HAS_LINK_TARGET_ID_LIST
    # Bit 1: HAS_LINKINFO
    # Bit 2: HAS_STRING
    # Bit 3: HAS_ICONLOCATION
    # Bit 4: HAS_ICON
    # Bit 5: HAS_NAME_STRING
    # Bit 6: HAS_RELATIVEPATH
    # Bit 7: HAS_WORKINGDIR
    # Bit 8: HAS_COMMANDLINE
    # Bit 9: HAS_ICON
    # Bit 10: HAS_UNRESOLVEDPATH
    # Bit 11: HAS_CLASSID
    
    has_link_target_id_list = bool(link_flags & 0x00000001)
    has_linkinfo = bool(link_flags & 0x00000002)
    has_string = bool(link_flags & 0x00000004)
    has_iconlocation = bool(link_flags & 0x00000008)
    has_icon = bool(link_flags & 0x00000010)
    has_name_string = bool(link_flags & 0x00000020)
    has_relativepath = bool(link_flags & 0x00000040)
    has_workingdir = bool(link_flags & 0x00000080)
    has_commandline = bool(link_flags & 0x00000100)
    has_unresolvedpath = bool(link_flags & 0x00000200)
    has_classid = bool(link_flags & 0x00000400)
    
    # Track which fields we can extract
    result = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
        "file_size": None,
        "icon_index": None,
        "creation_time": None,
        "access_time": None,
        "write_time": None,
    }
    
    # We need to track which fields were actually present vs absent
    # If a field is not present in the file, it should be null
    # If a field is present but we can't parse it, we should fail
    
    # The StringData block comes after the LinkInfo block if present
    # Let's calculate the offset of the StringData block
    
    # First, let's check if we have enough data for the header
    if len(data) < 76:
        raise ValueError("File truncated: header incomplete")
    
    # Calculate where the StringData block starts
    # It comes after any LinkTargetIDList and LinkInfo blocks
    string_data_offset = 76  # Start after header
    
    if has_link_target_id_list and link_target_id_list_offset > 0:
        # LinkTargetIDList is present, it's at link_target_id_list_offset
        # The size is link_target_id_list_size
        if link_target_id_list_offset + link_target_id_list_size > len(data):
            raise ValueError("LinkTargetIDList truncated")
        string_data_offset = max(string_data_offset, link_target_id_list_offset + link_target_id_list_size)
    
    if has_linkinfo and link_info_offset > 0:
        # LinkInfo is present
        if link_info_offset + link_info_size > len(data):
            raise ValueError("LinkInfo truncated")
        string_data_offset = max(string_data_offset, link_info_offset + link_info_size)
    
    # Now parse the StringData block if present
    if has_string:
        if string_data_offset + 4 > len(data):
            raise ValueError("StringData header truncated")
        
        # StringData header:
        # 4 bytes: Size of StringData block
        # 4 bytes: Flags (same as link_flags)
        # 4 bytes: Size of LocalBaseName
        # 4 bytes: Size of RelativePath
        # 4 bytes: Size of WorkingDir
        # 4 bytes: Size of CommandTail
        # 4 bytes: Size of IconLocation
        
        string_data_size = struct.unpack_from('<I', data, string_data_offset)[0]
        string_flags = struct.unpack_from('<I', data, string_data_offset + 4)[0]
        
        # Check if string data size is reasonable
        if string_data_size == 0 or string_data_size > len(data) - string_data_offset:
            # Be lenient - the size field might be unreliable, but let's check
            # Actually, if the size is 0 or too large, that's suspicious
            # But some files may have incorrect size fields. Let's try to parse
            # what we can.
            pass
        
        local_base_name_size = struct.unpack_from('<I', data, string_data_offset + 8)[0]
        relative_path_size = struct.unpack_from('<I', data, string_data_offset + 12)[0]
        working_dir_size = struct.unpack_from('<I', data, string_data_offset + 16)[0]
        command_tail_size = struct.unpack_from('<I', data, string_data_offset + 20)[0]
        icon_location_size = struct.unpack_from('<I', data, string_data_offset + 24)[0]
        
        # Now the strings follow
        str_offset = string_data_offset + 28
        
        # LocalBaseName
        name_string = None
        if has_name_string and local_base_name_size > 0:
            name_string = parse_string(data, str_offset)
            str_offset += local_base_name_size
        
        # RelativePath
        relative_path = None
        if has_relativepath and relative_path_size > 0:
            relative_path = parse_string(data, str_offset)
            str_offset += relative_path_size
        
        # WorkingDir
        working_dir = None
        if has_workingdir and working_dir_size > 0:
            working_dir = parse_string(data, str_offset)
            str_offset += working_dir_size
        
        # CommandTail
        command_line = None
        if has_commandline and command_tail_size > 0:
            command_line = parse_string(data, str_offset)
            str_offset += command_tail_size
        
        # IconLocation
        icon_location = None
        if has_iconlocation and icon_location_size > 0:
            icon_location = parse_string(data, str_offset)
            str_offset += icon_location_size
        
        result["name_string"] = name_string
        result["relative_path"] = relative_path
        result["working_dir"] = working_dir
        result["command_line_arguments"] = command_line
        result["icon_location"] = icon_location
        
        # Now look for IconIndex, FileSize, and timestamps
        # These come after the strings in the StringData block
        # But wait - the StringData block structure is:
        # - Header (28 bytes)
        # - LocalBaseName
        # - RelativePath
        # - WorkingDir
        # - CommandTail
        # - IconLocation
        # - IconIndex (4 bytes)
        # - FileSize (8 bytes)
        # - CreationTime (8 bytes)
        # - AccessTime (8 bytes)
        # - WriteTime (8 bytes)
        
        # Check if we have enough data for IconIndex
        if str_offset + 4 > len(data):
            # Not enough data for IconIndex
            # This could mean the file is truncated, or these fields aren't present
            # Let's check if the string_data_size accounts for these
            if string_data_size > 0:
                expected_end = string_data_offset + string_data_size
                if str_offset < expected_end:
                    # We have more data to parse
                    pass
                else:
                    # No more data in StringData block
                    pass
        
        # Try to parse IconIndex
        if str_offset + 4 <= len(data):
            # Check if this is within the StringData block
            if string_data_size > 0 and str_offset < string_data_offset + string_data_size:
                icon_index = struct.unpack_from('<i', data, str_offset)[0]
                result["icon_index"] = icon_index
                str_offset += 4
        
        # Try to parse FileSize
        if str_offset + 8 <= len(data):
            if string_data_size > 0 and str_offset < string_data_offset + string_data_size:
                file_size = struct.unpack_from('<Q', data, str_offset)[0]
                result["file_size"] = file_size
                str_offset += 8
        
        # Try to parse CreationTime
        if str_offset + 8 <= len(data):
            if string_data_size > 0 and str_offset < string_data_offset + string_data_size:
                creation_time = parse_timestamp(data, str_offset)
                result["creation_time"] = creation_time
                str_offset += 8
        
        # Try to parse AccessTime
        if str_offset + 8 <= len(data):
            if string_data_size > 0 and str_offset < string_data_offset + string_data_size:
                access_time = parse_timestamp(data, str_offset)
                result["access_time"] = access_time
                str_offset += 8
        
        # Try to parse WriteTime
        if str_offset + 8 <= len(data):
            if string_data_size > 0 and str_offset < string_data_offset + string_data_size:
                write_time = parse_timestamp(data, str_offset)
                result["write_time"] = write_time
                str_offset += 8
    
    # Convert datetimes to ISO 8601 format
    for key in ["creation_time", "access_time", "write_time"]:
        if result[key] is not None:
            result[key] = result[key].isoformat()
    
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
    except Exception as e:
        fail(f"Cannot read file: {e}")
    
    try:
        result = parse_link_file(data)
        
        # Build the final output
        output = {
            "name_string": result["name_string"],
            "relative_path": result["relative_path"],
            "working_dir": result["working_dir"],
            "command_line_arguments": result["command_line_arguments"],
            "icon_location": result["icon_location"],
            "file_size": result["file_size"] if result["file_size"] is not None else None,
            "icon_index": result["icon_index"] if result["icon_index"] is not None else None,
            "creation_time": result["creation_time"],
            "access_time": result["access_time"],
            "write_time": result["write_time"],
        }
        
        print(json.dumps(output))
        sys.exit(0)
        
    except ValueError as e:
        fail(str(e))
    except Exception as e:
        fail(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()