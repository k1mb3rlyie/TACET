#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files.
Extracts metadata in a digital forensics context.
"""

import sys
import json
import struct
import os
from datetime import datetime, timezone


def fail(message):
    """Print error JSON and exit with non-zero code."""
    print(json.dumps({"error": message}))
    sys.exit(1)


def parse_lnk(data):
    """
    Parse LNK file data and extract metadata.
    Returns a dict with the required keys.
    Raises ValueError on malformed data.
    """
    header_size = 4 + 4 + 4 + 4 + 4 + 2 + 2 + 4
    if len(data) < header_size:
        raise ValueError("File too small for LNK header")

    # Parse header
    signature = data[0:4]
    if signature != b'\x4c\x00\x00\x00':  # 0x0000004C
        raise ValueError("Invalid LNK signature")

    link_flags = struct.unpack_from('<I', data, 4)[0]
    file_attributes = struct.unpack_from('<I', data, 8)[0]
    
    # Creation time (FILETIME)
    creation_time_raw = struct.unpack_from('<Q', data, 12)[0]
    access_time_raw = struct.unpack_from('<Q', data, 20)[0]
    write_time_raw = struct.unpack_from('<Q', data, 28)[0]
    
    target_path_len = struct.unpack_from('<I', data, 36)[0]
    hotkey = struct.unpack_from('<H', data, 40)[0]
    show_cmd = struct.unpack_from('<H', data, 42)[0]
    reserved1 = struct.unpack_from('<I', data, 44)[0]
    
    # We don't need all of these, but we need to know where Link Target ID List starts
    # The header is 76 bytes total
    if len(data) < 76:
        raise ValueError("File too small for LNK header")
    
    # Link Target ID List
    id_list_size = struct.unpack_from('<I', data, 48)[0]
    if len(data) < 76:
        raise ValueError("File too small")
    
    # Local Base Path
    local_base_size = struct.unpack_from('<I', data, 52)[0]
    
    # Relative Path
    relative_path_size = struct.unpack_from('<I', data, 56)[0]
    
    # Common Name Path
    common_name_size = struct.unpack_from('<I', data, 60)[0]
    
    # Icon Location
    icon_location_size = struct.unpack_from('<I', data, 64)[0]
    
    # Icon Index
    icon_index = struct.unpack_from('<I', data, 68)[0]
    
    # Command Line Arguments
    command_line_args_size = struct.unpack_from('<I', data, 72)[0]
    
    # Archive Size (file size)
    archive_size = struct.unpack_from('<I', data, 76)[0]
    
    archive_file_attributes = struct.unpack_from('<I', data, 80)[0]
    
    if len(data) < 88:
        raise ValueError("File too small for fixed header")
    
    # Now we're at offset 88, which is where the Link Target ID List data starts
    offset = 88
    
    # Link Target ID List
    if id_list_size > 0:
        if len(data) < offset + id_list_size:
            raise ValueError("Truncated Link Target ID List")
        offset += id_list_size
    
    # Local Base Path
    if local_base_size > 0:
        if len(data) < offset + local_base_size:
            raise ValueError("Truncated Local Base Path")
        offset += local_base_size
    
    # Relative Path
    relative_path = None
    if relative_path_size > 0:
        if len(data) < offset + relative_path_size:
            raise ValueError("Truncated Relative Path")
        rel_path_bytes = data[offset:offset + relative_path_size]
        # Relative path is a null-terminated string
        # Find the null terminator
        null_idx = rel_path_bytes.find(b'\x00')
        if null_idx >= 0:
            relative_path = rel_path_bytes[:null_idx].decode('utf-16-le', errors='replace')
        else:
            # No null terminator, use the whole thing
            relative_path = rel_path_bytes.decode('utf-16-le', errors='replace')
        offset += relative_path_size
    
    # Common Name Path
    if common_name_size > 0:
        if len(data) < offset + common_name_size:
            raise ValueError("Truncated Common Name Path")
        offset += common_name_size
    
    # Icon Location
    icon_location = None
    if icon_location_size > 0:
        if len(data) < offset + icon_location_size:
            raise ValueError("Truncated Icon Location")
        icon_loc_bytes = data[offset:offset + icon_location_size]
        null_idx = icon_loc_bytes.find(b'\x00')
        if null_idx >= 0:
            icon_location = icon_loc_bytes[:null_idx].decode('utf-16-le', errors='replace')
        else:
            icon_location = icon_loc_bytes.decode('utf-16-le', errors='replace')
        offset += icon_location_size
    
    # Icon Index is already parsed
    
    # Command Line Arguments
    command_line_arguments = None
    if command_line_args_size > 0:
        if len(data) < offset + command_line_args_size:
            raise ValueError("Truncated Command Line Arguments")
        cmd_bytes = data[offset:offset + command_line_args_size]
        null_idx = cmd_bytes.find(b'\x00')
        if null_idx >= 0:
            command_line_arguments = cmd_bytes[:null_idx].decode('utf-16-le', errors='replace')
        else:
            command_line_arguments = cmd_bytes.decode('utf-16-le', errors='replace')
        offset += command_line_args_size
    
    # Now we need to parse the variable data blocks to find Name String and Working Directory
    # The variable data blocks start after the fixed header
    # Each block: struct (DWORD size, WORD identifier)
    
    name_string = None
    working_dir = None
    
    # Check if file size is valid
    if archive_file_attributes & 0x10:  # FILE_ATTRIBUTE_ARCHIVE
        file_size = archive_size
    else:
        # If not archive, file size might be 0 or invalid
        file_size = archive_size
    
    # Parse variable data blocks
    # We need to be careful: the blocks may be malformed
    while offset < len(data):
        if offset + 6 > len(data):
            break  # Not enough bytes for block header
        
        block_size = struct.unpack_from('<I', data, offset)[0]
        block_id = struct.unpack_from('<H', data, offset + 4)[0]
        
        if block_size < 6:
            break  # Invalid block size
        
        # Block data starts at offset + 6, block total size is block_size
        block_data_start = offset + 6
        block_end = offset + block_size
        
        if block_end > len(data):
            # Truncated block
            break
        
        # Process known block types
        if block_id == 0x0001:  # ENVIRONMENT_PROPERTIES
            pass
        elif block_id == 0x0002:  # ICON
            pass
        elif block_id == 0x0003:  # COMMAND_LINE
            pass
        elif block_id == 0x0004:  # ICON_LOCATION
            pass
        elif block_id == 0x0005:  # TRACKING
            pass
        elif block_id == 0x0006:  # SPECIAL_FOLDER
            pass
        elif block_id == 0x0007:  # DATA_LINK_TARGET
            pass
        elif block_id == 0x0008:  # LIST_OF_APPLIED_PROPERTIES
            pass
        elif block_id == 0x0009:  # ICON_ID
            pass
        elif block_id == 0x000A:  # LOCALIZED_DESCRIPTION
            pass
        elif block_id == 0x000B:  # RELATIVE_PATH
            pass
        
        # Look for NAME_STRING (0x0014) and WORKING_DIR (0x0011)
        if block_id == 0x0014:  # NAME_STRING
            # The block contains a null-terminated UTF-16LE string
            name_bytes = data[block_data_start:block_end]
            null_idx = name_bytes.find(b'\x00\x00')
            if null_idx >= 0:
                name_string = name_bytes[:null_idx].decode('utf-16-le', errors='replace')
            else:
                name_string = name_bytes.decode('utf-16-le', errors='replace')
        
        elif block_id == 0x0011:  # WORKING_DIR
            # The block contains a null-terminated UTF-16LE string
            work_bytes = data[block_data_start:block_end]
            null_idx = work_bytes.find(b'\x00\x00')
            if null_idx >= 0:
                working_dir = work_bytes[:null_idx].decode('utf-16-le', errors='replace')
            else:
                working_dir = work_bytes.decode('utf-16-le', errors='replace')
        
        elif block_id == 0x000C:  # DATA_LINK_TARGET_INFO
            pass
        elif block_id == 0x000D:  # COMMON_NAME
            pass
        elif block_id == 0x000E:  # ICON_LOCATION
            pass
        elif block_id == 0x000F:  # TRACKING
            pass
        elif block_id == 0x0010:  # DATA_LINK_ICON
            pass
        elif block_id == 0x0012:  # DATA_LINK_ICON_INDEX
            pass
        elif block_id == 0x0013:  # DATA_LINK_ICON_SIZE
            pass
        elif block_id == 0x0015:  # DATA_LINK_ICON_FILE
            pass
        elif block_id == 0x0016:  # DATA_LINK_ICON_INDEX
            pass
        elif block_id == 0x0017:  # DATA_LINK_ICON_SIZE
            pass
        elif block_id == 0x0018:  # DATA_LINK_ICON_FILE
            pass
        elif block_id == 0x0019:  # DATA_LINK_ICON_INDEX
            pass
        elif block_id == 0x001A:  # DATA_LINK_ICON_SIZE
            pass
        elif block_id == 0x001B:  # DATA_LINK_ICON_FILE
            pass
        elif block_id == 0x001C:  # DATA_LINK_ICON_INDEX
            pass
        elif block_id == 0x001D:  # DATA_LINK_ICON_SIZE
            pass
        elif block_id == 0x001E:  # DATA_LINK_ICON_FILE
            pass
        elif block_id == 0x001F:  # DATA_LINK_ICON_INDEX
            pass
        elif block_id == 0x0020:  # DATA_LINK_ICON_SIZE
            pass
        elif block_id == 0x0021:  # DATA_LINK_ICON_FILE
            pass
        
        # Move to next block
        offset = block_end
    
    # Convert FILETIME to ISO 8601
    def filetime_to_iso(ft):
        if ft == 0:
            return None
        # FILETIME is 100-nanosecond intervals since January 1, 1601
        # Convert to seconds
        seconds = ft / 10000000.0
        # Windows epoch is 1601-01-01, Unix epoch is 1970-01-01
        # Difference: 369 * 365 days + 89 leap days = 134774 days
        # 134774 * 86400 = 11644473600 seconds
        unix_time = seconds - 11644473600.0
        dt = datetime.fromtimestamp(unix_time, tz=timezone.utc)
        return dt.isoformat()
    
    creation_time = filetime_to_iso(creation_time_raw)
    access_time = filetime_to_iso(access_time_raw)
    write_time = filetime_to_iso(write_time_raw)
    
    # Determine icon index - if icon_location is present, icon_index might be meaningful
    # Otherwise, icon_index from header
    if icon_index == 0xFFFFFFFF:
        icon_index_val = 0
    else:
        icon_index_val = icon_index
    
    # For file_size: if the file is not an archive, the size might be unreliable
    # But we report what's in the file
    # If file attributes don't include archive, file_size might be 0 or invalid
    # We'll report the value as-is
    
    return {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index_val,
        "creation_time": creation_time,
        "access_time": access_time,
        "write_time": write_time
    }


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
    
    try:
        result = parse_lnk(data)
        print(json.dumps(result))
        sys.exit(0)
    except ValueError as e:
        fail(str(e))
    except Exception as e:
        fail(f"Parse error: {e}")


if __name__ == '__main__':
    main()