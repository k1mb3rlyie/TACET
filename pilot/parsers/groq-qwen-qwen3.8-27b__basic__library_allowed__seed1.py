#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files.
Extracts metadata from LNK files for digital forensics use.
"""

import sys
import struct
import json
import os
from datetime import datetime, timezone


def parse_filetime(ft):
    """
    Parse a Windows FILETIME (100ns intervals since 1601-01-01) to ISO 8601 UTC.
    Returns None if the value is 0 (which means no time).
    """
    if ft == 0:
        return None
    # FILETIME is 100ns intervals since 1601-01-01
    # Convert to seconds since epoch (1970-01-01)
    # Difference between 1601-01-01 and 1970-01-01 is 11644473600 seconds
    delta = 11644473600
    total_ns = ft * 100
    # Convert to seconds and microseconds
    total_seconds = total_ns // 1000000000
    remaining_ns = total_ns % 1000000000
    microseconds = remaining_ns // 1000
    
    # Check if this is a valid timestamp
    # A reasonable range for a timestamp
    if total_seconds < 0 or total_seconds > 4102444800:  # Year 2100
        return None
    
    epoch_seconds = total_seconds - delta
    if epoch_seconds < 0:
        # Before 1970, still valid but rare
        pass
    
    try:
        dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
        # Format with microseconds if present
        if microseconds:
            return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f"{microseconds:06d}" + '+00:00'
        else:
            return dt.strftime('%Y-%m-%dT%H:%M:%S+00:00')
    except (OverflowError, OSError, ValueError):
        return None


def parse_lnk(data):
    """
    Parse LNK file data and return a dictionary of fields.
    Raises ValueError on malformed data.
    """
    if len(data) < 76:
        raise ValueError("File too small to be a valid LNK file")
    
    # Verify header
    header = data[:76]
    header_id = header[0:4]
    if header_id != b'\x4c\x00\x00\x00':
        raise ValueError("Invalid LNK header signature")
    
    # Link CLSID should be 0114020000000000C000000000000046
    expected_clsid = bytes([
        0x01, 0x14, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x46, 0x00
    ])
    if header[4:20] != expected_clsid:
        raise ValueError("Invalid Link CLSID")
    
    # Parse header fields
    link_flags = struct.unpack_from('<I', header, 20)[0]
    file_type = struct.unpack_from('<I', header, 24)[0]
    item_id = struct.unpack_from('<I', header, 28)[0]
    creation_time = struct.unpack_from('<Q', header, 32)[0]
    access_time = struct.unpack_from('<Q', header, 40)[0]
    write_time = struct.unpack_from('<Q', header, 48)[0]
    file_size = struct.unpack_from('<Q', header, 56)[0]
    icon_index = struct.unpack_from('<I', header, 64)[0]
    command_line = struct.unpack_from('<I', header, 68)[0]
    driver = struct.unpack_from('<I', header, 72)[0]
    
    # Define flag bits
    LINKINFO_CONTEXT = 0x00000001
    ICONLOCATION_CONTEXT = 0x00000002
    COMMANDLINE_CONTEXT = 0x00000004
    ICON_ENVIRONMENT = 0x00000008
    UNKNOWN_CONTEXT = 0x00000010
    RELATIVEPATH_CONTEXT = 0x00000020
    WORKINGDIR_CONTEXT = 0x00000040
    DDRAW_DESTINATION = 0x00000080
    DISPLAYNAME_CONTEXT = 0x00000100
    RELIDLIST_CONTEXT = 0x00000200
    LOCALBASEPATH_CONTEXT = 0x00000400
    NETWORKRELIDLIST_CONTEXT = 0x00000800
    NETWORKPROVIDER_ID_CONTEXT = 0x00001000
    COMMANDLINE_ARGUMENTS = 0x00002000
    ICONLOCATION = 0x00004000
    UNKNOWN_FLAGS = 0x00008000
    LOCALBASEPATH = 0x00010000
    ICON_ENVIRONMENT = 0x00020000
    NETWORK_PROVIDER_ID = 0x00040000
    NETWORK_NAME = 0x00080000
    MAPPED_NETWORK_DRIVE = 0x00100000
    UNIVERSAL_NAME_RESOLVED = 0x00200000
    DDEINFO_CONTEXT = 0x00400000
    NOUIACCESS_CONTEXT = 0x00800000
    ICONLOCATION_CONTEXT_OLD = 0x01000000
    UNKNOWN_CONTEXT_OLD = 0x02000000
    COMMANDLINE_ARGUMENTS_OLD = 0x04000000
    ICON_LOCATION_OLD = 0x08000000
    ICON_ENVIRONMENT_OLD = 0x10000000
    UNKNOWN_FLAGS_OLD = 0x20000000
    NETWORK_RELIDLIST_CONTEXT_OLD = 0x40000000
    NETWORK_PROVIDER_ID_CONTEXT_OLD = 0x80000000
    
    # Initialize result fields as None
    result = {
        'name_string': None,
        'relative_path': None,
        'working_dir': None,
        'command_line_arguments': None,
        'icon_location': None,
        'file_size': file_size,
        'icon_index': icon_index,
        'creation_time': parse_filetime(creation_time),
        'access_time': parse_filetime(access_time),
        'write_time': parse_filetime(write_time),
    }
    
    # Offset after header
    offset = 76
    
    # Helper to read UTF-16 string at offset, returns (string, new_offset)
    def read_utf16_string(data, offset, max_len=None):
        """Read a null-terminated UTF-16LE string."""
        if offset >= len(data):
            raise ValueError("Offset out of bounds")
        
        # Read until null terminator
        end = offset
        while end + 1 < len(data):
            if data[end] == 0 and data[end + 1] == 0:
                break
            end += 2
            if max_len is not None and end - offset > max_len:
                break
        
        if end + 1 >= len(data):
            raise ValueError("Unterminated string")
        
        string_data = data[offset:end]
        try:
            s = string_data.decode('utf-16-le')
        except UnicodeDecodeError:
            # Try to be lenient but still validate
            s = string_data.decode('utf-16-le', errors='replace')
        
        return s, end + 2
    
    # Parse additional data blocks based on flags
    # The order of blocks in the file is fixed:
    # 1. LinkInfo (LINKINFO_CONTEXT)
    # 2. StringData (DISPLAYNAME_CONTEXT, RELATIVEPATH_CONTEXT, WORKINGDIR_CONTEXT, COMMANDLINE_ARGUMENTS, ICONLOCATION)
    # 3. IconLocation (ICONLOCATION_CONTEXT)
    # 4. IconEnvironment (ICON_ENVIRONMENT / ICON_ENVIRONMENT_OLD)
    # 5. IconLocationOld (ICON_LOCATION_OLD)
    # 6. CommandTail (COMMANDLINE_ARGUMENTS_OLD)
    # 7. DDEInfo (DDEINFO_CONTEXT)
    # 8. NoEntryAccess (NOUIACCESS_CONTEXT)
    # 9. RelIdList (RELIDLIST_CONTEXT / NETWORK_RELIDLIST_CONTEXT_OLD)
    # 10. LocalBasePath (LOCALBASEPATH_CONTEXT / LOCAL_BASEPATH)
    # 11. NetworkProviderId (NETWORKPROVIDER_ID_CONTEXT / NETWORK_PROVIDER_ID_CONTEXT_OLD)
    # 12. NetworkName (NETWORK_NAME)
    # 13. MappedNetworkDrive (MAPPED_NETWORK_DRIVE)
    # 14. UniversalNameResolved (UNIVERSAL_NAME_RESOLVED)
    # 15. IconLocation (ICONLOCATION_CONTEXT) - actually this is the one we care about
    
    # Actually, let me re-read the spec more carefully.
    
    # LinkInfo block
    if link_flags & LINKINFO_CONTEXT:
        if offset + 4 > len(data):
            raise ValueError("Truncated LinkInfo block")
        linkinfo_length = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if offset + linkinfo_length > len(data):
            raise ValueError("LinkInfo block exceeds file size")
        # We don't need to parse LinkInfo details for our output
        offset += linkinfo_length
    
    # String Data Block
    # This block contains:
    # - Common String Data Table (if DISPLAYNAME_CONTEXT or RELATIVEPATH_CONTEXT or WORKINGDIR_CONTEXT or COMMANDLINE_ARGUMENTS or ICONLOCATION)
    # - Local Base Path (if LOCALBASEPATH_CONTEXT or LOCAL_BASEPATH)
    # - Relative Path (if RELATIVEPATH_CONTEXT)
    # - Working Directory (if WORKINGDIR_CONTEXT)
    # - Command Line Arguments (if COMMANDLINE_ARGUMENTS or COMMANDLINE_ARGUMENTS_OLD)
    # - Icon Location (if ICONLOCATION or ICON_LOCATION_OLD)
    # - Icon Environment (if ICON_ENVIRONMENT or ICON_ENVIRONMENT_OLD)
    
    has_string_data = (
        (link_flags & DISPLAYNAME_CONTEXT) or
        (link_flags & RELATIVEPATH_CONTEXT) or
        (link_flags & WORKINGDIR_CONTEXT) or
        (link_flags & COMMANDLINE_ARGUMENTS) or
        (link_flags & ICONLOCATION) or
        (link_flags & COMMANDLINE_ARGUMENTS_OLD) or
        (link_flags & ICON_LOCATION_OLD) or
        (link_flags & ICON_ENVIRONMENT) or
        (link_flags & ICON_ENVIRONMENT_OLD) or
        (link_flags & LOCALBASEPATH_CONTEXT) or
        (link_flags & LOCAL_BASEPATH)
    )
    
    if has_string_data:
        # Common String Data Table
        # First 2 bytes: count of strings in the table
        if offset + 2 > len(data):
            raise ValueError("Truncated string data block")
        string_count = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        
        # Read all strings in the table
        strings = []
        for i in range(string_count):
            if offset + 2 > len(data):
                raise ValueError("Truncated string table")
            string_length = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if offset + string_length * 2 > len(data):
                raise ValueError("String table entry exceeds file size")
            string_data = data[offset:offset + string_length * 2]
            try:
                s = string_data.decode('utf-16-le')
            except UnicodeDecodeError:
                s = string_data.decode('utf-16-le', errors='replace')
            strings.append(s)
            offset += string_length * 2
        
        # Now read the individual string references
        # Each is a 2-byte index into the string table (0xFFFF means no string)
        
        # Local Base Path
        if link_flags & (LOCALBASEPATH_CONTEXT | LOCAL_BASEPATH):
            if offset + 2 > len(data):
                raise ValueError("Truncated local base path reference")
            idx = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if idx != 0xFFFF and idx < len(strings):
                pass  # We don't output local base path
        
        # Relative Path
        if link_flags & RELATIVEPATH_CONTEXT:
            if offset + 2 > len(data):
                raise ValueError("Truncated relative path reference")
            idx = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if idx != 0xFFFF and idx < len(strings):
                result['relative_path'] = strings[idx]
        
        # Working Directory
        if link_flags & WORKINGDIR_CONTEXT:
            if offset + 2 > len(data):
                raise ValueError("Truncated working directory reference")
            idx = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if idx != 0xFFFF and idx < len(strings):
                result['working_dir'] = strings[idx]
        
        # Command Line Arguments
        if link_flags & (COMMANDLINE_ARGUMENTS | COMMANDLINE_ARGUMENTS_OLD):
            if offset + 2 > len(data):
                raise ValueError("Truncated command line arguments reference")
            idx = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if idx != 0xFFFF and idx < len(strings):
                result['command_line_arguments'] = strings[idx]
        
        # Icon Location
        if link_flags & (ICONLOCATION | ICON_LOCATION_OLD):
            if offset + 2 > len(data):
                raise ValueError("Truncated icon location reference")
            idx = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if idx != 0xFFFF and idx < len(strings):
                result['icon_location'] = strings[idx]
        
        # Icon Environment
        if link_flags & (ICON_ENVIRONMENT | ICON_ENVIRONMENT_OLD):
            if offset + 2 > len(data):
                raise ValueError("Truncated icon environment reference")
            idx = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            # We don't output icon environment
    
    # Icon Location block (separate from string data)
    # This is a different block that comes after the string data block
    # Format: 4 bytes length, 4 bytes icon index, then null-terminated UTF-16 string
    if link_flags & ICONLOCATION_CONTEXT:
        if offset + 8 > len(data):
            raise ValueError("Truncated icon location block")
        block_length = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        icon_idx = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        # The rest of the block is a null-terminated UTF-16 string
        if offset + block_length > len(data):
            raise ValueError("Icon location block exceeds file size")
        # Read the string part (block_length - 8 bytes)
        str_end = offset + block_length
        if str_end > len(data):
            raise ValueError("Icon location string exceeds file size")
        # Find null terminator
        str_data = data[offset:str_end]
        # Decode as UTF-16LE, stripping null terminator
        # The string is null-terminated, so we need to handle that
        # Find the null terminator
        end = 0
        while end + 1 < len(str_data):
            if str_data[end] == 0 and str_data[end + 1] == 0:
                break
            end += 2
        if end < len(str_data):
            str_data = str_data[:end]
        try:
            result['icon_location'] = str_data.decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16 in icon location")
        offset += block_length
    
    # Icon Environment block
    if link_flags & ICON_ENVIRONMENT:
        if offset + 4 > len(data):
            raise ValueError("Truncated icon environment block")
        block_length = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if offset + block_length > len(data):
            raise ValueError("Icon environment block exceeds file size")
        offset += block_length
    
    # We don't need to parse the remaining blocks for our output fields
    
    return result


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: parser.py <path-to-lnk-file>"}))
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        if not os.path.isfile(filepath):
            print(json.dumps({"error": "File not found"}))
            sys.exit(0)
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        if len(data) < 76:
            print(json.dumps({"error": "File too small to be a valid LNK file"}))
            sys.exit(0)
        
        result = parse_lnk(data)
        
        # Build the output JSON
        output = {
            "name_string": result['name_string'],
            "relative_path": result['relative_path'],
            "working_dir": result['working_dir'],
            "command_line_arguments": result['command_line_arguments'],
            "icon_location": result['icon_location'],
            "file_size": result['file_size'],
            "icon_index": result['icon_index'],
            "creation_time": result['creation_time'],
            "access_time": result['access_time'],
            "write_time": result['write_time'],
        }
        
        print(json.dumps(output))
        sys.exit(0)
    
    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {str(e)}"}))
        sys.exit(0)


if __name__ == '__main__':
    main()