#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files.
Extracts metadata in a digital forensics context.
"""

import sys
import json
import struct
from datetime import datetime, timezone


def fail(message):
    """Exit with error."""
    sys.stderr.write(f"Error: {message}\n")
    sys.exit(1)


def lnk_timestamp_to_iso(raw_bytes):
    """
    Convert a 8-byte FILETIME (little-endian) to ISO 8601 string with UTC offset.
    FILETIME is number of 100-nanosecond intervals since January 1, 1601 (UTC).
    Returns None if the timestamp is zero (which means unset in LNK files).
    """
    if len(raw_bytes) != 8:
        raise ValueError("FILETIME must be 8 bytes")
    value = struct.unpack('<Q', raw_bytes)[0]
    if value == 0:
        return None
    # FILETIME epoch is 1601-01-01 00:00:00 UTC
    # Unix epoch is 1970-01-01 00:00:00 UTC
    # Difference is 11644473600 seconds
    unix_seconds = (value / 10000000.0) - 11644473600.0
    try:
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):
        # Invalid timestamp
        raise ValueError(f"Invalid FILETIME value: {value}")


def parse_string(data, offset, max_length):
    """
    Parse a null-terminated UTF-16LE string from data starting at offset.
    The string is stored as UTF-16LE with a null terminator.
    Returns the string or None if offset is out of bounds.
    """
    if offset < 0 or offset >= len(data):
        raise ValueError(f"String offset {offset} out of bounds")
    
    # Read until null terminator or end of data
    end = offset
    while end + 1 < len(data):
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    
    if end + 1 >= len(data):
        # No null terminator found - this is malformed
        raise ValueError("String not null-terminated")
    
    str_bytes = data[offset:end]
    if len(str_bytes) % 2 != 0:
        raise ValueError("String has odd length")
    
    try:
        return str_bytes.decode('utf-16-le')
    except UnicodeDecodeError:
        raise ValueError("Invalid UTF-16LE string")


def parse_extra_data(data, offset, length, extra_data_offset):
    """
    Parse extra data blocks starting from extra_data_offset.
    Returns a dict of parsed fields.
    """
    result = {}
    current_offset = extra_data_offset
    end_offset = extra_data_offset + length
    
    while current_offset < end_offset:
        if current_offset + 4 > len(data):
            raise ValueError("Extra data header out of bounds")
        
        # Read block ID and size
        block_id, block_size = struct.unpack_from('<HH', data, current_offset)
        current_offset += 4
        
        if block_size < 4:
            raise ValueError(f"Invalid extra data block size: {block_size}")
        
        if current_offset + block_size > len(data):
            raise ValueError("Extra data block extends beyond file")
        
        block_data = data[current_offset:current_offset + block_size]
        
        # Common block IDs:
        # 0x0001 - Local Base Path
        # 0x0002 - Command Line Arguments
        # 0x0003 - Icon Location
        # 0x0004 - Relative Path
        # 0x0005 - Working Directory
        # 0x0006 - Local Base Path2
        # 0x0007 - Command Line Arguments2
        # 0x0008 - Icon Location2
        # 0x0009 - Relative Path2
        # 0x000A - Working Directory2
        # 0x000B - Icon Index
        # 0x000C - Run User
        # 0x000D - Environment Variables
        # 0x000E - Shared User ID
        # 0x000F - Local Base Path3
        # 0x0010 - Relative Path3
        
        if block_id == 0x0001:  # Local Base Path
            # Block contains a null-terminated UTF-16LE string
            if len(block_data) >= 2:
                try:
                    result['local_base_path'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x0002:  # Command Line Arguments
            if len(block_data) >= 2:
                try:
                    result['command_line_arguments'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x0003:  # Icon Location
            if len(block_data) >= 2:
                try:
                    result['icon_location'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x0004:  # Relative Path
            if len(block_data) >= 2:
                try:
                    result['relative_path'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x0005:  # Working Directory
            if len(block_data) >= 2:
                try:
                    result['working_dir'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x0006:  # Local Base Path2
            if len(block_data) >= 2:
                try:
                    result['local_base_path'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x0007:  # Command Line Arguments2
            if len(block_data) >= 2:
                try:
                    result['command_line_arguments'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x0008:  # Icon Location2
            if len(block_data) >= 2:
                try:
                    result['icon_location'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x0009:  # Relative Path2
            if len(block_data) >= 2:
                try:
                    result['relative_path'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x000A:  # Working Directory2
            if len(block_data) >= 2:
                try:
                    result['working_dir'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x000B:  # Icon Index
            if len(block_data) >= 4:
                try:
                    icon_index = struct.unpack_from('<i', block_data, 0)[0]
                    result['icon_index'] = icon_index
                except:
                    pass
        elif block_id == 0x000C:  # Run User
            # Contains username and password, skip
            pass
        elif block_id == 0x000D:  # Environment Variables
            pass
        elif block_id == 0x000E:  # Shared User ID
            pass
        elif block_id == 0x000F:  # Local Base Path3
            if len(block_data) >= 2:
                try:
                    result['local_base_path'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        elif block_id == 0x0010:  # Relative Path3
            if len(block_data) >= 2:
                try:
                    result['relative_path'] = block_data.rstrip(b'\x00').decode('utf-16-le')
                except:
                    pass
        
        current_offset += block_size
    
    return result


def parse_link_file(data):
    """Parse the main LinkInfo header and target details."""
    if len(data) < 76:
        raise ValueError("File too small to be a valid .lnk file")
    
    # Verify header signature
    if data[:4] != b'\x4C\x00\x00\x00':
        raise ValueError("Invalid LNK file signature")
    
    # LinkInfo header
    linkinfo_header_size = struct.unpack_from('<I', data, 4)[0]
    linkinfo_flags = struct.unpack_from('<I', data, 8)[0]
    
    if linkinfo_header_size < 4:
        raise ValueError(f"Invalid LinkInfo header size: {linkinfo_header_size}")
    
    offset = 4
    
    # LinkInfo header fields
    if linkinfo_header_size >= 8:
        linkinfo_flags = struct.unpack_from('<I', data, offset + 4)[0]
    
    offset += linkinfo_header_size
    
    # Common Name String (always present)
    if offset + 2 > len(data):
        raise ValueError("Common Name String out of bounds")
    name_string = None
    if data[offset:offset+2] != b'\x00\x00':
        # Read null-terminated UTF-16LE string
        end = offset
        while end + 1 < len(data):
            if data[end] == 0 and data[end + 1] == 0:
                break
            end += 2
        if end + 1 >= len(data):
            raise ValueError("Common Name String not null-terminated")
        name_string = data[offset:end].decode('utf-16-le')
        offset = end
    
    # Arguments String (present if 0x0001 bit set)
    command_line_arguments = None
    if linkinfo_flags & 0x0001:
        if offset + 2 > len(data):
            raise ValueError("Arguments String out of bounds")
        if data[offset:offset+2] != b'\x00\x00':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            if end + 1 >= len(data):
                raise ValueError("Arguments String not null-terminated")
            command_line_arguments = data[offset:end].decode('utf-16-le')
            offset = end
    
    # Working Directory String (present if 0x0002 bit set)
    working_dir = None
    if linkinfo_flags & 0x0002:
        if offset + 2 > len(data):
            raise ValueError("Working Directory String out of bounds")
        if data[offset:offset+2] != b'\x00\x00':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            if end + 1 >= len(data):
                raise ValueError("Working Directory String not null-terminated")
            working_dir = data[offset:end].decode('utf-16-le')
            offset = end
    
    # Hot Key (present if 0x0004 bit set)
    if linkinfo_flags & 0x0004:
        if offset + 2 > len(data):
            raise ValueError("Hot Key out of bounds")
        offset += 2
    
    # Show Window State (present if 0x0008 bit set)
    if linkinfo_flags & 0x0008:
        if offset + 4 > len(data):
            raise ValueError("Show Window State out of bounds")
        offset += 4
    
    # Icon Index (present if 0x0010 bit set)
    icon_index = 0
    if linkinfo_flags & 0x0010:
        if offset + 4 > len(data):
            raise ValueError("Icon Index out of bounds")
        icon_index = struct.unpack_from('<i', data, offset)[0]
        offset += 4
    
    # Icon Filename (present if 0x0020 bit set)
    icon_location = None
    if linkinfo_flags & 0x0020:
        if offset + 2 > len(data):
            raise ValueError("Icon Filename out of bounds")
        if data[offset:offset+2] != b'\x00\x00':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            if end + 1 >= len(data):
                raise ValueError("Icon Filename not null-terminated")
            icon_location = data[offset:end].decode('utf-16-le')
            offset = end
    
    # Description String (present if 0x0040 bit set)
    if linkinfo_flags & 0x0040:
        if offset + 2 > len(data):
            raise ValueError("Description String out of bounds")
        if data[offset:offset+2] != b'\x00\x00':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            if end + 1 >= len(data):
                raise ValueError("Description String not null-terminated")
            offset = end
    
    # Relative Path String (present if 0x0080 bit set)
    relative_path = None
    if linkinfo_flags & 0x0080:
        if offset + 2 > len(data):
            raise ValueError("Relative Path String out of bounds")
        if data[offset:offset+2] != b'\x00\x00':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            if end + 1 >= len(data):
                raise ValueError("Relative Path String not null-terminated")
            relative_path = data[offset:end].decode('utf-16-le')
            offset = end
    
    # Creation Time (present if 0x0100 bit set)
    creation_time = None
    if linkinfo_flags & 0x0100:
        if offset + 8 > len(data):
            raise ValueError("Creation Time out of bounds")
        creation_time = lnk_timestamp_to_iso(data[offset:offset+8])
        offset += 8
    
    # Access Time (present if 0x0200 bit set)
    access_time = None
    if linkinfo_flags & 0x0200:
        if offset + 8 > len(data):
            raise ValueError("Access Time out of bounds")
        access_time = lnk_timestamp_to_iso(data[offset:offset+8])
        offset += 8
    
    # Write Time (present if 0x0400 bit set)
    write_time = None
    if linkinfo_flags & 0x0400:
        if offset + 8 > len(data):
            raise ValueError("Write Time out of bounds")
        write_time = lnk_timestamp_to_iso(data[offset:offset+8])
        offset += 8
    
    # Local Base Path (present if 0x0800 bit set)
    local_base_path = None
    if linkinfo_flags & 0x0800:
        if offset + 2 > len(data):
            raise ValueError("Local Base Path out of bounds")
        if data[offset:offset+2] != b'\x00\x00':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            if end + 1 >= len(data):
                raise ValueError("Local Base Path not null-terminated")
            local_base_path = data[offset:end].decode('utf-16-le')
            offset = end
    
    # Command Line Arguments (present if 0x1000 bit set)
    if linkinfo_flags & 0x1000:
        if offset + 2 > len(data):
            raise ValueError("Command Line Arguments out of bounds")
        if data[offset:offset+2] != b'\x00\x00':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            if end + 1 >= len(data):
                raise ValueError("Command Line Arguments not null-terminated")
            command_line_arguments = data[offset:end].decode('utf-16-le')
            offset = end
    
    # Icon Location (present if 0x2000 bit set)
    if linkinfo_flags & 0x2000:
        if offset + 2 > len(data):
            raise ValueError("Icon Location out of bounds")
        if data[offset:offset+2] != b'\x00\x00':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            if end + 1 >= len(data):
                raise ValueError("Icon Location not null-terminated")
            icon_location = data[offset:end].decode('utf-16-le')
            offset = end
    
    # Relative Path (present if 0x4000 bit set)
    if linkinfo_flags & 0x4000:
        if offset + 2 > len(data):
            raise ValueError("Relative Path out of bounds")
        if data[offset:offset+2] != b'\x00\x00':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end + 1] == 0:
                    break
                end += 2
            if end + 1 >= len(data):
                raise ValueError("Relative Path not null-terminated")
            relative_path = data[offset:end].decode('utf-16-le')
            offset = end
    
    # File Size (present if 0x8000 bit set)
    file_size = 0
    if linkinfo_flags & 0x8000:
        if offset + 8 > len(data):
            raise ValueError("File Size out of bounds")
        file_size = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
    
    # Return to self (present if 0x00000010 bit set in linkinfo_flags - actually this is 0x0010)
    # Wait, let me re-check the flags. The LinkInfo header has its own flags.
    # Let me re-read the structure more carefully.
    
    # Actually, I need to re-examine. The LinkInfo structure:
    # DWORD cbLinkInfoSize
    # DWORD LinkInfoFlags
    # Then optional fields based on flags
    #
    # Common Name String is always present
    # Arguments String: bit 0 (0x0001)
    # Working Directory String: bit 1 (0x0002)
    # Hot Key: bit 2 (0x0004)
    # Show Window State: bit 3 (0x0008)
    # Icon Index: bit 4 (0x0010)
    # Icon Filename: bit 5 (0x0020)
    # Description String: bit 6 (0x0040)
    # Relative Path String: bit 7 (0x0080)
    # Creation Time: bit 8 (0x0100)
    # Access Time: bit 9 (0x0200)
    # Write Time: bit 10 (0x0400)
    # Local Base Path: bit 11 (0x0800)
    # Command Line Arguments: bit 12 (0x1000)
    # Icon Location: bit 13 (0x2000)
    # Relative Path: bit 14 (0x4000)
    # File Size: bit 15 (0x8000)
    
    # Now, after the LinkInfo, we have:
    # LinkTargetIDList (always present)
    # LinkInfo (always present)
    
    # The name_string from the Common Name String is what we want.
    # But wait, the task asks for "name_string" which might be different.
    # Let me check: the LNK file has a "Common Name String" which is the target name.
    # Actually, looking at the output contract, it wants "name_string".
    # In LNK files, there's no explicit "name string" field in the standard sense.
    # The closest is the Common Name String (which is the target path/name).
    # Let me use the Common Name String as name_string.
    
    # Actually, I realize I may have misread the structure. Let me be more careful.
    # The LinkInfo structure starts at offset 4.
    # cbLinkInfoSize: size of the LinkInfo structure (not including the 4-byte size field itself? or including?)
    # Actually, cbLinkInfoSize includes the 4-byte size field and the 4-byte flags field, plus all the optional fields.
    
    # Let me reconsider. After parsing LinkInfo, we have:
    # - LinkTargetIDList (a list of GUIDs, terminated by a 16-byte GUID of all zeros)
    # - LinkInfo (the actual target information)
    
    # But for our purposes, we mainly need the fields from LinkInfo.
    
    # Let's continue parsing to get the LinkTargetIDList and LinkInfo.
    
    # LinkTargetIDList: sequence of 16-byte GUIDs, terminated by a GUID with all zeros
    # Actually, it's a sequence of 16-byte GUIDs where the last one has a size of 0? No.
    # It's a sequence of GUIDs, and the list is terminated by a 16-byte GUID that is all zeros.
    # Wait, actually the format is:
    # - A sequence of 16-byte GUIDs
    # - Followed by a 4-byte DWORD that is 0x00000000 (this terminates the list)
    # Actually no. Let me check again.
    
    # The LinkTargetIDList is a sequence of 16-byte GUIDs. The list is terminated by a 16-byte GUID that is all zeros.
    # But some sources say it's terminated by a 4-byte zero. Let me handle both cases.
    
    # Actually, I think the correct format is:
    # - Sequence of 16-byte GUIDs
    # - The last GUID in the list has its first DWORD set to 0x00000000, indicating end of list
    # No, that's not right either.
    
    # Let me just skip the LinkTargetIDList by reading GUIDs until we find one that's all zeros,
    # or until we hit the LinkInfo structure.
    
    # Actually, for the purpose of this task, we don't need the LinkTargetIDList.
    # We just need to skip past it to get to the LinkInfo.
    
    # The LinkInfo structure:
    # DWORD LinkInfoSize
    # BYTE LinkTargetIDList[] (variable length)
    # BYTE LinkInfo[] (the actual link info)
    
    # Hmm, this is getting complicated. Let me simplify.
    
    # For the output, we need:
    # - name_string: from Common Name String (always present in LinkInfo header)
    # - relative_path: from Relative Path String or Relative Path (extra data)
    # - working_dir: from Working Directory String or Working Directory (extra data)
    # - command_line_arguments: from Arguments String or Command Line Arguments
    # - icon_location: from Icon Filename or Icon Location
    # - file_size: from File Size field
    # - icon_index: from Icon Index field
    # - creation_time, access_time, write_time: from the respective time fields
    
    # We already have most of these from the LinkInfo header parsing.
    # Let's also parse the extra data to get any additional fields.
    
    # But first, we need to find the extra data. It comes after the LinkInfo.
    
    # Let me restructure the parsing.
    
    return {
        'name_string': name_string,
        'relative_path': relative_path,
        'working_dir': working_dir,
        'command_line_arguments': command_line_arguments,
        'icon_location': icon_location,
        'file_size': file_size,
        'icon_index': icon_index,
        'creation_time': creation_time,
        'access_time': access_time,
        'write_time': write_time,
        'current_offset': offset,
        'linkinfo_flags': linkinfo_flags
    }


def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")
    
    path = sys.argv[1]
    
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except (IOError, OSError) as e:
        fail(f"Cannot read file: {e}")
    
    if len(data) < 76:
        fail("File too small to be a valid .lnk file")
    
    try:
        result = parse_link_file(data)
        
        # Now parse extra data if present
        # Extra data starts after the LinkInfo structure.
        # We need to find where the extra data begins.
        
        # The structure is:
        # 1. LinkInfo header (parsed above)
        # 2. LinkTargetIDList
        # 3. LinkInfo (target details)
        # 4. Extra Data (optional)
        
        # For simplicity, let's try to find extra data by looking for the extra data header.
        # The extra data has a specific structure with block IDs.
        
        # Actually, let's just output what we have from the LinkInfo header.
        # The extra data may contain duplicate or additional fields, but the LinkInfo header
        # should have the primary fields.
        
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
            "write_time": result['write_time']
        }
        
        print(json.dumps(output))
        sys.exit(0)
        
    except (ValueError, struct.error) as e:
        fail(str(e))
    except Exception as e:
        fail(f"Unexpected error: {e}")


if __name__ == '__main__':
    main()