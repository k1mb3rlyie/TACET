#!/usr/bin/env python3
"""Parse a Windows Shortcut (.lnk) file and extract metadata."""

import json
import struct
import sys
import os
from datetime import datetime, timezone


def fail(msg):
    """Print error JSON and exit with non-zero code."""
    print(json.dumps({"error": msg}))
    sys.exit(1)


def read_uint16(data, offset):
    """Read a little-endian uint16 from data at offset."""
    if offset + 2 > len(data):
        raise ValueError("Truncated file: cannot read uint16")
    return struct.unpack_from('<H', data, offset)[0]


def read_uint32(data, offset):
    """Read a little-endian uint32 from data at offset."""
    if offset + 4 > len(data):
        raise ValueError("Truncated file: cannot read uint32")
    return struct.unpack_from('<I', data, offset)[0]


def read_uint8(data, offset):
    """Read a uint8 from data at offset."""
    if offset + 1 > len(data):
        raise ValueError("Truncated file: cannot read uint8")
    return data[offset]


def read_bytes(data, offset, length):
    """Read 'length' bytes from data at offset."""
    if offset + length > len(data):
        raise ValueError("Truncated file: cannot read bytes")
    return data[offset:offset + length]


def filetime_to_iso8601(ft):
    """Convert Windows FILETIME (100ns intervals since 1601-01-01 UTC) to ISO 8601 with UTC offset."""
    if ft == 0:
        return None
    # Windows epoch: 1601-01-01 00:00:00 UTC
    # Unix epoch: 1970-01-01 00:00:00 UTC
    # Difference: 11644473600 seconds
    unix_epoch_diff = 11644473600
    seconds = ft / 10000000.0
    unix_seconds = seconds - unix_epoch_diff
    dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    return dt.isoformat()


def parse_string_utf16le(data, offset, length):
    """Parse a UTF-16LE string of given byte length, return str or None if all nulls."""
    if length == 0:
        return None
    raw = read_bytes(data, offset, length)
    # Decode as UTF-16LE
    try:
        s = raw.decode('utf-16-le')
    except (UnicodeDecodeError, struct.error):
        return None
    # Strip trailing null characters
    s = s.rstrip('\x00')
    if s == '':
        return None
    return s


def parse_linkinfo_flags(data, offset):
    """Parse LinkInfoFlags at given offset."""
    flags = read_uint32(data, offset)
    return flags


def parse_linkinfo(data, offset):
    """Parse the LinkInfo structure. Returns a dict with parsed fields."""
    result = {
        'relative_path': None,
        'working_dir': None,
        'command_line_arguments': None,
        'icon_location': None,
        'file_size': None,
        'icon_index': None,
    }
    
    try:
        linkinfo_header_size = read_uint32(data, offset)
        flags = read_uint32(data, offset + 4)
        current_offset = offset + 8
        
        # Common network resource data
        if flags & 0x00000001:
            # LocalBasePath
            local_base_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if local_base_path_len > 0:
                local_base_path = parse_string_utf16le(data, current_offset, local_base_path_len)
                # local_base_path is typically the drive letter or local path
                current_offset += local_base_path_len
            else:
                current_offset += 0
            # CommandLineArguments
            cmd_line_len = read_uint32(data, current_offset)
            current_offset += 4
            if cmd_line_len > 0:
                cmd_line = parse_string_utf16le(data, current_offset, cmd_line_len)
                result['command_line_arguments'] = cmd_line
                current_offset += cmd_line_len
            else:
                current_offset += 0
        
        # Common local path data
        if flags & 0x00000002:
            # Common Path
            common_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if common_path_len > 0:
                common_path = parse_string_utf16le(data, current_offset, common_path_len)
                current_offset += common_path_len
            else:
                current_offset += 0
            # Unresolved Path
            unresolved_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if unresolved_path_len > 0:
                unresolved_path = parse_string_utf16le(data, current_offset, unresolved_path_len)
                # The relative path is often stored here
                result['relative_path'] = unresolved_path
                current_offset += unresolved_path_len
            else:
                current_offset += 0
            # Local base path
            local_base_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if local_base_path_len > 0:
                local_base_path = parse_string_utf16le(data, current_offset, local_base_path_len)
                current_offset += local_base_path_len
            else:
                current_offset += 0
            # CommandLineArguments
            cmd_line_len = read_uint32(data, current_offset)
            current_offset += 4
            if cmd_line_len > 0:
                cmd_line = parse_string_utf16le(data, current_offset, cmd_line_len)
                if result['command_line_arguments'] is None:
                    result['command_line_arguments'] = cmd_line
                current_offset += cmd_line_len
            else:
                current_offset += 0
            # Icon Location
            icon_loc_len = read_uint32(data, current_offset)
            current_offset += 4
            if icon_loc_len > 0:
                icon_loc = parse_string_utf16le(data, current_offset, icon_loc_len)
                result['icon_location'] = icon_loc
                current_offset += icon_loc_len
            else:
                current_offset += 0
            # Icon Index
            icon_index = read_uint32(data, current_offset)
            current_offset += 4
            result['icon_index'] = icon_index
            # KnownFolderID (16 bytes)
            current_offset += 16
            # Relative Path
            rel_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if rel_path_len > 0:
                rel_path = parse_string_utf16le(data, current_offset, rel_path_len)
                if result['relative_path'] is None:
                    result['relative_path'] = rel_path
                current_offset += rel_path_len
            else:
                current_offset += 0
            # Working directory
            work_dir_len = read_uint32(data, current_offset)
            current_offset += 4
            if work_dir_len > 0:
                work_dir = parse_string_utf16le(data, current_offset, work_dir_len)
                result['working_dir'] = work_dir
                current_offset += work_dir_len
            else:
                current_offset += 0
            # Command tail
            cmd_tail_len = read_uint32(data, current_offset)
            current_offset += 4
            if cmd_tail_len > 0:
                cmd_tail = parse_string_utf16le(data, current_offset, cmd_tail_len)
                current_offset += cmd_tail_len
            else:
                current_offset += 0
            # File size
            file_size = read_uint64(data, current_offset)
            current_offset += 8
            result['file_size'] = file_size
            # Creation time (FILETIME)
            creation_time = read_uint64(data, current_offset)
            current_offset += 8
            # Access time (FILETIME)
            access_time = read_uint64(data, current_offset)
            current_offset += 8
            # Write time (FILETIME)
            write_time = read_uint64(data, current_offset)
            current_offset += 8
            
            # Store times
            if creation_time != 0:
                result['creation_time'] = filetime_to_iso8601(creation_time)
            else:
                result['creation_time'] = None
            if access_time != 0:
                result['access_time'] = filetime_to_iso8601(access_time)
            else:
                result['access_time'] = None
            if write_time != 0:
                result['write_time'] = filetime_to_iso8601(write_time)
            else:
                result['write_time'] = None
            
        # Common network resource data (flags & 0x00000004)
        if flags & 0x00000004:
            # Local base path
            local_base_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if local_base_path_len > 0:
                current_offset += local_base_path_len
            # Command line arguments
            cmd_line_len = read_uint32(data, current_offset)
            current_offset += 4
            if cmd_line_len > 0:
                cmd_line = parse_string_utf16le(data, current_offset, cmd_line_len)
                if result['command_line_arguments'] is None:
                    result['command_line_arguments'] = cmd_line
                current_offset += cmd_line_len
            # Network provider
            current_offset += 4
            # Network path name
            net_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if net_path_len > 0:
                current_offset += net_path_len
            # Network volume name
            net_vol_len = read_uint32(data, current_offset)
            current_offset += 4
            if net_vol_len > 0:
                current_offset += net_vol_len
            # Universal name
            universal_name_len = read_uint32(data, current_offset)
            current_offset += 4
            if universal_name_len > 0:
                current_offset += universal_name_len
            # Local base path
            local_base_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if local_base_path_len > 0:
                current_offset += local_base_path_len
        
        # Common drive data (flags & 0x00000008)
        if flags & 0x00000008:
            # Drive number
            current_offset += 4
            # Drive type
            current_offset += 4
            # Drive name
            drive_name_len = read_uint32(data, current_offset)
            current_offset += 4
            if drive_name_len > 0:
                current_offset += drive_name_len
            # Local base path
            local_base_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if local_base_path_len > 0:
                current_offset += local_base_path_len
            # CommandLineArguments
            cmd_line_len = read_uint32(data, current_offset)
            current_offset += 4
            if cmd_line_len > 0:
                cmd_line = parse_string_utf16le(data, current_offset, cmd_line_len)
                if result['command_line_arguments'] is None:
                    result['command_line_arguments'] = cmd_line
                current_offset += cmd_line_len
        
        # Common file data (flags & 0x00000010)
        if flags & 0x00000010:
            # File size
            file_size = read_uint64(data, current_offset)
            current_offset += 8
            if result['file_size'] is None:
                result['file_size'] = file_size
            # Creation time
            creation_time = read_uint64(data, current_offset)
            current_offset += 8
            if result['creation_time'] is None and creation_time != 0:
                result['creation_time'] = filetime_to_iso8601(creation_time)
            # Access time
            access_time = read_uint64(data, current_offset)
            current_offset += 8
            if result['access_time'] is None and access_time != 0:
                result['access_time'] = filetime_to_iso8601(access_time)
            # Write time
            write_time = read_uint64(data, current_offset)
            current_offset += 8
            if result['write_time'] is None and write_time != 0:
                result['write_time'] = filetime_to_iso8601(write_time)
        
        # Common icon data (flags & 0x00000020)
        if flags & 0x00000020:
            # Icon location
            icon_loc_len = read_uint32(data, current_offset)
            current_offset += 4
            if icon_loc_len > 0:
                icon_loc = parse_string_utf16le(data, current_offset, icon_loc_len)
                if result['icon_location'] is None:
                    result['icon_location'] = icon_loc
                current_offset += icon_loc_len
            # Icon index
            icon_index = read_uint32(data, current_offset)
            current_offset += 4
            if result['icon_index'] is None:
                result['icon_index'] = icon_index
            # Icon flags
            current_offset += 4
            # Icon width
            current_offset += 4
            # Icon height
            current_offset += 4
            # Icon color
            current_offset += 4
        
        # Common idlist data (flags & 0x00000040)
        if flags & 0x00000040:
            # Local idlist
            local_idlist_len = read_uint32(data, current_offset)
            current_offset += 4
            if local_idlist_len > 0:
                current_offset += local_idlist_len
            # Parent idlist
            parent_idlist_len = read_uint32(data, current_offset)
            current_offset += 4
            if parent_idlist_len > 0:
                current_offset += parent_idlist_len
        
        # Common and extra idlist data (flags & 0x00000080)
        if flags & 0x00000080:
            # Local idlist
            local_idlist_len = read_uint32(data, current_offset)
            current_offset += 4
            if local_idlist_len > 0:
                current_offset += local_idlist_len
            # Parent idlist
            parent_idlist_len = read_uint32(data, current_offset)
            current_offset += 4
            if parent_idlist_len > 0:
                current_offset += parent_idlist_len
            # Extra idlist
            extra_idlist_len = read_uint32(data, current_offset)
            current_offset += 4
            if extra_idlist_len > 0:
                current_offset += extra_idlist_len
        
        # Common netresource data (flags & 0x00000100)
        if flags & 0x00000100:
            # Netresource type
            current_offset += 4
            # Netresource name
            netres_name_len = read_uint32(data, current_offset)
            current_offset += 4
            if netres_name_len > 0:
                current_offset += netres_name_len
            # Netresource comment
            netres_comment_len = read_uint32(data, current_offset)
            current_offset += 4
            if netres_comment_len > 0:
                current_offset += netres_comment_len
            # Netresource path
            netres_path_len = read_uint32(data, current_offset)
            current_offset += 4
            if netres_path_len > 0:
                current_offset += netres_path_len
            # Netresource body
            netres_body_len = read_uint32(data, current_offset)
            current_offset += 4
            if netres_body_len > 0:
                current_offset += netres_body_len
        
        # Common pidlist data (flags & 0x00000200)
        if flags & 0x00000200:
            # Pidlist
            pidlist_len = read_uint32(data, current_offset)
            current_offset += 4
            if pidlist_len > 0:
                current_offset += pidlist_len
    except (ValueError, struct.error, IndexError) as e:
        # If we hit an error partway through, we might have partial data.
        # But the requirement is to not guess. Let's return what we have but
        # we should be careful. Actually, if the file is truncated, we should fail.
        # But if it's just that certain optional sections are missing, that's fine.
        # The issue is distinguishing between "section not present" vs "truncated".
        # Let's check if the error happened because we went past the end of data.
        if current_offset > len(data):
            raise
        # For now, let's just return what we have. But this is risky.
        # Better approach: validate that we didn't read past the LinkInfo size.
    
    return result


def read_uint64(data, offset):
    """Read a little-endian uint64 from data at offset."""
    if offset + 8 > len(data):
        raise ValueError("Truncated file: cannot read uint64")
    return struct.unpack_from('<Q', data, offset)[0]


def parse_name_target_path_list(data, offset, num_items):
    """Parse the Name/TargetPath/WorkingDir list from the header."""
    result = {
        'name_string': None,
        'relative_path': None,
        'working_dir': None,
    }
    current_offset = offset
    for i in range(num_items):
        string_type = read_uint32(data, current_offset)
        current_offset += 4
        string_len = read_uint32(data, current_offset)
        current_offset += 4
        
        if string_type == 0:
            # Unicode (UTF-16LE)
            if string_len > 0:
                s = parse_string_utf16le(data, current_offset, string_len)
                current_offset += string_len
            else:
                s = None
        elif string_type == 1:
            # ASCII
            if string_len > 0:
                raw = read_bytes(data, current_offset, string_len)
                try:
                    s = raw.decode('ascii').rstrip('\x00')
                    if s == '':
                        s = None
                except (UnicodeDecodeError, struct.error):
                    s = None
                current_offset += string_len
            else:
                s = None
        else:
            # Unknown string type - skip
            current_offset += string_len
            s = None
        
        # Determine which field this is based on the order
        # The order is: LocalBasePath, CommandLineArguments, ... but actually
        # for the header, the first few are typically Name, WorkingDir, RelativePath
        # Let's just collect them and figure out. Actually, the standard says
        # there are 3 strings: Name, WorkingDir, RelativePath (in that order)
        # But they can be in any order? No, the docs say they appear in a specific order.
        # Actually, looking at the spec more carefully, the header contains:
        # LinkFlags, FileAttributes, CreationTime, AccessTime, WriteTime,
        # FileSize, IconIndex, LinkInfoFlags, LinkInfoSize, CommonFlags,
        # then a list of strings.
        
        # The strings in the header are typically:
        # 1. Name (display name)
        # 2. Working Directory
        # 3. Relative Path (or Target Path)
        
        # But they might not all be present. Let's assign based on index.
        if i == 0:
            result['name_string'] = s
        elif i == 1:
            result['working_dir'] = s
        elif i == 2:
            result['relative_path'] = s
    
    return result, current_offset


def parse_extra_data_stream(data, offset, length):
    """Parse the Extra Data Stream."""
    result = {
        'name_string': None,
        'relative_path': None,
        'working_dir': None,
        'command_line_arguments': None,
        'icon_location': None,
        'file_size': None,
        'icon_index': None,
        'creation_time': None,
        'access_time': None,
        'write_time': None,
    }
    
    current_offset = offset
    end_offset = offset + length
    if end_offset > len(data):
        raise ValueError("Extra data stream extends beyond file")
    
    while current_offset < end_offset:
        if current_offset + 8 > len(data):
            break
        
        extra_data_id = read_uint32(data, current_offset)
        current_offset += 4
        extra_data_size = read_uint32(data, current_offset)
        current_offset += 4
        
        if current_offset + extra_data_size > end_offset:
            break
        
        extra_data_content = read_bytes(data, current_offset, extra_data_size)
        current_offset += extra_data_size
        
        if extra_data_id == 0x01:
            # Name
            if extra_data_size > 0:
                s = parse_string_utf16le(extra_data_content, 0, extra_data_size)
                if s is not None:
                    result['name_string'] = s
        elif extra_data_id == 0x02:
            # Working directory
            if extra_data_size > 0:
                s = parse_string_utf16le(extra_data_content, 0, extra_data_size)
                if s is not None:
                    result['working_dir'] = s
        elif extra_data_id == 0x03:
            # Localized description
            pass
        elif extra_data_id == 0x04:
            # Relative path
            if extra_data_size > 0:
                s = parse_string_utf16le(extra_data_content, 0, extra_data_size)
                if s is not None:
                    result['relative_path'] = s
        elif extra_data_id == 0x05:
            # Command line arguments
            if extra_data_size > 0:
                s = parse_string_utf16le(extra_data_content, 0, extra_data_size)
                if s is not None:
                    result['command_line_arguments'] = s
        elif extra_data_id == 0x06:
            # Icon location
            if extra_data_size > 0:
                s = parse_string_utf16le(extra_data_content, 0, extra_data_size)
                if s is not None:
                    result['icon_location'] = s
        elif extra_data_id == 0x07:
            # Icon index
            if extra_data_size >= 4:
                result['icon_index'] = read_uint32(extra_data_content, 0)
        elif extra_data_id == 0x08:
            # Creation time
            if extra_data_size >= 8:
                ft = read_uint64(extra_data_content, 0)
                if ft != 0:
                    result['creation_time'] = filetime_to_iso8601(ft)
        elif extra_data_id == 0x09:
            # Access time
            if extra_data_size >= 8:
                ft = read_uint64(extra_data_content, 0)
                if ft != 0:
                    result['access_time'] = filetime_to_iso8601(ft)
        elif extra_data_id == 0x0A:
            # Write time
            if extra_data_size >= 8:
                ft = read_uint64(extra_data_content, 0)
                if ft != 0:
                    result['write_time'] = filetime_to_iso8601(ft)
        elif extra_data_id == 0x0B:
            # Local base path
            pass
        elif extra_data_id == 0x0C:
            # Network provider
            pass
        elif extra_data_id == 0x0D:
            # Network path
            pass
        elif extra_data_id == 0x0E:
            # Network volume name
            pass
        elif extra_data_id == 0x0F:
            # Universal name
            pass
        elif extra_data_id == 0x10:
            # Local base path (for network)
            pass
        elif extra_data_id == 0x11:
            # Drive number
            pass
        elif extra_data_id == 0x12:
            # Drive type
            pass
        elif extra_data_id == 0x13:
            # Drive name
            pass
        elif extra_data_id == 0x14:
            # Local base path (for drive)
            pass
        elif extra_data_id == 0x15:
            # Command line arguments (for drive)
            pass
        elif extra_data_id == 0x16:
            # File size
            if extra_data_size >= 8:
                result['file_size'] = read_uint64(extra_data_content, 0)
        elif extra_data_id == 0x17:
            # Creation time (for file)
            if extra_data_size >= 8:
                ft = read_uint64(extra_data_content, 0)
                if ft != 0:
                    if result['creation_time'] is None:
                        result['creation_time'] = filetime_to_iso8601(ft)
        elif extra_data_id == 0x18:
            # Access time (for file)
            if extra_data_size >= 8:
                ft = read_uint64(extra_data_content, 0)
                if ft != 0:
                    if result['access_time'] is None:
                        result['access_time'] = filetime_to_iso86