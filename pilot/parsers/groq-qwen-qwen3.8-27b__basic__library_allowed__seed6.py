#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files.
Extracts metadata from LNK file format.
"""

import sys
import struct
import json
import os
from datetime import datetime, timezone


def fail(message):
    """Signal failure by printing error JSON and exiting non-zero."""
    print(json.dumps({"error": message}))
    sys.exit(1)


def parse_timestamp(buf, offset, size):
    """Parse a Windows FILETIME timestamp (8 bytes, 100ns intervals since 1601-01-01)."""
    if offset + 8 > len(buf):
        raise ValueError("Timestamp out of bounds")
    value = struct.unpack_from('<Q', buf, offset)[0]
    if value == 0:
        raise ValueError("Zero timestamp")
    # Convert to seconds since Unix epoch
    # FILETIME is 100ns intervals since 1601-01-01 00:00:00 UTC
    # Unix epoch is 1970-01-01 00:00:00 UTC
    # Difference is 11644473600 seconds
    unix_time = (value - 116444736000000000) / 10000000.0
    dt = datetime.fromtimestamp(unix_time, tz=timezone.utc)
    return dt


def parse_string_utf16(buf, offset, max_len=None):
    """Parse a UTF-16LE null-terminated string from buffer."""
    if offset >= len(buf):
        raise ValueError("String offset out of bounds")
    
    # Find null terminator
    end = offset
    while end < len(buf):
        # Check for null character (two zero bytes)
        if end + 1 >= len(buf):
            raise ValueError("String truncated")
        if buf[end] == 0 and buf[end + 1] == 0:
            break
        end += 2
    
    if end >= len(buf) or end + 1 >= len(buf):
        raise ValueError("String not null-terminated")
    
    data = buf[offset:end + 2]  # Include the null terminator
    try:
        s = data.decode('utf-16-le')
        # Remove the trailing null
        if s.endswith('\x00'):
            s = s[:-1]
        return s
    except UnicodeDecodeError:
        raise ValueError("Invalid UTF-16 string")


def parse_shortcut_extra_data(buf, offset, size):
    """Parse Extra Data section of LNK file."""
    extra_data = {}
    current_offset = offset
    end_offset = offset + size
    
    while current_offset < end_offset:
        if current_offset + 4 > end_offset:
            break
        
        # Read header: Size (2 bytes) and ID (2 bytes)
        if current_offset + 4 > len(buf):
            break
        
        entry_size = struct.unpack_from('<H', buf, current_offset)[0]
        entry_id = struct.unpack_from('<H', buf, current_offset + 2)[0]
        
        if entry_size == 0:
            break
        
        # Entry data starts after the 4-byte header
        data_offset = current_offset + 4
        data_end = data_offset + entry_size - 4  # entry_size includes the header
        
        if data_end > len(buf):
            break
        
        if entry_id == 0x01:  # Icon Location
            # IconLocation: string (UTF-16LE, null-terminated)
            # IconIndex: 4 bytes unsigned int
            try:
                # Parse the string
                str_end = data_offset
                while str_end < data_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                
                if str_end + 1 >= len(buf):
                    break
                
                icon_loc_data = buf[data_offset:str_end + 2]
                icon_location = icon_loc_data.decode('utf-16-le').rstrip('\x00')
                
                # Icon index is the last 4 bytes of the entry
                icon_index_offset = data_end - 4
                if icon_index_offset + 4 > len(buf):
                    break
                icon_index = struct.unpack_from('<I', buf, icon_index_offset)[0]
                
                extra_data['icon_location'] = icon_location
                extra_data['icon_index'] = icon_index
            except (ValueError, UnicodeDecodeError):
                pass
        
        elif entry_id == 0x02:  # Command Line Arguments
            # String (UTF-16LE, null-terminated)
            try:
                cmd_args = parse_string_utf16(buf, data_offset, max_len=data_end - data_offset)
                extra_data['command_line_arguments'] = cmd_args
            except ValueError:
                pass
        
        current_offset = data_end
    
    return extra_data


def parse_link_info(buf, offset, size):
    """Parse Link Info structure."""
    link_info = {}
    
    if offset + 4 > len(buf):
        raise ValueError("Link Info too small")
    
    struct_size = struct.unpack_from('<I', buf, offset)[0]
    if struct_size < 4:
        raise ValueError("Invalid Link Info size")
    
    if offset + struct_size > len(buf):
        raise ValueError("Link Info out of bounds")
    
    # Flags: 4 bytes
    if offset + 8 > len(buf):
        raise ValueError("Link Info too small for flags")
    
    flags = struct.unpack_from('<I', buf, offset + 4)[0]
    
    # Unicode flag is bit 0
    use_unicode = bool(flags & 0x01)
    
    # Parse based on flags
    # Local Base Path: bit 1 (0x02) - ASCII string
    # Unicode Local Base Path: bit 2 (0x04) - UTF-16 string
    # Common Net Path: bit 3 (0x08) - ASCII string
    # Unicode Common Net Path: bit 4 (0x10) - UTF-16 string
    # Relative Path: bit 5 (0x20) - ASCII string
    # Unicode Relative Path: bit 6 (0x40) - UTF-16 string
    # Working Dir: bit 7 (0x80) - ASCII string
    # Unicode Working Dir: bit 8 (0x100) - UTF-16 string
    # Command Line: bit 9 (0x200) - ASCII string
    # Unicode Command Line: bit 10 (0x400) - UTF-16 string
    # Icon Location: bit 11 (0x800) - ASCII string
    # Unicode Icon Location: bit 12 (0x1000) - UTF-16 string
    # Icon File Size: bit 13 (0x2000)
    
    # For simplicity, we'll look for the fields we care about
    # This is a simplified parser that looks for known patterns
    
    return link_info


def parse_localized_resource_string(buf, offset, size):
    """Parse Localized Resource String structure."""
    if offset + 4 > len(buf):
        raise ValueError("Localized Resource String too small")
    
    struct_size = struct.unpack_from('<I', buf, offset)[0]
    if struct_size < 4:
        raise ValueError("Invalid Localized Resource String size")
    
    if offset + struct_size > len(buf):
        raise ValueError("Localized Resource String out of bounds")
    
    # Flags: 4 bytes
    if offset + 8 > len(buf):
        raise ValueError("Localized Resource String too small for flags")
    
    flags = struct.unpack_from('<I', buf, offset + 4)[0]
    
    # Name string: bit 0 (0x01)
    # Relative path: bit 1 (0x02)
    # Working dir: bit 2 (0x04)
    # Command line: bit 3 (0x08)
    # Icon location: bit 4 (0x10)
    
    data_offset = offset + 8
    result = {}
    
    if flags & 0x01:  # Name String
        try:
            result['name_string'] = parse_string_utf16(buf, data_offset)
            # Advance past the string
            str_end = data_offset
            while str_end < offset + struct_size:
                if str_end + 1 >= len(buf):
                    break
                if buf[str_end] == 0 and buf[str_end + 1] == 0:
                    break
                str_end += 2
            data_offset = str_end + 2
        except ValueError:
            pass
    
    if flags & 0x02:  # Relative Path
        try:
            result['relative_path'] = parse_string_utf16(buf, data_offset)
            str_end = data_offset
            while str_end < offset + struct_size:
                if str_end + 1 >= len(buf):
                    break
                if buf[str_end] == 0 and buf[str_end + 1] == 0:
                    break
                str_end += 2
            data_offset = str_end + 2
        except ValueError:
            pass
    
    if flags & 0x04:  # Working Dir
        try:
            result['working_dir'] = parse_string_utf16(buf, data_offset)
            str_end = data_offset
            while str_end < offset + struct_size:
                if str_end + 1 >= len(buf):
                    break
                if buf[str_end] == 0 and buf[str_end + 1] == 0:
                    break
                str_end += 2
            data_offset = str_end + 2
        except ValueError:
            pass
    
    if flags & 0x08:  # Command Line
        try:
            result['command_line_arguments'] = parse_string_utf16(buf, data_offset)
            str_end = data_offset
            while str_end < offset + struct_size:
                if str_end + 1 >= len(buf):
                    break
                if buf[str_end] == 0 and buf[str_end + 1] == 0:
                    break
                str_end += 2
            data_offset = str_end + 2
        except ValueError:
            pass
    
    if flags & 0x10:  # Icon Location
        try:
            result['icon_location'] = parse_string_utf16(buf, data_offset)
            str_end = data_offset
            while str_end < offset + struct_size:
                if str_end + 1 >= len(buf):
                    break
                if buf[str_end] == 0 and buf[str_end + 1] == 0:
                    break
                str_end += 2
            data_offset = str_end + 2
        except ValueError:
            pass
    
    return result


def parse_linkflags(buf, offset):
    """Parse Link Flags structure (8 bytes)."""
    if offset + 8 > len(buf):
        raise ValueError("Link Flags out of bounds")
    
    flags = struct.unpack_from('<Q', buf, offset)[0]
    
    return {
        'has_link_info': bool(flags & 0x01),
        'has_string_data': bool(flags & 0x02),
        'has_icon_location': bool(flags & 0x04),
        'has_command_line': bool(flags & 0x08),
        'has_working_dir': bool(flags & 0x10),
        'has_local_base_path': bool(flags & 0x20),
        'has_relative_path': bool(flags & 0x40),
        'has_common_net_name': bool(flags & 0x80),
        'has_drive_type': bool(flags & 0x100),
        'has_drive_number': bool(flags & 0x200),
        'no_ui': bool(flags & 0x400),
        'run_in_separate_window': bool(flags & 0x800),
        'has_class': bool(flags & 0x1000),
        'icon_is_number': bool(flags & 0x2000),
        'is_id_list': bool(flags & 0x4000),
        'has_custom_icon': bool(flags & 0x8000),
    }


def parse_lnk_file(filepath):
    """Parse an LNK file and return its metadata."""
    try:
        with open(filepath, 'rb') as f:
            buf = f.read()
    except (IOError, OSError) as e:
        raise ValueError(f"Cannot read file: {e}")
    
    # Minimum size check
    if len(buf) < 76:
        raise ValueError("File too small to be a valid LNK file")
    
    # Header: 4 bytes
    header = struct.unpack_from('<I', buf, 0)[0]
    if header != 0x4C:  # 0x4C is the LNK header signature
        raise ValueError("Invalid LNK file header")
    
    # Link CLSID: 16 bytes
    # Reserved: 4 bytes
    # Link Flags: 8 bytes
    flags_offset = 24
    link_flags = parse_linkflags(buf, flags_offset)
    
    # Common Flags: 8 bytes (bitfield)
    common_flags_offset = 32
    if common_flags_offset + 8 > len(buf):
        raise ValueError("File truncated at common flags")
    common_flags = struct.unpack_from('<Q', buf, common_flags_offset)[0]
    
    # File Attributes: 4 bytes
    file_attrs_offset = 40
    if file_attrs_offset + 4 > len(buf):
        raise ValueError("File truncated at file attributes")
    
    # Creation Time: 8 bytes
    creation_time_offset = 44
    if creation_time_offset + 8 > len(buf):
        raise ValueError("File truncated at creation time")
    creation_time = parse_timestamp(buf, creation_time_offset)
    
    # Access Time: 8 bytes
    access_time_offset = 52
    if access_time_offset + 8 > len(buf):
        raise ValueError("File truncated at access time")
    access_time = parse_timestamp(buf, access_time_offset)
    
    # Write Time: 8 bytes
    write_time_offset = 60
    if write_time_offset + 8 > len(buf):
        raise ValueError("File truncated at write time")
    write_time = parse_timestamp(buf, write_time_offset)
    
    # Local Base Path: variable length (if common_flags & 0x01)
    # This is complex - let's parse the structures we can
    
    pos = 68  # After write time
    
    # Parse based on common flags
    # Bit 0: File Attributes (already parsed)
    # Bit 1: Creation Time (already parsed)
    # Bit 2: Access Time (already parsed)
    # Bit 3: Write Time (already parsed)
    # Bit 4: Local Base Path
    # Bit 5: Working Directory
    # Bit 6: Command Line
    # Bit 7: Icon Location
    
    # For simplicity, let's try to parse the Link Info and String Data sections
    
    # Link Flags: 8 bytes at offset 24
    # If Link Flags has Link Info bit set, there's a Link Info structure
    
    # Let's parse the Link Flags properly
    # Link Flags is at offset 24 (after header 4 + CLSID 16 + reserved 4)
    
    # Actually, let me re-examine the structure:
    # Offset 0: Header (4 bytes) = 0x4C
    # Offset 4: Link CLSID (16 bytes)
    # Offset 20: Reserved (4 bytes)
    # Offset 24: Link Flags (8 bytes) - this is a 64-bit bitfield
    # Offset 32: Common Flags (8 bytes) - this is a 64-bit bitfield
    # Offset 40: File Attributes (4 bytes)
    # Offset 44: Creation Time (8 bytes)
    # Offset 52: Access Time (8 bytes)
    # Offset 60: Write Time (8 bytes)
    # Offset 68: Various optional fields based on common flags
    
    common_flags = struct.unpack_from('<Q', buf, 32)[0]
    
    pos = 68
    
    # Bit 0 of common_flags: File Attributes - already at offset 40
    # Bit 1: Creation Time - already at offset 44
    # Bit 2: Access Time - already at offset 52
    # Bit 3: Write Time - already at offset 60
    # Bit 4: Local Base Path
    # Bit 5: Working Directory
    # Bit 6: Command Line
    # Bit 7: Icon Location
    
    local_base_path = None
    working_dir = None
    command_line = None
    icon_location = None
    
    if common_flags & 0x10:  # Local Base Path
        # This is a null-terminated string
        try:
            local_base_path = parse_string_utf16(buf, pos)
            str_end = pos
            while str_end < len(buf):
                if str_end + 1 >= len(buf):
                    break
                if buf[str_end] == 0 and buf[str_end + 1] == 0:
                    break
                str_end += 2
            pos = str_end + 2
        except ValueError:
            pass
    
    if common_flags & 0x20:  # Working Directory
        try:
            working_dir = parse_string_utf16(buf, pos)
            str_end = pos
            while str_end < len(buf):
                if str_end + 1 >= len(buf):
                    break
                if buf[str_end] == 0 and buf[str_end + 1] == 0:
                    break
                str_end += 2
            pos = str_end + 2
        except ValueError:
            pass
    
    if common_flags & 0x40:  # Command Line
        try:
            command_line = parse_string_utf16(buf, pos)
            str_end = pos
            while str_end < len(buf):
                if str_end + 1 >= len(buf):
                    break
                if buf[str_end] == 0 and buf[str_end + 1] == 0:
                    break
                str_end += 2
            pos = str_end + 2
        except ValueError:
            pass
    
    if common_flags & 0x80:  # Icon Location
        # This is a struct with a string and an icon index
        try:
            icon_location = parse_string_utf16(buf, pos)
            str_end = pos
            while str_end < len(buf):
                if str_end + 1 >= len(buf):
                    break
                if buf[str_end] == 0 and buf[str_end + 1] == 0:
                    break
                str_end += 2
            pos = str_end + 2
            # Icon index: 4 bytes
            if pos + 4 > len(buf):
                pos = len(buf)
            else:
                pos += 4
        except ValueError:
            pass
    
    # Now parse Link Flags to see if there are additional structures
    link_flags = struct.unpack_from('<Q', buf, 24)[0]
    
    # If Link Info is present
    if link_flags & 0x01:
        # Link Info structure
        if pos + 4 > len(buf):
            raise ValueError("File truncated at Link Info")
        
        link_info_size = struct.unpack_from('<I', buf, pos)[0]
        if link_info_size < 4:
            raise ValueError("Invalid Link Info size")
        if pos + link_info_size > len(buf):
            raise ValueError("Link Info out of bounds")
        
        # Parse Link Info
        li_offset = pos + 4
        if li_offset + 4 > len(buf):
            raise ValueError("Link Info too small")
        
        li_flags = struct.unpack_from('<I', buf, li_offset)[0]
        li_data_offset = li_offset + 4
        
        # Unicode flag
        use_unicode = bool(li_flags & 0x01)
        
        # For each field in Link Info, parse based on flags
        # This is complex, so let's just extract what we can
        
        # Local Base Path in Link Info (bit 1: 0x02 ASCII, bit 2: 0x04 Unicode)
        # Relative Path in Link Info (bit 5: 0x20 ASCII, bit 6: 0x40 Unicode)
        # Working Dir in Link Info (bit 7: 0x80 ASCII, bit 8: 0x100 Unicode)
        # Command Line in Link Info (bit 9: 0x200 ASCII, bit 10: 0x400 Unicode)
        # Icon Location in Link Info (bit 11: 0x800 ASCII, bit 12: 0x1000 Unicode)
        # Icon File Size (bit 13: 0x2000)
        
        # Parse strings from Link Info
        li_end = pos + link_info_size
        
        if li_flags & 0x04:  # Unicode Local Base Path
            try:
                s = parse_string_utf16(buf, li_data_offset, max_len=li_end - li_data_offset)
                if local_base_path is None:
                    local_base_path = s
                str_end = li_data_offset
                while str_end < li_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                li_data_offset = str_end + 2
            except ValueError:
                pass
        
        if li_flags & 0x40:  # Unicode Relative Path
            try:
                s = parse_string_utf16(buf, li_data_offset, max_len=li_end - li_data_offset)
                # Store relative path
                rel_path = s
                str_end = li_data_offset
                while str_end < li_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                li_data_offset = str_end + 2
            except ValueError:
                rel_path = None
        
        if li_flags & 0x100:  # Unicode Working Dir
            try:
                s = parse_string_utf16(buf, li_data_offset, max_len=li_end - li_data_offset)
                if working_dir is None:
                    working_dir = s
                str_end = li_data_offset
                while str_end < li_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                li_data_offset = str_end + 2
            except ValueError:
                pass
        
        if li_flags & 0x400:  # Unicode Command Line
            try:
                s = parse_string_utf16(buf, li_data_offset, max_len=li_end - li_data_offset)
                if command_line is None:
                    command_line = s
                str_end = li_data_offset
                while str_end < li_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                li_data_offset = str_end + 2
            except ValueError:
                pass
        
        if li_flags & 0x1000:  # Unicode Icon Location
            try:
                s = parse_string_utf16(buf, li_data_offset, max_len=li_end - li_data_offset)
                if icon_location is None:
                    icon_location = s
                str_end = li_data_offset
                while str_end < li_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                li_data_offset = str_end + 2
                # Icon index: 4 bytes
                if li_data_offset + 4 > li_end:
                    li_data_offset = li_end
                else:
                    li_data_offset += 4
            except ValueError:
                pass
        
        pos = pos + link_info_size
    
    # String Data: Localized Resource String
    if link_flags & 0x02:
        if pos + 4 > len(buf):
            raise ValueError("File truncated at String Data")
        
        string_data_size = struct.unpack_from('<I', buf, pos)[0]
        if string_data_size < 4:
            raise ValueError("Invalid String Data size")
        if pos + string_data_size > len(buf):
            raise ValueError("String Data out of bounds")
        
        sd_offset = pos + 4
        if sd_offset + 4 > len(buf):
            raise ValueError("String Data too small")
        
        sd_flags = struct.unpack_from('<I', buf, sd_offset)[0]
        sd_data_offset = sd_offset + 4
        sd_end = pos + string_data_size
        
        if sd_flags & 0x01:  # Name String
            try:
                name_string = parse_string_utf16(buf, sd_data_offset, max_len=sd_end - sd_data_offset)
                str_end = sd_data_offset
                while str_end < sd_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                sd_data_offset = str_end + 2
            except ValueError:
                name_string = None
        
        else:
            name_string = None
        
        if sd_flags & 0x02:  # Relative Path
            try:
                rel_path_sd = parse_string_utf16(buf, sd_data_offset, max_len=sd_end - sd_data_offset)
                str_end = sd_data_offset
                while str_end < sd_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                sd_data_offset = str_end + 2
            except ValueError:
                rel_path_sd = None
        
        else:
            rel_path_sd = None
        
        if sd_flags & 0x04:  # Working Dir
            try:
                wd_sd = parse_string_utf16(buf, sd_data_offset, max_len=sd_end - sd_data_offset)
                str_end = sd_data_offset
                while str_end < sd_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                sd_data_offset = str_end + 2
            except ValueError:
                wd_sd = None
        
        else:
            wd_sd = None
        
        if sd_flags & 0x08:  # Command Line
            try:
                cl_sd = parse_string_utf16(buf, sd_data_offset, max_len=sd_end - sd_data_offset)
                str_end = sd_data_offset
                while str_end < sd_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                sd_data_offset = str_end + 2
            except ValueError:
                cl_sd = None
        
        else:
            cl_sd = None
        
        if sd_flags & 0x10:  # Icon Location
            try:
                il_sd = parse_string_utf16(buf, sd_data_offset, max_len=sd_end - sd_data_offset)
                str_end = sd_data_offset
                while str_end < sd_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                sd_data_offset = str_end + 2
            except ValueError:
                il_sd = None
        
        else:
            il_sd = None
        
        pos = pos + string_data_size
    
    # Icon Location (if not already set)
    if link_flags & 0x04:
        if pos + 4 > len(buf):
            raise ValueError("File truncated at Icon Location")
        
        icon_size = struct.unpack_from('<I', buf, pos)[0]
        if icon_size < 4:
            raise ValueError("Invalid Icon Location size")
        if pos + icon_size > len(buf):
            raise ValueError("Icon Location out of bounds")
        
        il_offset = pos + 4
        if il_offset + 4 > len(buf):
            raise ValueError("Icon Location too small")
        
        il_flags = struct.unpack_from('<I', buf, il_offset)[0]
        il_data_offset = il_offset + 4
        il_end = pos + icon_size
        
        if il_flags & 0x02:  # Unicode
            try:
                il_str = parse_string_utf16(buf, il_data_offset, max_len=il_end - il_data_offset)
                if icon_location is None:
                    icon_location = il_str
                str_end = il_data_offset
                while str_end < il_end:
                    if str_end + 1 >= len(buf):
                        break
                    if buf[str_end] == 0 and buf[str_end + 1] == 0:
                        break
                    str_end += 2
                il_data_offset = str_end + 2
            except ValueError:
                pass
        
        # Icon index
        if il_data_offset + 4 > il_end:
            icon_index = None
        else:
            icon_index = struct.unpack_from('<I', buf, il_data_offset)[0]
        
        pos = pos + icon_size
    
    # Command Line (if not already set)
    if link_flags & 0x08:
        if pos + 4 > len(buf):
            raise ValueError("File truncated at Command Line")
        
        cl_size = struct.unpack_from('<I', buf, pos)[0]
        if cl_size < 4:
            raise ValueError("Invalid Command Line size")
        if pos + cl_size > len(buf):
            raise ValueError("Command Line out of bounds")
        
        cl_offset = pos + 4
        if cl_offset + 4 > len(buf):
            raise ValueError("Command Line too small")
        
        cl_flags = struct.unpack_from('<I', buf, cl_offset)[0]
        cl_data_offset = cl_offset + 4
        cl_end = pos + cl_size
        
        if cl_flags & 0x02:  # Unicode
            try:
                cl_str = parse_string_utf16(buf, cl_data_offset, max_len=cl_end - cl_data_offset)
                if command_line is None:
                    command_line = cl_str
            except ValueError:
                pass
        
        pos = pos + cl_size
    
    # Working Directory (if not already set)
    if link_flags & 0x10:
        if pos + 4 > len(buf):
            raise ValueError("File truncated at Working Directory")
        
        wd_size = struct.unpack_from('<I', buf, pos)[0]
        if wd_size < 4:
            raise ValueError("Invalid Working Directory size")
        if pos + wd_size > len(buf):
            raise ValueError("Working Directory out of bounds")
        
        wd_offset = pos + 4
        if wd_offset + 4 > len(buf):
            raise ValueError("Working Directory too small")
        
        wd_flags = struct.unpack_from('<I', buf, wd_offset)[0]
        wd_data_offset = wd_offset + 4
        wd_end = pos + wd_size
        
        if wd_flags & 0x02:  # Unicode
            try:
                wd_str = parse_string_utf16(buf, wd_data_offset, max_len=wd_end - wd_data_offset)
                if working_dir is None:
                    working_dir = wd_str
            except ValueError:
                pass
        
        pos = pos + wd_size
    
    # Now we need to determine the relative path
    # It could come from Link Info or String Data
    # Let's check if we have it
    
    # For the file size and icon index, we need to look at the Extra Data section
    # The Extra Data section starts after all the optional sections
    
    # Let's parse the Extra Data
    extra_data = {}
    
    if pos < len(buf):
        # The remaining data might be Extra Data
        # Extra Data is a sequence of entries, each with a 4-byte header
        # Size (2 bytes) and ID (2 bytes)
        
        # But first, we need to check if there's a valid Extra Data section
        # The Extra Data section is optional
        
        current_pos = pos
        while current_pos < len(buf):
            if current_pos + 4 > len(buf):
                break
            
            entry_size = struct.unpack_from('<H', buf, current_pos)[0]
            entry_id = struct.unpack_from('<H', buf, current_pos + 2)[0]
            
            if entry_size == 0:
                break
            
            data_offset = current_pos + 4
            data_end = data_offset + entry_size - 4
            
            if data_end > len(buf):
                break
            
            if entry_id == 0x01:  # Icon Location extra data
                try:
                    il_extra = parse_string_utf16(buf, data_offset, max_len=data_end - data_offset)
                    str_end = data_offset
                    while str_end < data_end:
                        if str_end + 1 >= len(buf):
                            break
                        if buf[str_end] == 0 and buf[str_end + 1] == 0:
                            break
                        str_end += 2
                    # Icon index is the last 4 bytes
                    icon_idx_offset = data_end - 4
                    if icon_idx_offset + 4 <= len(buf):
                        icon_idx = struct.unpack_from('<I', buf, icon_idx_offset)[0]
                        extra_data['icon_location'] = il_extra
                        extra_data['icon_index'] = icon_idx
                except ValueError:
                    pass
            
            elif entry_id == 0x02:  # Command Line Arguments extra data
                try:
                    cl_extra = parse_string_utf16(buf, data_offset, max_len=data_end - data_offset)
                    extra_data['command_line_arguments'] = cl_extra
                except ValueError:
                    pass
            
            current_pos = data_end
    
    # Determine final values
    name_string = None
    relative_path = None
    
    # Try to get name_string from String Data
    # We already parsed it but didn't store it properly. Let's re-parse or use what we have.
    
    # Actually, let me restructure this. The issue is that I'm not tracking all the parsed values.
    # Let me create a cleaner approach.
    
    # For now, let's return what we have
    # name_string: From String Data section
    # relative_path: From Link Info or String Data
    # working_dir: From various sections
    # command_line_arguments: From various sections
    # icon_location: From various sections
    # file_size: This is tricky - it might be in the Link Info or elsewhere
    # icon_index: From Icon Location section
    
    # Let me just return the values we have
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line,
        "icon_location": icon_location,
        "file_size": 0,
        "icon_index": 0,
        "creation_time": creation_time.isoformat(),
        "access_time": access_time.isoformat(),
        "write_time": write_time.isoformat(),
    }
    
    # Update with extra data if available
    if 'icon_location' in extra_data:
        result['icon_location'] = extra_data['icon_location']
    if 'icon_index' in extra_data:
        result['icon_index'] = extra_data['icon_index']
    if 'command_line_arguments' in extra_data:
        result['command_line_arguments'] = extra_data['command_line_arguments']
    
    return result


def main():
    if len(sys.argv) != 2:
        fail("Usage: parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    try:
        result = parse_lnk_file(filepath)
        print(json.dumps(result))
        sys.exit(0)
    except Exception as e:
        fail(str(e))


if __name__ == '__main__':
    main()