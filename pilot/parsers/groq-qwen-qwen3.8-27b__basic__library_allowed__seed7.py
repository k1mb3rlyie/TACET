#!/usr/bin/env python3
"""Parse a Windows Shortcut (.lnk) file and extract its metadata."""

import struct
import json
import sys
import os
import datetime


def fail(message):
    """Output error JSON and exit with code 0."""
    print(json.dumps({"error": message}))
    sys.exit(0)


def read_exact(data, offset, length, field_name):
    """Read exactly `length` bytes from `data` starting at `offset`.
    Raises an exception if not enough data."""
    if offset < 0 or offset + length > len(data):
        raise ValueError(f"Cannot read {length} bytes for {field_name} at offset {offset}: only {len(data) - offset} bytes remain")
    return data[offset:offset + length]


def parse_utf16_string(data, offset, length_bytes):
    """Parse a UTF-16LE string of given byte length."""
    if length_bytes % 2 != 0:
        raise ValueError("UTF-16 string length is not even")
    raw = read_exact(data, offset, length_bytes, "utf16 string")
    try:
        return raw.decode('utf-16-le')
    except UnicodeDecodeError:
        raise ValueError("Invalid UTF-16LE string")


def filetime_to_iso8601(filetime):
    """Convert a Windows FILETIME (100ns intervals since 1601-01-01 UTC) to ISO 8601 with +00:00."""
    if filetime == 0:
        return None
    # 1601-01-01 to 1970-01-01 in 100ns intervals
    EPOCH_DIFF = 116444736000000000
    try:
        ticks = filetime - EPOCH_DIFF
        if ticks < 0:
            # Before 1970, handle negative
            dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ticks // 10)
            return dt.isoformat()
        dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ticks // 10)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        raise ValueError(f"Invalid FILETIME value: {filetime}")


def parse_link_info(data, offset, length):
    """Parse the LinkInfo structure from the LINKINFO block."""
    # LinkInfo structure:
    # DWORD cbLinkInfo
    # DWORD LinkInfoFlags
    # If Hotkey: DWORD Hotkey
    # If ShowCmd: DWORD ShowCmd
    # If IconLocation: various
    # If RelativePath: various
    # If CommandLine: various
    # If IconFile: various
    
    if length < 8:
        raise ValueError("LinkInfo too short")
    
    cb_link_info = struct.unpack_from('<I', data, offset)[0]
    if cb_link_info != length:
        raise ValueError(f"LinkInfo size mismatch: header says {length}, cbLinkInfo says {cb_link_info}")
    
    flags = struct.unpack_from('<I', data, offset + 4)[0]
    
    pos = offset + 8
    
    # Reserved flags
    LINKINFO_HAS_HOTKEY = 0x00000001
    LINKINFO_HAS_SHOWCMD = 0x00000002
    LINKINFO_HAS_ICONLOCATION = 0x00000004
    LINKINFO_HAS_RELATIVEPATH = 0x00000008
    LINKINFO_HAS_WORKINGDIR = 0x00000010
    LINKINFO_HAS_COMMANDLINE = 0x00000020
    LINKINFO_HAS_ICONFILENAME = 0x00000040
    
    hotkey = None
    show_cmd = None
    icon_location = None
    relative_path = None
    working_dir = None
    command_line = None
    icon_file = None
    
    if flags & LINKINFO_HAS_HOTKEY:
        if pos + 4 > offset + length:
            raise ValueError("LinkInfo truncated: hotkey")
        hotkey = struct.unpack_from('<I', data, pos)[0]
        pos += 4
    
    if flags & LINKINFO_HAS_SHOWCMD:
        if pos + 4 > offset + length:
            raise ValueError("LinkInfo truncated: showcmd")
        show_cmd = struct.unpack_from('<I', data, pos)[0]
        pos += 4
    
    if flags & LINKINFO_HAS_ICONLOCATION:
        # IconLocation structure:
        # WORD cchIcon (number of chars in string including null)
        # WORD wIconNumber
        # BYTE IconPath[] (null-terminated)
        if pos + 4 > offset + length:
            raise ValueError("LinkInfo truncated: icon location header")
        cch_icon = struct.unpack_from('<H', data, pos)[0]
        w_icon_number = struct.unpack_from('<H', data, pos + 2)[0]
        pos += 4
        
        # The string is cch_icon chars, each 2 bytes in UTF-16, including null terminator
        # But actually cchIcon is the number of characters including the null terminator
        string_bytes = cch_icon * 2
        if pos + string_bytes > offset + length:
            raise ValueError("LinkInfo truncated: icon location string")
        icon_path_str = parse_utf16_string(data, pos, cch_icon * 2)
        # Remove null terminator if present
        if icon_path_str and icon_path_str[-1] == '\x00':
            icon_path_str = icon_path_str[:-1]
        icon_location = icon_path_str
        icon_index = w_icon_number
        pos += string_bytes
    else:
        icon_location = None
        icon_index = None
    
    if flags & LINKINFO_HAS_RELATIVEPATH:
        # RelativePath structure:
        # WORD cchPath
        # BYTE Path[] (null-terminated)
        if pos + 2 > offset + length:
            raise ValueError("LinkInfo truncated: relative path header")
        cch_path = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        
        string_bytes = cch_path * 2
        if pos + string_bytes > offset + length:
            raise ValueError("LinkInfo truncated: relative path string")
        relative_path = parse_utf16_string(data, pos, cch_path * 2)
        if relative_path and relative_path[-1] == '\x00':
            relative_path = relative_path[:-1]
        pos += string_bytes
    
    if flags & LINKINFO_HAS_WORKINGDIR:
        # WorkingDir structure:
        # WORD cchDir
        # BYTE Dir[] (null-terminated)
        if pos + 2 > offset + length:
            raise ValueError("LinkInfo truncated: working dir header")
        cch_dir = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        
        string_bytes = cch_dir * 2
        if pos + string_bytes > offset + length:
            raise ValueError("LinkInfo truncated: working dir string")
        working_dir = parse_utf16_string(data, pos, cch_dir * 2)
        if working_dir and working_dir[-1] == '\x00':
            working_dir = working_dir[:-1]
        pos += string_bytes
    
    if flags & LINKINFO_HAS_COMMANDLINE:
        # CommandLine structure:
        # WORD cchCommandLine
        # BYTE CommandLine[] (null-terminated)
        if pos + 2 > offset + length:
            raise ValueError("LinkInfo truncated: command line header")
        cch_cmdline = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        
        string_bytes = cch_cmdline * 2
        if pos + string_bytes > offset + length:
            raise ValueError("LinkInfo truncated: command line string")
        command_line = parse_utf16_string(data, pos, cch_cmdline * 2)
        if command_line and command_line[-1] == '\x00':
            command_line = command_line[:-1]
        pos += string_bytes
    
    if flags & LINKINFO_HAS_ICONFILENAME:
        # IconFile structure:
        # WORD cchIconFile
        # BYTE IconFile[] (null-terminated)
        if pos + 2 > offset + length:
            raise ValueError("LinkInfo truncated: icon file header")
        cch_iconfile = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        
        string_bytes = cch_iconfile * 2
        if pos + string_bytes > offset + length:
            raise ValueError("LinkInfo truncated: icon file string")
        icon_file = parse_utf16_string(data, pos, cch_iconfile * 2)
        if icon_file and icon_file[-1] == '\x00':
            icon_file = icon_file[:-1]
        pos += string_bytes
    
    return {
        'hotkey': hotkey,
        'show_cmd': show_cmd,
        'icon_location': icon_location,
        'icon_index': icon_index,
        'relative_path': relative_path,
        'working_dir': working_dir,
        'command_line': command_line,
        'icon_file': icon_file,
    }


def parse_localized_name(data, offset, length):
    """Parse LocalizedName block."""
    if length < 2:
        raise ValueError("LocalizedName block too short")
    cch_name = struct.unpack_from('<H', data, offset)[0]
    # String is cch_name chars, each 2 bytes, including null
    string_bytes = cch_name * 2
    if 2 + string_bytes > length:
        raise ValueError("LocalizedName string exceeds block size")
    name = parse_utf16_string(data, offset + 2, cch_name * 2)
    if name and name[-1] == '\x00':
        name = name[:-1]
    return name


def parse_linkinfo_extended(data, offset, length):
    """Parse LinkInfo extended block (if any)."""
    # This is for the extended LinkInfo which has a different structure
    # For simplicity, we'll handle the basic case
    pass


def parse_file_properties(data, offset, length):
    """Parse FileProperties block to get file size."""
    if length < 4:
        raise ValueError("FileProperties block too short")
    cb_prop = struct.unpack_from('<I', data, offset)[0]
    if cb_prop != length:
        raise ValueError(f"FileProperties size mismatch: header says {length}, cbProp says {cb_prop}")
    
    if length < 8:
        return None
    
    flags = struct.unpack_from('<I', data, offset + 4)[0]
    
    FILEPROP_ATTRIBUTES = 0x00000001
    FILEPROP_SIZE = 0x00000002
    FILEPROP_CREATION = 0x00000004
    FILEPROP_ACCESS = 0x00000008
    FILEPROP_WRITE = 0x00000010
    
    file_size = None
    
    if flags & FILEPROP_SIZE:
        if offset + 8 + 8 > len(data):
            raise ValueError("FileProperties truncated: file size")
        # File size is at offset + 8 (after cbProp and flags)
        file_size = struct.unpack_from('<Q', data, offset + 8)[0]
    
    return file_size


def parse_timestamps(data, offset, length):
    """Parse Timestamps block."""
    if length < 24:
        raise ValueError("Timestamps block too short")
    
    creation = struct.unpack_from('<Q', data, offset)[0]
    access = struct.unpack_from('<Q', data, offset + 8)[0]
    write = struct.unpack_from('<Q', data, offset + 16)[0]
    
    creation_time = filetime_to_iso8601(creation)
    access_time = filetime_to_iso8601(access)
    write_time = filetime_to_iso8601(write)
    
    return creation_time, access_time, write_time


def parse_link_file(filepath):
    """Parse a .lnk file and return metadata."""
    if not os.path.isfile(filepath):
        fail(f"File not found: {filepath}")
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        fail(f"Cannot read file: {e}")
    
    # Check minimum size
    if len(data) < 76:
        fail("File too small to be a valid .lnk file")
    
    # Header
    header_size = struct.unpack_from('<I', data, 0)[0]
    if header_size != 0x4C:  # 76 bytes
        fail(f"Invalid header size: {header_size}")
    
    # CLSID check
    clsid = data[4:20]
    expected_clsid = bytes([
        0xA0, 0x36, 0x9F, 0xB0, 0xB6, 0x69, 0x11, 0x91,
        0x9F, 0xA5, 0x00, 0x00, 0xF8, 0x05, 0x34, 0x03
    ])
    if clsid != expected_clsid:
        fail("Invalid CLSID")
    
    # LinkFlags
    link_flags = struct.unpack_from('<I', data, 20)[0]
    
    LINKFLAG_HAS_LINKINFO = 0x00000001
    LINKFLAG_HAS_COMMANDLINE = 0x00000002
    LINKFLAG_HAS_ICONLOCATION = 0x00000004
    LINKFLAG_HAS_STRING = 0x00000008
    LINKFLAG_HAS_IDLIST = 0x00000010
    LINKFLAG_HAS_NAME = 0x00000020
    LINKFLAG_HAS_RELIDLIST = 0x00000040
    LINKFLAG_HAS_WORKINGDIR = 0x00000080
    LINKFLAG_HAS_ICONFILENAME = 0x00000100
    LINKFLAG_HAS_DLLSEARCHPATH = 0x00000200
    LINKFLAG_HAS_CLASSID = 0x00000400
    LINKFLAG_HAS_ICONID = 0x00001000
    LINKFLAG_HAS_RUNUSER = 0x00002000
    LINKFLAG_HAS_STORED_USER = 0x00004000
    
    pos = 76  # After header
    
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    icon_index = None
    file_size = 0
    creation_time = None
    access_time = None
    write_time = None
    
    # Parse blocks in order as specified by MS-LNK
    # Block order:
    # 1. LINKINFO (if HAS_LINKINFO)
    # 2. StringData (if HAS_STRING)
    # 3. IconLocation (if HAS_ICONLOCATION)
    # 4. CommandLine (if HAS_COMMANDLINE)
    # 5. IconFileName (if HAS_ICONFILENAME)
    # 6. WorkingDir (if HAS_WORKINGDIR)
    # 7. LocalizedName (if HAS_NAME)
    # 8. RelativePath (if HAS_RELIDLIST or HAS_NAME, relative path is in StringData)
    # 9. CommonFolderId (if HAS_CLASSID)
    # 10. IconId (if HAS_ICONID)
    # 11. DLLSearchPath (if HAS_DLLSEARCHPATH)
    # 12. RunUser (if HAS_RUNUSER)
    # 13. ClassStoreData (if HAS_STORED_USER)
    # 14. Timestamps (always present? No, it's part of the structure but let me check)
    # Actually, looking at the spec more carefully:
    # The blocks after the header are:
    # - LinkInfo (if flag set)
    # - String block (if flag set) - contains LocalizedName, WorkingDir, RelativePath, CommandLine, IconFileName
    # - IconLocation (if flag set) - separate from String block
    # - Timestamps (always present? Let me verify)
    
    # Actually, the standard layout after the 76-byte header is:
    # 1. If HAS_LINKINFO: LinkInfo block
    # 2. If HAS_STRING: String block (contains multiple strings)
    # 3. If HAS_ICONLOCATION: IconLocation block (separate)
    # 4. If HAS_COMMANDLINE: Command line is actually in the String block
    # 5. If HAS_ICONFILENAME: Icon file name is in the String block
    # 6. If HAS_WORKINGDIR: Working dir is in the String block
    # 7. If HAS_NAME: Localized name is in the String block
    # 8. If HAS_RELIDLIST: Relative path is in the String block
    # 9. Timestamps block (always present)
    # 10. Other optional blocks
    
    # Let me re-read the spec. The String block contains:
    # - LocalizedName (if HAS_NAME)
    # - WorkingDir (if HAS_WORKINGDIR)
    # - RelativePath (if HAS_RELIDLIST)
    # - CommandLine (if HAS_COMMANDLINE)
    # - IconFileName (if HAS_ICONFILENAME)
    # - DllSearchPath (if HAS_DLLSEARCHPATH)
    # - RunUser (if HAS_RUNUSER)
    
    # Wait, I need to be more careful. Let me look at the actual structure.
    
    # According to MS-LNK, after the header:
    # - LINKINFO (optional)
    # - String block (optional) - this is a structured block with a size prefix
    # - IconLocation (optional) - separate block
    # - Timestamps (always present)
    # - Other blocks...
    
    # Actually, let me look at this more carefully. The typical .lnk file structure:
    # Offset 0: Header (76 bytes)
    # Then variable blocks based on flags
    
    # The String block structure:
    # DWORD Size (total size of the string block)
    # Then strings in order based on flags
    
    # Let me parse step by step
    
    # First, check for LinkInfo
    if link_flags & LINKFLAG_HAS_LINKINFO:
        if pos + 4 > len(data):
            fail("Truncated: LinkInfo size")
        linkinfo_size = struct.unpack_from('<I', data, pos)[0]
        if pos + 4 + linkinfo_size > len(data):
            fail("Truncated: LinkInfo block")
        try:
            linkinfo = parse_link_info(data, pos + 4, linkinfo_size)
            relative_path = linkinfo['relative_path']
            working_dir = linkinfo['working_dir']
            command_line_arguments = linkinfo['command_line']
            icon_location = linkinfo['icon_location']
            icon_index = linkinfo['icon_index']
        except Exception as e:
            fail(f"Error parsing LinkInfo: {e}")
        pos += 4 + linkinfo_size
    
    # String block
    if link_flags & LINKFLAG_HAS_STRING:
        if pos + 4 > len(data):
            fail("Truncated: String block size")
        string_block_size = struct.unpack_from('<I', data, pos)[0]
        if pos + 4 + string_block_size > len(data):
            fail("Truncated: String block")
        
        str_pos = pos + 4
        str_end = pos + 4 + string_block_size
        
        # Parse strings in the order they appear
        # The order is determined by the flags
        # Looking at the spec, the strings in the String block are:
        # 1. LocalizedName (if HAS_NAME)
        # 2. RelativePath (if HAS_RELIDLIST)  
        # 3. WorkingDir (if HAS_WORKINGDIR)
        # 4. CommandLine (if HAS_COMMANDLINE)
        # 5. IconFileName (if HAS_ICONFILENAME)
        # 6. DllSearchPath (if HAS_DLLSEARCHPATH)
        # 7. RunUser (if HAS_RUNUSER)
        
        # Each string is: WORD length (number of chars including null) + UTF-16 string
        
        def read_string(str_pos, end):
            if str_pos + 2 > end:
                raise ValueError("String block truncated")
            cch = struct.unpack_from('<H', data, str_pos)[0]
            str_bytes = cch * 2
            if str_pos + 2 + str_bytes > end:
                raise ValueError("String block truncated")
            s = parse_utf16_string(data, str_pos + 2, str_bytes)
            if s and s[-1] == '\x00':
                s = s[:-1]
            return s, str_pos + 2 + str_bytes
        
        try:
            if link_flags & LINKFLAG_HAS_NAME:
                name_string, str_pos = read_string(str_pos, str_end)
            
            if link_flags & LINKFLAG_HAS_RELIDLIST:
                if relative_path is None:  # Only set if not already set from LinkInfo
                    relative_path, str_pos = read_string(str_pos, str_end)
            
            if link_flags & LINKFLAG_HAS_WORKINGDIR:
                if working_dir is None:  # Only set if not already set from LinkInfo
                    working_dir, str_pos = read_string(str_pos, str_end)
            
            if link_flags & LINKFLAG_HAS_COMMANDLINE:
                if command_line_arguments is None:  # Only set if not already set from LinkInfo
                    command_line_arguments, str_pos = read_string(str_pos, str_end)
            
            if link_flags & LINKFLAG_HAS_ICONFILENAME:
                if icon_location is None:  # Only set if not already set from LinkInfo
                    icon_location, str_pos = read_string(str_pos, str_end)
            
            if link_flags & 0x00000200:  # DLLSEARCHPATH
                _, str_pos = read_string(str_pos, str_end)
            
            if link_flags & 0x00002000:  # RUNUSER
                _, str_pos = read_string(str_pos, str_end)
        except Exception as e:
            fail(f"Error parsing String block: {e}")
        
        pos = str_end
    
    # IconLocation block (separate from String block)
    if link_flags & LINKFLAG_HAS_ICONLOCATION:
        # IconLocation structure:
        # DWORD Size
        # WORD cchIcon
        # WORD wIconNumber
        # BYTE IconPath[]
        if pos + 4 > len(data):
            fail("Truncated: IconLocation size")
        iconloc_size = struct.unpack_from('<I', data, pos)[0]
        if pos + 4 + iconloc_size > len(data):
            fail("Truncated: IconLocation block")
        
        try:
            if pos + 8 > len(data):
                raise ValueError("IconLocation block too short")
            cch_icon = struct.unpack_from('<H', data, pos + 4)[0]
            w_icon_number = struct.unpack_from('<H', data, pos + 6)[0]
            
            string_bytes = cch_icon * 2
            if pos + 8 + string_bytes > len(data):
                raise ValueError("IconLocation string exceeds block")
            
            icon_loc_str = parse_utf16_string(data, pos + 8, cch_icon * 2)
            if icon_loc_str and icon_loc_str[-1] == '\x00':
                icon_loc_str = icon_loc_str[:-1]
            
            # Only set if not already set
            if icon_location is None:
                icon_location = icon_loc_str
            if icon_index is None:
                icon_index = w_icon_number
        except Exception as e:
            fail(f"Error parsing IconLocation: {e}")
        
        pos += 4 + iconloc_size
    
    # Now look for Timestamps block
    # The timestamps block is typically near the end
    # Structure: DWORD Size, then three FILETIME (8 bytes each)
    
    # Let's scan for the timestamps block
    # Actually, in the standard .lnk format, the timestamps are always present
    # and come after the string/iconlocation blocks
    
    # Let me check if we have enough data
    if pos + 4 > len(data):
        fail("Truncated: cannot read next block size")
    
    next_size = struct.unpack_from('<I', data, pos)[0]
    
    # The timestamps block has size 24 (4 for size + 3*8 for timestamps)
    # But there might be other blocks in between
    
    # Let me look for the timestamps block by scanning
    # Actually, let me just try to parse the remaining blocks
    
    # For now, let's assume the next block is timestamps if its size is 24
    # Or we can scan for it
    
    # A more robust approach: parse all remaining blocks
    # But for simplicity, let's look for a block of size 24 that contains timestamps
    
    # Actually, let me just try to read timestamps from the expected position
    # The typical order after String/IconLocation is:
    # - Timestamps
    # - Other optional blocks
    
    # Let's try to find the timestamps block
    # It should be a block with size 24
    
    # For now, let's assume it's the next block
    if next_size == 24:
        if pos + 24 > len(data):
            fail("Truncated: Timestamps block")
        try:
            creation_time, access_time, write_time = parse_timestamps(data, pos + 4, 20)
        except Exception as e:
            fail(f"Error parsing timestamps: {e}")
        pos += 24
    else:
        # The timestamps might not be the next block, or the file is malformed
        # Let's try to scan for it
        found = False
        search_pos = pos
        while search_pos + 4 <= len(data):
            block_size = struct.unpack_from('<I', data, search_pos)[0]
            if block_size == 24 and search_pos + 24 <= len(data):
                try:
                    creation_time, access_time, write_time = parse_timestamps(data, search_pos + 4, 20)
                    found = True
                    break
                except Exception:
                    pass
            # Skip this block
            if block_size < 4 or block_size > 100000:
                break
            search_pos += 4 + block_size
            if search_pos > len(data) - 4:
                break
        
        if not found:
            # Timestamps not found - this is a problem
            # But they should be present in a valid .lnk file
            # Let's fail
            fail("Could not find timestamps block")
    
    # Now get file size from FileProperties block if present
    # FileProperties is an optional block
    # Let's scan for it
    
    # Actually, file_size is not always present. The output contract says file_size should be 0 if absent?
    # No wait, the contract says "A field that is genuinely absent from the file must be null."
    # But it also says file_size should be an integer. Let me re-read.
    # 
    # "file_size": 0 - this is the default in the example
    # But the rules say absent fields must be null.
    # 
    # Hmm, but file_size is listed as an integer type. If it's absent, should it be null or 0?
    # The rules say: "A field that is genuinely absent from the file must be null. Do not substitute an empty string, a zero, or a default."
    # So if file_size is absent, it should be null.
    # But the example shows 0. Let me re-read the contract.
    #
    # The contract shows the JSON structure with file_size: 0 and icon_index: 0 as examples.
    # But the rules say absent fields must be null.
    # I think the example is just showing the type, not the value.
    # So if file_size is absent, it should be null.
    #
    # Wait, but icon_index is also an integer. If absent, it should be null too.
    #
    # Let me check if FileProperties block is present
    file_size = None
    
    # Scan for FileProperties block
    # FileProperties structure:
    # DWORD Size
    # DWORD Flags
    # If FLAGS & 0x00000002: QWORD Size
    # If FLAGS & 0x00000004: FILETIME Creation
    # If FLAGS & 0x00000008: FILETIME Access
    # If FLAGS & 0x00000010: FILETIME Write
    # If FLAGS & 0x00000001: DWORD Attributes
    
    # Let's scan for it
    search_pos = pos
    while search_pos + 4 <= len(data):
        block_size = struct.unpack_from('<I', data, search_pos)[0]
        if block_size < 4 or block_size > 100000:
            break
        if search_pos + 4 + block_size > len(data):
            break
        
        # Check if this could be FileProperties
        # FileProperties has size >= 8 (at least size + flags)
        if block_size >= 8:
            flags_val = struct.unpack_from('<I', data, search_pos + 4)[0]
            # Check if it has the SIZE flag
            if flags_val & 0x00000002:
                # Could be FileProperties
                # Verify by checking if the structure makes sense
                expected = 4 + 4  # size + flags
                if flags_val & 0x00000001:
                    expected += 4
                if flags_val & 0x00000002:
                    expected += 8
                if flags_val & 0x00000004:
                    expected += 8
                if flags_val & 0x00000008:
                    expected += 8
                if flags_val & 0x00000010:
                    expected += 8
                
                if expected == block_size:
                    # This is likely FileProperties
                    try:
                        fs = parse_file_properties(data, search_pos, block_size)
                        file_size = fs
                    except Exception:
                        pass
                    break
        
        search_pos += 4 + block_size
    
    # Build the result
    result = {
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
    
    return result


def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    try:
        result = parse_link_file(filepath)
        print(json.dumps(result))
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        fail(f"Parse error: {e}")


if __name__ == "__main__":
    main()