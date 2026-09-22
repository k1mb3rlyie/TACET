import sys
import struct
import json
import os
from datetime import datetime, timezone

def windows_filetime_to_iso8601(ft):
    """Convert Windows FILETIME (100ns intervals since 1601-01-01) to ISO 8601 UTC string."""
    if ft == 0:
        return None
    # Windows epoch is 1601-01-01T00:00:00Z
    # Unix epoch is 1970-01-01T00:00:00Z
    # Difference: 369 days + ... actually 11644473600 seconds
    unix_ts = (ft / 10000000.0) - 11644473600.0
    dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    return dt.isoformat()

def read_uint16(data, offset):
    if offset + 2 > len(data):
        raise ValueError("Truncated file: cannot read uint16")
    return struct.unpack_from('<H', data, offset)[0]

def read_uint32(data, offset):
    if offset + 4 > len(data):
        raise ValueError("Truncated file: cannot read uint32")
    return struct.unpack_from('<I', data, offset)[0]

def read_uint64(data, offset):
    if offset + 8 > len(data):
        raise ValueError("Truncated file: cannot read uint64")
    return struct.unpack_from('<Q', data, offset)[0]

def read_filetime(data, offset):
    if offset + 8 > len(data):
        raise ValueError("Truncated file: cannot read FILETIME")
    return struct.unpack_from('<Q', data, offset)[0]

def parse_string_block(data, offset, length):
    """Parse a string block from offset with given length (in bytes)."""
    if offset + length > len(data):
        raise ValueError("Truncated file: string block extends beyond data")
    raw = data[offset:offset + length]
    # Try UTF-16LE first (Windows standard)
    try:
        s = raw.decode('utf-16-le')
        # Strip null terminator if present
        if s.endswith('\x00'):
            s = s[:-1]
        return s
    except (UnicodeDecodeError, ValueError):
        pass
    # Try UTF-8
    try:
        s = raw.decode('utf-8')
        if s.endswith('\x00'):
            s = s[:-1]
        return s
    except (UnicodeDecodeError, ValueError):
        pass
    # Try ASCII/Latin-1 as last resort
    try:
        s = raw.decode('latin-1')
        if s.endswith('\x00'):
            s = s[:-1]
        return s
    except:
        raise ValueError("Cannot decode string block")

def parse_localized_name(data, offset, size):
    """Parse LocalizedNameBlock."""
    if size < 2:
        raise ValueError("Localized name block too small")
    # LocalizedNameLength is WORD (2 bytes)
    name_len = read_uint16(data, offset)
    if offset + 2 + name_len > len(data):
        raise ValueError("Truncated file: localized name extends beyond data")
    s = parse_string_block(data, offset + 2, name_len)
    return s

def parse_linkinfo(data, offset, size):
    """Parse LinkInfoBlock."""
    if size < 4:
        raise ValueError("LinkInfo block too small")
    # LinkInfoSize is DWORD
    linkinfo_size = read_uint32(data, offset)
    # We need at least 24 bytes for fixed fields
    if size < 24:
        raise ValueError("LinkInfo block too small for fixed fields")
    
    # Offset 4: LinkFlags is DWORD (but we already have it from header)
    # Actually, LinkInfoSize is at offset 0 (4 bytes), then:
    # Offset 4: LinkFlags (4 bytes) - same as in header
    # Offset 8: FileAttributes (4 bytes)
    # Offset 12: CreationTime (8 bytes)
    # Offset 20: AccessTime (8 bytes)
    # Offset 28: WriteTime (8 bytes)
    # Offset 36: FileSize (8 bytes)
    # Offset 44: IconLocation (variable)
    # Offset 44 + iconloc_len: RelativePath (variable)
    # Then: CommonName, ParserPath, NetworkProviderName
    
    if size < 44:
        raise ValueError("LinkInfo block too small for timestamps and file size")
    
    file_size = read_uint64(data, offset + 36)
    
    # IconLocation: WORD length + data
    iconloc_len = read_uint16(data, offset + 44)
    if offset + 44 + 2 + iconloc_len > len(data):
        raise ValueError("Truncated file: icon location extends beyond data")
    icon_loc = None
    if iconloc_len > 0:
        icon_loc = parse_string_block(data, offset + 46, iconloc_len)
    
    # RelativePath: WORD length + data
    relpath_offset = offset + 44 + 2 + iconloc_len
    if relpath_offset + 2 > len(data):
        raise ValueError("Truncated file: cannot read relative path length")
    relpath_len = read_uint16(data, relpath_offset)
    if relpath_offset + 2 + relpath_len > len(data):
        raise ValueError("Truncated file: relative path extends beyond data")
    relative_path = None
    if relpath_len > 0:
        relative_path = parse_string_block(data, relpath_offset + 2, relpath_len)
    
    return {
        "file_size": file_size,
        "icon_location": icon_loc,
        "relative_path": relative_path
    }

def parse_working_dir(data, offset, size):
    """Parse WorkingDirectoryBlock."""
    if size < 2:
        raise ValueError("Working directory block too small")
    wd_len = read_uint16(data, offset)
    if offset + 2 + wd_len > len(data):
        raise ValueError("Truncated file: working directory extends beyond data")
    if wd_len == 0:
        return None
    return parse_string_block(data, offset + 2, wd_len)

def parse_command_line_args(data, offset, size):
    """Parse CommandLineArgumentsBlock."""
    if size < 2:
        raise ValueError("Command line args block too small")
    args_len = read_uint16(data, offset)
    if offset + 2 + args_len > len(data):
        raise ValueError("Truncated file: command line args extends beyond data")
    if args_len == 0:
        return None
    return parse_string_block(data, offset + 2, args_len)

def parse_icon_location(data, offset, size):
    """Parse IconLocationBlock."""
    if size < 2:
        raise ValueError("Icon location block too small")
    icon_len = read_uint16(data, offset)
    if offset + 2 + icon_len > len(data):
        raise ValueError("Truncated file: icon location extends beyond data")
    if icon_len == 0:
        return None
    return parse_string_block(data, offset + 2, icon_len)

def parse_icon_index(data, offset, size):
    """Parse IconIndexBlock."""
    if size < 4:
        raise ValueError("Icon index block too small")
    idx = read_uint32(data, offset)
    return idx

def parse_creation_time(data, offset, size):
    """Parse CreationTimeBlock."""
    if size < 8:
        raise ValueError("Creation time block too small")
    ft = read_filetime(data, offset)
    if ft == 0:
        return None
    return windows_filetime_to_iso8601(ft)

def parse_access_time(data, offset, size):
    """Parse AccessTimeBlock."""
    if size < 8:
        raise ValueError("Access time block too small")
    ft = read_filetime(data, offset)
    if ft == 0:
        return None
    return windows_filetime_to_iso8601(ft)

def parse_write_time(data, offset, size):
    """Parse WriteTimeBlock."""
    if size < 8:
        raise ValueError("Write time block too small")
    ft = read_filetime(data, offset)
    if ft == 0:
        return None
    return windows_filetime_to_iso8601(ft)

def parse_lnk_file(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    
    if len(data) < 76:
        raise ValueError("File too small to be a valid LNK file")
    
    # Check header
    # CLSID: 8 bytes {00021401-0000-0000-C000-000000000046}
    expected_clsid = bytes([
        0x4C, 0x00, 0x02, 0x01,  # Actually, let me use the correct CLSID
    ])
    # The CLSID for LNK is: 00 02 14 01 00 00 00 00 C0 00 00 00 00 00 00 46
    # Wait, let me be precise. The LNK format starts with:
    # Bytes 0-15: CLSID {00021401-0000-0000-C000-000000000046}
    # In little-endian: 4C 01 14 00 01 00 00 00 C0 00 00 00 00 00 00 46
    # Let me just check the first 4 bytes are 0x4C011400 or similar
    # Actually, the standard signature is:
    # 00 02 14 01 00 00 00 00 C0 00 00 00 00 00 00 46
    # But stored in little-endian for the 16-byte GUID
    # Let me just verify it's a reasonable LNK file by checking structure
    
    # Offset 16: LinkFlags (4 bytes)
    link_flags = read_uint32(data, 16)
    
    # If no flags are set, there are no additional data blocks
    # But we still need to parse the header properly
    
    # Let's define the flags
    LINKINFO_FLAG = 0x00000001
    LINKBASEOBJECT_FLAG = 0x00000002
    COMMAND_LINE_ARGUMENTS_FLAG = 0x00000004
    ICONLOCATION_FLAG = 0x00000010
    RELATIVEPATH_FLAG = 0x00000040
    WORKINGDIR_FLAG = 0x00000080
    LOCALIZEDNAME_FLAG = 0x00000400
    ICONINDEX_FLAG = 0x00000800
    CREATIONTIME_FLAG = 0x00001000
    ACCESSTIME_FLAG = 0x00002000
    WRITETIME_FLAG = 0x00004000
    
    # Default values
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    file_size = 0
    icon_index = 0
    creation_time = None
    access_time = None
    write_time = None
    
    # Parse blocks starting at offset 76
    offset = 76
    
    if link_flags & LINKINFO_FLAG:
        # LinkInfoBlock
        # First DWORD is LinkInfoSize
        if offset + 4 > len(data):
            raise ValueError("Truncated file: cannot read LinkInfo size")
        linkinfo_size = read_uint32(data, offset)
        if linkinfo_size == 0 or linkinfo_size > 0x10000:
            raise ValueError("Invalid LinkInfo size")
        if offset + linkinfo_size > len(data):
            raise ValueError("Truncated file: LinkInfo block extends beyond data")
        
        li = parse_linkinfo(data, offset, linkinfo_size)
        file_size = li["file_size"]
        icon_location = li["icon_location"]
        relative_path = li["relative_path"]
        offset += linkinfo_size
    
    if link_flags & COMMAND_LINE_ARGUMENTS_FLAG:
        if offset + 2 > len(data):
            raise ValueError("Truncated file: cannot read command line args length")
        args_len = read_uint16(data, offset)
        if offset + 2 + args_len > len(data):
            raise ValueError("Truncated file: command line args extends beyond data")
        if args_len > 0:
            command_line_arguments = parse_string_block(data, offset + 2, args_len)
        offset += 2 + args_len
    
    if link_flags & ICONLOCATION_FLAG:
        if offset + 2 > len(data):
            raise ValueError("Truncated file: cannot read icon location length")
        icon_len = read_uint16(data, offset)
        if offset + 2 + icon_len > len(data):
            raise ValueError("Truncated file: icon location extends beyond data")
        if icon_len > 0:
            icon_location = parse_string_block(data, offset + 2, icon_len)
        offset += 2 + icon_len
    
    if link_flags & RELATIVEPATH_FLAG:
        if offset + 2 > len(data):
            raise ValueError("Truncated file: cannot read relative path length")
        rel_len = read_uint16(data, offset)
        if offset + 2 + rel_len > len(data):
            raise ValueError("Truncated file: relative path extends beyond data")
        if rel_len > 0:
            relative_path = parse_string_block(data, offset + 2, rel_len)
        offset += 2 + rel_len
    
    if link_flags & WORKINGDIR_FLAG:
        if offset + 2 > len(data):
            raise ValueError("Truncated file: cannot read working dir length")
        wd_len = read_uint16(data, offset)
        if offset + 2 + wd_len > len(data):
            raise ValueError("Truncated file: working dir extends beyond data")
        if wd_len > 0:
            working_dir = parse_string_block(data, offset + 2, wd_len)
        offset += 2 + wd_len
    
    if link_flags & LOCALIZEDNAME_FLAG:
        if offset + 2 > len(data):
            raise ValueError("Truncated file: cannot read localized name length")
        name_len = read_uint16(data, offset)
        if offset + 2 + name_len > len(data):
            raise ValueError("Truncated file: localized name extends beyond data")
        if name_len > 0:
            name_string = parse_string_block(data, offset + 2, name_len)
        offset += 2 + name_len
    
    if link_flags & ICONINDEX_FLAG:
        if offset + 4 > len(data):
            raise ValueError("Truncated file: cannot read icon index")
        icon_index = read_uint32(data, offset)
        offset += 4
    
    if link_flags & CREATIONTIME_FLAG:
        if offset + 8 > len(data):
            raise ValueError("Truncated file: cannot read creation time")
        ft = read_filetime(data, offset)
        if ft != 0:
            creation_time = windows_filetime_to_iso8601(ft)
        offset += 8
    
    if link_flags & ACCESSTIME_FLAG:
        if offset + 8 > len(data):
            raise ValueError("Truncated file: cannot read access time")
        ft = read_filetime(data, offset)
        if ft != 0:
            access_time = windows_filetime_to_iso8601(ft)
        offset += 8
    
    if link_flags & WRITETIME_FLAG:
        if offset + 8 > len(data):
            raise ValueError("Truncated file: cannot read write time")
        ft = read_filetime(data, offset)
        if ft != 0:
            write_time = windows_filetime_to_iso8601(ft)
        offset += 8
    
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
        print(json.dumps({"error": "Usage: parser.py <path-to-lnk-file>"}))
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.isfile(filepath):
        print(json.dumps({"error": "File not found"}))
        sys.exit(1)
    
    try:
        result = parse_lnk_file(filepath)
        print(json.dumps(result))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(0)

if __name__ == "__main__":
    main()