#!/usr/bin/env python3
import struct
import sys
import json
import os


def timestamp_to_iso8601(ts):
    """Convert Windows FILETIME (100ns intervals since 1601-01-01) to ISO 8601 with UTC offset."""
    # Windows epoch is 1601-01-01 00:00:00 UTC
    # Python datetime epoch is 1970-01-01 00:00:00 UTC
    # Difference: 11644473600 seconds = 116444736000000000 in 100ns units
    WINDOWS_EPOCH_OFFSET = 116444736000000000
    
    if ts == 0:
        return None
    
    seconds_since_1970 = (ts - WINDOWS_EPOCH_OFFSET) / 10000000.0
    
    import datetime
    try:
        dt = datetime.datetime.fromtimestamp(seconds_since_1970, tz=datetime.timezone.utc)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def read_string_utf16le(data, offset, max_len=None):
    """Read a null-terminated UTF-16LE string from data at offset."""
    if offset >= len(data):
        raise ValueError("Offset out of bounds")
    
    # Find null terminator
    end = offset
    while end + 1 < len(data):
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    else:
        # If we hit the end without finding null terminator, that's a problem
        # But let's check if we're at the very end
        if end + 1 >= len(data):
            # Check if the last char is null
            if end + 1 < len(data) and data[end] == 0 and data[end + 1] == 0:
                pass
            else:
                raise ValueError("No null terminator found for string")
    
    if max_len is not None and end - offset > max_len * 2:
        raise ValueError("String exceeds max length")
    
    raw = data[offset:end]
    try:
        return raw.decode('utf-16-le')
    except UnicodeDecodeError:
        raise ValueError("Invalid UTF-16LE string")


def parse_string_block(data, offset, expected_len):
    """Parse a string block from the LNK file. Returns (string, new_offset) or (None, new_offset) if absent."""
    # The string block starts with a 4-byte little-endian length
    if offset + 4 > len(data):
        raise ValueError("Truncated string block header")
    
    str_len = struct.unpack('<I', data[offset:offset+4])[0]
    offset += 4
    
    # str_len is in bytes (includes the null terminator)
    if str_len == 0:
        return None, offset
    
    # Validate str_len is reasonable
    if str_len > len(data) - offset:
        raise ValueError("String block length exceeds available data")
    
    if str_len % 2 != 0:
        raise ValueError("String block length is not even")
    
    # The string data follows, null-terminated
    raw = data[offset:offset+str_len]
    offset += str_len
    
    # Check for null terminator
    if len(raw) < 2 or raw[-2:] != b'\x00\x00':
        raise ValueError("String block missing null terminator")
    
    try:
        s = raw[:-2].decode('utf-16-le')
    except UnicodeDecodeError:
        raise ValueError("Invalid UTF-16LE in string block")
    
    return s, offset


def parse_linkinfo(data, offset):
    """Parse LinkInfo structure. Returns dict with relative_path, working_dir, etc."""
    result = {}
    
    if offset + 4 > len(data):
        raise ValueError("Truncated LinkInfo header")
    
    cbLinkInfoSize = struct.unpack('<I', data[offset:offset+4])[0]
    offset += 4
    
    if cbLinkInfoSize < 4:
        raise ValueError("Invalid LinkInfo size")
    
    if offset + cbLinkInfoSize > len(data):
        raise ValueError("LinkInfo extends beyond file")
    
    # LocalBasePath
    local_base_path_offset = offset
    if local_base_path_offset + 4 > offset + cbLinkInfoSize:
        raise ValueError("Truncated LinkInfo")
    
    lbp_len = struct.unpack('<I', data[local_base_path_offset:local_base_path_offset+4])[0]
    local_base_path_offset += 4
    
    if lbp_len > 0:
        if local_base_path_offset + lbp_len > offset + cbLinkInfoSize:
            raise ValueError("LocalBasePath extends beyond LinkInfo")
        raw = data[local_base_path_offset:local_base_path_offset+lbp_len]
        local_base_path_offset += lbp_len
        if len(raw) < 2 or raw[-2:] != b'\x00\x00':
            raise ValueError("LocalBasePath missing null terminator")
        try:
            result['relative_path'] = raw[:-2].decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16LE in LocalBasePath")
    else:
        result['relative_path'] = None
    
    # Common Path
    common_path_offset = local_base_path_offset
    if common_path_offset + 4 > offset + cbLinkInfoSize:
        raise ValueError("Truncated LinkInfo")
    
    cp_len = struct.unpack('<I', data[common_path_offset:common_path_offset+4])[0]
    common_path_offset += 4
    
    if cp_len > 0:
        if common_path_offset + cp_len > offset + cbLinkInfoSize:
            raise ValueError("CommonPath extends beyond LinkInfo")
        # CommonPath is ASCII, null-terminated
        raw = data[common_path_offset:common_path_offset+cp_len]
        common_path_offset += cp_len
        if len(raw) < 1 or raw[-1] != b'\x00':
            raise ValueError("CommonPath missing null terminator")
        try:
            common_path = raw[:-1].decode('ascii')
        except (UnicodeDecodeError, ValueError):
            raise ValueError("Invalid ASCII in CommonPath")
        # Combine with local base path
        if result.get('relative_path') is not None:
            result['relative_path'] = common_path + result['relative_path']
        else:
            result['relative_path'] = common_path
    
    # Working directory
    working_dir_offset = common_path_offset
    if working_dir_offset + 4 > offset + cbLinkInfoSize:
        raise ValueError("Truncated LinkInfo")
    
    wd_len = struct.unpack('<I', data[working_dir_offset:working_dir_offset+4])[0]
    working_dir_offset += 4
    
    if wd_len > 0:
        if working_dir_offset + wd_len > offset + cbLinkInfoSize:
            raise ValueError("WorkingDir extends beyond LinkInfo")
        raw = data[working_dir_offset:working_dir_offset+wd_len]
        working_dir_offset += wd_len
        if len(raw) < 2 or raw[-2:] != b'\x00\x00':
            raise ValueError("WorkingDir missing null terminator")
        try:
            result['working_dir'] = raw[:-2].decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16LE in WorkingDir")
    else:
        result['working_dir'] = None
    
    return result


def parse_linktargetidlist(data, offset):
    """Parse LinkTargetIDList. Returns new offset."""
    if offset + 2 > len(data):
        raise ValueError("Truncated LinkTargetIDList")
    
    id_list_size = struct.unpack('<H', data[offset:offset+2])[0]
    offset += 2
    
    if id_list_size < 2:
        raise ValueError("Invalid LinkTargetIDList size")
    
    if offset + id_list_size > len(data):
        raise ValueError("LinkTargetIDList extends beyond file")
    
    # Each entry is: 2-byte size, then that many bytes of GUID
    while id_list_size > 0:
        if offset + 2 > len(data):
            raise ValueError("Truncated LinkTargetIDList entry")
        entry_size = struct.unpack('<H', data[offset:offset+2])[0]
        offset += 2
        
        if entry_size < 2:
            raise ValueError("Invalid LinkTargetIDList entry size")
        
        if offset + entry_size > len(data):
            raise ValueError("LinkTargetIDList entry extends beyond file")
        
        offset += entry_size
        id_list_size -= 2 + entry_size
    
    return offset


def parse_string_block_optional(data, offset):
    """Parse an optional string block. Returns (string_or_None, new_offset)."""
    if offset + 4 > len(data):
        raise ValueError("Truncated optional string block header")
    
    str_len = struct.unpack('<I', data[offset:offset+4])[0]
    offset += 4
    
    if str_len == 0:
        return None, offset
    
    if str_len % 2 != 0:
        raise ValueError("String block length is not even")
    
    if offset + str_len > len(data):
        raise ValueError("String block extends beyond file")
    
    raw = data[offset:offset+str_len]
    offset += str_len
    
    if len(raw) < 2 or raw[-2:] != b'\x00\x00':
        raise ValueError("String block missing null terminator")
    
    try:
        return raw[:-2].decode('utf-16-le'), offset
    except UnicodeDecodeError:
        raise ValueError("Invalid UTF-16LE in string block")


def parse_link_flags(data, offset):
    """Parse LinkFlags. Returns (flags, new_offset)."""
    if offset + 4 > len(data):
        raise ValueError("Truncated LinkFlags")
    
    flags = struct.unpack('<I', data[offset:offset+4])[0]
    return flags, offset + 4


def parse_filetime(data, offset):
    """Parse a FILETIME (8 bytes). Returns timestamp as int or None."""
    if offset + 8 > len(data):
        raise ValueError("Truncated FILETIME")
    
    ts = struct.unpack('<Q', data[offset:offset+8])[0]
    return ts


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: parser.py <path-to-lnk-file>"}))
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except (IOError, OSError) as e:
        print(json.dumps({"error": f"Cannot read file: {e}"}))
        sys.exit(1)
    
    # Minimum LNK file size: 76-byte header + at least some content
    if len(data) < 76:
        print(json.dumps({"error": "File too small to be a valid LNK file"}))
        sys.exit(1)
    
    try:
        # Parse header
        # LinkFlagsSize (4 bytes)
        link_flags_size = struct.unpack('<I', data[0:4])[0]
        if link_flags_size != 4:
            raise ValueError(f"Invalid LinkFlagsSize: {link_flags_size}")
        
        # LinkFileFlags (4 bytes)
        link_file_flags = struct.unpack('<I', data[4:8])[0]
        
        # FileAttributes (4 bytes)
        file_attributes = struct.unpack('<I', data[8:12])[0]
        
        # CreationTime (8 bytes)
        creation_time_ts = struct.unpack('<Q', data[12:20])[0]
        
        # AccessTime (8 bytes)
        access_time_ts = struct.unpack('<Q', data[20:28])[0]
        
        # WriteTime (8 bytes)
        write_time_ts = struct.unpack('<Q', data[28:36])[0]
        
        # FileSize (8 bytes)
        file_size = struct.unpack('<Q', data[36:44])[0]
        
        # IconIndex (4 bytes)
        icon_index = struct.unpack('<I', data[44:48])[0]
        
        # CommandFlags (4 bytes)
        command_flags = struct.unpack('<I', data[48:52])[0]
        
        # Reserved1 (4 bytes)
        # Reserved2 (8 bytes)
        # Reserved3 (16 bytes)
        
        # Verify reserved fields are zero (optional check, but let's be lenient)
        
        offset = 76
        
        # Parse based on flags
        # 0x00000001 = LinkInfo
        # 0x00000002 = StringDataBlock
        # 0x00000004 = IconLocation
        # 0x00000008 = IconFileName
        # 0x00000010 = RelativePath
        # 0x00000020 = WorkingDir
        # 0x00000040 = CommandLine
        # 0x00000080 = Icon
        # 0x00000100 = RunUser
        # 0x00000200 = UUID
        # 0x00000400 = LocalBasePath
        # 0x00000800 = CommonPath
        # 0x00001000 = NetName
        # 0x00002000 = NetPathType
        # 0x00004000 = DriveType
        # 0x00008000 = DriveNumber
        # 0x00010000 = NoResolve
        # 0x00020000 = NetAnsiPath
        # 0x00040000 = UniversalName
        # 0x00080000 = NetAnsiAlt
        # 0x00100000 = CustomIcon
        # 0x00200000 = LocalBasePath2
        # 0x00400000 = CommonPath2
        
        # First, check if LinkFlagsSize matches what we expect
        # The header is 76 bytes, so offset should be 76
        
        # Parse LinkInfo if flag is set
        has_link_info = bool(link_file_flags & 0x00000001)
        has_string_data = bool(link_file_flags & 0x00000002)
        has_icon_location = bool(link_file_flags & 0x00000004)
        has_command_line = bool(link_file_flags & 0x00000040)
        
        # UnlinkFlags are for the link info
        # Parse LinkTargetIDList if has_link_info or has_string_data or has_icon_location or has_command_line
        # Actually, LinkTargetIDList comes before LinkInfo if LinkInfo is present
        # Let me re-read the format:
        #
        # The LNK file format:
        # 1. Header (76 bytes)
        # 2. LinkTargetIDList (if LinkTargetIDList flag is set, which is part of LinkInfo... no wait)
        #
        # Actually, looking at the MS-LNK spec more carefully:
        # After the fixed header, the following structures may be present:
        # - LinkTargetIDList (if LinkTargetIDList is present, which is indicated by... hmm)
        #
        # Let me reconsider. The LinkFileFlags bits:
        # Bit 0: Has LinkInfo
        # Bit 1: Has StringDataBlock
        # Bit 2: Has IconLocation
        # ...
        #
        # The order in the file after the 76-byte header:
        # 1. If Has LinkInfo (bit 0): LinkTargetIDList, then LinkInfo
        # 2. If Has StringDataBlock (bit 1): StringDataBlock
        # 3. If Has IconLocation (bit 2): IconLocation
        # 4. If Has CommandLine (bit 6): CommandLine string
        #
        # Wait, I need to check the actual order. Let me think about this more carefully.
        #
        # According to the Microsoft documentation:
        # The LNK file contains the following:
        # 1. Fixed header (76 bytes)
        # 2. LinkTargetIDList (optional)
        # 3. LinkInfo (optional)
        # 4. StringDataBlock (optional)
        # 5. IconLocation (optional)
        # 6. CommandLine (optional)
        #
        # But the flags indicate which are present. The LinkTargetIDList is always present
        # if LinkInfo is present? No, I think LinkTargetIDList is a separate thing.
        #
        # Let me look at this differently. The LinkFileFlags:
        # 0x00000001 - Has LinkInfo
        # 0x00000002 - Has StringDataBlock  
        # 0x00000004 - Has IconLocation
        # 0x00000008 - Has IconFileName
        # 0x00000010 - Has RelativePath
        # 0x00000020 - Has WorkingDir
        # 0x00000040 - Has CommandLine
        # 0x00000080 - Has Icon
        # 0x00000100 - Has RunUser
        # 0x00000200 - Has UUID
        # 0x00000400 - Has LocalBasePath
        # 0x00000800 - Has CommonPath
        # 0x00001000 - Has NetName
        # 0x00002000 - Has NetPathType
        # 0x00004000 - Has DriveType
        # 0x00008000 - Has DriveNumber
        # 0x00010000 - Has NoResolve
        # 0x00020000 - Has NetAnsiPath
        # 0x00040000 - Has UniversalName
        # 0x00080000 - Has NetAnsiAlt
        # 0x00100000 - Has CustomIcon
        # 0x00200000 - Has LocalBasePath2
        # 0x00400000 - Has CommonPath2
        #
        # The LinkInfo structure contains:
        # - Size (4 bytes)
        # - LocalBasePath
        # - CommonPath
        # - WorkingDir
        # - RelativePath
        # - CommandLine
        # - IconLocation
        # - IconFileName
        #
        # So the LinkInfo is a single structure that contains all these sub-fields.
        # The flags indicate which sub-fields are present within LinkInfo.
        #
        # And LinkTargetIDList is separate, coming before LinkInfo.
        
        # Let's parse in the correct order:
        # 1. LinkTargetIDList (if present)
        # 2. LinkInfo (if present)
        # 3. StringDataBlock (if present)
        # 4. IconLocation (if present)
        # 5. CommandLine (if present)
        
        # Actually, I recall now that LinkTargetIDList is not controlled by LinkFileFlags
        # but is always present if the file is not empty. Let me check...
        #
        # No, I think the order is:
        # After the 76-byte header:
        # - If Has LinkInfo: LinkTargetIDList followed by LinkInfo
        # - If Has StringDataBlock: StringDataBlock
        # - If Has IconLocation: IconLocation  
        # - If Has CommandLine: CommandLine
        #
        # But wait, I've seen implementations where LinkTargetIDList is parsed first
        # regardless, and it's present in most LNK files.
        
        # Let me try a different approach: parse based on what's in the file.
        
        name_string = None
        relative_path = None
        working_dir = None
        command_line_arguments = None
        icon_location = None
        
        # Parse LinkTargetIDList first (it's commonly present)
        # It has a 2-byte size header
        if offset + 2 <= len(data):
            id_list_size = struct.unpack('<H', data[offset:offset+2])[0]
            # Check if it looks like a valid LinkTargetIDList
            # Each entry is at least 2 bytes (size field) + GUID
            # Minimum size for one entry is 18 (2 + 16)
            if id_list_size >= 18 and id_list_size <= len(data) - offset:
                # Try to parse it
                try:
                    new_offset = parse_linktargetidlist(data, offset)
                    offset = new_offset
                except ValueError:
                    # Not a valid LinkTargetIDList, so it might not be present
                    # Reset offset
                    pass
        
        # Now parse based on flags
        # Has LinkInfo
        if has_link_info:
            link_info = parse_linkinfo(data, offset)
            offset += struct.unpack('<I', data[0:4])[0]  # This is wrong, let me fix
            # Actually, I need to track the offset properly
            # Let me redo this
        
        # Let me restart the parsing logic more carefully
        
        offset = 76
        
        # Parse LinkTargetIDList if present
        # The LinkTargetIDList is present if the file has it. It's identified by its structure.
        # In practice, most LNK files have it. Let's try to detect it.
        
        # A cleaner approach: parse sequentially based on flags
        
        # First, check for LinkTargetIDList
        # It's present in most LNK files. The size is 2 bytes, and it must be even.
        # Let's assume it's present and try to parse it.
        
        if offset + 2 <= len(data):
            potential_id_list_size = struct.unpack('<H', data[offset:offset+2])[0]
            # Validate: size should be reasonable and even
            if 0 < potential_id_list_size <= len(data) - offset and potential_id_list_size % 2 == 0:
                try:
                    offset = parse_linktargetidlist(data, offset)
                except ValueError:
                    # Not a valid ID list, skip
                    pass
        
        # Now parse LinkInfo if flag is set
        if has_link_info:
            # LinkInfo starts with a 4-byte size
            if offset + 4 > len(data):
                raise ValueError("Truncated LinkInfo header")
            
            link_info_size = struct.unpack('<I', data[offset:offset+4])[0]
            if link_info_size < 4:
                raise ValueError("Invalid LinkInfo size")
            
            if offset + link_info_size > len(data):
                raise ValueError("LinkInfo extends beyond file")
            
            li_offset = offset + 4
            
            # Parse LocalBasePath
            if li_offset + 4 > offset + link_info_size:
                raise ValueError("Truncated LinkInfo")
            lbp_len = struct.unpack('<I', data[li_offset:li_offset+4])[0]
            li_offset += 4
            
            if lbp_len > 0:
                if li_offset + lbp_len > offset + link_info_size:
                    raise ValueError("LocalBasePath extends beyond LinkInfo")
                raw = data[li_offset:li_offset+lbp_len]
                li_offset += lbp_len
                if len(raw) < 2 or raw[-2:] != b'\x00\x00':
                    raise ValueError("LocalBasePath missing null terminator")
                try:
                    local_base = raw[:-2].decode('utf-16-le')
                except UnicodeDecodeError:
                    raise ValueError("Invalid UTF-16LE in LocalBasePath")
            else:
                local_base = None
            
            # Parse CommonPath
            if li_offset + 4 > offset + link_info_size:
                raise ValueError("Truncated LinkInfo")
            cp_len = struct.unpack('<I', data[li_offset:li_offset+4])[0]
            li_offset += 4
            
            if cp_len > 0:
                if li_offset + cp_len > offset + link_info_size:
                    raise ValueError("CommonPath extends beyond LinkInfo")
                raw = data[li_offset:li_offset+cp_len]
                li_offset += cp_len
                if len(raw) < 1 or raw[-1] != b'\x00':
                    raise ValueError("CommonPath missing null terminator")
                try:
                    common_path = raw[:-1].decode('ascii')
                except (UnicodeDecodeError, ValueError):
                    raise ValueError("Invalid ASCII in CommonPath")
            else:
                common_path = None
            
            # Parse WorkingDir
            if li_offset + 4 > offset + link_info_size:
                raise ValueError("Truncated LinkInfo")
            wd_len = struct.unpack('<I', data[li_offset:li_offset+4])[0]
            li_offset += 4
            
            if wd_len > 0:
                if li_offset + wd_len > offset + link_info_size:
                    raise ValueError("WorkingDir extends beyond LinkInfo")
                raw = data[li_offset:li_offset+wd_len]
                li_offset += wd_len
                if len(raw) < 2 or raw[-2:] != b'\x00\x00':
                    raise ValueError("WorkingDir missing null terminator")
                try:
                    working_dir = raw[:-2].decode('utf-16-le')
                except UnicodeDecodeError:
                    raise ValueError("Invalid UTF-16LE in WorkingDir")
            
            # Parse RelativePath
            if li_offset + 4 > offset + link_info_size:
                raise ValueError("Truncated LinkInfo")
            rp_len = struct.unpack('<I', data[li_offset:li_offset+4])[0]
            li_offset += 4
            
            if rp_len > 0:
                if li_offset + rp_len > offset + link_info_size:
                    raise ValueError("RelativePath extends beyond LinkInfo")
                raw = data[li_offset:li_offset+rp_len]
                li_offset += rp_len
                if len(raw) < 2 or raw[-2:] != b'\x00\x00':
                    raise ValueError("RelativePath missing null terminator")
                try:
                    rel_path = raw[:-2].decode('utf-16-le')
                except UnicodeDecodeError:
                    raise ValueError("Invalid UTF-16LE in RelativePath")
                # Combine with local base and common path
                if local_base is not None:
                    rel_path = local_base + rel_path
                if common_path is not None:
                    rel_path = common_path + rel_path
                relative_path = rel_path
            
            # Parse CommandLine
            if li_offset + 4 > offset + link_info_size:
                raise ValueError("Truncated LinkInfo")
            cl_len = struct.unpack('<I', data[li_offset:li_offset+4])[0]
            li_offset += 4
            
            if cl_len > 0:
                if li_offset + cl_len > offset + link_info_size:
                    raise ValueError("CommandLine extends beyond LinkInfo")
                raw = data[li_offset:li_offset+cl_len]
                li_offset += cl_len
                if len(raw) < 2 or raw[-2:] != b'\x00\x00':
                    raise ValueError("CommandLine missing null terminator")
                try:
                    command_line_arguments = raw[:-2].decode('utf-16-le')
                except UnicodeDecodeError:
                    raise ValueError("Invalid UTF-16LE in CommandLine")
            
            # Parse IconLocation
            if li_offset + 4 > offset + link_info_size:
                raise ValueError("Truncated LinkInfo")
            il_len = struct.unpack('<I', data[li_offset:li_offset+4])[0]
            li_offset += 4
            
            if il_len > 0:
                if li_offset + il_len > offset + link_info_size:
                    raise ValueError("IconLocation extends beyond LinkInfo")
                raw = data[li_offset:li_offset+il_len]
                li_offset += il_len
                if len(raw) < 2 or raw[-2:] != b'\x00\x00':
                    raise ValueError("IconLocation missing null terminator")
                try:
                    icon_location = raw[:-2].decode('utf-16-le')
                except UnicodeDecodeError:
                    raise ValueError("Invalid UTF-16LE in IconLocation")
            
            # Parse IconFileName
            if li_offset + 4 > offset + link_info_size:
                raise ValueError("Truncated LinkInfo")
            ifn_len = struct.unpack('<I', data[li_offset:li_offset+4])[0]
            li_offset += 4
            
            if ifn_len > 0:
                if li_offset + ifn_len > offset + link_info_size:
                    raise ValueError("IconFileName extends beyond LinkInfo")
                raw = data[li_offset:li_offset+ifn_len]
                li_offset += ifn_len
                if len(raw) < 2 or raw[-2:] != b'\x00\x00':
                    raise ValueError("IconFileName missing null terminator")
                try:
                    icon_file_name = raw[:-2].decode('utf-16-le')
                except UnicodeDecodeError:
                    raise ValueError("Invalid UTF-16LE in IconFileName")
                # IconFileName is the icon location if IconLocation is not set
                if icon_location is None:
                    icon_location = icon_file_name
            
            offset = offset + link_info_size
        
        # Parse StringDataBlock if flag is set
        if has_string_data:
            if offset + 4 > len(data):
                raise ValueError("Truncated StringDataBlock header")
            
            sdb_len = struct.unpack('<I', data[offset:offset+4])[0]
            if sdb_len < 4:
                raise ValueError("Invalid StringDataBlock size")
            
            if offset + sdb_len > len(data):
                raise ValueError("StringDataBlock extends beyond file")
            
            sdb_offset = offset + 4
            
            # Parse NameString
            if sdb_offset + 4 > offset + sdb_len:
                raise ValueError("Truncated StringDataBlock")
            
            ns_len = struct.unpack('<I', data[sdb_offset:sdb_offset+4])[0]
            sdb_offset += 4
            
            if ns_len > 0:
                if sdb_offset + ns_len > offset + sdb_len:
                    raise ValueError("NameString extends beyond StringDataBlock")
                raw = data[sdb_offset:sdb_offset+ns_len]
                sdb_offset += ns_len
                if len(raw) < 2 or raw[-2:] != b'\x00\x00':
                    raise ValueError("NameString missing null terminator")
                try:
                    name_string = raw[:-2].decode('utf-16-le')
                except UnicodeDecodeError:
                    raise ValueError("Invalid UTF-16LE in NameString")
            
            offset = offset + sdb_len
        
        # If we didn't get name_string from StringDataBlock, it's null
        # If we didn't get other fields, they remain null
        
        # Convert timestamps
        creation_time = timestamp_to_iso8601(creation_time_ts)
        access_time = timestamp_to_iso8601(access_time_ts)
        write_time = timestamp_to_iso8601(write_time_ts)
        
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
        
        print(json.dumps(result))
        sys.exit(0)
    
    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {e}"}))
        sys.exit(0)


if __name__ == "__main__":
    main()