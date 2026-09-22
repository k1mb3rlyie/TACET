#!/usr/bin/env python3
import struct
import sys
import json
import uuid
from datetime import datetime, timezone, timedelta

HEADER_SIZE = 0x4C
LINK_CLSID = uuid.UUID('00021401-0000-0000-C000-000000000046')

LINKFLAGS_HASLINKTARGETIDLIST = 0x00000001
LINKFLAGS_HASLINKINFO = 0x00000002
LINKFLAGS_HASNAME = 0x00000004
LINKFLAGS_HASRELATIVEPATH = 0x00000008
LINKFLAGS_HASWORKINGDIR = 0x00000010
LINKFLAGS_HASARGUMENTS = 0x00000020
LINKFLAGS_HASICONLOCATION = 0x00000040
LINKFLAGS_ISUNICODE = 0x00000080

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)


def filetime_to_iso(ft):
    """Convert 64-bit FILETIME (100ns intervals since 1601-01-01 UTC) to ISO 8601 string with UTC offset."""
    if ft == 0:
        # Some lnk files use 0 for no time. But per spec, 0 is a valid FILETIME (1601-01-01).
        # However, in practice, 0 often means "unset". The spec says FILETIME is unsigned 64-bit.
        # We'll convert it faithfully.
        pass
    try:
        dt = FILETIME_EPOCH + timedelta(microseconds=ft // 10)
        return dt.isoformat()
    except (OverflowError, OSError):
        raise ValueError(f"FILETIME value {ft} out of range")


def read_fixed(data, offset, size, name):
    if offset < 0 or offset + size > len(data):
        raise ValueError(f"Truncated: cannot read {size} bytes at offset {offset} for {name}")
    return data[offset:offset + size]


def parse_id_list(data, offset):
    """
    Parse IDList. Returns new offset.
    IDList is a sequence of items. Each item:
      - 2 bytes: length in bytes of the item (including the 2-byte length itself? No.)
    Actually, per MS-SHLLINK, the IDList is an array of IDLIST structures.
    Each entry:
      - WORD: size of the entry in bytes (including the WORD itself and the null terminator)
      - bytes: the data, null-terminated
    
    We just need to skip it. Let's read entries until we hit a zero-length or run out.
    Actually, the IDList is terminated by a 2-byte zero (null terminator for the list? No.)
    
    Per MS-SHLLINK 2.2.1:
    The IDList is a variable-length array of IDLIST entries. Each entry consists of:
    - A 16-bit unsigned integer specifying the size of the entry, in bytes, including the 16-bit integer and the null terminator.
    - A variable-length byte array containing the IDLIST entry data, null-terminated.
    
    The entire IDList is terminated by a 2-byte zero.
    
    So we read:
    - 2 bytes: size (if 0, end of IDList)
    - (size - 2) bytes of data
    Repeat until size is 0.
    """
    while True:
        if offset + 2 > len(data):
            raise ValueError("Truncated IDList")
        size = struct.unpack_from('<H', data, offset)[0]
        if size == 0:
            offset += 2
            break
        if size < 2:
            raise ValueError(f"Invalid IDList entry size: {size}")
        if offset + size > len(data):
            raise ValueError("Truncated IDList entry")
        offset += size
    return offset


def parse_link_info(data, offset):
    """
    Parse LinkInfo. Returns new offset.
    Per MS-SHLLINK 2.2.2:
    LinkInfo consists of:
    - LinkInfoSize: DWORD (size of the entire LinkInfo structure, including this field)
    - HeaderSize: WORD (size of the LinkInfo header, in bytes)
    - Flags: WORD
    - (optional) CommonNetworkRelativeLength: DWORD
    - (optional) CommonNetworkRelativePath: variable
    - (optional) LocalBasePath: variable
    - (optional) CommonPathSuffix: variable
    
    We'll read LinkInfoSize and skip that many bytes.
    """
    if offset + 4 > len(data):
        raise ValueError("Truncated LinkInfo")
    link_info_size = struct.unpack_from('<I', data, offset)[0]
    if link_info_size < 4:
        raise ValueError(f"Invalid LinkInfoSize: {link_info_size}")
    # Skip the entire LinkInfo
    if offset + link_info_size > len(data):
        raise ValueError("Truncated LinkInfo")
    offset += link_info_size
    return offset


def parse_string_section(data, offset, is_unicode):
    """
    Parse a StringData section.
    Returns (string_value, new_offset).
    """
    if offset + 2 > len(data):
        raise ValueError("Truncated StringData: cannot read CountCharacters")
    count_chars = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    if is_unicode:
        byte_count = count_chars * 2
    else:
        byte_count = count_chars
    
    if offset + byte_count > len(data):
        raise ValueError("Truncated StringData: string data exceeds file bounds")
    
    raw = data[offset:offset + byte_count]
    offset += byte_count
    
    if is_unicode:
        try:
            s = raw.decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16LE string data")
    else:
        try:
            s = raw.decode('cp1252')
        except UnicodeDecodeError:
            # Try ascii as fallback? Or fail.
            try:
                s = raw.decode('latin-1')
            except:
                raise ValueError("Invalid string encoding")
    
    return s, offset


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: parser.py <path-to-lnk-file>"}))
        sys.exit(1)
    
    filepath = sys.argv[1]
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except (IOError, OSError) as e:
        print(json.dumps({"error": f"Cannot read file: {str(e)}"}))
        sys.exit(1)
    
    try:
        # Parse header
        if len(data) < HEADER_SIZE:
            raise ValueError("File too small for ShellLinkHeader")
        
        header_size = struct.unpack_from('<I', data, 0x00)[0]
        if header_size != HEADER_SIZE:
            raise ValueError(f"Invalid HeaderSize: {header_size:#x}, expected {HEADER_SIZE:#x}")
        
        clsid_bytes = data[0x04:0x14]
        clsid = uuid.UUID(bytes=clsid_bytes)
        if clsid != LINK_CLSID:
            raise ValueError(f"Invalid LinkCLSID: {clsid}, expected {LINK_CLSID}")
        
        link_flags = struct.unpack_from('<I', data, 0x14)[0]
        file_attributes = struct.unpack_from('<I', data, 0x18)[0]
        creation_time_ft = struct.unpack_from('<Q', data, 0x1C)[0]
        access_time_ft = struct.unpack_from('<Q', data, 0x24)[0]
        write_time_ft = struct.unpack_from('<Q', data, 0x2C)[0]
        file_size = struct.unpack_from('<I', data, 0x34)[0]  # unsigned
        icon_index = struct.unpack_from('<i', data, 0x38)[0]  # signed
        show_command = struct.unpack_from('<I', data, 0x3C)[0]
        hot_key = struct.unpack_from('<H', data, 0x40)[0]
        reserved1 = struct.unpack_from('<H', data, 0x42)[0]
        reserved2 = struct.unpack_from('<I', data, 0x44)[0]
        reserved3 = struct.unpack_from('<I', data, 0x48)[0]
        
        if reserved1 != 0:
            raise ValueError(f"Reserved1 is not zero: {reserved1:#x}")
        if reserved2 != 0:
            raise ValueError(f"Reserved2 is not zero: {reserved2:#x}")
        if reserved3 != 0:
            raise ValueError(f"Reserved3 is not zero: {reserved3:#x}")
        
        is_unicode = bool(link_flags & LINKFLAGS_ISUNICODE)
        
        offset = HEADER_SIZE
        
        # Process optional structures in order
        if link_flags & LINKFLAGS_HASLINKTARGETIDLIST:
            offset = parse_id_list(data, offset)
        
        if link_flags & LINKFLAGS_HASLINKINFO:
            offset = parse_link_info(data, offset)
        
        # Parse StringData sections in order
        name_string = None
        relative_path = None
        working_dir = None
        command_line_arguments = None
        icon_location = None
        
        if link_flags & LINKFLAGS_HASNAME:
            name_string, offset = parse_string_section(data, offset, is_unicode)
        
        if link_flags & LINKFLAGS_HASRELATIVEPATH:
            relative_path, offset = parse_string_section(data, offset, is_unicode)
        
        if link_flags & LINKFLAGS_HASWORKINGDIR:
            working_dir, offset = parse_string_section(data, offset, is_unicode)
        
        if link_flags & LINKFLAGS_HASARGUMENTS:
            command_line_arguments, offset = parse_string_section(data, offset, is_unicode)
        
        if link_flags & LINKFLAGS_HASICONLOCATION:
            icon_location, offset = parse_string_section(data, offset, is_unicode)
        
        # Now we should be at EXTRA_DATA
        # EXTRA_DATA is a sequence of blocks terminated by TerminalBlock (DWORD < 0x04)
        # We don't need to parse the extra data for the output, but we should verify
        # that the structure is valid. However, the spec says "After the StringData sections,
        # the file ends with a sequence of extra data blocks terminated by a TerminalBlock."
        # We'll just check that we can read at least the terminal block marker.
        
        if offset >= len(data):
            # No extra data, which might be okay if there's no extra data at all?
            # But the spec says there IS a sequence terminated by TerminalBlock.
            # If offset == len(data), there's no terminal block. Is that valid?
            # Per the spec, the file ends with the extra data. If there's no extra data,
            # maybe it's just empty. Let's be lenient here and not fail, since the
            # required fields are already parsed.
            pass
        else:
            # Try to parse extra data blocks to verify structure
            while offset + 4 <= len(data):
                block_type = struct.unpack_from('<I', data, offset)[0]
                if block_type < 0x00000004:
                    # TerminalBlock
                    offset += 4
                    break
                else:
                    # Read the size of this block
                    if offset + 4 > len(data):
                        raise ValueError("Truncated extra data block")
                    block_size = struct.unpack_from('<I', data, offset + 4)[0]
                    if block_size < 8:
                        raise ValueError(f"Invalid extra data block size: {block_size}")
                    # Skip the block
                    if offset + block_size > len(data):
                        raise ValueError("Truncated extra data block")
                    offset += block_size
            else:
                # Loop finished without break, meaning we ran out of data without finding TerminalBlock
                raise ValueError("Missing TerminalBlock in EXTRA_DATA")
        
        # Convert timestamps
        creation_time = filetime_to_iso(creation_time_ft)
        access_time = filetime_to_iso(access_time_ft)
        write_time = filetime_to_iso(write_time_ft)
        
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
        print(json.dumps({"error": f"Unexpected error: {str(e)}"}))
        sys.exit(0)


if __name__ == '__main__':
    main()