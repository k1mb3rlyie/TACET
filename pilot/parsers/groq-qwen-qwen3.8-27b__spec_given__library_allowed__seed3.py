#!/usr/bin/env python3
"""
MS-SHLLINK (.lnk) parser for digital forensics.

Parses a Windows Shortcut file and extracts metadata per the MS-SHLLINK spec.
Designed to handle damaged, incomplete, or tampered files gracefully.
"""

import json
import struct
import sys
import os
from datetime import datetime, timezone, timedelta

# MS-SHLLINK constants
LINK_HEADER_SIZE = 0x0000004C  # 76 bytes
LINK_CLSID = bytes.fromhex(
    "0002140100000000c0000000000000000046"
)

# LinkFlags
LINKFLAG_HASLINKTARGETIDLIST = 0x00000001
LINKFLAG_HASLINKINFO = 0x00000002
LINKFLAG_HASNAME = 0x00000004
LINKFLAG_HASRELATIVEPATH = 0x00000008
LINKFLAG_HASWORKINGDIR = 0x00000010
LINKFLAG_HASARGUMENTS = 0x00000020
LINKFLAG_HASICONLOCATION = 0x00000040
LINKFLAG_ISUNICODE = 0x00000080

# FILETIME epoch: 1601-01-01 00:00:00 UTC
FILETIME_EPOCH = datetime(1601, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
FILETIME_SECONDS_PER_100NS = 10_000_000  # 100ns intervals per second


class ParseError(Exception):
    """Raised when the .lnk file is malformed or cannot be parsed."""
    pass


def read_exact(data: bytes, offset: int, size: int, field_name: str) -> bytes:
    """Read exactly `size` bytes from `data` at `offset`.
    
    Raises ParseError if not enough data remains.
    """
    if offset < 0 or offset + size > len(data):
        raise ParseError(
            f"Truncated file: cannot read {size} bytes for {field_name} "
            f"at offset {offset} (file size: {len(data)})"
        )
    return data[offset:offset + size]


def parse_filetime(ft_value: int) -> datetime:
    """Convert a FILETIME (100-nanosecond intervals since 1601-01-01 UTC) 
    to a datetime object.
    
    Raises ParseError if the value is out of range for a valid datetime.
    """
    if ft_value < 0:
        raise ParseError(f"Invalid FILETIME value: {ft_value}")
    
    # Maximum representable datetime in Python
    max_dt = datetime.max.replace(tzinfo=timezone.utc)
    min_dt = datetime.min.replace(tzinfo=timezone.utc)
    
    # Convert 100ns intervals to seconds and microseconds
    total_seconds = ft_value // FILETIME_SECONDS_PER_100NS
    remaining_100ns = ft_value % FILETIME_SECONDS_PER_100NS
    microseconds = int(remaining_100ns * 100)  # 100ns -> 0.1 microseconds
    
    # Check bounds
    if total_seconds > 2932467599:  # Roughly year 9999
        raise ParseError(f"FILETIME value out of range: {ft_value}")
    
    dt = FILETIME_EPOCH + timedelta(seconds=total_seconds, microseconds=microseconds)
    
    # Verify it's representable
    if dt < min_dt or dt > max_dt:
        raise ParseError(f"FILETIME value out of representable range: {ft_value}")
    
    return dt


def format_filetime(ft_value: int) -> str:
    """Convert FILETIME to ISO 8601 string with UTC offset."""
    dt = parse_filetime(ft_value)
    return dt.isoformat()


def parse_string_data(data: bytes, offset: int, is_unicode: bool, 
                       field_name: str) -> tuple:
    """Parse a StringData section.
    
    Returns (string_value, new_offset).
    """
    # Read CountCharacters (unsigned 16-bit)
    count_chars_bytes = read_exact(data, offset, 2, f"{field_name} CountCharacters")
    count_chars = struct.unpack('<H', count_chars_bytes)[0]
    
    if count_chars == 0:
        return "", offset + 2
    
    offset += 2
    
    if is_unicode:
        str_bytes = count_chars * 2
        str_bytes_data = read_exact(data, offset, str_bytes, f"{field_name} string")
        try:
            value = str_bytes_data.decode('utf-16-le')
        except UnicodeDecodeError as e:
            raise ParseError(f"Invalid UTF-16LE string in {field_name}: {e}")
    else:
        str_bytes = count_chars
        str_bytes_data = read_exact(data, offset, str_bytes, f"{field_name} string")
        try:
            value = str_bytes_data.decode('cp1252')
        except UnicodeDecodeError as e:
            # Try latin-1 as fallback, which never fails
            value = str_bytes_data.decode('latin-1')
    
    return value, offset + str_bytes


def parse_id_list(data: bytes, offset: int) -> int:
    """Parse the IDList structure and return the new offset.
    
    The IDList is a sequence of null-terminated strings (or items) followed by
    a double-null terminator. The exact size is not fixed, so we scan for the
    double-null terminator.
    """
    start_offset = offset
    
    # The IDList ends with a double null byte (two consecutive 0x00 bytes)
    # We need to be careful: each item is a length-prefixed string, but for
    # our purposes, we just need to find the end.
    # 
    # Actually, per MS-SHLLINK, the IDList is:
    #   For each item:
    #     Length (1 byte, in characters, not including the null)
    #     Item (Length characters)
    #     0x00 (null terminator)
    #   Then:
    #     0x00 (final null)
    #
    # So we scan through items until we hit a length of 0, then another 0.
    
    pos = offset
    while True:
        if pos >= len(data):
            raise ParseError("IDList extends beyond end of file")
        
        length = data[pos]
        if length == 0:
            # Check for the final null
            if pos + 1 >= len(data):
                raise ParseError("IDList truncated: missing final null")
            if data[pos + 1] == 0:
                return pos + 2
            else:
                raise ParseError("IDList malformed: expected double null terminator")
        
        pos += 1  # skip length byte
        if pos + length + 1 > len(data):
            raise ParseError(f"IDList item extends beyond end of file at offset {pos}")
        pos += length  # skip item
        if pos >= len(data):
            raise ParseError("IDList truncated: missing null terminator for item")
        if data[pos] != 0:
            raise ParseError(f"IDList item at offset {pos - length} not null-terminated")
        pos += 1  # skip null terminator


def parse_link_info(data: bytes, offset: int) -> int:
    """Parse the LinkInfo structure and return the new offset.
    
    LinkInfo header is 0x1C (28) bytes, but it may contain additional data.
    The LinkInfoSize field tells us the total size.
    """
    # Read LinkInfoSize (4 bytes)
    link_info_size_bytes = read_exact(data, offset, 4, "LinkInfoSize")
    link_info_size = struct.unpack('<I', link_info_size_bytes)[0]
    
    # LinkInfoSize must be at least 0x1C (28)
    if link_info_size < 0x1C:
        raise ParseError(f"Invalid LinkInfoSize: {link_info_size}")
    
    # Verify we have enough data
    if offset + link_info_size > len(data):
        raise ParseError(
            f"LinkInfo extends beyond end of file: size {link_info_size}, "
            f"offset {offset}, file size {len(data)}"
        )
    
    return offset + link_info_size


def parse_shell_link(data: bytes) -> dict:
    """Parse a ShellLink file and return the extracted metadata."""
    
    # Minimum size check
    if len(data) < LINK_HEADER_SIZE:
        raise ParseError(
            f"File too small: {len(data)} bytes, minimum is {LINK_HEADER_SIZE}"
        )
    
    # Parse ShellLinkHeader
    header = read_exact(data, 0, LINK_HEADER_SIZE, "ShellLinkHeader")
    
    # HeaderSize
    header_size = struct.unpack('<I', header[0x00:0x04])[0]
    if header_size != LINK_HEADER_SIZE:
        raise ParseError(
            f"Invalid HeaderSize: 0x{header_size:08X}, expected 0x{LINK_HEADER_SIZE:08X}"
        )
    
    # LinkCLSID
    link_clsid = header[0x04:0x14]
    if link_clsid != LINK_CLSID:
        raise ParseError(
            f"Invalid LinkCLSID: {link_clsid.hex()}, "
            f"expected {LINK_CLSID.hex()}"
        )
    
    # LinkFlags
    link_flags = struct.unpack('<I', header[0x14:0x18])[0]
    
    # FileAttributes
    file_attributes = struct.unpack('<I', header[0x18:0x1C])[0]
    
    # CreationTime
    creation_time_raw = struct.unpack('<Q', header[0x1C:0x24])[0]
    
    # AccessTime
    access_time_raw = struct.unpack('<Q', header[0x24:0x2C])[0]
    
    # WriteTime
    write_time_raw = struct.unpack('<Q', header[0x2C:0x34])[0]
    
    # FileSize (unsigned 32-bit)
    file_size = struct.unpack('<I', header[0x34:0x38])[0]
    
    # IconIndex (signed 32-bit)
    icon_index = struct.unpack('<i', header[0x38:0x3C])[0]
    
    # ShowCommand
    show_command = struct.unpack('<I', header[0x3C:0x40])[0]
    
    # HotKey
    hotkey = struct.unpack('<H', header[0x40:0x42])[0]
    
    # Reserved1
    reserved1 = struct.unpack('<H', header[0x42:0x44])[0]
    if reserved1 != 0:
        raise ParseError(f"Reserved1 is non-zero: 0x{reserved1:04X}")
    
    # Reserved2
    reserved2 = struct.unpack('<I', header[0x44:0x48])[0]
    if reserved2 != 0:
        raise ParseError(f"Reserved2 is non-zero: 0x{reserved2:08X}")
    
    # Reserved3
    reserved3 = struct.unpack('<I', header[0x48:0x4C])[0]
    if reserved3 != 0:
        raise ParseError(f"Reserved3 is non-zero: 0x{reserved3:08X}")
    
    # Determine if strings are Unicode
    is_unicode = bool(link_flags & LINKFLAG_ISUNICODE)
    
    # Current offset after header
    offset = LINK_HEADER_SIZE
    
    # Parse optional sections based on flags
    # Order: IDList, LinkInfo, then StringData sections
    
    # 1. IDList (HasLinkTargetIDList)
    if link_flags & LINKFLAG_HASLINKTARGETIDLIST:
        offset = parse_id_list(data, offset)
    
    # 2. LinkInfo (HasLinkInfo)
    if link_flags & LINKFLAG_HASLINKINFO:
        offset = parse_link_info(data, offset)
    
    # 3. StringData sections in order:
    #    NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
    
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    # NAME_STRING
    if link_flags & LINKFLAG_HASNAME:
        name_string, offset = parse_string_data(
            data, offset, is_unicode, "NAME_STRING"
        )
    
    # RELATIVE_PATH
    if link_flags & LINKFLAG_HASRELATIVEPATH:
        relative_path, offset = parse_string_data(
            data, offset, is_unicode, "RELATIVE_PATH"
        )
    
    # WORKING_DIR
    if link_flags & LINKFLAG_HASWORKINGDIR:
        working_dir, offset = parse_string_data(
            data, offset, is_unicode, "WORKING_DIR"
        )
    
    # COMMAND_LINE_ARGUMENTS
    if link_flags & LINKFLAG_HASARGUMENTS:
        command_line_arguments, offset = parse_string_data(
            data, offset, is_unicode, "COMMAND_LINE_ARGUMENTS"
        )
    
    # ICON_LOCATION
    if link_flags & LINKFLAG_HASICONLOCATION:
        icon_location, offset = parse_string_data(
            data, offset, is_unicode, "ICON_LOCATION"
        )
    
    # 4. EXTRA_DATA blocks
    # After StringData, there is a sequence of extra data blocks terminated by
    # a TerminalBlock: a 32-bit value less than 0x00000004.
    #
    # We don't need to parse these for our output, but we should verify that
    # the remaining data is plausible (i.e., ends with a terminal block).
    # However, the spec says the file ends with these blocks. If there's no
    # extra data, that's fine.
    #
    # Actually, the requirement is just to extract the specified fields.
    # We don't need to validate the extra data blocks for the output contract,
    # but we should ensure we haven't left garbage that indicates corruption.
    #
    # For safety, let's just check that we can at least read to the end
    # without issues. The extra data blocks are optional in the sense that
    # they may not be present. We'll leave them unparsed since they don't
    # affect our output fields.
    
    # Format timestamps
    creation_time_str = format_filetime(creation_time_raw)
    access_time_str = format_filetime(access_time_raw)
    write_time_str = format_filetime(write_time_raw)
    
    return {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time_str,
        "access_time": access_time_str,
        "write_time": write_time_str,
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python parser.py <path-to-lnk-file>", file=sys.stderr)
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        if not os.path.exists(filepath):
            raise ParseError(f"File not found: {filepath}")
        
        if not os.path.isfile(filepath):
            raise ParseError(f"Not a regular file: {filepath}")
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        result = parse_shell_link(data)
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)
    
    except ParseError as e:
        print(json.dumps({"error": str(e)}), file=sys.stdout)
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {str(e)}"}), file=sys.stdout)
        sys.exit(0)


if __name__ == "__main__":
    main()