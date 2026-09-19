#!/usr/bin/env python3
"""Parse a Windows Shortcut (.lnk) file per MS-SHLLINK spec."""

import json
import struct
import sys
import uuid
from datetime import datetime, timezone, timedelta

# Constants
HEADER_SIZE = 0x4C
LINK_CLSID = uuid.UUID("00021401-0000-0000-C000-000000000046")

# LinkFlags
LF_HAS_LINK_TARGET_ID_LIST = 0x00000001
LF_HAS_LINK_INFO = 0x00000002
LF_HAS_NAME = 0x00000004
LF_HAS_RELATIVE_PATH = 0x00000008
LF_HAS_WORKING_DIR = 0x00000010
LF_HAS_ARGUMENTS = 0x00000020
LF_HAS_ICON_LOCATION = 0x00000040
LF_IS_UNICODE = 0x00000080

# FILETIME epoch: 1601-01-01 00:00:00 UTC
FILETIME_EPOCH = datetime(1601, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
TICKS_PER_SECOND = 10_000_000


def error_exit(msg: str):
    print(json.dumps({"error": msg}), file=sys.stdout)
    sys.exit(1)


def filetime_to_iso(ft_val: int) -> str:
    """Convert FILETIME (100ns intervals since 1601-01-01 UTC) to ISO 8601 with UTC offset."""
    if ft_val == 0:
        # Zero FILETIME is technically valid (1601-01-01), but in practice often means unset.
        # Per spec it's a valid timestamp. We'll return it.
        pass
    try:
        dt = FILETIME_EPOCH + timedelta(microseconds=(ft_val * 100))
        # Ensure timezone is UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except (OverflowError, ValueError):
        raise ValueError(f"FILETIME value {ft_val} not representable")


def read_string(data: bytes, offset: int, is_unicode: bool):
    """
    Read a StringData section at the given offset.
    Returns (string_value, new_offset).
    If the section is not present (shouldn't be called if flag not set), returns (None, offset).
    """
    if offset + 2 > len(data):
        raise ValueError("Truncated: not enough data for CountCharacters")
    
    count_chars = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    
    if is_unicode:
        byte_len = count_chars * 2
    else:
        byte_len = count_chars
    
    if offset + byte_len > len(data):
        raise ValueError(f"Truncated: string of {count_chars} chars ({byte_len} bytes) exceeds data")
    
    raw = data[offset:offset + byte_len]
    offset += byte_len
    
    if is_unicode:
        try:
            s = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16LE string data")
    else:
        try:
            s = raw.decode("latin-1")
        except UnicodeDecodeError:
            raise ValueError("Invalid string data")
    
    return s, offset


def parse_idlist(data: bytes, offset: int):
    """
    Parse the IDList structure. Returns new offset.
    IDList is a sequence of ID structs, each:
      - 2-byte length (length of the ID bytes, not including the 2-byte length field)
      - that many bytes
    Terminated by a 2-byte zero length.
    """
    while True:
        if offset + 2 > len(data):
            raise ValueError("Truncated IDList")
        id_len = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        if id_len == 0:
            break
        if offset + id_len > len(data):
            raise ValueError("Truncated IDList entry")
        offset += id_len
    return offset


def parse_link_info(data: bytes, offset: int):
    """
    Parse the LinkInfo structure. Returns new offset.
    LinkInfo:
      0x00: dwSize (4 bytes) - size of LinkInfo structure
      0x04: cbOffsetExtraData (4 bytes) - offset to extra data within LinkInfo
      0x08: LinkInfoHeader
      ...
      LocalBasePath
      LocalRelativePath
      CommonNetworkRelativePath
      Hotkey
      IconLocation
      Description
      RelativePath
      ParserData
      ExtraData (if cbOffsetExtraData < dwSize)
    
    For our purposes, we just need to skip past the LinkInfo.
    The dwSize tells us the total size of the LinkInfo.
    """
    if offset + 8 > len(data):
        raise ValueError("Truncated LinkInfo header")
    
    dw_size = struct.unpack_from("<I", data, offset)[0]
    cb_offset_extra = struct.unpack_from("<I", data, offset + 4)[0]
    
    if dw_size == 0:
        raise ValueError("Invalid LinkInfo size")
    
    # The LinkInfo structure is dw_size bytes total.
    # We need to verify it fits in the data.
    if offset + dw_size > len(data):
        raise ValueError("Truncated LinkInfo")
    
    # Basic sanity: dw_size should be at least 12 (header)
    if dw_size < 12:
        raise ValueError("Invalid LinkInfo size too small")
    
    # Skip the entire LinkInfo
    offset += dw_size
    
    return offset


def parse_lnk(data: bytes) -> dict:
    """Parse the .lnk file data and return the result dict."""
    
    # Check minimum size
    if len(data) < HEADER_SIZE:
        raise ValueError("File too small for ShellLinkHeader")
    
    # Parse header
    header_size = struct.unpack_from("<I", data, 0x00)[0]
    if header_size != HEADER_SIZE:
        raise ValueError(f"Invalid HeaderSize: {header_size:#x}, expected {HEADER_SIZE:#x}")
    
    # LinkCLSID
    clsid_bytes = data[0x04:0x14]
    try:
        file_clsid = uuid.UUID(bytes_le=clsid_bytes)
    except Exception:
        raise ValueError("Invalid LinkCLSID")
    if file_clsid != LINK_CLSID:
        raise ValueError(f"Invalid LinkCLSID: {file_clsid}")
    
    link_flags = struct.unpack_from("<I", data, 0x14)[0]
    # file_attributes = struct.unpack_from("<I", data, 0x18)[0]  # not needed in output
    
    # FILETIMEs
    creation_time_val = struct.unpack_from("<Q", data, 0x1C)[0]
    access_time_val = struct.unpack_from("<Q", data, 0x24)[0]
    write_time_val = struct.unpack_from("<Q", data, 0x2C)[0]
    
    # FileSize - unsigned 32-bit
    file_size = struct.unpack_from("<I", data, 0x34)[0]
    
    # IconIndex - signed 32-bit
    icon_index = struct.unpack_from("<i", data, 0x38)[0]
    
    # show_command = struct.unpack_from("<I", data, 0x3C)[0]  # not needed
    # hotkey = struct.unpack_from("<H", data, 0x40)[0]  # not needed
    
    # Reserved fields must be zero
    reserved1 = struct.unpack_from("<H", data, 0x42)[0]
    reserved2 = struct.unpack_from("<I", data, 0x44)[0]
    reserved3 = struct.unpack_from("<I", data, 0x48)[0]
    if reserved1 != 0:
        raise ValueError("Reserved1 is not zero")
    if reserved2 != 0:
        raise ValueError("Reserved2 is not zero")
    if reserved3 != 0:
        raise ValueError("Reserved3 is not zero")
    
    # Convert FILETIMEs
    try:
        creation_time = filetime_to_iso(creation_time_val)
        access_time = filetime_to_iso(access_time_val)
        write_time = filetime_to_iso(write_time_val)
    except ValueError as e:
        raise ValueError(f"Invalid FILETIME: {e}")
    
    # Now parse the variable-length sections
    offset = HEADER_SIZE
    is_unicode = bool(link_flags & LF_IS_UNICODE)
    
    # Parse IDList if present
    if link_flags & LF_HAS_LINK_TARGET_ID_LIST:
        offset = parse_idlist(data, offset)
    
    # Parse LinkInfo if present
    if link_flags & LF_HAS_LINK_INFO:
        offset = parse_link_info(data, offset)
    
    # Now parse StringData sections in order
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    if link_flags & LF_HAS_NAME:
        name_string, offset = read_string(data, offset, is_unicode)
    
    if link_flags & LF_HAS_RELATIVE_PATH:
        relative_path, offset = read_string(data, offset, is_unicode)
    
    if link_flags & LF_HAS_WORKING_DIR:
        working_dir, offset = read_string(data, offset, is_unicode)
    
    if link_flags & LF_HAS_ARGUMENTS:
        command_line_arguments, offset = read_string(data, offset, is_unicode)
    
    if link_flags & LF_HAS_ICON_LOCATION:
        icon_location, offset = read_string(data, offset, is_unicode)
    
    # Now we should be at the EXTRA_DATA section
    # EXTRA_DATA is a sequence of blocks terminated by a TerminalBlock (32-bit value < 4)
    # We don't need to parse extra data for the output, but we should verify the structure
    # is well-formed if we want to be thorough. However, the spec says the file ends with
    # extra data blocks. For our purposes, we've extracted all we need.
    # But let's do a minimal check: if there's remaining data, it should be extra data.
    # We'll just skip it. The key thing is we've read all the string sections.
    
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
        "write_time": write_time,
    }


def main():
    if len(sys.argv) != 2:
        error_exit("Usage: parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (IOError, OSError) as e:
        error_exit(f"Cannot read file: {e}")
    
    try:
        result = parse_lnk(data)
    except Exception as e:
        error_exit(str(e))
    
    print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()