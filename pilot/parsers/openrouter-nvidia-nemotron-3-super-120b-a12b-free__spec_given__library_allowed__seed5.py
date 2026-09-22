#!/usr/bin/env python3
import struct
import sys
import json
from datetime import datetime, timezone, timedelta

# Constants
HEADER_SIZE = 0x4C
EXPECTED_CLSID = bytes.fromhex('01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46')
FILETIME_EPOCH_DIFF = 11644473600  # seconds between 1601-01-01 and 1970-01-01
TICKS_PER_SECOND = 10_000_000

def read_bytes(data, offset, length):
    if offset + length > len(data):
        raise ValueError("Insufficient data")
    return data[offset:offset + length], offset + length

def parse_filetime(ft_bytes):
    ft = struct.unpack('<Q', ft_bytes)[0]
    try:
        unix_seconds = ft // TICKS_PER_SECOND - FILETIME_EPOCH_DIFF
        # Handle negative timestamps (before 1970) - allowed
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        return dt.isoformat(timespec='seconds')
    except (OverflowError, ValueError) as e:
        raise ValueError(f"Invalid FILETIME value: {e}")

def parse_idlist(data, offset):
    while True:
        if offset + 2 > len(data):
            raise ValueError("IDList size field incomplete")
        size_bytes, offset = read_bytes(data, offset, 2)
        size = struct.unpack('<H', size_bytes)[0]
        if size == 0:
            break
        if size < 2:
            raise ValueError("Invalid IDList item size")
        if offset + (size - 2) > len(data):
            raise ValueError("IDList item exceeds buffer")
        offset += size - 2
    return offset

def parse_linkinfo(data, offset):
    if offset + 4 > len(data):
        raise ValueError("LinkInfo size missing")
    size_bytes, offset = read_bytes(data, offset, 4)
    linkinfo_size = struct.unpack('<I', size_bytes)[0]
    if linkinfo_size < 4:
        raise ValueError("LinkInfo size too small")
    if offset + linkinfo_size > len(data):
        raise ValueError("LinkInfo exceeds buffer")
    offset += linkinfo_size
    return offset

def parse_string(data, offset, is_unicode):
    if offset + 2 > len(data):
        raise ValueError("String length missing")
    len_bytes, offset = read_bytes(data, offset, 2)
    char_count = struct.unpack('<H', len_bytes)[0]
    if is_unicode:
        byte_len = char_count * 2
    else:
        byte_len = char_count
    if offset + byte_len > len(data):
        raise ValueError("String data incomplete")
    str_bytes, offset = read_bytes(data, offset, byte_len)
    if is_unicode:
        try:
            s = str_bytes.decode('utf-16-le')
        except UnicodeDecodeError as e:
            raise ValueError(f"Unicode string decode error: {e}")
    else:
        # Latin-1 losslessly maps each byte to a Unicode code point
        s = str_bytes.decode('latin-1')
    return s, offset

def parse_extra_data(data, offset):
    while offset < len(data):
        if offset + 4 > len(data):
            raise ValueError("Extra data block size incomplete")
        size_bytes, offset = read_bytes(data, offset, 4)
        block_size = struct.unpack('<I', size_bytes)[0]
        if block_size < 4:
            # Terminal block
            break
        if offset + (block_size - 4) > len(data):
            raise ValueError("Extra data block exceeds buffer")
        offset += block_size - 4
    if offset != len(data):
        raise ValueError("Trailing data after terminal block")
    return offset

def main():
    if len(sys.argv) != 2:
        err = {"error": "Usage: python parser.py <path-to-lnk-file>"}
        print(json.dumps(err))
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        err = {"error": f"Cannot open file: {e}"}
        print(json.dumps(err))
        sys.exit(1)

    try:
        if len(data) < HEADER_SIZE:
            raise ValueError("File too small for header")
        header, offset = read_bytes(data, 0, HEADER_SIZE)
        (header_size,
         link_clsid_raw,
         link_flags,
         file_attributes,
         creation_time_raw,
         access_time_raw,
         write_time_raw,
         file_size,
         icon_index,
         show_command,
         hot_key,
         reserved1,
         reserved2,
         reserved3) = struct.unpack('<I16sIIQQQIIIIHHIIII',
                                    header)

        if header_size != HEADER_SIZE:
            raise ValueError(f"Invalid HeaderSize: 0x{header_size:08X}")
        if link_clsid_raw != EXPECTED_CLSID:
            raise ValueError("Invalid LinkCLSID")
        # Reserved fields are not strictly validated per spec; ignore.

        # Parse optional IDList
        if link_flags & 0x00000001:
            offset = parse_idlist(data, offset)

        # Parse optional LinkInfo
        if link_flags & 0x00000002:
            offset = parse_linkinfo(data, offset)

        is_unicode = bool(link_flags & 0x00000080)

        # Helper to get string or null
        def get_string(flag):
            if not (link_flags & flag):
                return None
            nonlocal offset
            s, offset = parse_string(data, offset, is_unicode)
            return s

        name_string = get_string(0x00000004)          # HasName
        relative_path = get_string(0x00000008)       # HasRelativePath
        working_dir = get_string(0x00000010)         # HasWorkingDir
        command_line_arguments = get_string(0x00000020)  # HasArguments
        icon_location = get_string(0x00000040)       # HasIconLocation

        # Parse timestamps
        creation_time_iso = parse_filetime(creation_time_raw)
        access_time_iso = parse_filetime(access_time_raw)
        write_time_iso = parse_filetime(write_time_raw)

        # Parse extra data (must consume rest of file)
        offset = parse_extra_data(data, offset)

        result = {
            "name_string": name_string,
            "relative_path": relative_path,
            "working_dir": working_dir,
            "command_line_arguments": command_line_arguments,
            "icon_location": icon_location,
            "file_size": file_size,
            "icon_index": icon_index,
            "creation_time": creation_time_iso,
            "access_time": access_time_iso,
            "write_time": write_time_iso,
        }
        print(json.dumps(result))
        sys.exit(0)

    except Exception as e:
        err = {"error": str(e)}
        print(json.dumps(err))
        sys.exit(1)

if __name__ == "__main__":
    main()