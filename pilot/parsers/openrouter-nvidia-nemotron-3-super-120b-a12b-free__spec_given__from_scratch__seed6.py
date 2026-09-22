#!/usr/bin/env python3
import struct
import sys
import json
from datetime import datetime, timezone, timedelta

# Constants
HEADER_SIZE_EXPECTED = 0x4C
LINK_CLSID = bytes.fromhex('0114020000000000C000000000000046')  # little-endian GUID

# FILETIME epoch difference (1601-01-01 to 1970-01-01) in seconds
_FILETIME_OFFSET = 11644473600


def _read_bytes(buf, offset, size):
    if offset + size > len(buf):
        raise ValueError("Truncated file")
    return buf[offset:offset + size], offset + size


def _parse_filetime(ft):
    # ft: unsigned 64-bit little-endian
    try:
        seconds = ft / 10_000_000.0 - _FILETIME_OFFSET
        # Check range of datetime
        if seconds < -sys.maxsize or seconds > sys.maxsize:
            raise ValueError
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        # Ensure within supported year range
        if dt < datetime.min.replace(tzinfo=timezone.utc) or dt > datetime.max.replace(tzinfo=timezone.utc):
            raise ValueError
        return dt
    except (OverflowError, ValueError):
        raise ValueError("Invalid FILETIME value")


def parse_lnk(data):
    offset = 0

    # Header
    header, offset = _read_bytes(data, offset, HEADER_SIZE_EXPECTED)
    (header_size,
     link_clsid,
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
     reserved3) = struct.unpack_from('<I16sIIQQQIIIIHHHH', header, 0)

    if header_size != HEADER_SIZE_EXPECTED:
        raise ValueError(f"Invalid HeaderSize: 0x{header_size:08X}")
    if link_clsid != LINK_CLSID:
        raise ValueError("Invalid LinkCLSID")

    is_unicode = bool(link_flags & 0x00000080)

    # Parse timestamps
    creation_time = _parse_filetime(creation_time_raw)
    access_time = _parse_filetime(access_time_raw)
    write_time = _parse_filetime(write_time_raw)

    # Skip IDList if present
    if link_flags & 0x00000001:
        while True:
            if offset + 2 > len(data):
                raise ValueError("Truncated IDList")
            item_size, = struct.unpack_from('<H', data, offset)
            offset += 2
            if item_size == 0:
                break
            if offset + item_size - 2 > len(data):
                raise ValueError("Truncated IDList item")
            offset += item_size - 2

    # Skip LinkInfo if present
    if link_flags & 0x00000002:
        if offset + 4 > len(data):
            raise ValueError("Truncated LinkInfo size")
        link_info_size, = struct.unpack_from('<I', data, offset)
        offset += 4
        if link_info_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if offset + link_info_size - 4 > len(data):
            raise ValueError("Truncated LinkInfo")
        offset += link_info_size - 4

    # Helper to read a string section if flag set
    def read_string_if(flag):
        nonlocal offset
        if not (link_flags & flag):
            return None
        if offset + 2 > len(data):
            raise ValueError("Truncated string length")
        char_count, = struct.unpack_from('<H', data, offset)
        offset += 2
        byte_count = char_count * (2 if is_unicode else 1)
        if offset + byte_count > len(data):
            raise ValueError("Truncated string data")
        raw = data[offset:offset + byte_count]
        offset += byte_count
        if is_unicode:
            try:
                return raw.decode('utf-8-le')
            except UnicodeDecodeError:
                # Fallback: replace errors
                return raw.decode('utf-8', errors='replace')
        else:
            # Latin-1 preserves byte values 1:1
            return raw.decode('latin-1')

    # Order: NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
    name_string = read_string_if(0x00000004)   # HasName
    relative_path = read_string_if(0x00000008) # HasRelativePath
    working_dir = read_string_if(0x00000010)   # HasWorkingDir
    command_line_arguments = read_string_if(0x00000020) # HasArguments
    icon_location = read_string_if(0x00000040) # HasIconLocation

    # At this point we ignore any extra data; just ensure we didn't overrun
    if offset > len(data):
        raise ValueError("Parsed past end of file")

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time.isoformat(timespec='seconds').replace('+00:00', 'Z').replace('Z', '+00:00'),
        "access_time": access_time.isoformat(timespec='seconds').replace('+00:00', 'Z').replace('Z', '+00:00'),
        "write_time": write_time.isoformat(timespec='seconds').replace('+00:00', 'Z').replace('Z', '+00:00'),
    }
    return result


def main():
    if len(sys.argv) != 2:
        print("Usage: python parser.py <path-to-lnk-file>", file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
        result = parse_lnk(data)
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()