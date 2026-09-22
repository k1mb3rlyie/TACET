import sys
import struct
import datetime
import json

def parse_lnk(data: bytes):
    if len(data) < 0x4C:
        raise ValueError('File too small for a valid LNK header')

    # ---- Header fields ----
    link_flags = struct.unpack_from('<I', data, 0x04)[0]
    # FileAttributes (not needed)
    # Creation time
    ct_low, ct_high = struct.unpack_from('<II', data, 0x0C)
    # Access time
    at_low, at_high = struct.unpack_from('<II', data, 0x14)
    # Write time
    wt_low, wt_high = struct.unpack_from('<II', data, 0x1C)
    # File size
    file_size = struct.unpack_from('<I', data, 0x24)[0]
    # Icon index
    icon_index = struct.unpack_from('<I', data, 0x28)[0]

    # ---- Flags for optional strings ----
    has_name = bool(link_flags & 0x00000004)
    has_relative = bool(link_flags & 0x00000008)
    has_working_dir = bool(link_flags & 0x00000010)
    has_arguments = bool(link_flags & 0x00000020)
    has_icon_location = bool(link_flags & 0x00000040)
    has_idlist = bool(link_flags & 0x00000001)
    has_linkinfo = bool(link_flags & 0x00000002)
    is_unicode = bool(link_flags & 0x00000080)

    offset = 0x4C  # start after header

    # ---- IDList ----
    if has_idlist:
        idlist_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2 + idlist_size
    else:
        # still read the size field (should be 0) and skip that many bytes
        idlist_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if idlist_size:
            offset += idlist_size

    # ---- LinkInfo ----
    if has_linkinfo:
        linkinfo_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if linkinfo_size < 4:
            raise ValueError('Invalid LinkInfo size')
        offset += linkinfo_size - 4

    # ---- String data helper ----
    def read_string(flag: bool):
        nonlocal offset
        if not flag:
            return None
        if offset + 2 > len(data):
            raise ValueError('Truncated string size field')
        size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if size == 0:
            return None
        if offset + size > len(data):
            raise ValueError('Truncated string data')
        raw = data[offset:offset + size]
        offset += size
        try:
            # Try UTF-16LE first (most common)
            s = raw.decode('utf-16le')
        except UnicodeDecodeError:
            # Fallback to system ANSI if Unicode flag not set
            try:
                s = raw.decode('mbcs')
            except Exception:
                raise ValueError('Failed to decode string')
        # Strip terminating null if present
        if s.endswith('\0'):
            s = s[:-1]
        return s

    name_string = read_string(has_name)
    relative_path = read_string(has_relative)
    working_dir = read_string(has_working_dir)
    command_line_arguments = read_string(has_arguments)
    icon_location = read_string(has_icon_location)

    # ---- FILETIME to ISO 8601 with UTC offset ----
    def filetime_to_iso(low: int, high: int):
        if low == 0 and high == 0:
            return None
        ft = (high << 32) | low
        # 100-nanosecond intervals since 1601-01-01 UTC to seconds since 1970-01-01 UTC
        ts = (ft - 116444736000000000) / 10000000.0
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return dt.isoformat()

    creation_time = filetime_to_iso(ct_low, ct_high)
    access_time = filetime_to_iso(at_low, at_high)
    write_time = filetime_to_iso(wt_low, wt_high)

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
        sys.stderr.write('Usage: python parser.py <path-to-lnk-file>\n')
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        print(json.dumps({'error': f'Cannot read file: {e}'}))
        sys.exit(1)

    try:
        result = parse_lnk(data)
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)

    print(json.dumps(result))
    sys.exit(0)

if __name__ == '__main__':
    main()