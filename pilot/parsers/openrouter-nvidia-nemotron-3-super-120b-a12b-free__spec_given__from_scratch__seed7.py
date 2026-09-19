import struct
import sys
import json
from datetime import datetime, timezone

def parse_idlist(data, start):
    offset = start
    while True:
        if offset + 2 > len(data):
            raise ValueError('IDList truncated')
        size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if size == 0:
            break
        if size < 2:
            raise ValueError('Invalid IDList size')
        if offset + size - 2 > len(data):
            raise ValueError('IDList data exceeds file')
        offset += size - 2
    return offset

def filetime_to_iso(ft):
    try:
        seconds = ft // 10_000_000 - 11644473600
    except Exception:
        raise ValueError('Invalid FILETIME value')
    try:
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OSError, OverflowError, ValueError) as e:
        raise ValueError(f'FILETIME out of range: {e}')
    return dt.isoformat()

def parse_lnk(data):
    if len(data) < 0x4C:
        raise ValueError('File too small for header')
    header = data[0:0x4C]

    header_size = struct.unpack_from('<I', header, 0)[0]
    if header_size != 0x4C:
        raise ValueError('Invalid HeaderSize')

    expected_clsid = bytes.fromhex('0114020000000000C000000000000046')
    if header[0x04:0x14] != expected_clsid:
        raise ValueError('Invalid LinkCLSID')

    link_flags = struct.unpack_from('<I', header, 0x14)[0]
    creation_time = struct.unpack_from('<Q', header, 0x1c)[0]
    access_time = struct.unpack_from('<Q', header, 0x24)[0]
    write_time = struct.unpack_from('<Q', header, 0x2c)[0]
    file_size = struct.unpack_from('<I', header, 0x34)[0]
    icon_index = struct.unpack_from('<i', header, 0x38)[0]  # signed
    # show_command, hot_key, reserved fields ignored

    offset = 0x4C

    if link_flags & 0x00000001:  # HasLinkTargetIDList
        offset = parse_idlist(data, offset)

    if link_flags & 0x00000002:  # HasLinkInfo
        if offset + 4 > len(data):
            raise ValueError('LinkInfo size missing')
        link_info_size = struct.unpack_from('<I', data, offset)[0]
        offset += link_info_size
        if offset > len(data):
            raise ValueError('LinkInfo exceeds file size')

    is_unicode = bool(link_flags & 0x00000080)
    string_order = [
        (0x00000004, 'name_string'),
        (0x00000008, 'relative_path'),
        (0x00000010, 'working_dir'),
        (0x00000020, 'command_line_arguments'),
        (0x00000040, 'icon_location')
    ]
    result = {}
    for flag, key in string_order:
        if link_flags & flag:
            if offset + 2 > len(data):
                raise ValueError(f'Missing count for {key}')
            count = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if is_unicode:
                bytecount = count * 2
            else:
                bytecount = count  # assume 1 byte per char (ANSI)
            if bytecount < 0:
                raise ValueError(f'Negative bytecount for {key}')
            if offset + bytecount > len(data):
                raise ValueError(f'String data exceeds file for {key}')
            s_bytes = data[offset:offset+bytecount]
            offset += bytecount
            try:
                if is_unicode:
                    s = s_bytes.decode('utf-16-le')
                else:
                    try:
                        s = s_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        s = s_bytes.decode('latin-1')
            except Exception as e:
                raise ValueError(f'Failed to decode string {key}: {e}')
            result[key] = s
        else:
            result[key] = None

    try:
        creation_iso = filetime_to_iso(creation_time)
        access_iso = filetime_to_iso(access_time)
        write_iso = filetime_to_iso(write_time)
    except ValueError as e:
        raise ValueError(f'Timestamp conversion error: {e}')

    return {
        "name_string": result['name_string'],
        "relative_path": result['relative_path'],
        "working_dir": result['working_dir'],
        "command_line_arguments": result['command_line_arguments'],
        "icon_location": result['icon_location'],
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_iso,
        "access_time": access_iso,
        "write_time": write_iso
    }

def main():
    if len(sys.argv) != 2:
        sys.stderr.write('Usage: python parser.py <path-to-lnk-file>\n')
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f'Cannot read file: {e}\n')
        sys.exit(1)
    try:
        result = parse_lnk(data)
    except Exception as e:
        sys.stderr.write(f'Error parsing LNK: {e}\n')
        sys.exit(1)
    print(json.dumps(result))

if __name__ == '__main__':
    main()