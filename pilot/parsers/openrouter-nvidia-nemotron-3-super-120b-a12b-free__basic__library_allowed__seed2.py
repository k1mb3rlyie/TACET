import sys
import struct
import json
import datetime

def get_u16(d, off):
    return struct.unpack_from('<H', d, off)[0]

def get_u32(d, off):
    return struct.unpack_from('<I', d, off)[0]

def get_u64(d, off):
    return struct.unpack_from('<Q', d, off)[0]

def filetime_to_iso(ft):
    # FILETIME: 100-nanosecond intervals since 1601-01-01 UTC
    if ft < 0:
        raise ValueError('Invalid FILETIME')
    # convert to microseconds
    microseconds = ft // 10
    seconds = microseconds // 1_000_000
    microseconds_rem = microseconds % 1_000_000
    dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) \
         + datetime.timedelta(seconds=seconds, microseconds=microseconds_rem)
    return dt.isoformat()

def parse_lnk(data):
    if len(data) < 0x4C:
        raise ValueError('File too small for LNk header')
    off = 0

    # Header fields
    link_flags = get_u32(off, data); off += 4
    file_attrs = get_u32(off, data); off += 4
    creation_ft = get_u64(off, data); off += 8
    access_ft = get_u64(off, data); off += 8
    write_ft = get_u64(off, data); off += 8
    file_size = get_u32(off, data); off += 4
    icon_index = get_u32(off, data); off += 4
    show_command = get_u32(off, data); off += 4
    hot_key = get_u16(off, data); off += 2
    # reserved WORD at 0x2E
    off += 2
    # skip remaining reserved DWORDs (7 of them) to reach 0x4C
    for _ in range(7):
        _ = get_u32(off, data); off += 4

    # LinkTargetIDList
    if off + 2 > len(data):
        raise ValueError('Missing LinkTargetIDList size')
    id_list_size = get_u16(data, off); off += 2
    if off + id_list_size > len(data):
        raise ValueError('LinkTargetIDList exceeds file size')
    off += id_list_size

    # LinkInfo
    if off + 4 > len(data):
        raise ValueError('Missing LinkInfo size')
    link_info_size = get_u32(data, off); off += 4
    if link_info_size < 0x1C:
        raise ValueError('LinkInfo size too small')
    if off + link_info_size > len(data):
        raise ValueError('LinkInfo exceeds file size')
    off += link_info_size

    # String Data (up to 5 strings)
    strings = []
    for _ in range(5):
        if off + 2 > len(data):
            raise ValueError('Missing string length')
        length = get_u16(data, off); off += 2
        if length == 0:
            strings.append(None)
            continue
        if off + length > len(data):
            raise ValueError('String data exceeds file size')
        raw = data[off:off+length]; off += length
        try:
            s = raw.decode('utf-16le')
        except UnicodeDecodeError:
            raise ValueError('Invalid UTF-16LE string in LNk')
        # Strip possible terminating null(s)
        if s.endswith('\x00'):
            s = s.rstrip('\x00')
        strings.append(s)

    # Build result
    result = {
        "name_string": strings[0],
        "relative_path": strings[1],
        "working_dir": strings[2],
        "command_line_arguments": strings[3],
        "icon_location": strings[4],
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_ft),
        "access_time": filetime_to_iso(access_ft),
        "write_time": filetime_to_iso(write_ft)
    }
    return result

def main():
    if len(sys.argv) != 2:
        err = {"error": "Usage: python parser.py <path-to-lnk-file>"}
        print(json.dumps(err, separators=(',', ':')))
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        err = {"error": f"Cannot read file: {e}"}
        print(json.dumps(err, separators=(',', ':')))
        sys.exit(1)

    try:
        result = parse_lnk(data)
        print(json.dumps(result, separators=(',', ':')))
        sys.exit(0)
    except Exception as e:
        err = {"error": str(e)}
        print(json.dumps(err, separators=(',', ':')))
        sys.exit(1)

if __name__ == '__main__':
    main()