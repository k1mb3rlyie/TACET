#!/usr/bin/env python3
import sys
import struct
import json
import datetime

def filetime_to_iso(ft):
    if ft == 0:
        return None
    # FILETIME is number of 100‑nanosecond intervals since 1601‑01‑01 UTC
    us = ft // 10  # convert to microseconds
    dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
    return dt.isoformat()

def read_uint16(data, off):
    if off + 2 > len(data):
        raise ValueError('Unexpected end of data while reading uint16')
    return struct.unpack_from('<H', data, off)[0], off + 2

def read_string(data, off, unicode_flag):
    length, off = read_uint16(data, off)
    byte_len = length * (2 if unicode_flag else 1)
    if off + byte_len > len(data):
        raise ValueError('String data truncated')
    raw = data[off:off + byte_len]
    off += byte_len
    if unicode_flag:
        s = raw.decode('utf-16le', errors='replace')
    else:
        s = raw.decode('utf-8', errors='replace')
    return s, off

def parse_lnk(data):
    if len(data) < 76:
        raise ValueError('File too short for LNK header')

    header_struct = struct.Struct('<I16sIIQQQI I I H H I I')
    (header_size, _, link_flags, file_attrs,
     creation_time, access_time, write_time,
     file_size, icon_index, show_cmd,
     hot_key, reserved1, reserved2, reserved3) = header_struct.unpack_from(data, 0)

    if header_size != 0x4C:
        raise ValueError('Invalid header size')

    offset = header_struct.size

    # Optional LinkTargetIDList
    if link_flags & 0x00000001:
        idlist_size, = struct.unpack_from('<H', data, offset)
        offset += 2 + idlist_size
        if offset > len(data):
            raise ValueError('LinkTargetIDList truncated')

    # Optional LinkInfo
    if link_flags & 0x00000002:
        if offset + 4 > len(data):
            raise ValueError('LinkInfo size truncated')
        linkinfo_size, = struct.unpack_from('<I', data, offset)
        offset += linkinfo_size
        if offset > len(data):
            raise ValueError('LinkInfo truncated')

    unicode_flag = bool(link_flags & 0x00000080)

    # StringData fields (order matters)
    name_string = None
    if link_flags & 0x00000004:
        name_string, offset = read_string(data, offset, unicode_flag)

    relative_path = None
    if link_flags & 0x00000008:
        relative_path, offset = read_string(data, offset, unicode_flag)

    working_dir = None
    if link_flags & 0x00000010:
        working_dir, offset = read_string(data, offset, unicode_flag)

    command_line_arguments = None
    if link_flags & 0x00000020:
        command_line_arguments, offset = read_string(data, offset, unicode_flag)

    icon_location = None
    if link_flags & 0x00000040:
        icon_location, offset = read_string(data, offset, unicode_flag)

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_time),
        "access_time": filetime_to_iso(access_time),
        "write_time": filetime_to_iso(write_time)
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
        parsed = parse_lnk(data)
        json.dump(parsed, sys.stdout, ensure_ascii=False)
        sys.stdout.write('\n')
        sys.exit(0)
    except Exception as e:
        err = {"error": str(e)}
        json.dump(err, sys.stdout, ensure_ascii=False)
        sys.stdout.write('\n')
        sys.exit(1)

if __name__ == '__main__':
    main()