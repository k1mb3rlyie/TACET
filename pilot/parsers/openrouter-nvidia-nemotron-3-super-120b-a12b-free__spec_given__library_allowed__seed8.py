#!/usr/bin/env python3
import sys
import struct
from datetime import datetime, timezone, timedelta
import json

def get_uint8(buf, off):
    return buf[off], off + 1

def get_uint16(buf, off):
    return int.from_bytes(buf[off:off+2], 'little'), off + 2

def get_uint32(buf, off):
    return int.from_bytes(buf[off:off+4], 'little'), off + 4

def get_int32(buf, off):
    return int.from_bytes(buf[off:off+4], 'little', signed=True), off + 4

def get_uint64(buf, off):
    return int.from_bytes(buf[off:off+8], 'little'), off + 8

def filetime_to_iso(ft):
    seconds = ft // 10000000
    remainder = ft % 10000000
    microseconds = remainder // 10
    dt = datetime(1601, 1, 1) + timedelta(seconds=seconds, microseconds=microseconds)
    dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat(timespec='microseconds')

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Cannot open file: {e}\n")
        sys.exit(1)

    if len(data) < 0x4C:
        sys.stderr.write("File too short for header\n")
        sys.exit(1)

    off = 0

    # HeaderSize
    header_size, off = get_uint32(data, off)
    if header_size != 0x4C:
        sys.stderr.write(f"Invalid HeaderSize: 0x{header_size:08X}\n")
        sys.exit(1)

    # LinkCLSID
    expected_clsid = bytes([0x01,0x14,0x02,0x00,
                            0x00,0x00,
                            0x00,0x00,
                            0xC0,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x46])
    clsid, off = data[off:off+16], off+16
    if clsid != expected_clsid:
        sys.stderr.write("Invalid LinkCLSID\n")
        sys.exit(1)

    # LinkFlags
    link_flags, off = get_uint32(data, off)
    # FileAttributes (unused)
    _, off = get_uint32(data, off)

    # Timestamps
    creation_time_ft, off = get_uint64(data, off)
    access_time_ft,   off = get_uint64(data, off)
    write_time_ft,    off = get_uint64(data, off)

    # FileSize (unsigned)
    file_size, off = get_uint32(data, off)
    # IconIndex (signed)
    icon_index, off = get_int32(data, off)
    # ShowCommand (unused)
    _, off = get_uint32(data, off)
    # HotKey (unused)
    _, off = get_uint16(data, off)
    # Reserved1 (should be zero)
    _, off = get_uint16(data, off)
    # Reserved2 (should be zero)
    _, off = get_uint32(data, off)
    # Reserved3 (should be zero)
    _, off = get_uint32(data, off)

    # Optional IDList
    if link_flags & 0x00000001:
        while True:
            if off + 2 > len(data):
                sys.stderr.write("Truncated IDList size field\n")
                sys.exit(1)
            id_size, off = get_uint16(data, off)
            if id_size == 0:
                break
            if id_size < 2:
                sys.stderr.write("Invalid IDList item size\n")
                sys.exit(1)
            if off + (id_size - 2) > len(data):
                sys.stderr.write("Truncated IDList item data\n")
                sys.exit(1)
            off += id_size - 2

    # Optional LinkInfo
    if link_flags & 0x00000002:
        if off + 4 > len(data):
            sys.stderr.write("Truncated LinkInfo size\n")
            sys.exit(1)
        link_info_size, off = get_uint32(data, off)
        if link_info_size < 0x1C:
            sys.stderr.write(f"LinkInfo size too small: 0x{link_info_size:08X}\n")
            sys.exit(1)
        if off + link_info_size > len(data):
            sys.stderr.write("LinkInfo exceeds file size\n")
            sys.exit(1)
        off += link_info_size

    # String sections
    is_unicode = bool(link_flags & 0x00000080)

    def read_string(flag):
        nonlocal off
        if not (link_flags & flag):
            return None
        if off + 2 > len(data):
            sys.stderr.write("Truncated string length\n")
            sys.exit(1)
        char_count, off = get_uint16(data, off)
        byte_len = char_count * (2 if is_unicode else 1)
        if off + byte_len > len(data):
            sys.stderr.write("Truncated string data\n")
            sys.exit(1)
        raw = data[off:off+byte_len]
        off += byte_len
        try:
            if is_unicode:
                s = raw.decode('utf-16-le')
            else:
                try:
                    s = raw.decode('mbcs')
                except (LookupError, UnicodeDecodeError):
                    s = raw.decode('cp1252')
        except UnicodeDecodeError as e:
            sys.stderr.write(f"Failed to decode string: {e}\n")
            sys.exit(1)
        return s

    name_string = read_string(0x00000004)
    relative_path = read_string(0x00000008)
    working_dir = read_string(0x00000010)
    command_line_arguments = read_string(0x00000020)
    icon_location = read_string(0x00000040)

    creation_iso = filetime_to_iso(creation_time_ft)
    access_iso   = filetime_to_iso(access_time_ft)
    write_iso    = filetime_to_iso(write_time_ft)

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_iso,
        "access_time": access_iso,
        "write_time": write_iso
    }

    json.dump(result, sys.stdout, ensure_ascii=False)
    sys.stdout.write('\n')
    sys.exit(0)

if __name__ == "__main__":
    main()