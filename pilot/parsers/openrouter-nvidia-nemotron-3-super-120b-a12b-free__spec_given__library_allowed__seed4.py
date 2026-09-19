#!/usr/bin/env python3
import sys
import struct
import json
import datetime

def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)

def read_uint8(buf, off):
    return struct.unpack_from('<B', buf, off)[0], off + 1

def read_uint16(buf, off):
    return struct.unpack_from('<H', buf, off)[0], off + 2

def read_uint32(buf, off):
    return struct.unpack_from('<I', buf, off)[0], off + 4

def read_int32(buf, off):
    return struct.unpack_from('<i', buf, off)[0], off + 4

def read_uint64(buf, off):
    return struct.unpack_from('<Q', buf, off)[0], off + 8

def filetime_to_iso(ft):
    # ft: 100-ns intervals since 1601-01-01 UTC
    try:
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = base + datetime.timedelta(microseconds=ft // 10)
        return dt.isoformat()
    except Exception:
        raise ValueError("Invalid FILETIME value")

def parse_lnk(data):
    n = len(data)
    off = 0

    # Header (76 bytes)
    if n < 76:
        raise ValueError("File too short for header")
    header_size, = read_uint32(data, off); off += 4
    if header_size != 0x4C:
        raise ValueError(f"Invalid HeaderSize {header_size:#x}")

    # LinkCLSID
    expected_clsid = bytes([0x01,0x14,0x02,0x00,
                            0x00,0x00,0x00,0x00,
                            0xC0,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x46])
    clsid = data[off:off+16]; off += 16
    if clsid != expected_clsid:
        raise ValueError("Invalid LinkCLSID")

    link_flags, = read_uint32(data, off); off += 4
    _file_attributes, = read_uint32(data, off); off += 4

    creation_ft, = read_uint64(data, off); off += 8
    access_ft, = read_uint64(data, off); off += 8
    write_ft, = read_uint64(data, off); off += 8

    file_size, = read_uint32(data, off); off += 4  # unsigned
    icon_index, = read_int32(data, off); off += 4   # signed
    _show_command, = read_uint32(data, off); off += 4
    _hotkey, = read_uint16(data, off); off += 2
    _reserved1, = read_uint16(data, off); off += 2
    _reserved2, = read_uint32(data, off); off += 4
    _reserved3, = read_uint32(data, off); off += 4

    # Optional IDList
    if link_flags & 0x00000001:
        while True:
            if off + 2 > n:
                raise ValueError("IDList size field beyond EOF")
            id_size, = read_uint16(data, off); off += 2
            if id_size == 0:
                break
            if id_size < 2:
                raise ValueError("Invalid IDList item size")
            if off + (id_size - 2) > n:
                raise ValueError("IDList item data beyond EOF")
            off += id_size - 2

    # Optional LinkInfo
    if link_flags & 0x00000002:
        if off + 4 > n:
            raise ValueError("LinkInfoSize beyond EOF")
        link_info_size, = read_uint32(data, off); off += 4
        if link_info_size < 24:
            raise ValueError("LinkInfo too small")
        # read fixed part (20 more bytes)
        needed = 24 - 4  # we already read LinkInfoSize
        if off + needed > n:
            raise ValueError("LinkInfo fixed part beyond EOF")
        off += needed  # skip HeaderSize, LinkInfoFlags, VolumeIDOffset, LocalBasePathOffset, NetworkShareOffset
        # skip remainder
        remain = link_info_size - 24
        if off + remain > n:
            raise ValueError("LinkInfo data beyond EOF")
        off += remain

    # String sections (order fixed)
    is_unicode = bool(link_flags & 0x00000080)
    string_defs = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]
    results = {}
    for flag, key in string_defs:
        if link_flags & flag:
            if off + 2 > n:
                raise ValueError(f"String count missing for {key}")
            count_chars, = read_uint16(data, off); off += 2
            char_size = 2 if is_unicode else 1
            byte_len = count_chars * char_size
            if off + byte_len > n:
                raise ValueError(f"String data missing for {key}")
            raw = data[off:off+byte_len]; off += byte_len
            try:
                if is_unicode:
                    s = raw.decode('utf-16-le')
                else:
                    s = raw.decode('utf-8')
            except Exception:
                raise ValueError(f"Failed to decode string {key}")
            results[key] = s
        else:
            results[key] = None

    # Convert timestamps
    creation_iso = filetime_to_iso(creation_ft)
    access_iso = filetime_to_iso(access_ft)
    write_iso = filetime_to_iso(write_ft)

    output = {
        "name_string": results["name_string"],
        "relative_path": results["relative_path"],
        "working_dir": results["working_dir"],
        "command_line_arguments": results["command_line_arguments"],
        "icon_location": results["icon_location"],
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_iso,
        "access_time": access_iso,
        "write_time": write_iso,
    }
    return output

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
        result = parse_lnk(data)
        print(json.dumps(result, separators=(',', ':')))
    except Exception as e:
        fail(str(e))

if __name__ == "__main__":
    main()