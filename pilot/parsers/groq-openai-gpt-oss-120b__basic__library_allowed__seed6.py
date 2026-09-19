#!/usr/bin/env python3
import sys
import struct
import json
import datetime

def filetime_to_iso(ft):
    # FILETIME is number of 100‑nanosecond intervals since 1601‑01‑01 UTC
    try:
        ft_int = int.from_bytes(ft, byteorder='little', signed=False)
    except Exception:
        return None
    if ft_int == 0:
        # treat as epoch zero (1601‑01‑01)
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    else:
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ft_int // 10)
    return dt.isoformat()

def read_uint16(data, off):
    return struct.unpack_from('<H', data, off)[0], off + 2

def read_uint32(data, off):
    return struct.unpack_from('<I', data, off)[0], off + 4

def read_int32(data, off):
    return struct.unpack_from('<i', data, off)[0], off + 4

def read_bytes(data, off, length):
    if off + length > len(data):
        raise ValueError('unexpected end of data')
    return data[off:off+length], off + length

def parse_string(data, off, is_unicode):
    # read count (2 bytes)
    if off + 2 > len(data):
        raise ValueError('truncated string length')
    count, off = read_uint16(data, off)
    if is_unicode:
        byte_len = count * 2
        raw, off = read_bytes(data, off, byte_len)
        try:
            s = raw.decode('utf-16le', errors='replace')
        except Exception:
            s = ''
    else:
        raw, off = read_bytes(data, off, count)
        try:
            s = raw.decode('utf-8', errors='replace')
        except Exception:
            s = ''
    # strip terminating null if present
    s = s.rstrip('\x00')
    return s, off

def error(msg):
    out = {"error": msg}
    print(json.dumps(out, ensure_ascii=False))
    sys.exit(1)

def main():
    if len(sys.argv) != 2:
        error("usage: parser.py <path-to-lnk-file>")
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        error(f"cannot read file: {e}")

    if len(data) < 76:
        error("file too short for Shell Link header")

    # Header
    header_size, = struct.unpack_from('<I', data, 0)
    if header_size != 0x4C:
        error("invalid header size")
    clsid = data[4:20]
    expected_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    if clsid != expected_clsid:
        error("invalid CLSID")
    link_flags, = struct.unpack_from('<I', data, 20)
    # file attributes ignored
    # timestamps
    creation_time = data[28:36]
    access_time = data[36:44]
    write_time = data[44:52]
    file_size, = struct.unpack_from('<I', data, 52)
    icon_index, = struct.unpack_from('<i', data, 56)
    # skip rest of header
    offset = 76

    # Flags
    HasLinkTargetIDList = bool(link_flags & 0x00000001)
    HasLinkInfo = bool(link_flags & 0x00000002)
    HasName = bool(link_flags & 0x00000004)
    HasRelativePath = bool(link_flags & 0x00000008)
    HasWorkingDir = bool(link_flags & 0x00000010)
    HasArguments = bool(link_flags & 0x00000020)
    HasIconLocation = bool(link_flags & 0x00000040)
    IsUnicode = bool(link_flags & 0x00000080)

    # Optional LinkTargetIDList
    if HasLinkTargetIDList:
        if offset + 2 > len(data):
            error("truncated LinkTargetIDList size")
        idlist_size, offset = read_uint16(data, offset)
        if offset + idlist_size > len(data):
            error("truncated LinkTargetIDList")
        offset += idlist_size  # skip

    # Optional LinkInfo
    if HasLinkInfo:
        if offset + 4 > len(data):
            error("truncated LinkInfo size")
        linkinfo_size, offset = read_uint32(data, offset)
        if offset - 4 + linkinfo_size > len(data):
            error("truncated LinkInfo")
        offset += linkinfo_size - 4  # already consumed size field

    # StringData (order matters)
    def maybe_read(flag):
        nonlocal offset
        if flag:
            s, offset = parse_string(data, offset, IsUnicode)
            return s
        else:
            return None

    try:
        name_string = maybe_read(HasName)
        relative_path = maybe_read(HasRelativePath)
        working_dir = maybe_read(HasWorkingDir)
        command_line_arguments = maybe_read(HasArguments)
        icon_location = maybe_read(HasIconLocation)
    except ValueError as e:
        error(f"failed to parse string data: {e}")

    # Build result
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

    # Ensure timestamps are not None (should always be convertible)
    if None in (result["creation_time"], result["access_time"], result["write_time"]):
        error("failed to convert timestamps")

    print(json.dumps(result, ensure_ascii=False))
    sys.exit(0)

if __name__ == "__main__":
    main()