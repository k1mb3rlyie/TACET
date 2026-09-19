#!/usr/bin/env python3
import sys
import struct
import json
import datetime
from pathlib import Path

class LnkParseError(Exception):
    pass

def read_bytes(data, offset, size):
    if offset + size > len(data):
        raise LnkParseError("unexpected end of file")
    return data[offset:offset+size], offset + size

def read_uint16(data, offset):
    b, offset = read_bytes(data, offset, 2)
    return struct.unpack("<H", b)[0], offset

def read_uint32(data, offset):
    b, offset = read_bytes(data, offset, 4)
    return struct.unpack("<I", b)[0], offset

def read_int32(data, offset):
    b, offset = read_bytes(data, offset, 4)
    return struct.unpack("<i", b)[0], offset

def read_uint64(data, offset):
    b, offset = read_bytes(data, offset, 8)
    return struct.unpack("<Q", b)[0], offset

def filetime_to_iso(ft):
    # FILETIME is number of 100‑ns intervals since 1601‑01‑01 UTC
    try:
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        microseconds = ft // 10
        dt = base + datetime.timedelta(microseconds=microseconds)
        return dt.isoformat()
    except Exception:
        raise LnkParseError("invalid FILETIME value")

def parse_string(data, offset, is_unicode):
    count, offset = read_uint16(data, offset)
    byte_len = count * (2 if is_unicode else 1)
    raw, offset = read_bytes(data, offset, byte_len)
    try:
        if is_unicode:
            s = raw.decode("utf-16le", errors="replace")
        else:
            s = raw.decode("utf-8", errors="replace")
    except Exception:
        raise LnkParseError("failed to decode string")
    return s, offset

def parse_lnk(data: bytes):
    offset = 0
    # ShellLinkHeader (76 bytes)
    header_size, offset = read_uint32(data, offset)
    if header_size != 0x4C:
        raise LnkParseError("invalid HeaderSize")
    # CLSID
    clsid_raw, offset = read_bytes(data, offset, 16)
    expected_clsid = b'\x01\x14\x02\x00' + b'\x00'*12 + b'\xC0\x00\x00\x00\x00\x00\x00\x46'  # little‑endian representation
    if clsid_raw != expected_clsid:
        raise LnkParseError("invalid LinkCLSID")
    link_flags, offset = read_uint32(data, offset)
    file_attrib, offset = read_uint32(data, offset)
    creation_ft, offset = read_uint64(data, offset)
    access_ft, offset = read_uint64(data, offset)
    write_ft, offset = read_uint64(data, offset)
    file_size, offset = read_uint32(data, offset)
    icon_index, offset = read_int32(data, offset)
    show_cmd, offset = read_uint32(data, offset)
    hotkey, offset = read_uint16(data, offset)
    # Reserved fields
    _, offset = read_uint16(data, offset)  # Reserved1
    _, offset = read_uint32(data, offset)  # Reserved2
    _, offset = read_uint32(data, offset)  # Reserved3

    # Optional structures
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        idlist_size, offset = read_uint16(data, offset)
        _, offset = read_bytes(data, offset, idlist_size)

    if link_flags & 0x00000002:  # HasLinkInfo
        linkinfo_size, offset = read_uint32(data, offset)
        _, offset = read_bytes(data, offset, linkinfo_size - 4)  # size includes the size field itself

    is_unicode = bool(link_flags & 0x00000080)

    # StringData sections in order
    def get_section(flag_bit):
        return (link_flags & flag_bit) != 0

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if get_section(0x00000004):  # HasName
        name_string, offset = parse_string(data, offset, is_unicode)
    if get_section(0x00000008):  # HasRelativePath
        relative_path, offset = parse_string(data, offset, is_unicode)
    if get_section(0x00000010):  # HasWorkingDir
        working_dir, offset = parse_string(data, offset, is_unicode)
    if get_section(0x00000020):  # HasArguments
        command_line_arguments, offset = parse_string(data, offset, is_unicode)
    if get_section(0x00000040):  # HasIconLocation
        icon_location, offset = parse_string(data, offset, is_unicode)

    # Build result
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_ft),
        "access_time": filetime_to_iso(access_ft),
        "write_time": filetime_to_iso(write_ft)
    }
    return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    path = Path(sys.argv[1])
    try:
        data = path.read_bytes()
    except Exception as e:
        err = {"error": f"cannot read file: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

    try:
        result = parse_lnk(data)
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)
    except LnkParseError as e:
        err = {"error": str(e)}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)
    except Exception as e:
        err = {"error": f"unexpected error: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

if __name__ == "__main__":
    main()