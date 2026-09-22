#!/usr/bin/env python3
import sys
import struct
import json
import datetime
from datetime import timezone, timedelta

class ParseError(Exception):
    pass

def read_exact(data, offset, size):
    if offset + size > len(data):
        raise ParseError("Unexpected end of file")
    return data[offset:offset+size], offset+size

def le_uint32(b):
    return struct.unpack("<I", b)[0]

def le_uint16(b):
    return struct.unpack("<H", b)[0]

def le_int32(b):
    return struct.unpack("<i", b)[0]

def filetime_to_iso(ft):
    # ft is unsigned 64‑bit count of 100‑ns intervals since 1601‑01‑01 UTC
    try:
        base = datetime.datetime(1601, 1, 1, tzinfo=timezone.utc)
        microseconds = ft // 10
        dt = base + timedelta(microseconds=microseconds)
        return dt.isoformat()
    except Exception:
        raise ParseError("Invalid FILETIME value")

def parse_lnk(data):
    offset = 0
    # ---- Header ----
    header_bytes, offset = read_exact(data, offset, 76)
    hdr_sz = le_uint32(header_bytes[0:4])
    if hdr_sz != 0x4C:
        raise ParseError("HeaderSize != 0x4C")
    expected_clsid = bytes([0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46])
    if header_bytes[4:20] != expected_clsid:
        raise ParseError("LinkCLSID mismatch")
    link_flags = le_uint32(header_bytes[20:24])
    # file attributes ignored
    creation_ft = le_uint64 = struct.unpack("<Q", header_bytes[28:36])[0]
    access_ft   = struct.unpack("<Q", header_bytes[36:44])[0]
    write_ft    = struct.unpack("<Q", header_bytes[44:52])[0]
    file_size   = le_uint32(header_bytes[52:56])
    icon_index  = le_int32(header_bytes[56:60])
    # skip remaining header fields (10 bytes)
    offset = 76

    # ---- Optional IDList ----
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        size_bytes, offset = read_exact(data, offset, 2)
        idlist_size = le_uint16(size_bytes)
        _, offset = read_exact(data, offset, idlist_size)  # IDList bytes
        # terminal 0x00 0x00
        term, offset = read_exact(data, offset, 2)
        if term != b'\x00\x00':
            raise ParseError("IDList terminator missing")

    # ---- Optional LinkInfo ----
    if link_flags & 0x00000002:  # HasLinkInfo
        size_bytes, offset = read_exact(data, offset, 4)
        linkinfo_size = le_uint32(size_bytes)
        if linkinfo_size < 4:
            raise ParseError("Invalid LinkInfo size")
        _, offset = read_exact(data, offset, linkinfo_size - 4)  # already read size field

    # ---- StringData ----
    unicode = bool(link_flags & 0x00000080)  # IsUnicode
    def read_string():
        cnt_bytes, off = read_exact(data, offset, 2)
        cnt = le_uint16(cnt_bytes)
        byte_len = cnt * (2 if unicode else 1)
        str_bytes, off = read_exact(data, off, byte_len)
        try:
            if unicode:
                s = str_bytes.decode('utf-16le', errors='replace')
            else:
                s = str_bytes.decode('utf-8', errors='replace')
        except Exception:
            s = ''
        return s, off

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if link_flags & 0x00000004:  # HasName
        name_string, offset = read_string()
    if link_flags & 0x00000008:  # HasRelativePath
        relative_path, offset = read_string()
    if link_flags & 0x00000010:  # HasWorkingDir
        working_dir, offset = read_string()
    if link_flags & 0x00000020:  # HasArguments
        command_line_arguments, offset = read_string()
    if link_flags & 0x00000040:  # HasIconLocation
        icon_location, offset = read_string()

    # ---- Build result ----
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
    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
        parsed = parse_lnk(data)
        json.dump(parsed, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)
    except ParseError as e:
        err = {"error": str(e)}
        json.dump(err, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)
    except Exception as e:
        err = {"error": "Unable to read file"}
        json.dump(err, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)

if __name__ == "__main__":
    main()