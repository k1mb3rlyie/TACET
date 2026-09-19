#!/usr/bin/env python3
import sys
import struct
import json
import datetime

class ParseError(Exception):
    pass

def filetime_to_iso(ft):
    if ft == 0:
        return None
    # FILETIME is number of 100‑ns intervals since 1601‑01‑01 UTC
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    try:
        dt = epoch + datetime.timedelta(microseconds=ft // 10)
    except OverflowError:
        raise ParseError("Invalid FILETIME value")
    return dt.isoformat()

def read_uint16(data, off):
    if off + 2 > len(data):
        raise ParseError("Unexpected end of file while reading uint16")
    return struct.unpack_from('<H', data, off)[0], off + 2

def read_uint32(data, off):
    if off + 4 > len(data):
        raise ParseError("Unexpected end of file while reading uint32")
    return struct.unpack_from('<I', data, off)[0], off + 4

def read_uint64(data, off):
    if off + 8 > len(data):
        raise ParseError("Unexpected end of file while reading uint64")
    return struct.unpack_from('<Q', data, off)[0], off + 8

def read_bytes(data, off, size):
    if off + size > len(data):
        raise ParseError("Unexpected end of file while reading bytes")
    return data[off:off+size], off + size

def parse_lnk(data: bytes):
    if len(data) < 76:
        raise ParseError("File too short for header")
    off = 0

    header_size, off = read_uint32(data, off)
    if header_size != 76:
        raise ParseError("Invalid header size")

    link_clsid, off = read_bytes(data, off, 16)
    expected_clsid = bytes.fromhex('0114020000000000c000000000000046')
    if link_clsid != expected_clsid:
        raise ParseError("Invalid LinkCLSID GUID")

    link_flags, off = read_uint32(data, off)
    _, off = read_uint32(data, off)          # FileAttributes (ignored)

    creation_time_raw, off = read_uint64(data, off)
    access_time_raw, off = read_uint64(data, off)
    write_time_raw, off = read_uint64(data, off)

    file_size, off = read_uint32(data, off)
    icon_index, off = read_uint32(data, off)

    # Skip ShowCommand (4), HotKey (2), Reserved1 (2), Reserved2 (4), Reserved3 (4)
    off += 4 + 2 + 2 + 4 + 4

    # Optional structures
    if link_flags & 0x00000001:   # HasLinkTargetIDList
        idlist_size, off = read_uint16(data, off)
        off, _ = off, off + idlist_size  # skip ID list
        if off > len(data):
            raise ParseError("ID list exceeds file size")
        off += idlist_size

    if link_flags & 0x00000002:   # HasLinkInfo
        linkinfo_size, off = read_uint32(data, off)
        if linkinfo_size < 4:
            raise ParseError("Invalid LinkInfo size")
        off += linkinfo_size - 4
        if off > len(data):
            raise ParseError("LinkInfo exceeds file size")

    is_unicode = bool(link_flags & 0x00000080)

    def read_string():
        nonlocal off
        length, off = read_uint16(data, off)
        byte_len = length * (2 if is_unicode else 1)
        raw, off = read_bytes(data, off, byte_len)
        try:
            return raw.decode('utf-16le' if is_unicode else 'utf-8')
        except UnicodeDecodeError:
            raise ParseError("Failed to decode string")

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if link_flags & 0x00000004:   # HasName
        name_string = read_string()
    if link_flags & 0x00000008:   # HasRelativePath
        relative_path = read_string()
    if link_flags & 0x00000010:   # HasWorkingDir
        working_dir = read_string()
    if link_flags & 0x00000020:   # HasArguments
        command_line_arguments = read_string()
    if link_flags & 0x00000040:   # HasIconLocation
        icon_location = read_string()

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_time_raw),
        "access_time": filetime_to_iso(access_time_raw),
        "write_time": filetime_to_iso(write_time_raw)
    }

    # Convert any None timestamps to null in JSON (already handled)
    return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Failed to read file: {e}\n")
        print(json.dumps({"error": "cannot read file"}))
        sys.exit(1)

    try:
        parsed = parse_lnk(data)
    except ParseError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    except Exception as e:
        # Unexpected errors should also be reported as parsing failures
        print(json.dumps({"error": "unexpected parsing error"}))
        sys.exit(1)

    json.dump(parsed, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    sys.exit(0)

if __name__ == "__main__":
    main()