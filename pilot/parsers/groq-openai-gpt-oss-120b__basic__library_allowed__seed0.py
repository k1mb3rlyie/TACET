#!/usr/bin/env python3
import sys
import json
import struct
import datetime
import traceback

# Link flag bits
HAS_LINK_TARGET_IDLIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080

def filetime_to_iso(ts):
    """Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01 UTC) to ISO‑8601."""
    # FILETIME of 0 is valid (1601‑01‑01T00:00:00+00:00)
    micros = ts // 10  # to microseconds
    dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=micros)
    return dt.isoformat()

def read_uint16(data, offset):
    if offset + 2 > len(data):
        raise ValueError("Unexpected end of file while reading uint16")
    return struct.unpack_from("<H", data, offset)[0], offset + 2

def read_uint32(data, offset):
    if offset + 4 > len(data):
        raise ValueError("Unexpected end of file while reading uint32")
    return struct.unpack_from("<I", data, offset)[0], offset + 4

def read_uint64(data, offset):
    if offset + 8 > len(data):
        raise ValueError("Unexpected end of file while reading uint64")
    return struct.unpack_from("<Q", data, offset)[0], offset + 8

def read_string(data, offset, is_unicode):
    """Read a string according to the .lnk specification."""
    length, offset = read_uint16(data, offset)  # number of characters (unicode) or bytes (ansi)
    if is_unicode:
        byte_len = length * 2
        if offset + byte_len > len(data):
            raise ValueError("Unexpected end of file while reading Unicode string")
        raw = data[offset:offset + byte_len]
        try:
            s = raw.decode('utf-16le')
        except Exception:
            s = raw.decode('utf-16le', errors='replace')
        offset += byte_len
    else:
        if offset + length > len(data):
            raise ValueError("Unexpected end of file while reading ANSI string")
        raw = data[offset:offset + length]
        try:
            s = raw.decode('utf-8')
        except Exception:
            s = raw.decode('utf-8', errors='replace')
        offset += length
    return s, offset

def parse_lnk(data):
    if len(data) < 76:
        raise ValueError("File too short to contain a valid .lnk header")

    # Header size (must be 0x4C)
    hdr_size, pos = read_uint32(data, 0)
    if hdr_size != 0x4C:
        raise ValueError(f"Invalid header size: expected 0x4C, got 0x{hdr_size:X}")

    # Skip LinkCLSID (16 bytes)
    pos += 16

    # LinkFlags and FileAttributes
    link_flags, pos = read_uint32(data, pos)
    file_attrs, pos = read_uint32(data, pos)

    # Timestamps
    creation_time_raw, pos = read_uint64(data, pos)
    access_time_raw, pos = read_uint64(data, pos)
    write_time_raw, pos = read_uint64(data, pos)

    # FileSize, IconIndex, ShowCommand, HotKey, Reserved
    file_size, pos = read_uint32(data, pos)
    icon_index, pos = read_uint32(data, pos)
    # Skip ShowCommand (4), HotKey (2), Reserved1 (2), Reserved2 (4), Reserved3 (4)
    pos += 4 + 2 + 2 + 4 + 4

    # Optional structures
    if link_flags & HAS_LINK_TARGET_IDLIST:
        idlist_size, pos = read_uint16(data, pos)
        if pos + idlist_size > len(data):
            raise ValueError("IDList size exceeds file length")
        pos += idlist_size

    if link_flags & HAS_LINK_INFO:
        linkinfo_size, pos = read_uint32(data, pos)
        if pos + linkinfo_size - 4 > len(data):
            raise ValueError("LinkInfo size exceeds file length")
        pos += linkinfo_size - 4  # we already consumed the size field

    # StringData
    is_unicode = bool(link_flags & IS_UNICODE)

    def maybe_read(flag):
        if link_flags & flag:
            s, new_pos = read_string(data, pos_ref[0], is_unicode)
            pos_ref[0] = new_pos
            return s
        return None

    pos_ref = [pos]  # mutable holder for current position

    name_string = maybe_read(HAS_NAME)
    relative_path = maybe_read(HAS_RELATIVE_PATH)
    working_dir = maybe_read(HAS_WORKING_DIR)
    command_line_arguments = maybe_read(HAS_ARGUMENTS)
    icon_location = maybe_read(HAS_ICON_LOCATION)

    # Build result
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
        sys.stdout.flush()
        sys.exit(0)
    except Exception as e:
        # Output error JSON and exit non‑zero
        err_obj = {"error": str(e)}
        json.dump(err_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()