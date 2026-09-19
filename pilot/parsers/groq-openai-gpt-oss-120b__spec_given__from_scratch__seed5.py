#!/usr/bin/env python3
import sys
import struct
import json
import datetime
import uuid

def fatal(msg):
    sys.stdout.write(json.dumps({"error": msg}))
    sys.exit(1)

def need(data, offset, size, what):
    if offset + size > len(data):
        fatal(f"unexpected end of file while reading {what}")
    return data[offset:offset+size]

def read_uint32(data, offset, what):
    return struct.unpack_from("<I", need(data, offset, 4, what))[0]

def read_uint16(data, offset, what):
    return struct.unpack_from("<H", need(data, offset, 2, what))[0]

def read_int32(data, offset, what):
    return struct.unpack_from("<i", need(data, offset, 4, what))[0]

def filetime_to_iso(ft):
    # ft is unsigned 64-bit count of 100‑ns intervals since 1601‑01‑01 UTC
    try:
        micros = ft // 10
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = base + datetime.timedelta(microseconds=micros)
        return dt.isoformat().replace('+00:00', '+00:00')
    except Exception:
        fatal("invalid FILETIME value")

def main():
    if len(sys.argv) != 2:
        fatal("usage: parser.py <path-to-lnk-file>")
    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        fatal(f"cannot read file: {e}")

    offset = 0

    # ---- ShellLinkHeader (76 bytes) ----
    if len(data) < 76:
        fatal("file too short for ShellLinkHeader")

    header_size = read_uint32(data, offset, "HeaderSize")
    if header_size != 0x4C:
        fatal("invalid HeaderSize")
    offset += 4

    # GUID
    guid_bytes = need(data, offset, 16, "LinkCLSID")
    try:
        guid = uuid.UUID(bytes_le=guid_bytes)
    except Exception:
        fatal("invalid GUID format")
    expected_guid = uuid.UUID("{00021401-0000-0000-C000-000000000046}")
    if guid != expected_guid:
        fatal("unexpected LinkCLSID")
    offset += 16

    link_flags = read_uint32(data, offset, "LinkFlags")
    offset += 4
    file_attrs = read_uint32(data, offset, "FileAttributes")
    offset += 4

    creation_ft = struct.unpack_from("<Q", need(data, offset, 8, "CreationTime"))[0]
    offset += 8
    access_ft = struct.unpack_from("<Q", need(data, offset, 8, "AccessTime"))[0]
    offset += 8
    write_ft = struct.unpack_from("<Q", need(data, offset, 8, "WriteTime"))[0]
    offset += 8

    file_size = read_uint32(data, offset, "FileSize")
    offset += 4
    icon_index = read_int32(data, offset, "IconIndex")
    offset += 4

    # remaining fields we don't need for output, just skip
    offset += 4   # ShowCommand
    offset += 2   # HotKey
    offset += 2   # Reserved1
    offset += 4   # Reserved2
    offset += 4   # Reserved3

    # ---- Optional IDList ----
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        idlist_size = read_uint16(data, offset, "IDListSize")
        offset += 2
        need(data, offset, idlist_size, "IDList")
        offset += idlist_size

    # ---- Optional LinkInfo ----
    if link_flags & 0x00000002:  # HasLinkInfo
        linkinfo_size = read_uint32(data, offset, "LinkInfoSize")
        if linkinfo_size < 4:
            fatal("invalid LinkInfoSize")
        need(data, offset, linkinfo_size, "LinkInfo")
        offset += linkinfo_size

    # ---- StringData sections (in fixed order) ----
    is_unicode = bool(link_flags & 0x00000080)

    def read_string(flag_bit):
        nonlocal offset
        if not (link_flags & flag_bit):
            return None
        char_count = read_uint16(data, offset, "StringCount")
        offset += 2
        byte_len = char_count * (2 if is_unicode else 1)
        raw = need(data, offset, byte_len, "StringData")
        offset += byte_len
        try:
            if is_unicode:
                return raw.decode('utf-16le')
            else:
                return raw.decode('utf-8', errors='replace')
        except Exception:
            fatal("failed to decode string")

    name_string = read_string(0x00000004)          # HasName
    relative_path = read_string(0x00000008)        # HasRelativePath
    working_dir = read_string(0x00000010)          # HasWorkingDir
    command_line_arguments = read_string(0x00000020)  # HasArguments
    icon_location = read_string(0x00000040)        # HasIconLocation

    # ---- Build output ----
    out = {
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

    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    sys.exit(0)

if __name__ == "__main__":
    main()