#!/usr/bin/env python3
import sys
import struct
import json
import datetime

# FILETIME conversion (100‑ns intervals since 1601‑01‑01 UTC)
def filetime_to_iso(ft):
    try:
        ft_int = ft
        if ft_int == 0:
            # treat zero as the epoch start per FILETIME definition
            dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        else:
            us = ft_int // 10  # convert to microseconds
            dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
        return dt.isoformat()
    except Exception:
        return None

def read_uint16(data, off):
    return struct.unpack_from("<H", data, off)[0], off + 2

def read_uint32(data, off):
    return struct.unpack_from("<I", data, off)[0], off + 4

def read_uint64(data, off):
    return struct.unpack_from("<Q", data, off)[0], off + 8

def parse_lnk(data):
    off = 0
    # ---------- Header ----------
    if len(data) < 76:
        raise ValueError("File too short for ShellLink header")
    header_size, off = read_uint32(data, off)
    if header_size != 0x4C:
        raise ValueError("Invalid ShellLink header size")
    # CLSID (16 bytes) – we just skip/validate
    clsid = data[off:off+16]
    off += 16
    expected_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    if clsid != expected_clsid:
        raise ValueError("Invalid ShellLink CLSID")
    link_flags, off = read_uint32(data, off)
    file_attrs, off = read_uint32(data, off)
    creation_ft, off = read_uint64(data, off)
    access_ft, off = read_uint64(data, off)
    write_ft, off = read_uint64(data, off)
    file_size, off = read_uint32(data, off)
    icon_index, off = read_uint32(data, off)
    # remaining fields we skip
    off += 4 + 2 + 2 + 4 + 4  # ShowCommand, HotKey, Reserved1, Reserved2, Reserved3

    # ---------- Optional structures ----------
    # LinkTargetIDList
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        if off + 2 > len(data):
            raise ValueError("Truncated IDListSize")
        idlist_size, off = read_uint16(data, off)
        if off + idlist_size > len(data):
            raise ValueError("Truncated IDList")
        off += idlist_size

    # LinkInfo
    if link_flags & 0x00000002:  # HasLinkInfo
        if off + 4 > len(data):
            raise ValueError("Truncated LinkInfoSize")
        linkinfo_size, off = read_uint32(data, off)
        if off + linkinfo_size - 4 > len(data):
            raise ValueError("Truncated LinkInfo")
        off += linkinfo_size - 4  # already consumed size field

    # ---------- StringData ----------
    # Determine if strings are Unicode
    is_unicode = bool(link_flags & 0x00000080)  # HasUnicode

    def read_string():
        nonlocal off
        if off + 2 > len(data):
            raise ValueError("Truncated string length")
        length, off = read_uint16(data, off)
        byte_len = length * (2 if is_unicode else 1)
        if off + byte_len > len(data):
            raise ValueError("Truncated string data")
        raw = data[off:off+byte_len]
        off += byte_len
        if is_unicode:
            try:
                return raw.decode('utf-16le')
            except Exception:
                return raw.decode('utf-16le', errors='replace')
        else:
            try:
                return raw.decode('utf-8')
            except Exception:
                return raw.decode('utf-8', errors='replace')

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if link_flags & 0x00000004:  # HasName
        name_string = read_string()
    if link_flags & 0x00000008:  # HasRelativePath
        relative_path = read_string()
    if link_flags & 0x00000010:  # HasWorkingDir
        working_dir = read_string()
    if link_flags & 0x00000020:  # HasArguments
        command_line_arguments = read_string()
    if link_flags & 0x00000040:  # HasIconLocation
        icon_location = read_string()

    # ---------- Build result ----------
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

    # Replace empty strings with null if they were present but empty
    for key in ["name_string", "relative_path", "working_dir",
                "command_line_arguments", "icon_location"]:
        if result[key] == "":
            result[key] = ""

    return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        err = {"error": f"Cannot read file: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

    try:
        result = parse_lnk(data)
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)
    except Exception as e:
        err = {"error": str(e)}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

if __name__ == "__main__":
    main()