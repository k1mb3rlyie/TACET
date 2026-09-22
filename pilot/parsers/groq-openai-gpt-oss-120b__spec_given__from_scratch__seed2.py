#!/usr/bin/env python3
import sys
import struct
import json
import datetime

def ft_to_iso(ft: int) -> str:
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    try:
        dt = epoch + datetime.timedelta(microseconds=ft // 10)
    except Exception as e:
        raise ValueError("Invalid FILETIME value") from e
    return dt.isoformat()

def parse_lnk(data: bytes) -> dict:
    if len(data) < 0x4C:
        raise ValueError("File too short for header")
    header_size, = struct.unpack_from("<I", data, 0)
    if header_size != 0x4C:
        raise ValueError("Invalid HeaderSize")
    expected_clsid = bytes(
        [0x01, 0x14, 0x02, 0x00,
         0x00, 0x00,
         0x00, 0x00,
         0xC0, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x46]
    )
    if data[4:20] != expected_clsid:
        raise ValueError("Invalid LinkCLSID")
    link_flags, = struct.unpack_from("<I", data, 0x14)
    # timestamps
    creation, = struct.unpack_from("<Q", data, 0x1C)
    access, = struct.unpack_from("<Q", data, 0x24)
    write, = struct.unpack_from("<Q", data, 0x2C)
    file_size, = struct.unpack_from("<I", data, 0x34)
    icon_index, = struct.unpack_from("<i", data, 0x38)

    ptr = 0x4C

    # IDList
    if link_flags & 0x00000001:
        if ptr + 2 > len(data):
            raise ValueError("Truncated IDList size")
        idlist_size, = struct.unpack_from("<H", data, ptr)
        ptr += 2
        if ptr + idlist_size > len(data):
            raise ValueError("Truncated IDList")
        ptr += idlist_size

    # LinkInfo
    if link_flags & 0x00000002:
        if ptr + 4 > len(data):
            raise ValueError("Truncated LinkInfo size")
        linkinfo_size, = struct.unpack_from("<I", data, ptr)
        ptr += 4
        if linkinfo_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if ptr + (linkinfo_size - 4) > len(data):
            raise ValueError("Truncated LinkInfo")
        ptr += (linkinfo_size - 4)

    is_unicode = bool(link_flags & 0x00000080)

    string_names = [
        "name_string",
        "relative_path",
        "working_dir",
        "command_line_arguments",
        "icon_location",
    ]
    string_flags = [
        0x00000004,
        0x00000008,
        0x00000010,
        0x00000020,
        0x00000040,
    ]

    strings = {}
    for name, flag in zip(string_names, string_flags):
        if link_flags & flag:
            if ptr + 2 > len(data):
                raise ValueError(f"Truncated {name} length")
            count, = struct.unpack_from("<H", data, ptr)
            ptr += 2
            byte_len = count * (2 if is_unicode else 1)
            if ptr + byte_len > len(data):
                raise ValueError(f"Truncated {name} data")
            raw = data[ptr : ptr + byte_len]
            ptr += byte_len
            if is_unicode:
                s = raw.decode("utf-16le", errors="replace")
            else:
                s = raw.decode("utf-8", errors="replace")
            strings[name] = s
        else:
            strings[name] = None

    result = {
        "name_string": strings["name_string"],
        "relative_path": strings["relative_path"],
        "working_dir": strings["working_dir"],
        "command_line_arguments": strings["command_line_arguments"],
        "icon_location": strings["icon_location"],
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": ft_to_iso(creation),
        "access_time": ft_to_iso(access),
        "write_time": ft_to_iso(write),
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
    except Exception as exc:
        json.dump({"error": str(exc)}, sys.stdout, ensure_ascii=False)

if __name__ == "__main__":
    main()