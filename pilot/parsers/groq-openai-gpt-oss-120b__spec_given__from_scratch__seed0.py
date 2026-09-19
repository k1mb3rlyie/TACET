#!/usr/bin/env python3
import sys
import struct
import json
import datetime

# ---------- helpers ----------
def filetime_to_iso(ft):
    """Convert Windows FILETIME (100‑ns since 1601‑01‑01 UTC) to ISO‑8601 string."""
    try:
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = base + datetime.timedelta(microseconds=ft // 10)
        return dt.isoformat()
    except Exception:
        return None

def read_uint(data, offset, fmt):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError("unexpected end of file")
    return struct.unpack_from(fmt, data, offset)[0], offset + size

def read_bytes(data, offset, length):
    if offset + length > len(data):
        raise ValueError("unexpected end of file")
    return data[offset:offset+length], offset + length

def error(msg):
    sys.stdout.write(json.dumps({"error": msg}, ensure_ascii=False))
    sys.exit(1)

# ---------- main ----------
def main():
    if len(sys.argv) != 2:
        error("usage: parser.py <path-to-lnk-file>")

    try:
        with open(sys.argv[1], "rb") as f:
            data = f.read()
    except Exception as e:
        error(f"cannot read file: {e}")

    offset = 0
    # ---- ShellLinkHeader (76 bytes) ----
    try:
        header_size, offset = read_uint(data, offset, "<I")
        if header_size != 0x4C:
            error("invalid HeaderSize")
        link_clsid_raw, offset = read_bytes(data, offset, 16)
        expected_clsid = struct.pack("<IHH8B", 0x00021401, 0, 0, 0xC0, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x46)
        if link_clsid_raw != expected_clsid:
            error("invalid LinkCLSID")
        link_flags, offset = read_uint(data, offset, "<I")
        file_attrs, offset = read_uint(data, offset, "<I")
        creation_ft, offset = read_uint(data, offset, "<Q")
        access_ft, offset = read_uint(data, offset, "<Q")
        write_ft, offset = read_uint(data, offset, "<Q")
        file_size, offset = read_uint(data, offset, "<I")
        icon_index, offset = read_uint(data, offset, "<i")   # signed
        show_cmd, offset = read_uint(data, offset, "<I")
        hot_key, offset = read_uint(data, offset, "<H")
        reserved1, offset = read_uint(data, offset, "<H")
        reserved2, offset = read_uint(data, offset, "<I")
        reserved3, offset = read_uint(data, offset, "<I")
    except ValueError as ve:
        error(f"header parsing error: {ve}")

    # ---- optional structures ----
    # 0x00000001 HasLinkTargetIDList
    if link_flags & 0x00000001:
        try:
            idlist_size, offset = read_uint(data, offset, "<H")
            # size includes the 2‑byte size field itself
            to_skip = idlist_size - 2
            if to_skip < 0:
                error("invalid IDList size")
            offset += to_skip
            if offset > len(data):
                raise ValueError
        except ValueError:
            error("cannot read IDList")

    # 0x00000002 HasLinkInfo
    if link_flags & 0x00000002:
        try:
            linkinfo_size, offset = read_uint(data, offset, "<I")
            to_skip = linkinfo_size - 4
            if to_skip < 0:
                error("invalid LinkInfo size")
            offset += to_skip
            if offset > len(data):
                raise ValueError
        except ValueError:
            error("cannot read LinkInfo")

    # ---- StringData ----
    is_unicode = bool(link_flags & 0x00000080)

    def read_string():
        nonlocal offset
        count, offset = read_uint(data, offset, "<H")
        byte_len = count * (2 if is_unicode else 1)
        raw, offset = read_bytes(data, offset, byte_len)
        if is_unicode:
            try:
                return raw.decode("utf-16le", errors="replace")
            except Exception:
                return raw.decode("utf-16le", errors="replace")
        else:
            return raw.decode("cp1252", errors="replace")

    # map flags to output keys in order
    sections = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]

    result = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_ft),
        "access_time": filetime_to_iso(access_ft),
        "write_time": filetime_to_iso(write_ft),
    }

    for flag, key in sections:
        if link_flags & flag:
            try:
                result[key] = read_string()
            except ValueError as ve:
                error(f"cannot read {key}: {ve}")

    # ---- output ----
    sys.stdout.write(json.dumps(result, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()