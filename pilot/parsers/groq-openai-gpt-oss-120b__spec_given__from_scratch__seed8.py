#!/usr/bin/env python3
import sys
import struct
import json
import datetime
import uuid

def error(msg):
    out = {"error": msg}
    json.dump(out, sys.stdout, ensure_ascii=False)
    sys.exit(1)

def filetime_to_iso(ft):
    # ft is unsigned 64‑bit integer
    try:
        # 100‑nanosecond intervals since 1601‑01‑01 UTC
        seconds = ft / 10_000_000
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = epoch + datetime.timedelta(seconds=seconds)
        # isoformat with seconds precision and explicit +00:00 offset
        return dt.isoformat(timespec='seconds')
    except Exception:
        raise ValueError("invalid FILETIME")

def read_struct(data, offset, fmt):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise EOFError("unexpected end of file")
    return struct.unpack_from(fmt, data, offset), offset + size

def parse_lnk(data: bytes):
    if len(data) < 76:
        raise EOFError("file too short for ShellLinkHeader")

    # ---- ShellLinkHeader -------------------------------------------------
    (header_size,), off = read_struct(data, 0, "<I")
    if header_size != 0x4C:
        raise ValueError("HeaderSize != 0x4C")

    (clsid_bytes,), off = read_struct(data, off, "16s")
    expected_clsid = uuid.UUID('00021401-0000-0000-C000-000000000046').bytes_le
    if clsid_bytes != expected_clsid:
        raise ValueError("LinkCLSID does not match expected GUID")

    (link_flags,), off = read_struct(data, off, "<I")
    (file_attrs,), off = read_struct(data, off, "<I")
    (creation_ft,), off = read_struct(data, off, "<Q")
    (access_ft,), off = read_struct(data, off, "<Q")
    (write_ft,), off = read_struct(data, off, "<Q")
    (file_size_u,), off = read_struct(data, off, "<I")
    (icon_index_i,), off = read_struct(data, off, "<i")
    # Remaining fields are not needed for output, just skip them
    off += 4 + 2 + 2 + 4 + 4  # ShowCommand, HotKey, Reserved1, Reserved2, Reserved3

    # ---- Optional LinkTargetIDList ---------------------------------------
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        (idlist_size,), off = read_struct(data, off, "<H")
        if off + idlist_size > len(data):
            raise EOFError("IDList size exceeds file length")
        off += idlist_size

    # ---- Optional LinkInfo -----------------------------------------------
    if link_flags & 0x00000002:  # HasLinkInfo
        (linkinfo_size,), off = read_struct(data, off, "<I")
        if linkinfo_size < 4:
            raise ValueError("LinkInfoSize too small")
        if off + (linkinfo_size - 4) > len(data):
            raise EOFError("LinkInfo size exceeds file length")
        off += linkinfo_size - 4

    # ---- StringData -------------------------------------------------------
    is_unicode = bool(link_flags & 0x00000080)

    def read_string(flag_bit):
        nonlocal off
        if not (link_flags & flag_bit):
            return None
        (char_count,), off = read_struct(data, off, "<H")
        byte_len = char_count * (2 if is_unicode else 1)
        if off + byte_len > len(data):
            raise EOFError("String data exceeds file length")
        raw = data[off:off + byte_len]
        off += byte_len
        try:
            if is_unicode:
                return raw.decode('utf-16le')
            else:
                return raw.decode('utf-8', errors='replace')
        except Exception as e:
            raise ValueError(f"failed to decode string: {e}")

    name_string = read_string(0x00000004)          # HasName
    relative_path = read_string(0x00000008)        # HasRelativePath
    working_dir = read_string(0x00000010)          # HasWorkingDir
    command_line_arguments = read_string(0x00000020)  # HasArguments
    icon_location = read_string(0x00000040)        # HasIconLocation

    # ---- Build result ------------------------------------------------------
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size_u,
        "icon_index": icon_index_i,
        "creation_time": filetime_to_iso(creation_ft),
        "access_time": filetime_to_iso(access_ft),
        "write_time": filetime_to_iso(write_ft)
    }
    return result

def main():
    if len(sys.argv) != 2:
        error("usage: python parser.py <path-to-lnk-file>")
    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        error(f"cannot read file: {e}")

    try:
        result = parse_lnk(data)
    except Exception as e:
        error(str(e))

    json.dump(result, sys.stdout, ensure_ascii=False)
    sys.stdout.flush()
    sys.exit(0)

if __name__ == "__main__":
    main()