#!/usr/bin/env python3
import sys
import struct
import json
import datetime
import pathlib

# ---------- helpers ----------
def error(msg):
    out = {"error": msg}
    json.dump(out, sys.stdout, ensure_ascii=False)
    sys.stdout.flush()
    sys.exit(0)

def read_struct(data, offset, fmt):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError("unexpected end of file while reading struct")
    return struct.unpack_from(fmt, data, offset), offset + size

def read_bytes(data, offset, length):
    if offset + length > len(data):
        raise ValueError("unexpected end of file while reading bytes")
    return data[offset:offset+length], offset + length

def filetime_to_iso(ft):
    # FILETIME is 100‑ns intervals since 1601‑01‑01 UTC
    try:
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        micros = ft // 10
        dt = base + datetime.timedelta(microseconds=micros)
        return dt.isoformat()
    except Exception:
        raise ValueError("invalid FILETIME value")

def decode_string(raw, is_unicode):
    if is_unicode:
        # UTF‑16LE, count is in characters, raw length should be even
        try:
            return raw.decode('utf-16le')
        except Exception:
            raise ValueError("failed to decode UTF-16LE string")
    else:
        # ANSI – use the system default encoding with replacement for safety
        try:
            return raw.decode(sys.getfilesystemencoding(), errors='replace')
        except Exception:
            raise ValueError("failed to decode ANSI string")

# ---------- main parser ----------
def parse_lnk(path):
    data = pathlib.Path(path).read_bytes()
    if len(data) < 76:
        raise ValueError("file too short for ShellLinkHeader")

    # Header
    (header_size,), off = read_struct(data, 0, "<I")
    if header_size != 0x4C:
        raise ValueError("invalid HeaderSize")
    (clsid_bytes,), off = read_struct(data, 4, "16s")
    expected_clsid = bytes([0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46])
    if clsid_bytes != expected_clsid:
        raise ValueError("invalid LinkCLSID")
    (link_flags,), off = read_struct(data, 0x14, "<I")
    # skip FileAttributes (4)
    off = 0x1C
    (creation_ft,), off = read_struct(data, off, "<Q")
    (access_ft,), off = read_struct(data, off, "<Q")
    (write_ft,), off = read_struct(data, off, "<Q")
    (file_size,), off = read_struct(data, off, "<I")
    (icon_index,), off = read_struct(data, off, "<i")
    # remaining fields are not needed for output
    # offset now at 0x48 (after Reserved3)
    offset = 0x4C

    # Optional IDList
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        (idlist_size,), offset = read_struct(data, offset, "<H")
        _, offset = read_bytes(data, offset, idlist_size)

    # Optional LinkInfo
    if link_flags & 0x00000002:  # HasLinkInfo
        (linkinfo_size,), offset = read_struct(data, offset, "<I")
        _, offset = read_bytes(data, offset, linkinfo_size - 4)  # size includes the 4 bytes we already read

    # StringData order
    def maybe_read_string(flag_bit):
        nonlocal offset
        if link_flags & flag_bit:
            (char_count,), offset = read_struct(data, offset, "<H")
            byte_len = char_count * (2 if (link_flags & 0x00000080) else 1)
            raw, offset = read_bytes(data, offset, byte_len)
            return decode_string(raw, bool(link_flags & 0x00000080))
        return None

    name_string = maybe_read_string(0x00000004)          # HasName
    relative_path = maybe_read_string(0x00000008)       # HasRelativePath
    working_dir = maybe_read_string(0x00000010)         # HasWorkingDir
    command_line_arguments = maybe_read_string(0x00000020)  # HasArguments
    icon_location = maybe_read_string(0x00000040)       # HasIconLocation

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

# ---------- entry point ----------
def main():
    if len(sys.argv) != 2:
        error("usage: python parser.py <path-to-lnk-file>")
    try:
        parsed = parse_lnk(sys.argv[1])
        json.dump(parsed, sys.stdout, ensure_ascii=False)
        sys.stdout.flush()
        sys.exit(0)
    except Exception as e:
        error(str(e))

if __name__ == "__main__":
    main()