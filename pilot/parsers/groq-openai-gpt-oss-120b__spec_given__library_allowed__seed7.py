#!/usr/bin/env python3
import sys
import json
import struct
import datetime
import uuid

# ---------- Helpers ----------
class ParseError(Exception):
    pass

def read_uint16(data, off):
    if off + 2 > len(data):
        raise ParseError("Unexpected end of file while reading uint16")
    return struct.unpack_from("<H", data, off)[0], off + 2

def read_uint32(data, off):
    if off + 4 > len(data):
        raise ParseError("Unexpected end of file while reading uint32")
    return struct.unpack_from("<I", data, off)[0], off + 4

def read_int32(data, off):
    if off + 4 > len(data):
        raise ParseError("Unexpected end of file while reading int32")
    return struct.unpack_from("<i", data, off)[0], off + 4

def read_uint64(data, off):
    if off + 8 > len(data):
        raise ParseError("Unexpected end of file while reading uint64")
    return struct.unpack_from("<Q", data, off)[0], off + 8

def filetime_to_iso(ft):
    # FILETIME is 100‑ns intervals since 1601‑01‑01 UTC
    try:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        seconds = ft / 10_000_000
        dt = epoch + datetime.timedelta(seconds=seconds)
        return dt.isoformat()
    except Exception:
        raise ParseError("Invalid FILETIME value")

def decode_string(data, off, count, is_unicode):
    byte_len = count * (2 if is_unicode else 1)
    if off + byte_len > len(data):
        raise ParseError("Unexpected end of file while reading string")
    raw = data[off:off + byte_len]
    off += byte_len
    if is_unicode:
        try:
            s = raw.decode("utf-16le")
        except UnicodeDecodeError:
            s = raw.decode("utf-16le", errors="replace")
    else:
        # ANSI / system codepage – fall back to utf‑8 with replacement
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            s = raw.decode("utf-8", errors="replace")
    return s, off

# ---------- Main parser ----------
def parse_lnk(data: bytes):
    if len(data) < 76:
        raise ParseError("File too short for ShellLinkHeader")

    off = 0
    header_size, off = read_uint32(data, off)
    if header_size != 0x4C:
        raise ParseError(f"Invalid HeaderSize 0x{header_size:08X}")

    link_clsid = data[off:off + 16]
    off += 16
    expected_clsid = uuid.UUID("00021401-0000-0000-C000-000000000046").bytes_le
    if link_clsid != expected_clsid:
        raise ParseError("LinkCLSID does not match expected value")

    link_flags, off = read_uint32(data, off)
    file_attrs, off = read_uint32(data, off)

    creation_ft, off = read_uint64(data, off)
    access_ft, off = read_uint64(data, off)
    write_ft, off = read_uint64(data, off)

    file_size, off = read_uint32(data, off)
    icon_index, off = read_int32(data, off)
    show_cmd, off = read_uint32(data, off)
    hotkey, off = read_uint16(data, off)
    reserved1, off = read_uint16(data, off)
    reserved2, off = read_uint32(data, off)
    reserved3, off = read_uint32(data, off)

    # Verify reserved fields are zero
    if any(v != 0 for v in (reserved1, reserved2, reserved3)):
        raise ParseError("Reserved fields are non‑zero")

    # ---------- Optional structures ----------
    # IDList
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        idlist_size, off = read_uint16(data, off)
        if idlist_size < 2:
            raise ParseError("Invalid IDList size")
        remaining = idlist_size - 2
        if off + remaining > len(data):
            raise ParseError("IDList exceeds file size")
        off += remaining

    # LinkInfo
    if link_flags & 0x00000002:  # HasLinkInfo
        linkinfo_size, off = read_uint32(data, off)
        if linkinfo_size < 4:
            raise ParseError("Invalid LinkInfo size")
        remaining = linkinfo_size - 4
        if off + remaining > len(data):
            raise ParseError("LinkInfo exceeds file size")
        off += remaining

    # ---------- StringData ----------
    is_unicode = bool(link_flags & 0x00000080)

    def maybe_read_string(flag_bit):
        nonlocal off
        if link_flags & flag_bit:
            cnt, off = read_uint16(data, off)
            s, off = decode_string(data, off, cnt, is_unicode)
            return s
        return None

    name_string = maybe_read_string(0x00000004)          # HasName
    relative_path = maybe_read_string(0x00000008)        # HasRelativePath
    working_dir = maybe_read_string(0x00000010)          # HasWorkingDir
    command_line_arguments = maybe_read_string(0x00000020)  # HasArguments
    icon_location = maybe_read_string(0x00000040)        # HasIconLocation

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
    return result

# ---------- Entry point ----------
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
        parsed = parse_lnk(data)
        print(json.dumps(parsed, ensure_ascii=False))
        sys.exit(0)
    except ParseError as pe:
        err = {"error": str(pe)}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)
    except Exception as e:
        err = {"error": f"Unexpected error: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

if __name__ == "__main__":
    main()