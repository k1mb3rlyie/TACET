#!/usr/bin/env python3
import sys
import struct
import json
import datetime

class LNKParseError(Exception):
    pass

def read_fmt(data, offset, fmt):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise LNKParseError("Unexpected end of file while reading structure")
    return struct.unpack_from(fmt, data, offset), offset + size

def read_bytes(data, offset, length):
    if offset + length > len(data):
        raise LNKParseError("Unexpected end of file while reading bytes")
    return data[offset:offset+length], offset + length

def filetime_to_iso(ft):
    # ft is unsigned 64‑bit integer (100‑ns intervals since 1601‑01‑01 UTC)
    try:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        micros = ft // 10
        dt = epoch + datetime.timedelta(microseconds=micros)
        return dt.isoformat()
    except Exception:
        raise LNKParseError("Invalid FILETIME value")

def parse_lnk(data):
    offset = 0
    # ----- ShellLinkHeader (76 bytes) -----
    (header_vals,), offset = read_fmt(data, offset, "<I16sI I Q Q Q I i I H H I I I")
    # Unpack manually for clarity
    (HeaderSize,
     LinkCLSID,
     LinkFlags,
     FileAttributes,
     CreationTime,
     AccessTime,
     WriteTime,
     FileSize,
     IconIndex,
     ShowCommand,
     HotKey,
     Reserved1,
     Reserved2,
     Reserved3) = header_vals

    if HeaderSize != 0x4C:
        raise LNKParseError("Invalid HeaderSize")
    expected_clsid = bytes.fromhex('01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46')
    if LinkCLSID != expected_clsid:
        raise LNKParseError("Invalid LinkCLSID")

    # ----- Optional IDList -----
    if LinkFlags & 0x00000001:  # HasLinkTargetIDList
        (idlist_size,), offset = read_fmt(data, offset, "<H")
        _, offset = read_bytes(data, offset, idlist_size)

    # ----- Optional LinkInfo -----
    if LinkFlags & 0x00000002:  # HasLinkInfo
        (linkinfo_size,), offset = read_fmt(data, offset, "<I")
        _, offset = read_bytes(data, offset, linkinfo_size - 4)  # size includes the 4‑byte size field

    # ----- StringData -----
    unicode = bool(LinkFlags & 0x00000080)  # IsUnicode
    char_width = 2 if unicode else 1
    decode = lambda b: b.decode('utf-16le') if unicode else b.decode('utf-8', errors='replace')

    def read_string():
        nonlocal offset
        (char_count,), offset = read_fmt(data, offset, "<H")
        byte_len = char_count * char_width
        raw, offset = read_bytes(data, offset, byte_len)
        return decode(raw)

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if LinkFlags & 0x00000004:  # HasName
        name_string = read_string()
    if LinkFlags & 0x00000008:  # HasRelativePath
        relative_path = read_string()
    if LinkFlags & 0x00000010:  # HasWorkingDir
        working_dir = read_string()
    if LinkFlags & 0x00000020:  # HasArguments
        command_line_arguments = read_string()
    if LinkFlags & 0x00000040:  # HasIconLocation
        icon_location = read_string()

    # ----- Build result -----
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": FileSize,
        "icon_index": IconIndex,
        "creation_time": filetime_to_iso(CreationTime),
        "access_time": filetime_to_iso(AccessTime),
        "write_time": filetime_to_iso(WriteTime)
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
    except Exception as e:
        err = {"error": f"Cannot read file: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

    try:
        parsed = parse_lnk(data)
        print(json.dumps(parsed, ensure_ascii=False))
        sys.exit(0)
    except LNKParseError as e:
        err = {"error": str(e)}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)
    except Exception as e:
        err = {"error": f"Unexpected error: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

if __name__ == "__main__":
    main()