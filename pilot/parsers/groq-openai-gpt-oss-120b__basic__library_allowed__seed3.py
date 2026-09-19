#!/usr/bin/env python3
import sys
import json
import struct
import datetime
import os

# ----- helpers ---------------------------------------------------------------

def filetime_to_iso(ft):
    """Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01 UTC) to ISO‑8601."""
    if ft == 0:
        return None
    us = ft // 10  # to microseconds
    try:
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
        return dt.isoformat()
    except Exception:
        return None

def read_exact(f, n):
    data = f.read(n)
    if len(data) != n:
        raise EOFError("unexpected end of file")
    return data

def read_uint16(f):
    return struct.unpack("<H", read_exact(f, 2))[0]

def read_uint32(f):
    return struct.unpack("<I", read_exact(f, 4))[0]

def read_uint64(f):
    return struct.unpack("<Q", read_exact(f, 8))[0]

def read_string(f, is_unicode):
    length = read_uint16(f)
    if is_unicode:
        raw = read_exact(f, length * 2)
        try:
            return raw.decode("utf-16le", errors="replace")
        except Exception:
            return raw.decode("utf-16le", errors="replace")
    else:
        raw = read_exact(f, length)
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("utf-8", errors="replace")

# ----- main parser -----------------------------------------------------------

def parse_lnk(path):
    result = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
        "file_size": 0,
        "icon_index": 0,
        "creation_time": None,
        "access_time": None,
        "write_time": None,
    }

    with open(path, "rb") as f:
        # ----- Header ---------------------------------------------------------
        header = read_exact(f, 76)
        (
            header_size,
            link_clsid,
            link_flags,
            file_attrs,
            creation_time,
            access_time,
            write_time,
            file_size,
            icon_index,
            show_cmd,
            hot_key,
            reserved1,
            reserved2,
            reserved3,
        ) = struct.unpack("<I16sI4sQQQIiiii", header)

        if header_size != 0x4C:
            raise ValueError("Invalid header size")

        # Store header values
        result["file_size"] = file_size
        result["icon_index"] = icon_index
        result["creation_time"] = filetime_to_iso(creation_time)
        result["access_time"] = filetime_to_iso(access_time)
        result["write_time"] = filetime_to_iso(write_time)

        # Flags
        HAS_LINK_TARGET_IDLIST = 0x00000001
        HAS_LINK_INFO = 0x00000002
        HAS_NAME = 0x00000004
        HAS_RELATIVE_PATH = 0x00000008
        HAS_WORKING_DIR = 0x00000010
        HAS_ARGUMENTS = 0x00000020
        HAS_ICON_LOCATION = 0x00000040
        IS_UNICODE = 0x00000080

        is_unicode = bool(link_flags & IS_UNICODE)

        # ----- Optional IDList ------------------------------------------------
        if link_flags & HAS_LINK_TARGET_IDLIST:
            idlist_size = read_uint16(f)          # size of IDList structure
            _ = read_exact(f, idlist_size)        # skip it

        # ----- Optional LinkInfo ---------------------------------------------
        if link_flags & HAS_LINK_INFO:
            linkinfo_size = read_uint32(f)        # total size of LinkInfo
            if linkinfo_size < 4:
                raise ValueError("Invalid LinkInfo size")
            _ = read_exact(f, linkinfo_size - 4)  # skip rest of LinkInfo

        # ----- StringData -----------------------------------------------------
        # Order: Name, RelativePath, WorkingDir, CommandLineArguments, IconLocation
        if link_flags & HAS_NAME:
            result["name_string"] = read_string(f, is_unicode)
        if link_flags & HAS_RELATIVE_PATH:
            result["relative_path"] = read_string(f, is_unicode)
        if link_flags & HAS_WORKING_DIR:
            result["working_dir"] = read_string(f, is_unicode)
        if link_flags & HAS_ARGUMENTS:
            result["command_line_arguments"] = read_string(f, is_unicode)
        if link_flags & HAS_ICON_LOCATION:
            result["icon_location"] = read_string(f, is_unicode)

    return result

# ----- entry point -----------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    path = sys.argv[1]

    if not os.path.isfile(path):
        sys.stderr.write(f"File not found: {path}\n")
        sys.exit(1)

    try:
        data = parse_lnk(path)
        json.dump(data, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as e:
        # On any parsing error, output the error JSON as required
        err = {"error": str(e)}
        json.dump(err, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()