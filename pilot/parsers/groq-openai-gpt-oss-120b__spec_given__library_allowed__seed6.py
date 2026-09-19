#!/usr/bin/env python3
import sys
import struct
import json
import datetime
import argparse
from pathlib import Path

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def read_struct(data: bytes, offset: int, fmt: str):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError("Unexpected end of file while reading structure")
    return struct.unpack_from(fmt, data, offset), offset + size

def read_uint16(data: bytes, offset: int):
    (val,), offset = read_struct(data, offset, "<H")
    return val, offset

def read_uint32(data: bytes, offset: int):
    (val,), offset = read_struct(data, offset, "<I")
    return val, offset

def read_uint64(data: bytes, offset: int):
    (val,), offset = read_struct(data, offset, "<Q")
    return val, offset

def filetime_to_iso(ft: int) -> str:
    # FILETIME is number of 100‑ns intervals since 1601‑01‑01 UTC
    try:
        us = ft // 10  # convert to microseconds
        epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = epoch_start + datetime.timedelta(microseconds=us)
        return dt.isoformat()
    except Exception:
        raise ValueError("Invalid FILETIME value")

def decode_string(data: bytes, offset: int, count: int, unicode: bool):
    byte_len = count * (2 if unicode else 1)
    if offset + byte_len > len(data):
        raise ValueError("String data exceeds file size")
    raw = data[offset: offset + byte_len]
    offset += byte_len
    if unicode:
        try:
            s = raw.decode('utf-16le')
        except UnicodeDecodeError:
            s = raw.decode('utf-16le', errors='replace')
    else:
        # ANSI – best‑effort using utf‑8 with replacement
        try:
            s = raw.decode('utf-8')
        except UnicodeDecodeError:
            s = raw.decode('utf-8', errors='replace')
    return s, offset

# ----------------------------------------------------------------------
# Main parser
# ----------------------------------------------------------------------
def parse_lnk(path: Path):
    data = path.read_bytes()
    offset = 0

    # ---- ShellLinkHeader (76 bytes) ----
    if len(data) < 0x4C:
        raise ValueError("File too short for ShellLinkHeader")
    # HeaderSize
    header_size, offset = read_uint32(data, offset)
    if header_size != 0x4C:
        raise ValueError(f"Invalid HeaderSize: 0x{header_size:08X}")

    # LinkCLSID
    link_clsid_bytes = data[offset: offset + 16]
    offset += 16
    expected_clsid = bytes.fromhex('0114020000000000C000000000000046')
    if link_clsid_bytes != expected_clsid:
        raise ValueError("LinkCLSID does not match expected value")

    # LinkFlags
    link_flags, offset = read_uint32(data, offset)

    # FileAttributes (ignored for output)
    _, offset = read_uint32(data, offset)

    # Timestamps
    creation_ft, offset = read_uint64(data, offset)
    access_ft, offset = read_uint64(data, offset)
    write_ft, offset = read_uint64(data, offset)

    # FileSize (unsigned)
    file_size, offset = read_uint32(data, offset)

    # IconIndex (signed)
    (icon_index,), offset = read_struct(data, offset, "<i")

    # ShowCommand, HotKey, Reserved1, Reserved2, Reserved3 (skip)
    offset += 4 + 2 + 2 + 4 + 4

    # ---- Optional IDList ----
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        idlist_size, offset = read_uint16(data, offset)
        if idlist_size < 2:
            raise ValueError("Invalid IDList size")
        # size includes the two size bytes themselves
        remaining = idlist_size - 2
        if offset + remaining > len(data):
            raise ValueError("IDList exceeds file size")
        offset += remaining

    # ---- Optional LinkInfo ----
    if link_flags & 0x00000002:  # HasLinkInfo
        linkinfo_size, offset = read_uint32(data, offset)
        if linkinfo_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if offset + (linkinfo_size - 4) > len(data):
            raise ValueError("LinkInfo exceeds file size")
        offset += (linkinfo_size - 4)

    # ---- StringData sections (ordered) ----
    unicode_strings = bool(link_flags & 0x00000080)  # IsUnicode
    fields = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
    }
    flag_to_key = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]

    for flag, key in flag_to_key:
        if link_flags & flag:
            count, offset = read_uint16(data, offset)
            s, offset = decode_string(data, offset, count, unicode_strings)
            fields[key] = s

    # ---- ExtraData (ignored) ----
    # The spec defines a terminal block with size < 0x00000004.
    # We simply stop parsing here; no need to validate further.

    # Build final JSON object
    result = {
        "name_string": fields["name_string"],
        "relative_path": fields["relative_path"],
        "working_dir": fields["working_dir"],
        "command_line_arguments": fields["command_line_arguments"],
        "icon_location": fields["icon_location"],
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_ft),
        "access_time": filetime_to_iso(access_ft),
        "write_time": filetime_to_iso(write_ft),
    }
    return result

# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Parse a Windows .lnk shortcut")
    parser.add_argument("lnk_path", type=Path, help="Path to .lnk file")
    args = parser.parse_args()

    try:
        output = parse_lnk(args.lnk_path)
        json.dump(output, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as exc:
        err_obj = {"error": str(exc)}
        json.dump(err_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)

if __name__ == "__main__":
    main()