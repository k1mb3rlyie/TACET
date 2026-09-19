#!/usr/bin/env python3
import sys
import json
import struct
import datetime
from pathlib import Path

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def error(msg: str, exit_code: int = 1) -> None:
    """Print a JSON error object to stdout and exit."""
    json.dump({"error": msg}, sys.stdout, ensure_ascii=False)
    sys.stdout.flush()
    sys.exit(exit_code)


def read_uint16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise ValueError("unexpected end of file while reading uint16")
    return struct.unpack_from("<H", data, offset)[0], offset + 2


def read_uint32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise ValueError("unexpected end of file while reading uint32")
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def read_int32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise ValueError("unexpected end of file while reading int32")
    return struct.unpack_from("<i", data, offset)[0], offset + 4


def read_uint64(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(data):
        raise ValueError("unexpected end of file while reading uint64")
    return struct.unpack_from("<Q", data, offset)[0], offset + 8


def filetime_to_iso(ft: int) -> str:
    """
    Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01 UTC)
    to an ISO‑8601 string with explicit +00:00 offset.
    """
    # FILETIME of 0 is allowed – treat as epoch 1601‑01‑01
    try:
        us = (ft - 116444736000000000) // 10  # convert to microseconds
        dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
        return dt.isoformat()
    except Exception as e:
        raise ValueError(f"invalid FILETIME value {ft}") from e


def decode_string(data: bytes, offset: int, count: int, is_unicode: bool) -> tuple[str, int]:
    """
    Decode a string of `count` characters starting at `offset`.
    Returns the string and the new offset.
    """
    if is_unicode:
        byte_len = count * 2
        if offset + byte_len > len(data):
            raise ValueError("unexpected end of file while reading Unicode string")
        raw = data[offset: offset + byte_len]
        try:
            s = raw.decode("utf-16le")
        except UnicodeDecodeError:
            s = raw.decode("utf-16le", errors="replace")
        return s, offset + byte_len
    else:
        byte_len = count
        if offset + byte_len > len(data):
            raise ValueError("unexpected end of file while reading ANSI string")
        raw = data[offset: offset + byte_len]
        # The spec uses the system code page; we fall back to latin‑1 to preserve bytes.
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            s = raw.decode("latin-1", errors="replace")
        return s, offset + byte_len


# ----------------------------------------------------------------------
# Core parser
# ----------------------------------------------------------------------
def parse_lnk(data: bytes) -> dict:
    # Minimum size check (header)
    if len(data) < 0x4C:
        raise ValueError("file too short for ShellLinkHeader")

    offset = 0

    # HeaderSize
    header_size, offset = read_uint32(data, offset)
    if header_size != 0x4C:
        raise ValueError(f"invalid HeaderSize {header_size:#x}")

    # LinkCLSID
    expected_clsid = bytes([
        0x01, 0x14, 0x02, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x46,
    ])
    clsid = data[offset: offset + 16]
    if len(clsid) != 16 or clsid != expected_clsid:
        raise ValueError("invalid LinkCLSID")
    offset += 16

    # LinkFlags
    link_flags, offset = read_uint32(data, offset)

    # FileAttributes (skip)
    _, offset = read_uint32(data, offset)

    # CreationTime, AccessTime, WriteTime
    creation_ft, offset = read_uint64(data, offset)
    access_ft, offset = read_uint64(data, offset)
    write_ft, offset = read_uint64(data, offset)

    creation_time = filetime_to_iso(creation_ft)
    access_time = filetime_to_iso(access_ft)
    write_time = filetime_to_iso(write_ft)

    # FileSize (unsigned)
    file_size, offset = read_uint32(data, offset)

    # IconIndex (signed)
    icon_index, offset = read_int32(data, offset)

    # ShowCommand (skip)
    _, offset = read_uint32(data, offset)

    # HotKey (skip)
    _, offset = read_uint16(data, offset)

    # Reserved1, Reserved2, Reserved3 (skip)
    _, offset = read_uint16(data, offset)   # Reserved1
    _, offset = read_uint32(data, offset)   # Reserved2
    _, offset = read_uint32(data, offset)   # Reserved3

    # --------------------------------------------------------------
    # Optional IDList
    # --------------------------------------------------------------
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        idlist_size, offset = read_uint16(data, offset)
        if offset + idlist_size > len(data):
            raise ValueError("IDList size exceeds file length")
        offset += idlist_size

    # --------------------------------------------------------------
    # Optional LinkInfo
    # --------------------------------------------------------------
    if link_flags & 0x00000002:  # HasLinkInfo
        linkinfo_size, offset = read_uint32(data, offset)
        if linkinfo_size < 4:
            raise ValueError("invalid LinkInfo size")
        if offset - 4 + linkinfo_size > len(data):
            raise ValueError("LinkInfo size exceeds file length")
        offset += linkinfo_size - 4  # we already consumed the size field

    # --------------------------------------------------------------
    # StringData sections (in fixed order)
    # --------------------------------------------------------------
    is_unicode = bool(link_flags & 0x00000080)

    def maybe_read(flag_bit: int) -> str | None:
        nonlocal offset
        if link_flags & flag_bit:
            char_count, offset = read_uint16(data, offset)
            s, offset = decode_string(data, offset, char_count, is_unicode)
            return s
        return None

    name_string = maybe_read(0x00000004)          # HasName
    relative_path = maybe_read(0x00000008)       # HasRelativePath
    working_dir = maybe_read(0x00000010)         # HasWorkingDir
    command_line_arguments = maybe_read(0x00000020)  # HasArguments
    icon_location = maybe_read(0x00000040)       # HasIconLocation

    # --------------------------------------------------------------
    # Build result
    # --------------------------------------------------------------
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time,
        "access_time": access_time,
        "write_time": write_time,
    }
    return result


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) != 2:
        error("usage: python parser.py <path-to-lnk-file>", exit_code=2)

    path = Path(sys.argv[1])
    if not path.is_file():
        error("file not found or not a regular file")

    try:
        data = path.read_bytes()
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