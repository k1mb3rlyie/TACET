#!/usr/bin/env python3
import sys
import struct
import json
import datetime
from datetime import timezone, timedelta

# ---------- helpers ----------
def error(msg):
    """Print error JSON and exit with non‑zero code."""
    sys.stdout.write(json.dumps({"error": msg}, ensure_ascii=False))
    sys.exit(1)


def read_bytes(data, offset, size):
    if offset + size > len(data):
        raise ValueError("unexpected end of file")
    return data[offset:offset + size]


def unpack_from(fmt, data, offset):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError("unexpected end of file")
    return struct.unpack_from(fmt, data, offset), offset + size


def filetime_to_iso(ft):
    """Convert a Windows FILETIME (100‑ns intervals since 1601‑01‑01) to ISO‑8601."""
    try:
        base = datetime.datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = base + timedelta(microseconds=ft // 10)
        return dt.isoformat()
    except Exception:
        raise ValueError("invalid FILETIME value")


# ---------- main parser ----------
def parse_lnk(data):
    # ----- ShellLinkHeader (76 bytes) -----
    if len(data) < 76:
        raise ValueError("file too short for ShellLinkHeader")

    # HeaderSize
    (header_size,), pos = unpack_from("<I", data, 0)
    if header_size != 0x4C:
        raise ValueError("invalid HeaderSize")

    # LinkCLSID
    link_clsid = read_bytes(data, 4, 16)
    expected_clsid = bytes.fromhex(
        "01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46".replace(" ", "")
    )
    if link_clsid != expected_clsid:
        raise ValueError("invalid LinkCLSID")

    # LinkFlags
    (link_flags,), pos = unpack_from("<I", data, 0x14)

    # FileAttributes (skip)
    (_,), pos = unpack_from("<I", data, 0x18)

    # Times
    (creation_ft,), pos = unpack_from("<Q", data, 0x1C)
    (access_ft,), pos = unpack_from("<Q", data, 0x24)
    (write_ft,), pos = unpack_from("<Q", data, 0x2C)

    # FileSize (unsigned)
    (file_size,), pos = unpack_from("<I", data, 0x34)

    # IconIndex (signed)
    (icon_index,), pos = unpack_from("<i", data, 0x38)

    # The rest of the header fields are not needed for output
    pos = 0x4C  # after fixed header

    # ----- Optional IDList -----
    HAS_IDLIST = 0x00000001
    if link_flags & HAS_IDLIST:
        (idlist_size,), pos = unpack_from("<H", data, pos)
        pos += idlist_size
        if pos > len(data):
            raise ValueError("IDList exceeds file length")

    # ----- Optional LinkInfo -----
    HAS_LINKINFO = 0x00000002
    if link_flags & HAS_LINKINFO:
        (linkinfo_size,), pos = unpack_from("<I", data, pos)
        pos += linkinfo_size - 4  # already consumed size field
        if pos > len(data):
            raise ValueError("LinkInfo exceeds file length")

    # ----- StringData -----
    IS_UNICODE = 0x00000080
    unicode = bool(link_flags & IS_UNICODE)

    def read_string_section():
        (char_count,), new_pos = unpack_from("<H", data, pos)
        byte_len = char_count * (2 if unicode else 1)
        string_bytes = read_bytes(data, new_pos, byte_len)
        try:
            if unicode:
                s = string_bytes.decode("utf-16le", errors="replace")
            else:
                s = string_bytes.decode("utf-8", errors="replace")
        except Exception:
            s = ""
        return s, new_pos + byte_len

    # Prepare result placeholders
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

    # Mapping of flag bits to result keys in the required order
    flag_key_pairs = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]

    for flag, key in flag_key_pairs:
        if link_flags & flag:
            s, pos = read_string_section()
            result[key] = s
        else:
            result[key] = None

    # ----- ExtraData (ignored) -----
    # We stop parsing here; any remaining bytes are considered extra data.

    return result


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        error(f"cannot read file: {e}")

    try:
        parsed = parse_lnk(data)
    except Exception as e:
        error(str(e))

    sys.stdout.write(json.dumps(parsed, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()