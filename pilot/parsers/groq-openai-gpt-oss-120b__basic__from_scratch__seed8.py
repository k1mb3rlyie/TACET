#!/usr/bin/env python3
import sys
import struct
import json
import datetime

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def filetime_to_iso(ft):
    """Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01 UTC) to ISO‑8601."""
    if ft == 0:
        return None
    us = ft // 10  # to microseconds
    dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
    return dt.isoformat()


def read_string(data, offset, unicode):
    """Read a string from *data* at *offset* according to the LNK spec."""
    if unicode:
        if offset + 2 > len(data):
            raise ValueError('truncated string length')
        (char_count,) = struct.unpack_from('<H', data, offset)
        offset += 2
        byte_len = char_count * 2
        if offset + byte_len > len(data):
            raise ValueError('truncated Unicode string')
        raw = data[offset:offset + byte_len]
        try:
            s = raw.decode('utf-16le')
        except UnicodeDecodeError as e:
            raise ValueError('invalid UTF‑16 string') from e
        offset += byte_len
        return s, offset
    else:
        if offset + 1 > len(data):
            raise ValueError('truncated string length')
        char_count = data[offset]
        offset += 1
        if offset + char_count > len(data):
            raise ValueError('truncated ANSI string')
        raw = data[offset:offset + char_count]
        # ANSI strings use the system code page; utf‑8 with replacement is a reasonable fallback
        s = raw.decode('utf-8', errors='replace')
        offset += char_count
        return s, offset


# ----------------------------------------------------------------------
# Core parser
# ----------------------------------------------------------------------
def parse_lnk(data):
    if len(data) < 76:
        raise ValueError('file too short for Shell Link header')

    # Shell Link Header (76 bytes)
    hdr = struct.unpack_from('<I16sIIQQQIIIHHII', data, 0)
    (header_size, link_clsid, link_flags, file_attrs,
     creation_ft, access_ft, write_ft,
     file_size, icon_index, show_cmd,
     hot_key, reserved1, reserved2, reserved3) = hdr

    if header_size != 0x4C:
        raise ValueError('invalid header size')
    expected_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    if link_clsid != expected_clsid:
        raise ValueError('invalid LinkCLSID')

    # Prepare result with defaults (null for optional strings)
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
        "write_time": filetime_to_iso(write_ft)
    }

    offset = header_size

    # LinkTargetIDList (optional)
    if link_flags & 0x00000001:
        if offset + 2 > len(data):
            raise ValueError('truncated IDList size')
        (idlist_size,) = struct.unpack_from('<H', data, offset)
        if offset + idlist_size > len(data):
            raise ValueError('truncated IDList')
        offset += idlist_size

    # LinkInfo (optional)
    if link_flags & 0x00000002:
        if offset + 4 > len(data):
            raise ValueError('truncated LinkInfo size')
        (linkinfo_size,) = struct.unpack_from('<I', data, offset)
        if linkinfo_size == 0:
            pass
        else:
            if offset + linkinfo_size > len(data):
                raise ValueError('truncated LinkInfo')
            offset += linkinfo_size

    # StringData (optional strings)
    unicode = bool(link_flags & 0x00000080)
    string_flags = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location")
    ]

    for flag, name in string_flags:
        if link_flags & flag:
            s, offset = read_string(data, offset, unicode)
            result[name] = s

    return result


# ----------------------------------------------------------------------
# Main entry point
# ----------------------------------------------------------------------
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
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as exc:
        err = {"error": str(exc)}
        json.dump(err, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()