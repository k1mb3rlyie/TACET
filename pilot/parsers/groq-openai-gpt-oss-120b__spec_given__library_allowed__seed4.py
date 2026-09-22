#!/usr/bin/env python3
import sys
import struct
import json
import datetime
import traceback

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def filetime_to_iso(ft):
    """
    Convert a Windows FILETIME (100‑ns intervals since 1601‑01‑01 UTC)
    to an ISO‑8601 string with explicit +00:00 offset.
    """
    try:
        # FILETIME is unsigned 64‑bit
        ft = int(ft)
        # Number of 100‑ns intervals between 1601‑01‑01 and 1970‑01‑01
        EPOCH_DIFF = 116444736000000000
        # Convert to seconds since Unix epoch
        unix_ts = (ft - EPOCH_DIFF) / 10_000_000
        dt = datetime.datetime.utcfromtimestamp(unix_ts)
        # isoformat without microseconds, add explicit UTC offset
        return dt.replace(microsecond=0).isoformat() + "+00:00"
    except Exception as e:
        raise ValueError(f"Invalid FILETIME value {ft}") from e


def read_uint16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def read_uint32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def read_int32(data, offset):
    return struct.unpack_from("<i", data, offset)[0]


def read_uint64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def decode_string(raw, is_unicode):
    if is_unicode:
        # UTF‑16LE, count is characters => bytes = count*2
        return raw.decode("utf-16le", errors="replace")
    else:
        # ANSI – best effort with Windows‑1252
        return raw.decode("cp1252", errors="replace")


def parse_lnk(data):
    # ------------------------------------------------------------------
    # Header (76 bytes)
    # ------------------------------------------------------------------
    if len(data) < 0x4C:
        raise ValueError("File too short for ShellLinkHeader")

    header_size = read_uint32(data, 0x00)
    if header_size != 0x4C:
        raise ValueError(f"HeaderSize mismatch: expected 0x4C, got {header_size:#x}")

    # LinkCLSID must be 00021401-0000-0000-C000-000000000046
    expected_clsid = b'\x01\x14\x02\x00' + b'\x00' * 12 + b'\xC0\x00\x00\x00' + b'\x46\x00\x00\x00'
    # Simpler: compare the raw 16‑byte GUID
    actual_clsid = data[0x04:0x14]
    if actual_clsid != b'\x01\x14\x02\x00' + b'\x00'*12 + b'\xC0\x00\x00\x00' + b'\x46\x00\x00\x00':
        raise ValueError("LinkCLSID does not match expected value")

    link_flags = read_uint32(data, 0x14)
    file_attrs = read_uint32(data, 0x18)

    creation_ft = read_uint64(data, 0x1C)
    access_ft   = read_uint64(data, 0x24)
    write_ft    = read_uint64(data, 0x2C)

    file_size = read_uint32(data, 0x34)
    icon_index = read_int32(data, 0x38)
    # other fields not needed for output
    # ------------------------------------------------------------------
    # Prepare result skeleton
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Move cursor after header
    # ------------------------------------------------------------------
    cursor = 0x4C
    data_len = len(data)

    # ------------------------------------------------------------------
    # Optional IDList
    # ------------------------------------------------------------------
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        if cursor + 2 > data_len:
            raise ValueError("Truncated IDList size field")
        idlist_size = read_uint16(data, cursor)
        cursor += 2
        if cursor + idlist_size > data_len:
            raise ValueError("Truncated IDList data")
        cursor += idlist_size  # skip IDList

    # ------------------------------------------------------------------
    # Optional LinkInfo
    # ------------------------------------------------------------------
    if link_flags & 0x00000002:  # HasLinkInfo
        if cursor + 4 > data_len:
            raise ValueError("Truncated LinkInfo size field")
        linkinfo_size = read_uint32(data, cursor)
        if linkinfo_size < 0x00000000:
            raise ValueError("Invalid LinkInfo size")
        cursor += 4
        if cursor + (linkinfo_size - 4) > data_len:
            raise ValueError("Truncated LinkInfo data")
        cursor += (linkinfo_size - 4)  # skip rest of LinkInfo

    # ------------------------------------------------------------------
    # StringData sections (in fixed order)
    # ------------------------------------------------------------------
    is_unicode = bool(link_flags & 0x00000080)  # IsUnicode

    string_flags = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]

    for flag, key in string_flags:
        if link_flags & flag:
            # Need at least 2 bytes for CountCharacters
            if cursor + 2 > data_len:
                raise ValueError(f"Truncated {key} CountCharacters")
            count = read_uint16(data, cursor)
            cursor += 2
            byte_len = count * (2 if is_unicode else 1)
            if cursor + byte_len > data_len:
                raise ValueError(f"Truncated {key} string data")
            raw = data[cursor:cursor + byte_len]
            cursor += byte_len
            result[key] = decode_string(raw, is_unicode)

    # ------------------------------------------------------------------
    # Done – any remaining data is ExtraData (ignored)
    # ------------------------------------------------------------------
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
        sys.exit(0)

    try:
        parsed = parse_lnk(data)
        print(json.dumps(parsed, ensure_ascii=False))
        sys.exit(0)
    except Exception as e:
        # For debugging, you could uncomment the following line:
        # traceback.print_exc(file=sys.stderr)
        err = {"error": str(e)}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(0)


if __name__ == "__main__":
    main()