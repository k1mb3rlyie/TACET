import sys
import struct
import datetime
import json

_FILETIME_EPOCH_DIFF = 116444736000000000  # 100-ns intervals from 1601-01-01 to 1970-01-01
_EXPECTED_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'


def _filetime_to_iso(ft: int) -> str:
    """Convert a Windows FILETIME to an ISO‑8601 string with UTC offset."""
    diff = ft - _FILETIME_EPOCH_DIFF  # may be negative
    seconds = diff // 10_000_000
    remainder_units = diff % 10_000_000  # always non‑negative
    microseconds = remainder_units // 10
    dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=seconds, microseconds=microseconds)
    dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.isoformat()


def main() -> None:
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        sys.stderr.write(f"Cannot read file: {exc}\n")
        sys.exit(1)

    if len(data) < 76:
        sys.stderr.write("File too short for a valid LNK header\n")
        sys.exit(1)

    try:
        (
            header_size,
            link_clsid,
            link_flags,
            _file_attrs,
            create_time,
            access_time,
            write_time,
            file_size,
            icon_index,
            _show_cmd,
            _hot_key,
            reserved1,
            reserved2,
            reserved3,
        ) = struct.unpack_from("<I 16s I I Q Q Q I i I H H I I", data, 0)
    except struct.error as exc:
        sys.stderr.write(f"Failed to unpack header: {exc}\n")
        sys.exit(1)

    if header_size != 0x4C:
        sys.stderr.write(f"Invalid HeaderSize: 0x{header_size:08X}\n")
        sys.exit(1)
    if link_clsid != _EXPECTED_CLSID:
        sys.stderr.write("Invalid LinkCLSID\n")
        sys.exit(1)
    if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
        sys.stderr.write("Reserved fields must be zero\n")
        sys.exit(1)

    offset = 76  # start after the fixed header

    # Skip LinkTargetIDList if present
    if link_flags & 0x00000001:
        if offset + 2 > len(data):
            sys.stderr.write("IDList size exceeds file bounds\n")
            sys.exit(1)
        (idlist_size,) = struct.unpack_from("<H", data, offset)
        offset += 2
        if offset + idlist_size > len(data):
            sys.stderr.write("IDList data exceeds file bounds\n")
            sys.exit(1)
        offset += idlist_size

    # Skip LinkInfo if present
    if link_flags & 0x00000002:
        if offset + 4 > len(data):
            sys.stderr.write("LinkInfo size exceeds file bounds\n")
            sys.exit(1)
        (li_size,) = struct.unpack_from("<I", data, offset)
        offset += 4
        if offset + li_size > len(data):
            sys.stderr.write("LinkInfo data exceeds file bounds\n")
            sys.exit(1)
        offset += li_size

    # Prepare result container
    result = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": None,
        "access_time": None,
        "write_time": None,
    }

    is_unicode = bool(link_flags & 0x00000080)

    string_specs = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]

    for flag, key in string_specs:
        if link_flags & flag:
            if offset + 2 > len(data):
                sys.stderr.write(f"String length missing for {key}\n")
                sys.exit(1)
            (char_count,) = struct.unpack_from("<H", data, offset)
            offset += 2
            byte_len = char_count * 2 if is_unicode else char_count
            if offset + byte_len > len(data):
                sys.stderr.write(f"String data exceeds file bounds for {key}\n")
                sys.exit(1)
            raw = data[offset:offset + byte_len]
            offset += byte_len
            try:
                decoded = raw.decode("utf-16-le") if is_unicode else raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                sys.stderr.write(f"Failed to decode string for {key}: {exc}\n")
                sys.exit(1)
            result[key] = decoded
        else:
            result[key] = None

    # Convert timestamps
    try:
        result["creation_time"] = _filetime_to_iso(create_time)
        result["access_time"] = _filetime_to_iso(access_time)
        result["write_time"] = _filetime_to_iso(write_time)
    except Exception as exc:
        sys.stderr.write(f"Timestamp conversion error: {exc}\n")
        sys.exit(1)

    # Emit JSON
    try:
        json_out = json.dumps(result, ensure_ascii=False)
    except Exception as exc:
        sys.stderr.write(f"JSON serialization error: {exc}\n")
        sys.exit(1)

    sys.stdout.write(json_out + "\n")


if __name__ == "__main__":
    main()