import sys
import struct
import json
import datetime

def filetime_to_iso(ft: int) -> str:
    """Convert FILETIME UTC timestamp to ISO 8601 string with UTC offset."""
    if ft == 0:
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    else:
        # FILETIME: 100-nanosecond intervals since 1601-01-01 UTC
        seconds_since_1601 = ft // 10_000_000
        unix_time = seconds_since_1601 - 11644473600  # seconds between 1601-01-01 and 1970-01-01
        dt = datetime.datetime.fromtimestamp(unix_time, tz=datetime.timezone.utc)
    # Strip subseconds for consistent output
    dt = dt.replace(microsecond=0)
    return dt.isoformat()

def read_string(data: bytearray, start_offset: int, unicode_flag: bool) -> str | None:
    """Read a null-terminated string from data.
    Returns None if start_offset == 0 (field absent).
    Raises ValueError if the string is not properly terminated within the data.
    """
    if start_offset == 0:
        return None
    pos = start_offset
    if unicode_flag:
        # UTF-16LE, terminated by 0x0000
        while pos + 1 < len(data):
            if data[pos] == 0 and data[pos + 1] == 0:
                break
            pos += 2
        if pos + 1 >= len(data):
            raise ValueError("Unterminated Unicode string")
        # data[start_offset:pos] contains the UTF-16LE bytes (excluding terminator)
        raw = data[start_offset:pos]
        try:
            return raw.decode('utf-16le')
        except UnicodeDecodeError as e:
            raise ValueError(f"Invalid UTF-16LE string: {e}")
    else:
        # ANSI (single byte), terminated by 0x00
        while pos < len(data) and data[pos] != 0:
            pos += 1
        if pos >= len(data):
            raise ValueError("Unterminated ANSI string")
        raw = data[start_offset:pos]
        # Use latin-1 to map each byte 1:1 to Unicode without loss
        return raw.decode('latin-1')

def main() -> None:
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = bytearray(f.read())
    except OSError as e:
        sys.stderr.write(f"Cannot open file: {e}\n")
        sys.exit(1)

    if len(data) < 0x4C:
        sys.stderr.write("File too short for LNK header\n")
        sys.exit(1)

    try:
        header_size = struct.unpack_from("<I", data, 0)[0]
        if header_size != 0x4C:
            sys.stderr.write(f"Invalid header size {header_size}\n")
            sys.exit(1)

        # Optional CLSID check (not mandatory for parsing)
        expected_clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
        if data[4:20] != expected_clsid:
            # Not fatal; continue parsing
            pass

        link_flags = struct.unpack_from("<I", data, 0x14)[0]
        creation_time_ft = struct.unpack_from("<Q", data, 0x1C)[0]
        access_time_ft = struct.unpack_from("<Q", data, 0x24)[0]
        write_time_ft = struct.unpack_from("<Q", data, 0x2C)[0]
        file_size = struct.unpack_from("<I", data, 0x34)[0]
        icon_index = struct.unpack_from("<I", data, 0x38)[0]
        # Hotkey and reserved fields are not needed for output
    except struct.error as e:
        sys.stderr.write(f"Failed to parse header: {e}\n")
        sys.exit(1)

    unicode_flag = bool(link_flags & 0x00000080)
    has_link_info = bool(link_flags & 0x00000002)

    # Skip Item ID List
    cur = 0x4C  # start after header
    if cur + 2 > len(data):
        sys.stderr.write("File too short for ID list size\n")
        sys.exit(1)
    id_list_size = struct.unpack_from("<H", data, cur)[0]
    cur += 2
    id_list_end = cur + id_list_size
    if id_list_end > len(data):
        sys.stderr.write("ID list exceeds file size\n")
        sys.exit(1)
    cur = id_list_end

    # Skip LinkInfo if present
    if has_link_info:
        if cur + 4 > len(data):
            sys.stderr.write("File too short for LinkInfo size\n")
            sys.exit(1)
        link_info_size = struct.unpack_from("<I", data, cur)[0]
        if link_info_size == 0:
            sys.stderr.write("LinkInfo size zero\n")
            sys.exit(1)
        if cur + link_info_size > len(data):
            sys.stderr.write("LinkInfo exceeds file size\n")
            sys.exit(1)
        cur += link_info_size

    # Now at start of String Data block
    string_data_start = cur
    needed = 5 * 4  # five offsets
    if cur + needed > len(data):
        sys.stderr.write("File too short for string offsets\n")
        sys.exit(1)
    name_off = struct.unpack_from("<I", data, cur)[0]; cur += 4
    rel_off = struct.unpack_from("<I", data, cur)[0]; cur += 4
    work_off = struct.unpack_from("<I", data, cur)[0]; cur += 4
    cmd_off = struct.unpack_from("<I", data, cur)[0]; cur += 4
    icon_off = struct.unpack_from("<I", data, cur)[0]; cur += 4

    # Helper to read each string
    try:
        name_string = read_string(data, string_data_start + name_off, unicode_flag) if name_off else None
        relative_path = read_string(data, string_data_start + rel_off, unicode_flag) if rel_off else None
        working_dir = read_string(data, string_data_start + work_off, unicode_flag) if work_off else None
        command_line_arguments = read_string(data, string_data_start + cmd_off, unicode_flag) if cmd_off else None
        icon_location = read_string(data, string_data_start + icon_off, unicode_flag) if icon_off else None
    except ValueError as e:
        sys.stderr.write(f"Failed to read string data: {e}\n")
        sys.exit(1)

    # Convert timestamps
    creation_time_iso = filetime_to_iso(creation_time_ft)
    access_time_iso = filetime_to_iso(access_time_ft)
    write_time_iso = filetime_to_iso(write_time_ft)

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time_iso,
        "access_time": access_time_iso,
        "write_time": write_time_iso
    }

    json_output = json.dumps(result, separators=(',', ':'))
    sys.stdout.write(json_output + "\n")
    sys.exit(0)

if __name__ == "__main__":
    main()