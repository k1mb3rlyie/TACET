import sys
import struct
import datetime
import json

def filetime_to_iso(ft):
    """Convert FILETIME (100-ns since 1601-01-01 UTC) to ISO 8601 string with UTC offset."""
    try:
        # epoch start: 1601-01-01 00:00:00 UTC
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        # each tick is 100 ns = 0.1 microsecond
        dt = epoch + datetime.timedelta(microseconds=ft / 10)
        return dt.isoformat(timespec='microseconds')
    except Exception as e:
        raise ValueError(f"Invalid FILETIME value: {e}")

def read_lnk_string(data, offset, is_unicode):
    """Read a length-prefixed string from data at offset.
    Returns (string, new_offset). Raises ValueError on truncation or decode error."""
    if offset + 2 > len(data):
        raise ValueError("Truncated string length")
    str_len, = struct.unpack_from('<H', data, offset)
    offset += 2
    if is_unicode:
        byte_len = str_len * 2
        if offset + byte_len > len(data):
            raise ValueError("Truncated Unicode string")
        s_bytes = data[offset:offset + byte_len]
        offset += byte_len
        try:
            s = s_bytes.decode('utf-16-le')
        except UnicodeDecodeError as e:
            raise ValueError(f"Invalid UTF-16LE string: {e}")
    else:
        if offset + str_len > len(data):
            raise ValueError("Truncated ANSI string")
        s_bytes = data[offset:offset + str_len]
        offset += str_len
        # Latin-1 maps each byte 1:1 to Unicode code points, preserving raw bytes.
        s = s_bytes.decode('latin-1')
    return s, offset

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    path = sys.argv[1]

    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Cannot open file: {e}\n")
        sys.exit(1)

    if len(data) < 76:
        sys.stderr.write("File too small to be a valid LNK\n")
        sys.exit(1)

    # Parse fixed header (76 bytes)
    try:
        header_size = struct.unpack_from('<I', data, 0)[0]
        if header_size != 76:
            sys.stderr.write(f"Unexpected header size {header_size}\n")
            sys.exit(1)
        # link_clsid = data[4:20]  # ignored
        link_flags = struct.unpack_from('<I', data, 20)[0]
        # file_attributes = struct.unpack_from('<I', data, 24)[0]  # ignored
        creation_time = struct.unpack_from('<Q', data, 28)[0]
        access_time = struct.unpack_from('<Q', data, 36)[0]
        write_time = struct.unpack_from('<Q', data, 44)[0]
        file_size = struct.unpack_from('<I', data, 52)[0]
        icon_index = struct.unpack_from('<I', data, 56)[0]
        # show_command, hot_key, reserved1-3 omitted
    except struct.error as e:
        sys.stderr.write(f"Failed to parse header: {e}\n")
        sys.exit(1)

    offset = 76  # start after header

    # Optional LinkTargetIDList
    if link_flags & 0x00000001:
        if offset + 2 > len(data):
            sys.stderr.write("Truncated ID list size\n")
            sys.exit(1)
        id_list_size, = struct.unpack_from('<H', data, offset)
        offset += 2
        if offset + id_list_size > len(data):
            sys.stderr.write("Truncated ID list data\n")
            sys.exit(1)
        offset += id_list_size

    # Optional LinkInfo
    if link_flags & 0x00000002:
        start_link_info = offset
        if offset + 4 > len(data):
            sys.stderr.write("Truncated LinkInfo header size\n")
            sys.exit(1)
        link_info_header_size, = struct.unpack_from('<I', data, offset)
        offset += 4
        if link_info_header_size < 20:  # minimum fixed part size
            sys.stderr.write(f"Invalid LinkInfo header size {link_info_header_size}\n")
            sys.exit(1)
        offset = start_link_info + link_info_header_size
        if offset > len(data):
            sys.stderr.write("LinkInfo extends beyond file\n")
            sys.exit(1)

    # Determine string encoding
    is_unicode = bool(link_flags & 0x00000080)

    # Extract optional strings
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    try:
        if link_flags & 0x00000004:  # HasName
            name_string, offset = read_lnk_string(data, offset, is_unicode)
        if link_flags & 0x00000008:  # HasRelativePath
            relative_path, offset = read_lnk_string(data, offset, is_unicode)
        if link_flags & 0x00000010:  # HasWorkingDir
            working_dir, offset = read_lnk_string(data, offset, is_unicode)
        if link_flags & 0x00000020:  # HasArguments
            command_line_arguments, offset = read_lnk_string(data, offset, is_unicode)
        if link_flags & 0x00000040:  # HasIconLocation
            icon_location, offset = read_lnk_string(data, offset, is_unicode)
    except ValueError as e:
        sys.stderr.write(f"Failed to read string data: {e}\n")
        sys.exit(1)

    # Convert timestamps
    try:
        creation_iso = filetime_to_iso(creation_time)
        access_iso = filetime_to_iso(access_time)
        write_time_iso = filetime_to_iso(write_time)
    except ValueError as e:
        sys.stderr.write(f"Invalid timestamp: {e}\n")
        sys.exit(1)

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_iso,
        "access_time": access_iso,
        "write_time": write_time_iso
    }

    try:
        json_output = json.dumps(result, ensure_ascii=False)
    except Exception as e:
        sys.stderr.write(f"Failed to serialize JSON: {e}\n")
        sys.exit(1)

    sys.stdout.write(json_output + "\n")
    sys.exit(0)

if __name__ == "__main__":
    main()