import sys
import struct
import json
from datetime import datetime, timezone

def filetime_to_iso(ft: int) -> str:
    """Convert FILETIME (100-ns since 1601-01-01 UTC) to ISO 8601 with UTC offset."""
    # Seconds between 1601-01-01 and 1970-01-01
    epochs = ft / 10_000_000 - 11644473600
    dt = datetime.fromtimestamp(epochs, tz=timezone.utc)
    return dt.isoformat()

def parse_lnk(data: bytes):
    if len(data) < 64:
        raise ValueError("File too small to be a valid .lnk")
    pos = 0

    signature = data[pos:pos+4]
    pos += 4
    if signature != b'L\x00\x00\x00':
        raise ValueError("Invalid .lnk signature")

    link_flags = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    _file_attributes = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    creation_time = struct.unpack_from('<Q', data, pos)[0]
    pos += 8
    access_time = struct.unpack_from('<Q', data, pos)[0]
    pos += 8
    write_time = struct.unpack_from('<Q', data, pos)[0]
    pos += 8
    file_size = struct.unpack_from<'Q', data, pos)[0]
    pos += 8
    icon_index = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    _show_command = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    _hot_key = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    _fill = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    _reserved1 = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    _reserved2 = struct.unpack_from('<I', data, pos)[0]
    pos += 4

    # Optional ItemIDList
    if link_flags & 0x00000001:
        if pos + 2 > len(data):
            raise ValueError("Missing ItemIDList size")
        id_list_size = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        if id_list_size < 2:
            raise ValueError("Invalid ItemIDList size")
        if pos + (id_list_size - 2) > len(data):
            raise ValueError("ItemIDList exceeds file size")
        pos += (id_list_size - 2)

    # Optional LinkInfo
    if link_flags & 0x00000002:
        if pos + 4 > len(data):
            raise ValueError("Missing LinkInfo size")
        link_info_size = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if link_info_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if pos + (link_info_size - 4) > len(data):
            raise ValueError("LinkInfo exceeds file size")
        pos += (link_info_size - 4)

    is_unicode = bool(link_flags & 0x00000080)

    def read_string(flag):
        nonlocal pos
        if not (link_flags & flag):
            return None
        if pos + 2 > len(data):
            raise ValueError("Missing string length")
        str_len = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        if str_len < 0:
            raise ValueError("Negative string length")
        if pos + str_len > len(data):
            raise ValueError("String data exceeds file size")
        str_bytes = data[pos:pos+str_len]
        pos += str_len
        try:
            if is_unicode:
                return str_bytes.decode('utf-16-le')
            else:
                return str_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise ValueError(f"String decoding failed: {e}")

    name_string = read_string(0x00000004)   # HasName
    relative_path = read_string(0x00000008) # HasRelativePath
    working_dir = read_string(0x00000010)   # HasWorkingDir
    command_line_arguments = read_string(0x00000020) # HasArguments
    icon_location = read_string(0x00000040) # HasIconLocation

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_time),
        "access_time": filetime_to_iso(access_time),
        "write_time": filetime_to_iso(write_time)
    }
    return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Cannot read file: {e}\n")
        sys.exit(1)

    try:
        result = parse_lnk(data)
    except Exception as e:
        sys.stderr.write(f"Error parsing .lnk file: {e}\n")
        sys.exit(1)

    print(json.dumps(result, separators=(',', ':')))
    sys.exit(0)

if __name__ == "__main__":
    main()