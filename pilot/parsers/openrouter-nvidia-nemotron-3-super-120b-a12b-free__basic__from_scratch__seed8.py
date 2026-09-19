import sys
import struct
import json
from datetime import datetime, timezone, timedelta

def filetime_to_iso(ft: int) -> str:
    """Convert Windows FILETIME (100-ns since 1601-01-01 UTC) to ISO 8601 with UTC offset."""
    # 100-ns intervals to microseconds
    microseconds = ft // 10
    dt = datetime(1601, 1, 1) + timedelta(microseconds=microseconds)
    dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()

def read_string(data: bytes, pos: int, is_unicode: int):
    """Read a null-terminated string from data starting at pos.
    Returns (string, new_pos) where new_pos points after the terminating null(s)
    and any padding to align to a 4-byte boundary."""
    if is_unicode:
        i = pos
        while i + 1 < len(data):
            if data[i] == 0 and data[i + 1] == 0:
                break
            i += 2
        else:
            raise ValueError("Missing null terminator for Unicode string")
        string_bytes = data[pos:i]
        try:
            s = string_bytes.decode('utf-16-le')
        except UnicodeDecodeError as e:
            raise ValueError(f"Failed to decode Unicode string: {e}")
        new_pos = i + 2  # skip terminator
    else:
        i = pos
        while i < len(data):
            if data[i] == 0:
                break
            i += 1
        else:
            raise ValueError("Missing null terminator for ANSI string")
        string_bytes = data[pos:i]
        try:
            s = string_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise ValueError(f"Failed to decode ANSI string: {e}")
        new_pos = i + 1  # skip terminator

    # Align to 4-byte boundary
    padding = (4 - (new_pos % 4)) % 4
    new_pos += padding
    return s, new_pos

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Cannot read file: {e}\n")
        sys.exit(1)

    # Minimum size to read required header fields (up to IconIndex)
    if len(data) < 0x2C:
        sys.stderr.write("File too small to be a valid LNK\n")
        sys.exit(1)

    # Read HeaderSize to locate LinkInfo
    header_size = struct.unpack_from("<I", data, 0)[0]
    if header_size < 0x2C:
        sys.stderr.write("Invalid Link header size\n")
        sys.exit(1)
    if len(data) < header_size:
        sys.stderr.write("File smaller than indicated header size\n")
        sys.exit(1)

    # Link flags
    link_flags = struct.unpack_from("<I", data, 0x04)[0]

    # File size and icon index
    file_size = struct.unpack_from("<I", data, 0x24)[0]
    icon_index = struct.unpack_from("<I", data, 0x28)[0]

    # Timestamps
    try:
        creation_ft = struct.unpack_from("<Q", data, 0x0C)[0]
        access_ft   = struct.unpack_from("<Q", data, 0x14)[0]
        write_ft    = struct.unpack_from("<Q", data, 0x1C)[0]
    except struct.error:
        sys.stderr.write("Failed to read timestamp fields\n")
        sys.exit(1)

    creation_iso = filetime_to_iso(creation_ft)
    access_iso   = filetime_to_iso(access_ft)
    write_iso    = filetime_to_iso(write_ft)

    # Determine start of string data
    if link_flags & 0x00000002:  # HasLinkInfo
        linkinfo_offset = header_size
        if linkinfo_offset + 4 > len(data):
            sys.stderr.write("LinkInfo size out of bounds\n")
            sys.exit(1)
        linkinfo_size = struct.unpack_from("<I", data, linkinfo_offset)[0]
        if linkinfo_offset + linkinfo_size > len(data):
            sys.stderr.write("LinkInfo exceeds file size\n")
            sys.exit(1)
        string_data_start = linkinfo_offset + linkinfo_size
    else:
        string_data_start = header_size

    # Parse optional strings in order
    offset = string_data_start
    is_unicode = bool(link_flags & 0x00000080)

    def get_string(flag):
        nonlocal offset
        if link_flags & flag:
            try:
                s, offset = read_string(data, offset, is_unicode)
            except ValueError as e:
                sys.stderr.write(f"String parsing error: {e}\n")
                sys.exit(1)
            return s
        else:
            return None

    name_string       = get_string(0x00000004)  # HasName
    relative_path     = get_string(0x00000008)  # HasRelativePath
    working_dir       = get_string(0x00000010)  # HasWorkingDir
    command_line_args = get_string(0x00000020)  # HasArguments
    icon_location     = get_string(0x00000040)  # HasIconLocation

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_args,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_iso,
        "access_time": access_iso,
        "write_time": write_iso
    }

    sys.stdout.write(json.dumps(result))
    sys.exit(0)

if __name__ == "__main__":
    main()