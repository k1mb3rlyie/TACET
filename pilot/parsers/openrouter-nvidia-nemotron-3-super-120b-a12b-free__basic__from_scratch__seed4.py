import sys
import struct
import json
import datetime
import os

def filetime_to_iso(ft: int) -> str:
    """Convert FILETIME (100-ns since 1601-01-01 UTC) to ISO 8601 with UTC offset."""
    try:
        if ft < 0:
            raise ValueError("Negative FILETIME")
        # Convert to seconds since 1970-01-01 UTC
        seconds = (ft - 116444736000000000) / 10000000.0
        dt = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
        return dt.isoformat()
    except Exception as e:
        raise ValueError(f"Invalid FILETIME value: {e}")

def read_string(data: bytearray, offset: int, is_unicode: int):
    """Read a null-terminated string from data starting at offset.
    Returns (string, new_offset). Raises ValueError on failure."""
    start = offset
    if is_unicode:
        while offset + 1 < len(data):
            w = struct.unpack_from('<H', data, offset)[0]
            if w == 0:
                # terminator found
                string_bytes = data[start:offset]
                try:
                    s = string_bytes.decode('utf-16-le')
                except UnicodeDecodeError as e:
                    raise ValueError(f"UTF-16 decode error: {e}")
                offset += 2  # skip terminator
                return s, offset
            offset += 2
        raise ValueError("Missing Unicode string terminator")
    else:
        while offset < len(data):
            b = data[offset]
            if b == 0:
                string_bytes = data[start:offset]
                try:
                    s = string_bytes.decode('mbcs')
                except UnicodeDecodeError as e:
                    raise ValueError(f"ANSI decode error: {e}")
                offset += 1  # skip terminator
                return s, offset
            offset += 1
        raise ValueError("Missing ANSI string terminator")

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

    if len(data) < 68:
        sys.stderr.write("File too short for LNK header\n")
        sys.exit(1)

    try:
        (clsid, link_flags, file_attributes,
         creation_time, access_time, write_time,
         file_size, icon_index, show_command,
         hot_key, reserved1, reserved2) = struct.unpack_from('<16sIIQQQIIIHHI', data, 0)
    except struct.error as e:
        sys.stderr.write(f"Failed to unpack header: {e}\n")
        sys.exit(1)

    offset = 68
    is_unicode = bool(link_flags & 0x80)

    # Optional IDList
    if link_flags & 0x01:
        if offset + 2 > len(data):
            sys.stderr.write("IDList size missing\n")
            sys.exit(1)
        idlist_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if offset + idlist_size > len(data):
            sys.stderr.write("IDList data exceeds file size\n")
            sys.exit(1)
        offset += idlist_size

    # Optional LinkInfo
    if link_flags & 0x02:
        if offset + 4 > len(data):
            sys.stderr.write("LinkInfo size missing\n")
            sys.exit(1)
        linkinfosize = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if linkinfosize < 0:
            sys.stderr.write("Invalid LinkInfo size\n")
            sys.exit(1)
        if offset + linkinfosize > len(data):
            sys.stderr.write("LinkInfo data exceeds file size\n")
            sys.exit(1)
        # Minimal sanity check (optional)
        if linkinfosize < 0x1C:
            # Still skip; malformed but we continue
            pass
        offset += linkinfosize

    # Helper to fetch string if flag set
    def get_string(flag):
        nonlocal offset
        if link_flags & flag:
            try:
                s, offset = read_string(data, offset, is_unicode)
                return s
            except ValueError as e:
                sys.stderr.write(f"Failed to read string: {e}\n")
                sys.exit(1)
        else:
            return None

    name_string = get_string(0x04)      # HasName
    relative_path = get_string(0x08)    # HasRelativePath
    working_dir = get_string(0x10)      # HasWorkingDir
    command_line_arguments = get_string(0x20)  # HasArguments
    icon_location = get_string(0x40)    # HasIconLocation

    # Convert timestamps
    try:
        creation_iso = filetime_to_iso(creation_time)
        access_iso = filetime_to_iso(access_time)
        write_iso = filetime_to_iso(write_time)
    except ValueError as e:
        sys.stderr.write(f"Timestamp conversion error: {e}\n")
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
        "write_time": write_iso
    }

    # Output JSON to stdout
    try:
        json.dump(result, sys.stdout, ensure_ascii=False)
    except Exception as e:
        sys.stderr.write(f"Failed to write JSON: {e}\n")
        sys.exit(1)
    sys.stdout.write("\n")
    sys.exit(0)

if __name__ == "__main__":
    main()