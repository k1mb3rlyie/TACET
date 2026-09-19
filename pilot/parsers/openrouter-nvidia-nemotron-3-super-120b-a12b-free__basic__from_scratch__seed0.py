import sys
import struct
import json
from datetime import datetime, timezone, timedelta

def filetime_to_iso(ft: int) -> str:
    """Convert FILETIME uint64 to ISO 8601 string with UTC offset."""
    # FILETIME: 100-nanosecond intervals since 1601-01-01 UTC
    # Convert to microseconds (loss of sub‑microsecond precision is acceptable)
    microseconds = ft // 10
    base = datetime(1601, 1, 1, tzinfo=timezone.utc)
    dt = base + timedelta(microseconds=microseconds)
    return dt.isoformat()

def main() -> None:
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: parser.py <path-to-lnk-file>\n")
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Cannot open file: {e}\n")
        sys.exit(1)

    if len(data) < 76:
        sys.stderr.write("File too small to be a valid LNK\n")
        sys.exit(1)

    offset = 0
    try:
        # Header: cbSize(4), CLSID(16), dwFlags(4), dwFileAttributes(4),
        # ftCreation(8), ftAccess(8), ftWrite(8), dwFileSize(4),
        # dwIconIndex(4), dwShowCommand(4), wHotkey(2), wReserved(2),
        # dwReserved[2](8)
        (cbSize, _clsid, dwFlags, dwFileAttributes,
         ftCreation, ftAccess, ftWrite,
         dwFileSize, dwIconIndex, dwShowCommand,
         wHotkey, _wReserved, dwReserved1, dwReserved2) = struct.unpack_from(
            "<I 16s I I Q Q Q I I I H H II", data, offset)
    except struct.error as e:
        sys.stderr.write(f"Failed to unpack header: {e}\n")
        sys.exit(1)

    offset += 76

    if cbSize != 76:
        sys.stderr.write(f"Invalid cbSize {cbSize}, expected 76\n")
        sys.exit(1)

    try:
        creation_iso = filetime_to_iso(ftCreation)
        access_iso   = filetime_to_iso(ftAccess)
        write_iso    = filetime_to_iso(ftWrite)
    except Exception as e:
        sys.stderr.write(f"Failed to convert filetimes: {e}\n")
        sys.exit(1)

    # Output fields
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    def has_flag(flag: int) -> bool:
        return (dwFlags & flag) != 0

    try:
        # LinkTargetIDList
        if has_flag(0x00000001):
            if offset + 2 > len(data):
                raise ValueError("Truncated IDList size")
            idlist_size, = struct.unpack_from("<H", data, offset)
            offset += 2
            if offset + idlist_size > len(data):
                raise ValueError("Truncated IDList")
            offset += idlist_size

        # LinkInfo
        if has_flag(0x00000002):
            if offset + 4 > len(data):
                raise ValueError("Truncated LinkInfo size")
            linkinfo_size, = struct.unpack_from("<I", data, offset)
            offset += 4
            if linkinfo_size < 12:
                raise ValueError(f"Invalid LinkInfo size {linkinfo_size}")
            if offset + linkinfo_size - 4 > len(data):
                raise ValueError("Truncated LinkInfo")
            offset += linkinfo_size - 4

        # StringData (present if HasName flag set)
        if has_flag(0x00000004):
            is_unicode = bool(dwFlags & 0x00000080)
            # Order: Name, RelativePath, WorkingDir, CommandLineArguments, IconLocation
            fields = [
                ("name_string", name_string),
                ("relative_path", relative_path),
                ("working_dir", working_dir),
                ("command_line_arguments", command_line_arguments),
                ("icon_location", icon_location)
            ]
            for i, (attr, _) in enumerate(fields):
                if offset + 2 > len(data):
                    raise ValueError("Truncated string length")
                strlen, = struct.unpack_from("<H", data, offset)
                offset += 2
                if strlen == 0:
                    value = None
                else:
                    bytelen = strlen * (2 if is_unicode else 1)
                    if offset + bytelen > len(data):
                        raise ValueError(f"Truncated string data for {attr}")
                    raw = data[offset:offset + bytelen]
                    offset += bytelen
                    try:
                        if is_unicode:
                            value = raw.decode("utf-16-le")
                        else:
                            value = raw.decode("utf-8")
                    except UnicodeDecodeError as e:
                        raise ValueError(f"Failed to decode string {attr}: {e}")
                # assign back
                if attr == "name_string":
                    name_string = value
                elif attr == "relative_path":
                    relative_path = value
                elif attr == "working_dir":
                    working_dir = value
                elif attr == "command_line_arguments":
                    command_line_arguments = value
                elif attr == "icon_location":
                    icon_location = value
    except Exception as e:
        sys.stderr.write(f"Parsing error: {e}\n")
        sys.exit(1)

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": dwFileSize,
        "icon_index": dwIconIndex,
        "creation_time": creation_iso,
        "access_time": access_iso,
        "write_time": write_iso
    }

    print(json.dumps(result))

if __name__ == "__main__":
    main()