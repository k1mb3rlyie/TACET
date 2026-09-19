import sys
import struct
import datetime
import json

def _read_string(data: bytes, offset: int, is_unicode: bool):
    """Read a null-terminated string from data starting at offset.
    Returns (string, new_offset). Raises ValueError if terminator not found."""
    if is_unicode:
        i = offset
        n = len(data)
        while i + 1 < n:
            if data[i] == 0 and data[i + 1] == 0:
                break
            i += 2
        else:
            raise ValueError("Missing Unicode string terminator")
        raw = data[offset:i]
        try:
            s = raw.decode('utf-16le')
        except UnicodeDecodeError:
            s = raw.decode('utf-16le', errors='replace')
        return s, i + 2
    else:
        i = offset
        n = len(data)
        while i < n:
            if data[i] == 0:
                break
            i += 1
        else:
            raise ValueError("Missing ANSI string terminator")
        raw = data[offset:i]
        try:
            s = raw.decode('mbcs')
        except (LookupError, UnicodeDecodeError):
            s = raw.decode('latin-1', errors='replace')
        return s, i + 1

def _filetime_to_iso(ft: int) -> str:
    """Convert FILETIME UTC 100-ns since 1601-01-01 to ISO 8601 with UTC offset."""
    if ft < 0:
        raise ValueError("Invalid FILETIME")
    # Windows epoch to Unix epoch offset in 100-ns units
    UNIX_EPOCH_FILETIME = 116444736000000000
    try:
        seconds = (ft - UNIX_EPOCH_FILETIME) / 10000000.0
    except OverflowError:
        raise ValueError("FILETIME out of range")
    dt = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    return dt.isoformat()

def parse_lnk(data: bytes):
    if len(data) < 0x50:
        raise ValueError("File too small for LNK header")
    # Header: 0x50 bytes
    fmt = '<16sIIIQQQQIIHHIII'
    try:
        (_, link_flags, _,
         creation_time, access_time, write_time,
         file_size,
         icon_index, _show_command,
         _hotkey, _reserved,
         _reserved1, _reserved2, _reserved3) = struct.unpack(fmt, data[:0x50])
    except struct.error as e:
        raise ValueError(f"Failed to parse header: {e}")

    # Determine which optional string fields are present
    has_name = bool(link_flags & 0x00000004)
    has_rel_path = bool(link_flags & 0x00000008)
    has_work_dir = bool(link_flags & 0x00000010)
    has_args = bool(link_flags & 0x00000020)
    has_icon_loc = bool(link_flags & 0x00000040)
    is_unicode = bool(link_flags & 0x00000080)
    has_link_info = bool(link_flags & 0x00000002)

    offset = 0x50  # after header

    # LinkTargetIDList
    if offset + 2 > len(data):
        raise ValueError("Truncated IDList size field")
    idlist_size = struct.unpack('<H', data[offset:offset+2])[0]
    offset += 2
    if idlist_size < 0 or offset + idlist_size > len(data):
        raise ValueError("Invalid IDList size")
    offset += idlist_size  # skip IDList

    # LinkInfo (if present)
    if has_link_info:
        if offset + 4 > len(data):
            raise ValueError("Truncated LinkInfo size field")
        li_size = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        if li_size < 4 or offset + li_size > len(data):
            raise ValueError("Invalid LinkInfo size")
        offset += li_size  # skip LinkInfo

    # String data block starts here
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    # Helper to read a string if flag set
    def maybe_read(flag, target_name):
        nonlocal offset
        if flag:
            if offset >= len(data):
                raise ValueError("String data missing")
            s, offset = _read_string(data, offset, is_unicode)
            return s
        else:
            return None

    name_string = maybe_read(has_name, "name_string")
    relative_path = maybe_read(has_rel_path, "relative_path")
    working_dir = maybe_read(has_work_dir, "working_dir")
    command_line_arguments = maybe_read(has_args, "command_line_arguments")
    icon_location = maybe_read(has_icon_loc, "icon_location")

    # Build result
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": _filetime_to_iso(creation_time),
        "access_time": _filetime_to_iso(access_time),
        "write_time": _filetime_to_iso(write_time),
    }
    return result

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python parser.py <path-to-lnk-file>"}), file=sys.stdout)
        sys.exit(2)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
        result = parse_lnk(data)
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)
    except Exception as e:
        err = str(e)
        # Keep error message short-ish
        if len(err) > 200:
            err = err[:200] + "..."
        print(json.dumps({"error": err}), file=sys.stdout)
        sys.exit(1)

if __name__ == "__main__":
    main()