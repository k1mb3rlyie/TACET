#!/usr/bin/env python3
import sys
import json
import datetime

def _format_time(dt):
    """Convert datetime to ISO 8601 string with UTC offset.
    If dt is None, return None.
    Naive datetimes are treated as UTC.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    else:
        dt = dt.astimezone(datetime.timezone.utc)
    return dt.isoformat(timespec='seconds')

def main():
    if len(sys.argv) != 2:
        err = {"error": "Usage: python parser.py <path-to-lnk-file>"}
        print(json.dumps(err))
        sys.exit(1)

    path = sys.argv[1]

    try:
        import pylnk3
    except Exception as e:
        err = {"error": f"Failed to import required library: {e}"}
        print(json.dumps(err))
        sys.exit(1)

    try:
        lnk = pylnk3.LnkFile()
        lnk.parse(path)
    except Exception as e:
        err = {"error": f"Failed to parse .lnk file: {e}"}
        print(json.dumps(err))
        sys.exit(1)

    # Helper to get attribute, returning None if missing
    def get_attr(obj, name):
        return getattr(obj, name, None)

    # String fields: absent -> null, empty string -> ""
    name_string = get_attr(lnk, 'description')
    relative_path = get_attr(lnk, 'relative_path')
    working_dir = get_attr(lnk, 'working_dir')
    command_line_arguments = get_attr(lnk, 'arguments')
    icon_location = get_attr(lnk, 'icon_path')

    # Integer fields: absent -> null, zero is valid
    file_size_raw = get_attr(lnk, 'file_size')
    icon_index_raw = get_attr(lnk, 'icon_index')

    # Timestamp fields
    creation_time_raw = get_attr(lnk, 'create_time')
    access_time_raw = get_attr(lnk, 'access_time')
    write_time_raw = get_attr(lnk, 'modify_time')

    result = {
        "name_string": None if name_string is None else name_string,
        "relative_path": None if relative_path is None else relative_path,
        "working_dir": None if working_dir is None else working_dir,
        "command_line_arguments": None if command_line_arguments is None else command_line_arguments,
        "icon_location": None if icon_location is None else icon_location,
        "file_size": None if file_size_raw is None else file_size_raw,
        "icon_index": None if icon_index_raw is None else icon_index_raw,
        "creation_time": _format_time(creation_time_raw),
        "access_time": _format_time(access_time_raw),
        "write_time": _format_time(write_time_raw),
    }

    print(json.dumps(result, ensure_ascii=False))
    sys.exit(0)

if __name__ == "__main__":
    main()