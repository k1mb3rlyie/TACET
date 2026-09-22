#!/usr/bin/env python3
import sys
import json
import datetime
import os

def filetime_to_iso(filetime):
    """Convert Windows FILETIME (int) to ISO‑8601 string with UTC offset."""
    if filetime is None:
        return None
    try:
        # FILETIME is number of 100‑nanosecond intervals since 1601‑01‑01 UTC
        microseconds = int(filetime) // 10
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(
            microseconds=microseconds
        )
        return dt.isoformat()
    except Exception:
        return None


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    lnk_path = sys.argv[1]

    if not os.path.isfile(lnk_path):
        sys.stderr.write(f"File not found: {lnk_path}\n")
        sys.exit(1)

    try:
        # Try to import a known .lnk parsing library.
        # pylnk (pip install pylnk) provides LNKFile.
        from pylnk import LNKFile
        with open(lnk_path, "rb") as f:
            lnk = LNKFile(f)
    except Exception as e:
        # If the import or parsing fails, report an error.
        error_obj = {"error": f"Failed to parse .lnk file: {str(e)}"}
        print(json.dumps(error_obj, ensure_ascii=False))
        sys.exit(1)

    try:
        # Helper to safely fetch string attributes; they may be bytes.
        def get_str(attr):
            val = getattr(attr, None)
            if val is None:
                return None
            if isinstance(val, bytes):
                try:
                    return val.decode("utf-8", errors="replace")
                except Exception:
                    return None
            return str(val)

        # StringData may be absent; guard with getattr.
        string_data = getattr(lnk, "string_data", None)

        name_string = get_str(getattr(string_data, "name_string", None))
        relative_path = get_str(getattr(string_data, "relative_path", None))
        working_dir = get_str(getattr(string_data, "working_dir", None))
        command_line_arguments = get_str(getattr(string_data, "command_line_arguments", None))
        icon_location = get_str(getattr(string_data, "icon_location", None))

        # Header fields
        header = getattr(lnk, "header", None)

        file_size = getattr(header, "file_size", None)
        if file_size is not None:
            try:
                file_size = int(file_size)
            except Exception:
                file_size = None

        icon_index = getattr(header, "icon_index", None)
        if icon_index is not None:
            try:
                icon_index = int(icon_index)
            except Exception:
                icon_index = None

        creation_time = filetime_to_iso(getattr(header, "creation_time", None))
        access_time = filetime_to_iso(getattr(header, "access_time", None))
        write_time = filetime_to_iso(getattr(header, "write_time", None))

        result = {
            "name_string": name_string,
            "relative_path": relative_path,
            "working_dir": working_dir,
            "command_line_arguments": command_line_arguments,
            "icon_location": icon_location,
            "file_size": file_size if file_size is not None else 0,
            "icon_index": icon_index if icon_index is not None else 0,
            "creation_time": creation_time,
            "access_time": access_time,
            "write_time": write_time,
        }

        # Convert Python None to JSON null explicitly where appropriate.
        # file_size and icon_index must be numbers; if they were truly absent we keep 0 as per spec.
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)

    except Exception as exc:
        error_obj = {"error": f"Parsing error: {str(exc)}"}
        print(json.dumps(error_obj, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main()