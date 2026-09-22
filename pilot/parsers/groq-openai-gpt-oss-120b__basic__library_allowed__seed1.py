#!/usr/bin/env python3
import sys
import json
import datetime
import struct
import os

# ---------- helpers ----------
def filetime_to_iso(ft):
    """
    Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01 UTC)
    to an ISO‑8601 string with explicit UTC offset.
    """
    if ft is None or ft == 0:
        return None
    # FILETIME is unsigned 64‑bit
    try:
        ft = int(ft)
    except Exception:
        return None
    # Number of 100‑ns intervals between 1601‑01‑01 and 1970‑01‑01
    EPOCH_AS_FILETIME = 116444736000000000
    HUNDREDS_OF_NS = 10_000_000
    seconds, remainder = divmod(ft - EPOCH_AS_FILETIME, HUNDREDS_OF_NS)
    dt = datetime.datetime.utcfromtimestamp(seconds).replace(microsecond=(remainder // 10))
    return dt.replace(tzinfo=datetime.timezone.utc).isoformat()

def safe_str(value):
    """Return the string if it is non‑empty, otherwise None."""
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8', errors='replace')
        except Exception:
            return None
    if isinstance(value, str):
        return value if value != "" else None
    return None

def safe_int(value):
    """Return the int if it is non‑zero, otherwise None (zero can be a legitimate value)."""
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None

# ---------- main ----------
def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    lnk_path = sys.argv[1]

    try:
        # Try to import the third‑party parser
        try:
            from pylnk3.lnk_file import LnkFile
        except ImportError:
            sys.stderr.write("Required library 'pylnk3' is not installed.\n")
            sys.exit(1)

        if not os.path.isfile(lnk_path):
            raise FileNotFoundError(f"File not found: {lnk_path}")

        lnk = LnkFile(lnk_path)

        # Header fields
        hdr = getattr(lnk, "header", None)

        file_size = safe_int(getattr(hdr, "file_size", None))
        icon_index = safe_int(getattr(hdr, "icon_index", None))

        creation_time = filetime_to_iso(getattr(hdr, "creation_time", None))
        access_time   = filetime_to_iso(getattr(hdr, "access_time",   None))
        write_time    = filetime_to_iso(getattr(hdr, "write_time",    None))

        # StringData fields (may be absent)
        sd = getattr(lnk, "string_data", None)

        name_string = safe_str(getattr(sd, "name_string", None))
        relative_path = safe_str(getattr(sd, "relative_path", None))
        working_dir = safe_str(getattr(sd, "working_dir", None))
        command_line_arguments = safe_str(getattr(sd, "command_line_arguments", None))
        icon_location = safe_str(getattr(sd, "icon_location", None))

        result = {
            "name_string": name_string,
            "relative_path": relative_path,
            "working_dir": working_dir,
            "command_line_arguments": command_line_arguments,
            "icon_location": icon_location,
            "file_size": file_size,
            "icon_index": icon_index,
            "creation_time": creation_time,
            "access_time": access_time,
            "write_time": write_time
        }

        # Replace Python None with JSON null automatically via json.dump
        json.dump(result, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)

    except Exception as e:
        # Any parsing problem is reported as an error object
        error_obj = {"error": str(e)}
        json.dump(error_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)

if __name__ == "__main__":
    main()