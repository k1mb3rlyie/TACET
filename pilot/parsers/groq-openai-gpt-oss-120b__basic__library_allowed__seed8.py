#!/usr/bin/env python3
import sys
import struct
import json
import datetime
from pathlib import Path

def read_exact(f, n):
    data = f.read(n)
    if len(data) != n:
        raise ValueError(f"Unexpected end of file while reading {n} bytes")
    return data

def filetime_to_iso(ft):
    if ft == 0:
        return None
    # FILETIME is number of 100‑nanosecond intervals since 1601‑01‑01 UTC
    micros = ft // 10
    epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    dt = epoch_start + datetime.timedelta(microseconds=micros)
    return dt.isoformat()

def parse_lnk(path):
    with open(path, "rb") as f:
        # ----- Header -----
        header = read_exact(f, 76)
        (
            header_size,
            link_clsid,
            link_flags,
            file_attrs,
            creation_time,
            access_time,
            write_time,
            file_size,
            icon_index,
            show_cmd,
            hot_key,
            reserved1,
            reserved2,
            reserved3,
        ) = struct.unpack("<I16sI I Q Q Q I i I H H I I", header)

        if header_size != 0x4C:
            raise ValueError("Invalid header size")

        is_unicode = bool(link_flags & 0x00000080)

        # ----- Optional LinkTargetIDList -----
        if link_flags & 0x00000001:
            idlist_size = struct.unpack("<H", read_exact(f, 2))[0]
            _ = read_exact(f, idlist_size)  # skip

        # ----- Optional LinkInfo -----
        if link_flags & 0x00000002:
            linkinfo_size = struct.unpack("<I", read_exact(f, 4))[0]
            # already read 4 bytes of size, need to read the rest
            _ = read_exact(f, linkinfo_size - 4)

        # ----- StringData -----
        def read_string():
            if is_unicode:
                char_count = struct.unpack("<H", read_exact(f, 2))[0]
                raw = read_exact(f, char_count * 2)
                s = raw.decode("utf-16le", errors="replace")
                # strip terminating null if present
                if s and s[-1] == "\x00":
                    s = s[:-1]
                return s if s != "" else ""
            else:
                byte_count = struct.unpack("<H", read_exact(f, 2))[0]
                raw = read_exact(f, byte_count)
                s = raw.decode("mbcs", errors="replace")
                if s and s[-1] == "\x00":
                    s = s[:-1]
                return s if s != "" else ""

        name_string = None
        relative_path = None
        working_dir = None
        command_line_arguments = None
        icon_location = None

        if link_flags & 0x00000004:  # HasName
            name_string = read_string()
        if link_flags & 0x00000008:  # HasRelativePath
            relative_path = read_string()
        if link_flags & 0x00000010:  # HasWorkingDir
            working_dir = read_string()
        if link_flags & 0x00000020:  # HasArguments
            command_line_arguments = read_string()
        if link_flags & 0x00000040:  # HasIconLocation
            icon_location = read_string()

        # Convert timestamps
        creation_iso = filetime_to_iso(creation_time)
        access_iso = filetime_to_iso(access_time)
        write_iso = filetime_to_iso(write_time)

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
            "write_time": write_iso,
        }

        # Replace None for absent strings as required
        for key in ["name_string", "relative_path", "working_dir",
                    "command_line_arguments", "icon_location",
                    "creation_time", "access_time", "write_time"]:
            if result[key] is None:
                result[key] = None

        return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    lnk_path = Path(sys.argv[1])
    if not lnk_path.is_file():
        sys.stderr.write(f"File not found: {lnk_path}\n")
        sys.exit(1)

    try:
        data = parse_lnk(lnk_path)
        json.dump(data, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as e:
        err_obj = {"error": str(e)}
        json.dump(err_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)

if __name__ == "__main__":
    main()