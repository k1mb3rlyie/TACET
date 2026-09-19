#!/usr/bin/env python3
import sys
import struct
import datetime
import json

def parse_idlist(data, off):
    """Parse a Shell ID list, returning new offset."""
    while True:
        if off + 2 > len(data):
            raise ValueError("Truncated IDList")
        cb = data[off] | (data[off + 1] << 8)
        off += 2
        if cb == 0:
            break
        if cb < 2:
            raise ValueError("Invalid IDList item size")
        if off + cb - 2 > len(data):
            raise ValueError("Truncated IDList item")
        off += cb - 2
    return off

def parse_linkinfo(data, off):
    """Skip a LinkInfo structure, returning new offset."""
    if off + 4 > len(data):
        raise ValueError("Truncated LinkInfo size")
    link_info_size = struct.unpack_from("<I", data, off)[0]
    off += 4
    if off + link_info_size > len(data):
        raise ValueError("LinkInfo size exceeds file")
    off += link_info_size
    return off

def filetime_to_iso(ft):
    """Convert FILETIME to ISO 8601 string with UTC offset."""
    try:
        # seconds since 1601-01-01
        sec_since_1601 = ft // 10_000_000
        # subseconds in 100-ns units -> microseconds
        subsec = ft % 10_000_000
        microsec = subsec // 10
        # seconds between 1601-01-01 and 1970-01-01
        EPOCH_DIFF = 11644473600
        sec_since_1970 = sec_since_1601 - EPOCH_DIFF
        dt = datetime.datetime.fromtimestamp(sec_since_1970,
                                             tz=datetime.timezone.utc) \
               + datetime.timedelta(microseconds=microsec)
        return dt.isoformat()
    except Exception as e:
        raise ValueError(f"Invalid FILETIME value: {e}")

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
        print(json.dumps({"error": "Cannot read file"}))
        sys.exit(1)

    try:
        if len(data) < 0x4C:
            raise ValueError("File too small for a .lnk header")

        off = 0

        # HeaderSize
        header_size = struct.unpack_from("<I", data, off)[0]
        off += 4
        if header_size != 0x4C:
            raise ValueError(f"Invalid HeaderSize: 0x{header_size:08X}")

        # LinkCLSID
        expected_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
        clsid = data[off:off+16]
        off += 16
        if clsid != expected_clsid:
            raise ValueError("Invalid LinkCLSID")

        # LinkFlags
        link_flags = struct.unpack_from("<I", data, off)[0]
        off += 4

        # FileAttributes (ignored)
        off += 4

        # Timestamps
        creation_time = struct.unpack_from("<Q", data, off)[0]; off += 8
        access_time   = struct.unpack_from("<Q", data, off)[0]; off += 8
        write_time    = struct.unpack_from("<Q", data, off)[0]; off += 8

        # FileSize (unsigned)
        file_size = struct.unpack_from("<I", data, off)[0]; off += 4

        # IconIndex (signed)
        icon_index = struct.unpack_from("<i", data, off)[0]; off += 4

        # ShowCommand (ignored)
        off += 4

        # HotKey
        off += 2  # read but ignore
        # Reserved1
        off += 2
        # Reserved2
        off += 4
        # Reserved3
        off += 4

        # Optional IDList
        if link_flags & 0x00000001:
            off = parse_idlist(data, off)

        # Optional LinkInfo
        if link_flags & 0x00000002:
            off = parse_linkinfo(data, off)

        # String sections (in fixed order)
        string_specs = [
            (0x00000004, "name_string"),
            (0x00000008, "relative_path"),
            (0x00000010, "working_dir"),
            (0x00000020, "command_line_arguments"),
            (0x00000040, "icon_location"),
        ]
        results = {name: None for _, name in string_specs}
        is_unicode = bool(link_flags & 0x00000080)

        for flag, name in string_specs:
            if link_flags & flag:
                if off + 2 > len(data):
                    raise ValueError(f"Truncated length for {name}")
                count_chars = struct.unpack_from("<H", data, off)[0]
                off += 2
                if is_unicode:
                    byte_len = count_chars * 2
                    if off + byte_len > len(data):
                        raise ValueError(f"Truncated Unicode string for {name}")
                    raw = data[off:off+byte_len]
                    off += byte_len
                    try:
                        s = raw.decode("utf-16-le")
                    except UnicodeDecodeError as e:
                        raise ValueError(f"Invalid UTF-16LE string for {name}") from e
                else:
                    # ANSI: preserve bytes via latin-1
                    if off + count_chars > len(data):
                        raise ValueError(f"Truncated ANSI string for {name}")
                    raw = data[off:off+count_chars]
                    off += count_chars
                    s = raw.decode("latin-1")
                results[name] = s
            else:
                results[name] = None

        # Convert timestamps
        creation_iso = filetime_to_iso(creation_time)
        access_iso   = filetime_to_iso(access_time)
        write_iso    = filetime_to_iso(write_time)

        output = {
            "name_string": results["name_string"],
            "relative_path": results["relative_path"],
            "working_dir": results["working_dir"],
            "command_line_arguments": results["command_line_arguments"],
            "icon_location": results["icon_location"],
            "file_size": file_size,
            "icon_index": icon_index,
            "creation_time": creation_iso,
            "access_time": access_iso,
            "write_time": write_iso,
        }

        print(json.dumps(output, separators=(',', ':')))
        sys.exit(0)

    except Exception as e:
        sys.stderr.write(f"Error parsing .lnk file: {e}\n")
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()