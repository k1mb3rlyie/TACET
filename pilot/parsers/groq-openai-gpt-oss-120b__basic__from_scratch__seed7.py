#!/usr/bin/env python3
import sys
import struct
import json
import datetime

def filetime_to_iso(ft):
    if ft == 0:
        return None
    # FILETIME is 100‑nanosecond intervals since 1601‑01‑01 UTC
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    try:
        dt = epoch + datetime.timedelta(microseconds=ft // 10)
        return dt.isoformat()
    except Exception:
        return None

def read_string(data, offset, is_unicode):
    if offset + 2 > len(data):
        raise ValueError("Truncated string length")
    length = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if is_unicode:
        byte_len = length * 2
        if offset + byte_len > len(data):
            raise ValueError("Truncated Unicode string")
        raw = data[offset:offset + byte_len]
        try:
            s = raw.decode('utf-16le')
        except Exception:
            s = raw.decode('utf-16le', errors='replace')
        offset += byte_len
    else:
        byte_len = length
        if offset + byte_len > len(data):
            raise ValueError("Truncated ANSI string")
        raw = data[offset:offset + byte_len]
        try:
            s = raw.decode('utf-8')
        except Exception:
            s = raw.decode('utf-8', errors='replace')
        offset += byte_len
    return s, offset

def error(msg):
    err_obj = {"error": msg}
    print(json.dumps(err_obj, ensure_ascii=False))
    sys.exit(1)

def main():
    if len(sys.argv) != 2:
        error("Usage: parser.py <path-to-lnk-file>")
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        error(f"Cannot read file: {e}")

    try:
        if len(data) < 76:
            raise ValueError("File too short for header")
        header_size = struct.unpack_from('<I', data, 0)[0]
        if header_size != 0x4C:
            raise ValueError("Invalid header size")
        link_clsid = data[4:20]
        expected_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
        if link_clsid != expected_clsid:
            raise ValueError("Invalid LinkCLSID")
        link_flags = struct.unpack_from('<I', data, 20)[0]

        # timestamps
        creation_ft = struct.unpack_from('<Q', data, 28)[0]
        access_ft   = struct.unpack_from('<Q', data, 36)[0]
        write_ft    = struct.unpack_from('<Q', data, 44)[0]

        file_size  = struct.unpack_from('<I', data, 52)[0]
        icon_index = struct.unpack_from('<I', data, 56)[0]

        offset = 76

        # Optional LinkTargetIDList
        if link_flags & 0x00000001:
            if offset + 2 > len(data):
                raise ValueError("Truncated IDList size")
            idlist_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if offset + idlist_size > len(data):
                raise ValueError("Truncated IDList")
            offset += idlist_size

        # Optional LinkInfo
        if link_flags & 0x00000002:
            if offset + 4 > len(data):
                raise ValueError("Truncated LinkInfo size")
            linkinfo_size = struct.unpack_from('<I', data, offset)[0]
            if linkinfo_size < 4:
                raise ValueError("Invalid LinkInfo size")
            if offset + linkinfo_size > len(data):
                raise ValueError("Truncated LinkInfo")
            offset += linkinfo_size

        is_unicode = bool(link_flags & 0x00000080)

        # StringData fields (order matters)
        def maybe_read(flag):
            nonlocal offset
            if link_flags & flag:
                s, offset = read_string(data, offset, is_unicode)
                return s
            return None

        name_string = maybe_read(0x00000004)
        relative_path = maybe_read(0x00000008)
        working_dir = maybe_read(0x00000010)
        command_line_arguments = maybe_read(0x00000020)
        icon_location = maybe_read(0x00000040)

        result = {
            "name_string": name_string,
            "relative_path": relative_path,
            "working_dir": working_dir,
            "command_line_arguments": command_line_arguments,
            "icon_location": icon_location,
            "file_size": file_size,
            "icon_index": icon_index,
            "creation_time": filetime_to_iso(creation_ft),
            "access_time": filetime_to_iso(access_ft),
            "write_time": filetime_to_iso(write_ft)
        }

        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)

    except Exception as exc:
        error(str(exc))

if __name__ == "__main__":
    main()