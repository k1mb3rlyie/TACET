#!/usr/bin/env python3
import sys
import struct
import json
import datetime
import pathlib

HEADER_SIZE = 0x4C
EXPECTED_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'  # little‑endian GUID

LINK_FLAG_HAS_LINK_TARGET_IDLIST = 0x00000001
LINK_FLAG_HAS_LINK_INFO          = 0x00000002
LINK_FLAG_HAS_NAME               = 0x00000004
LINK_FLAG_HAS_RELATIVE_PATH      = 0x00000008
LINK_FLAG_HAS_WORKING_DIR        = 0x00000010
LINK_FLAG_HAS_ARGUMENTS          = 0x00000020
LINK_FLAG_HAS_ICON_LOCATION      = 0x00000040
LINK_FLAG_IS_UNICODE             = 0x00000080

def read_exact(f, n):
    data = f.read(n)
    if len(data) != n:
        raise ValueError(f'Unexpected end of file while reading {n} bytes')
    return data

def filetime_to_iso(ft):
    # FILETIME is unsigned 64‑bit count of 100‑ns intervals since 1601‑01‑01 UTC
    try:
        us = ft // 10  # convert to microseconds
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = base + datetime.timedelta(microseconds=us)
        return dt.isoformat()
    except Exception:
        raise ValueError('Invalid FILETIME value')

def parse_string(f, is_unicode):
    count_bytes = read_exact(f, 2)
    (char_count,) = struct.unpack('<H', count_bytes)
    byte_len = char_count * (2 if is_unicode else 1)
    raw = read_exact(f, byte_len)
    if is_unicode:
        try:
            return raw.decode('utf-16le')
        except Exception:
            raise ValueError('Failed to decode UTF‑16LE string')
    else:
        try:
            return raw.decode('cp1252')  # default Windows ANSI code page
        except Exception:
            raise ValueError('Failed to decode ANSI string')

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: parser.py <path-to-lnk-file>"}))
        sys.exit(0)

    path = pathlib.Path(sys.argv[1])
    try:
        with path.open('rb') as f:
            # ---------- Header ----------
            header = read_exact(f, HEADER_SIZE)
            (hdr_size,) = struct.unpack_from('<I', header, 0x00)
            if hdr_size != HEADER_SIZE:
                raise ValueError('HeaderSize mismatch')
            clsid = header[0x04:0x14]
            if clsid != EXPECTED_CLSID:
                raise ValueError('LinkCLSID mismatch')
            (link_flags,) = struct.unpack_from('<I', header, 0x14)
            (file_attrib,) = struct.unpack_from('<I', header, 0x18)
            (creation_ft,) = struct.unpack_from('<Q', header, 0x1C)
            (access_ft,)   = struct.unpack_from('<Q', header, 0x24)
            (write_ft,)    = struct.unpack_from('<Q', header, 0x2C)
            (file_size,)   = struct.unpack_from('<I', header, 0x34)
            (icon_index,)  = struct.unpack_from('<i', header, 0x38)  # signed
            # remaining fields are not needed for output

            is_unicode = bool(link_flags & LINK_FLAG_IS_UNICODE)

            # ---------- Optional IDList ----------
            if link_flags & LINK_FLAG_HAS_LINK_TARGET_IDLIST:
                size_bytes = read_exact(f, 2)
                (idlist_size,) = struct.unpack('<H', size_bytes)
                # idlist_size includes the size field itself
                remaining = idlist_size - 2
                if remaining < 0:
                    raise ValueError('Invalid IDList size')
                f.seek(remaining, 1)  # skip

            # ---------- Optional LinkInfo ----------
            if link_flags & LINK_FLAG_HAS_LINK_INFO:
                size_bytes = read_exact(f, 4)
                (linkinfo_size,) = struct.unpack('<I', size_bytes)
                if linkinfo_size < 4:
                    raise ValueError('Invalid LinkInfo size')
                f.seek(linkinfo_size - 4, 1)  # skip rest of LinkInfo

            # ---------- StringData ----------
            def get_section(flag):
                return (link_flags & flag) != 0

            name_string = None
            relative_path = None
            working_dir = None
            command_line_arguments = None
            icon_location = None

            if get_section(LINK_FLAG_HAS_NAME):
                name_string = parse_string(f, is_unicode)
            if get_section(LINK_FLAG_HAS_RELATIVE_PATH):
                relative_path = parse_string(f, is_unicode)
            if get_section(LINK_FLAG_HAS_WORKING_DIR):
                working_dir = parse_string(f, is_unicode)
            if get_section(LINK_FLAG_HAS_ARGUMENTS):
                command_line_arguments = parse_string(f, is_unicode)
            if get_section(LINK_FLAG_HAS_ICON_LOCATION):
                icon_location = parse_string(f, is_unicode)

            # ---------- Build output ----------
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
    except Exception as e:
        # any parsing problem -> error output
        print(json.dumps({"error": str(e)}))
        sys.exit(0)

if __name__ == "__main__":
    main()