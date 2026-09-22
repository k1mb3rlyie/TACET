#!/usr/bin/env python3
import sys
import struct
import json
import datetime
import os

def read_exact(f, n):
    data = f.read(n)
    if len(data) != n:
        raise ValueError("Unexpected end of file")
    return data

def parse_filetime(ft):
    # ft: 100-ns intervals since 1601-01-01 UTC
    try:
        # Convert to microseconds since 1601-01-01
        us = ft // 10
        # Seconds between 1601-01-01 and 1970-01-01
        epoch_diff = 11644473600
        seconds_since_epoch = us // 1_000_000 - epoch_diff
        microseconds = us % 1_000_000
        dt = datetime.datetime.fromtimestamp(seconds_since_epoch, tz=datetime.timezone.utc) + \
             datetime.timedelta(microseconds=microseconds)
        return dt.isoformat(timespec='seconds')
    except (OverflowError, OSError, ValueError):
        raise ValueError("Invalid FILETIME value")

def parse_lnk(path):
    with open(path, 'rb') as f:
        # ---- Header ----
        header = read_exact(f, 0x4C)
        if len(header) < 0x4C:
            raise ValueError("File too short for header")
        (header_size,
         link_clsid,
         link_flags,
         file_attributes,
         creation_time,
         access_time,
         write_time,
         file_size,
         icon_index,
         show_command,
         hot_key,
         reserved1,
         reserved2,
         reserved3) = struct.unpack('<I16sIIQQQQIIIIHHHH',
                                    header)
        if header_size != 0x4C:
            raise ValueError(f"Invalid HeaderSize: 0x{header_size:X}")
        expected_clsid = bytes.fromhex('0114020000000000C000000000000046')
        if link_clsid != expected_clsid:
            raise ValueError("Invalid LinkCLSID")
        # ---- Optional IDList ----
        if link_flags & 0x00000001:  # HasLinkTargetIDList
            while True:
                size_data = read_exact(f, 2)
                (size,) = struct.unpack('<H', size_data)
                if size == 0:
                    break
                if size < 2:
                    raise ValueError("Invalid IDList size")
                skip = size - 2
                if skip:
                    read_exact(f, skip)
        # ---- Optional LinkInfo ----
        if link_flags & 0x00000002:  # HasLinkInfo
            li_size_data = read_exact(f, 4)
            (li_size,) = struct.unpack('<I', li_size_data)
            if li_size < 4:
                raise ValueError("Invalid LinkInfo size")
            if li_size > 4:
                read_exact(f, li_size - 4)
        # ---- String sections ----
        is_unicode = bool(link_flags & 0x00000080)
        order = [
            (link_flags & 0x00000004, 'name_string'),          # HasName
            (link_flags & 0x00000008, 'relative_path'),       # HasRelativePath
            (link_flags & 0x00000010, 'working_dir'),         # HasWorkingDir
            (link_flags & 0x00000020, 'command_line_arguments'), # HasArguments
            (link_flags & 0x00000040, 'icon_location'),       # HasIconLocation
        ]
        results = {
            "name_string": None,
            "relative_path": None,
            "working_dir": None,
            "command_line_arguments": None,
            "icon_location": None,
            "file_size": file_size,
            "icon_index": icon_index,
            "creation_time": None,
            "access_time": None,
            "write_time": None,
        }
        for flag, key in order:
            if flag:
                cc_data = read_exact(f, 2)
                (cc,) = struct.unpack('<H', cc_data)
                if is_unicode:
                    byte_len = cc * 2
                    encoding = 'utf-16-le'
                else:
                    byte_len = cc
                    encoding = 'utf-8'  # best effort; will raise if invalid
                if byte_len:
                    str_bytes = read_exact(f, byte_len)
                else:
                    str_bytes = b''
                try:
                    results[key] = str_bytes.decode(encoding)
                except UnicodeDecodeError:
                    raise ValueError(f"Failed to decode string section {key}")
        # ---- Times ----
        results["creation_time"] = parse_filetime(creation_time)
        results["access_time"] = parse_filetime(access_time)
        results["write_time"] = parse_filetime(write_time)
        # Remove keys that should be null if not present (already None)
        return results

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    path = sys.argv[1]
    try:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        data = parse_lnk(path)
        print(json.dumps(data, separators=(',', ':')))
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        err_obj = {"error": str(e)}
        print(json.dumps(err_obj, separators=(',', ':')))
        sys.exit(0)

if __name__ == "__main__":
    main()