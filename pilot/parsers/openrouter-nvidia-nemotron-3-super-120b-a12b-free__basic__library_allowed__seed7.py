#!/usr/bin/env python3
import sys
import os
import json
from datetime import datetime, timezone, timedelta

class LnkParseError(Exception):
    pass

class LnkParser:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.length = len(data)

    def _ensure(self, n: int):
        if self.pos + n > self.length:
            raise LnkParseError("File too short")

    def read_bytes(self, n: int) -> bytes:
        self._ensure(n)
        b = self.data[self.pos:self.pos+n]
        self.pos += n
        return b

    def read_uint16(self) -> int:
        return int.from_bytes(self.read_bytes(2), 'little')

    def read_uint32(self) -> int:
        return int.from_bytes(self.read_bytes(4), 'little')

    def read_int32(self) -> int:
        return int.from_bytes(self.read_bytes(4), 'little', signed=True)

    def read_uint64(self) -> int:
        return int.from_bytes(self.read_bytes(8), 'little')

def filetime_to_iso(ft: int) -> str:
    # ft: 100-nanosecond intervals since 1601-01-01 UTC
    seconds = ft // 10_000_000
    remainder = ft % 10_000_000
    microseconds = remainder // 10
    dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds, microseconds=microseconds)
    return dt.isoformat()

def parse_lnk(path: str) -> dict:
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) < 0x4c:
        raise LnkParseError("File too small to be a valid LNK")
    parser = LnkParser(data)

    # Skip LinkCLSID (16 bytes)
    parser.read_bytes(16)

    link_flags = parser.read_uint32()
    _ = parser.read_uint32()  # FileAttributes (ignore)
    creation_time_ft = parser.read_uint64()
    access_time_ft = parser.read_uint64()
    write_time_ft = parser.read_uint64()
    _ = parser.read_uint32()  # FileSize of target (ignore)
    icon_index = parser.read_int32()
    _ = parser.read_uint32()  # ShowCommand
    _ = parser.read_uint16()  # HotKey
    parser.read_bytes(2)      # Reserved
    parser.read_bytes(4)      # Reserved1
    parser.read_bytes(4)      # Reserved2

    # Determine presence flags
    has_link_target_idlist = bool(link_flags & 0x00000001)
    has_link_info = bool(link_flags & 0x00000002)
    has_name = bool(link_flags & 0x00000004)
    has_relative_path = bool(link_flags & 0x00000008)
    has_working_dir = bool(link_flags & 0x00000010)
    has_arguments = bool(link_flags & 0x00000020)
    has_icon_location = bool(link_flags & 0x00000040)
    is_unicode = bool(link_flags & 0x00000400)  # UTF-16LE strings

    # Skip LinkTargetIDList
    if has_link_target_idlist:
        idlist_size = parser.read_uint16()
        parser.read_bytes(idlist_size)

    # Skip LinkInfo
    if has_link_info:
        link_info_size = parser.read_uint32()
        parser.read_bytes(link_info_size)

    def read_string_if_present(flag: bool) -> str | None:
        if not flag:
            return None
        strlen = parser.read_uint16()
        if strlen == 0:
            return ""  # empty string present
        str_bytes = parser.read_bytes(strlen)
        # Strip terminating null if present
        if str_bytes.endswith(b'\x00'):
            str_bytes = str_bytes[:-1]
        try:
            if is_unicode:
                return str_bytes.decode('utf-16le')
            else:
                return str_bytes.decode('mbcs')
        except UnicodeDecodeError as e:
            raise LnkParseError(f"Failed to decode string: {e}")

    try:
        name_string = read_string_if_present(has_name)
        relative_path = read_string_if_present(has_relative_path)
        working_dir = read_string_if_present(has_working_dir)
        command_line_arguments = read_string_if_present(has_arguments)
        icon_location = read_string_if_present(has_icon_location)
    except LnkParseError:
        raise
    except Exception as e:
        raise LnkParseError(f"Unexpected error reading strings: {e}")

    # Convert timestamps
    creation_time_iso = filetime_to_iso(creation_time_ft)
    access_time_iso = filetime_to_iso(access_time_ft)
    write_time_iso = filetime_to_iso(write_time_ft)

    # File size of the LNK file itself
    try:
        lnk_file_size = os.path.getsize(path)
    except OSError as e:
        raise LnkParseError(f"Cannot get file size: {e}")

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": lnk_file_size,
        "icon_index": icon_index,
        "creation_time": creation_time_iso,
        "access_time": access_time_iso,
        "write_time": write_time_iso,
    }
    return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    path = sys.argv[1]
    try:
        result = parse_lnk(path)
        sys.stdout.write(json.dumps(result, ensure_ascii=False))
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(0)
    except Exception as e:
        err_obj = {"error": str(e)}
        sys.stdout.write(json.dumps(err_obj, ensure_ascii=False))
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()