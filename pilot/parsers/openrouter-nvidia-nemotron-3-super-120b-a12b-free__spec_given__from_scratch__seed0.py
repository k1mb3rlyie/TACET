#!/usr/bin/env python3
import struct
import sys
import json
from datetime import datetime, timezone

def print_json_error(msg: str):
    sys.stderr.write(f"Error: {msg}\n")
    print(json.dumps({"error": msg}))
    sys.exit(0)

class LnkParser:
    def __init__(self, data: bytes):
        self.buf = data
        self.pos = 0
        self.name_string = None
        self.relative_path = None
        self.working_dir = None
        self.command_line_arguments = None
        self.icon_location = None
        self.file_size = 0
        self.icon_index = 0
        self.creation_time = None
        self.access_time = None
        self.write_time = None
        self.link_flags = 0
        self.is_unicode = False

    # ----- basic reads -------------------------------------------------
    def _ensure(self, n: int):
        if self.pos + n > len(self.buf):
            raise ValueError("Insufficient data")

    def read_uint16(self) -> int:
        self._ensure(2)
        v = int.from_bytes(self.buf[self.pos:self.pos+2], 'little')
        self.pos += 2
        return v

    def read_uint32(self) -> int:
        self._ensure(4)
        v = int.from_bytes(self.buf[self.pos:self.pos+4], 'little')
        self.pos += 4
        return v

    def read_int32(self) -> int:
        self._ensure(4)
        v = int.from_bytes(self.buf[self.pos:self.pos+4], 'little', signed=True)
        self.pos += 4
        return v

    def read_uint64(self) -> int:
        self._ensure(8)
        v = int.from_bytes(self.buf[self.pos:self.pos+8], 'little')
        self.pos += 8
        return v

    def read_bytes(self, n: int) -> bytes:
        self._ensure(n)
        b = self.buf[self.pos:self.pos+n]
        self.pos += n
        return b

    def skip(self, n: int):
        self._ensure(n)
        self.pos += n

    # ----- parsing -----------------------------------------------------
    def parse(self):
        # Header (76 bytes)
        header_size = self.read_uint32()
        if header_size != 0x4C:
            raise ValueError(f"Invalid HeaderSize: {header_size:#x}")

        link_clsid = self.read_bytes(16)
        expected_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'
        if link_clsid != expected_clsid:
            raise ValueError("Invalid LinkCLSID")

        self.link_flags = self.read_uint32()
        self.file_attributes = self.read_uint32()
        creation_ft = self.read_uint64()
        access_ft = self.read_uint64()
        write_ft = self.read_uint64()
        self.file_size = self.read_uint32()
        self.icon_index = self.read_int32()
        self._read_uint32()  # ShowCommand (unused)
        self._read_uint16()  # HotKey (unused)
        reserved1 = self.read_uint16()
        reserved2 = self.read_uint32()
        reserved3 = self.read_uint32()
        if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
            raise ValueError("Reserved fields non-zero")

        self.is_unicode = bool(self.link_flags & 0x00000080)

        # Optional IDList
        if self.link_flags & 0x00000001:
            self._skip_idlist()
        # Optional LinkInfo
        if self.link_flags & 0x00000002:
            self._skip_linkinfo()

        # String sections in fixed order
        self._parse_string_if_set(0x00000004, 'name_string')
        self._parse_string_if_set(0x00000008, 'relative_path')
        self._parse_string_if_set(0x00000010, 'working_dir')
        self._parse_string_if_set(0x00000020, 'command_line_arguments')
        self._parse_string_if_set(0x00000040, 'icon_location')

        # Timestamps
        self.creation_time = self._filetime_to_iso(creation_ft)
        self.access_time = self._filetime_to_iso(access_ft)
        self.write_time = self._filetime_to_iso(write_ft)

    def _skip_idlist(self):
        while True:
            if self.pos + 2 > len(self.buf):
                raise ValueError("Incomplete IDList")
            size = int.from_bytes(self.buf[self.pos:self.pos+2], 'little')
            self.pos += 2
            if size == 0:
                break
            if size < 2:
                raise ValueError("Invalid IDList item size")
            if self.pos + (size - 2) > len(self.buf):
                raise ValueError("IDList item exceeds buffer")
            self.pos += (size - 2)

    def _skip_linkinfo(self):
        if self.pos + 4 > len(self.buf):
            raise ValueError("Incomplete LinkInfo size")
        link_info_size = int.from_bytes(self.buf[self.pos:self.pos+4], 'little')
        self.pos += 4
        if link_info_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if self.pos + (link_info_size - 4) > len(self.buf):
            raise ValueError("LinkInfo exceeds buffer")
        self.pos += (link_info_size - 4)

    def _parse_string_if_set(self, flag: int, attr: str):
        if self.link_flags & flag:
            count = self.read_uint16()
            char_size = 2 if self.is_unicode else 1
            byte_len = count * char_size
            if self.pos + byte_len > len(self.buf):
                raise ValueError(f"String data exceeds buffer for {attr}")
            raw = self.buf[self.pos:self.pos+byte_len]
            self.pos += byte_len
            if self.is_unicode:
                try:
                    s = raw.decode('utf-16-le')
                except UnicodeDecodeError as e:
                    raise ValueError(f"Failed to decode Unicode string for {attr}: {e}")
            else:
                # Latin-1 gives a 1:1 mapping of byte values to Unicode code points
                s = raw.decode('latin-1')
            setattr(self, attr, s)
        else:
            setattr(self, attr, None)

    def _filetime_to_iso(self, ft: int) -> str:
        try:
            # 100-ns intervals since 1601-01-01 UTC -> seconds
            seconds_since_1601 = ft / 10_000_000.0
            # seconds between 1601-01-01 and 1970-01-01
            unix_seconds = seconds_since_1601 - 11644473600.0
            dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
            return dt.isoformat()
        except (OverflowError, ValueError, OSError) as e:
            raise ValueError(f"Invalid FILETIME value: {e}")

def main():
    if len(sys.argv) != 2:
        print_json_error("Usage: python parser.py <path-to-lnk-file>")
    data = None
    try:
        with open(sys.argv[1], 'rb') as f:
            data = f.read()
    except OSError as e:
        print_json_error(f"Cannot open file: {e}")
        return

    if data is None:
        print_json_error("Empty input")
        return

    parser = LnkParser(data)
    try:
        parser.parse()
    except Exception as e:
        print_json_error(str(e))
        return

    result = {
        "name_string": parser.name_string,
        "relative_path": parser.relative_path,
        "working_dir": parser.working_dir,
        "command_line_arguments": parser.command_line_arguments,
        "icon_location": parser.icon_location,
        "file_size": parser.file_size,
        "icon_index": parser.icon_index,
        "creation_time": parser.creation_time,
        "access_time": parser.access_time,
        "write_time": parser.write_time,
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()