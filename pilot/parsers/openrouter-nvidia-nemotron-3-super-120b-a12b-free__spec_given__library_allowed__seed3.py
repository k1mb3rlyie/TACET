#!/usr/bin/env python3
import sys
import json
import datetime
import timezone

def filetime_to_iso(ft: int) -> str:
    # FILETIME: 100-nanosecond intervals since 1601-01-01 UTC
    base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    dt = base + datetime.timedelta(seconds=ft / 10_000_000)
    return dt.isoformat()

class ParseError(Exception):
    pass

class Parser:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.len = len(data)

    def ensure(self, n: int) -> bytes:
        if self.pos + n > self.len:
            raise ParseError("Unexpected end of file")
        res = self.data[self.pos:self.pos+n]
        self.pos += n
        return res

    def uint8(self) -> int:
        return int.from_bytes(self.ensure(1), 'little')

    def uint16(self) -> int:
        return int.from_bytes(self.ensure(2), 'little')

    def uint32(self) -> int:
        return int.from_bytes(self.ensure(4), 'little')

    def int32(self) -> int:
        return int.from_bytes(self.ensure(4), 'little', signed=True)

    def uint64(self) -> int:
        return int.from_bytes(self.ensure(8), 'little')

    def skip(self, n: int):
        self.ensure(n)

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python parser.py <path-to-lnk-file>"}))
        sys.exit(0)

    try:
        with open(sys.argv[1], 'rb') as f:
            data = f.read()
    except OSError as e:
        print(json.dumps({"error": f"Cannot open file: {e}"}))
        sys.exit(0)

    try:
        p = Parser(data)

        # Header (76 bytes)
        if p.len < 0x4C:
            raise ParseError("File too short for ShellLink header")

        header_size = p.uint32()
        if header_size != 0x4C:
            raise ParseError(f"Invalid HeaderSize: 0x{header_size:08X}")

        expected_clsid = bytes([
            0x01, 0x14, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x46
        ])
        link_clsid = p.ensure(16)
        if link_clsid != expected_clsid:
            raise ParseError("Invalid LinkCLSID")

        link_flags = p.uint32()
        _file_attributes = p.uint32()  # ignored
        creation_time = p.uint64()
        access_time = p.uint64()
        write_time = p.uint64()
        file_size = p.uint32()
        icon_index = p.int32()
        _show_command = p.uint32()
        hot_key = p.uint16()  # ignored
        _reserved1 = p.uint16()  # ignored
        _reserved2 = p.uint32()  # ignored
        _reserved3 = p.uint32()  # ignored

        # Optional IDList
        if link_flags & 0x00000001:  # HasLinkTargetIDList
            idlist_size = p.uint16()
            p.skip(idlist_size)

        # Optional LinkInfo
        if link_flags & 0x00000002:  # HasLinkInfo
            linkinfo_size = p.uint32()
            p.skip(linkinfo_size)

        is_unicode = bool(link_flags & 0x00000080)

        def get_string(flag):
            if link_flags & flag:
                count = p.uint16()
                char_size = 2 if is_unicode else 1
                byte_len = count * char_size
                raw = p.ensure(byte_len)
                if is_unicode:
                    return raw.decode('utf-16le', errors='strict')
                else:
                    return raw.decode('latin-1')
            else:
                return None

        name_string = get_string(0x00000004)   # HasName
        relative_path = get_string(0x00000008) # HasRelativePath
        working_dir = get_string(0x00000010)   # HasWorkingDir
        command_line_arguments = get_string(0x00000020) # HasArguments
        icon_location = get_string(0x00000040) # HasIconLocation

        # Build output
        result = {
            "name_string": name_string,
            "relative_path": relative_path,
            "working_dir": working_dir,
            "command_line_arguments": command_line_arguments,
            "icon_location": icon_location,
            "file_size": file_size,
            "icon_index": icon_index,
            "creation_time": filetime_to_iso(creation_time),
            "access_time": filetime_to_iso(access_time),
            "write_time": filetime_to_iso(write_time),
        }
        print(json.dumps(result))
        sys.exit(0)

    except ParseError as pe:
        print(json.dumps({"error": str(pe)}))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {e}"}))
        sys.exit(0)

if __name__ == "__main__":
    main()