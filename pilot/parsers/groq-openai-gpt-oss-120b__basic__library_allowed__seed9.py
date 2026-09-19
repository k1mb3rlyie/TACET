#!/usr/bin/env python3
import sys
import struct
import json
from datetime import datetime, timezone

# ------------------------------------------------------------
# Helper functions for safe binary reading
# ------------------------------------------------------------
class Buffer:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.len = len(data)

    def _ensure(self, size: int):
        if self.pos + size > self.len:
            raise ValueError("unexpected end of file")

    def read(self, size: int) -> bytes:
        self._ensure(size)
        b = self.data[self.pos:self.pos + size]
        self.pos += size
        return b

    def read_uint16(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def read_uint32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def read_uint64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def skip(self, size: int):
        self._ensure(size)
        self.pos += size

# ------------------------------------------------------------
# FILETIME conversion
# ------------------------------------------------------------
def filetime_to_iso(ft: int) -> str:
    # 100‑nanosecond intervals since 1601‑01‑01
    if ft == 0:
        # keep as the epoch start – still a valid ISO string
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc)
    else:
        seconds, remainder = divmod(ft - 116444736000000000, 10_000_000)
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        # add sub‑second part
        dt = dt.replace(microsecond=int(remainder / 10))
    return dt.isoformat()

# ------------------------------------------------------------
# Main parsing routine
# ------------------------------------------------------------
def parse_lnk(data: bytes):
    buf = Buffer(data)

    # ---- Header (76 bytes) ----
    if buf.len < 76:
        raise ValueError("file too short for header")
    header_size = buf.read_uint32()
    if header_size != 0x4C:
        raise ValueError(f"invalid header size: {header_size:#x}")

    # skip LinkCLSID (16 bytes)
    buf.skip(16)

    link_flags = buf.read_uint32()
    file_attrs = buf.read_uint32()

    creation_time = buf.read_uint64()
    access_time = buf.read_uint64()
    write_time = buf.read_uint64()

    file_size = buf.read_uint32()
    icon_index = buf.read_uint32()

    # skip remaining header fields (ShowCommand, HotKey, Reserved)
    buf.skip(4 + 2 + 2 + 4 + 4)

    # ---- Optional sections ----
    HAS_LINK_TARGET_ID_LIST = 0x00000001
    HAS_LINK_INFO = 0x00000002
    HAS_NAME = 0x00000004
    HAS_RELATIVE_PATH = 0x00000008
    HAS_WORKING_DIR = 0x00000010
    HAS_ARGUMENTS = 0x00000020
    HAS_ICON_LOCATION = 0x00000040
    IS_UNICODE = 0x00000080

    # LinkTargetIDList
    if link_flags & HAS_LINK_TARGET_ID_LIST:
        idlist_size = buf.read_uint16()
        buf.skip(idlist_size)

    # LinkInfo
    if link_flags & HAS_LINK_INFO:
        link_info_size = buf.read_uint32()
        buf.skip(link_info_size - 4)  # size includes the 4‑byte size field itself

    # ---- StringData ----
    def read_string(is_unicode: bool) -> str:
        # length includes the null terminator
        count = buf.read_uint16()
        if is_unicode:
            raw = buf.read(count * 2)
            try:
                s = raw.decode('utf-16le', errors='strict')
            except UnicodeDecodeError as e:
                raise ValueError(f"unicode decode error: {e}")
        else:
            raw = buf.read(count)
            try:
                s = raw.decode('ansi', errors='strict')
            except UnicodeDecodeError as e:
                raise ValueError(f"ansi decode error: {e}")
        # strip terminating null if present
        if s and s[-1] == '\x00':
            s = s[:-1]
        return s

    is_unicode = bool(link_flags & IS_UNICODE)

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if link_flags & HAS_NAME:
        name_string = read_string(is_unicode)
    if link_flags & HAS_RELATIVE_PATH:
        relative_path = read_string(is_unicode)
    if link_flags & HAS_WORKING_DIR:
        working_dir = read_string(is_unicode)
    if link_flags & HAS_ARGUMENTS:
        command_line_arguments = read_string(is_unicode)
    if link_flags & HAS_ICON_LOCATION:
        icon_location = read_string(is_unicode)

    # Build result dict
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
    return result

# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------
def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        err = {"error": f"cannot read file: {e}"}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

    try:
        result = parse_lnk(data)
    except Exception as e:
        err = {"error": str(e)}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

    print(json.dumps(result, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()