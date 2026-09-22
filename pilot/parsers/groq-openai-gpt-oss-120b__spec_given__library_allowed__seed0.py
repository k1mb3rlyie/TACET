#!/usr/bin/env python3
import sys
import struct
import json
import datetime

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
class ParseError(Exception):
    pass


def read_exact(data: bytes, offset: int, size: int) -> bytes:
    if offset + size > len(data):
        raise ParseError("Unexpected end of file")
    return data[offset:offset + size]


def unpack_from(fmt: str, data: bytes, offset: int):
    size = struct.calcsize(fmt)
    chunk = read_exact(data, offset, size)
    return struct.unpack(fmt, chunk), offset + size


def filetime_to_iso(ft: int) -> str:
    # FILETIME is number of 100‑ns intervals since 1601‑01‑01 UTC
    try:
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        micros = ft // 10  # convert to microseconds
        dt = base + datetime.timedelta(microseconds=micros)
        # isoformat always includes offset when tzinfo is set
        return dt.isoformat()
    except Exception as e:
        raise ParseError(f"Invalid FILETIME value: {e}")


# ----------------------------------------------------------------------
# Main parser
# ----------------------------------------------------------------------
def parse_lnk(data: bytes):
    if len(data) < 76:
        raise ParseError("File too short for ShellLinkHeader")

    # ----- ShellLinkHeader -----
    offset = 0
    (header_size,), offset = unpack_from("<I", data, offset)
    if header_size != 0x4C:
        raise ParseError("HeaderSize is not 0x4C")

    expected_clsid = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    clsid = read_exact(data, offset, 16)
    if clsid != expected_clsid:
        raise ParseError("LinkCLSID does not match expected GUID")
    offset += 16

    (link_flags,), offset = unpack_from("<I", data, offset)
    (file_attrs,), offset = unpack_from("<I", data, offset)

    (creation_ft,), offset = unpack_from("<Q", data, offset)
    (access_ft,), offset = unpack_from("<Q", data, offset)
    (write_ft,), offset = unpack_from("<Q", data, offset)

    (file_size,), offset = unpack_from("<I", data, offset)
    (icon_index,), offset = unpack_from("<i", data, offset)   # signed
    (show_cmd,), offset = unpack_from("<I", data, offset)
    (hotkey,), offset = unpack_from("<H", data, offset)
    (reserved1,), offset = unpack_from("<H", data, offset)
    (reserved2,), offset = unpack_from("<I", data, offset)
    (reserved3,), offset = unpack_from("<I", data, offset)

    if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
        raise ParseError("Reserved fields are not zero")

    # ----- Optional IDList -----
    HAS_IDLIST = 0x00000001
    HAS_LINKINFO = 0x00000002
    IS_UNICODE = 0x00000080

    if link_flags & HAS_IDLIST:
        (idlist_size,), offset = unpack_from("<H", data, offset)
        offset += idlist_size
        if offset > len(data):
            raise ParseError("IDList exceeds file size")

    # ----- Optional LinkInfo -----
    if link_flags & HAS_LINKINFO:
        (linkinfo_size,), offset = unpack_from("<I", data, offset)
        offset += linkinfo_size - 4  # size includes the 4‑byte size field itself
        if offset > len(data):
            raise ParseError("LinkInfo exceeds file size")

    # ----- StringData -----
    def read_string(flag_bit):
        nonlocal offset
        if link_flags & flag_bit:
            (char_count,), offset = unpack_from("<H", data, offset)
            charsize = 2 if (link_flags & IS_UNICODE) else 1
            byte_len = char_count * charsize
            raw = read_exact(data, offset, byte_len)
            offset += byte_len
            try:
                if link_flags & IS_UNICODE:
                    return raw.decode('utf-16le')
                else:
                    return raw.decode('utf-8')
            except UnicodeDecodeError as e:
                raise ParseError(f"String decoding error: {e}")
        else:
            return None

    name_string = read_string(0x00000004)          # HasName
    relative_path = read_string(0x00000008)       # HasRelativePath
    working_dir = read_string(0x00000010)         # HasWorkingDir
    command_line_arguments = read_string(0x00000020)  # HasArguments
    icon_location = read_string(0x00000040)       # HasIconLocation

    # ----- Build result -----
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
    return result


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        sys.stderr.write(f"Failed to read file: {e}\n")
        sys.exit(1)

    try:
        parsed = parse_lnk(data)
        json.dump(parsed, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)
    except ParseError as e:
        err_obj = {"error": str(e)}
        json.dump(err_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)
    except Exception as e:
        # Unexpected error – treat as parsing failure
        err_obj = {"error": f"Unexpected error: {e}"}
        json.dump(err_obj, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()