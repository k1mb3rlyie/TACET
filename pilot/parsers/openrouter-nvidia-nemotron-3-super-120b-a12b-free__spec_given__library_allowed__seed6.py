#!/usr/bin/env python3
import sys
import json
import struct
import datetime

def fail(msg: str):
    """Print error JSON to stdout, write details to stderr, and exit with non-zero."""
    sys.stderr.write(msg + "\n")
    print(json.dumps({"error": msg}))
    sys.exit(1)

def parse_header(data: bytes):
    if len(data) < 0x4C:
        fail("File too small for a valid LNK header")
    (
        header_size,
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
        reserved3,
    ) = struct.unpack_from("<I 16s I I Q Q Q I i H H I I I", data, 0)

    if header_size != 0x4C:
        fail(f"Invalid HeaderSize: 0x{header_size:X}")
    expected_clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    if link_clsid != expected_clsid:
        fail("Invalid LinkCLSID")
    if reserved1 != 0 or reserved2 != 0 or reserved3 != 0:
        fail("Reserved header fields are non‑zero")
    return {
        "link_flags": link_flags,
        "file_attributes": file_attributes,
        "creation_time": creation_time,
        "access_time": access_time,
        "write_time": write_time,
        "file_size": file_size,
        "icon_index": icon_index,
        "show_command": show_command,
        "hot_key": hot_key,
    }

def skip_idlist(data: bytes, offset: int) -> int:
    while offset + 2 <= len(data):
        cb = data[offset] + (data[offset + 1] << 8)
        offset += 2
        if cb == 0:
            break
        if cb < 2:
            fail("Invalid IDList item size")
        if offset + cb - 2 > len(data):
            fail("IDList exceeds file size")
        offset += cb - 2
    else:
        fail("Missing IDList terminator")
    return offset

def skip_linkinfo(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        fail("LinkInfo size missing")
    link_info_size = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if link_info_size < 0:
        fail("Negative LinkInfo size")
    if offset + link_info_size > len(data):
        fail("LinkInfo exceeds file size")
    offset += link_info_size
    return offset

def read_string(data: bytes, offset: int, is_unicode: bool):
    if offset + 2 > len(data):
        fail("String length missing")
    count_chars = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    byte_len = count_chars * 2 if is_unicode else count_chars
    if offset + byte_len > len(data):
        fail("String exceeds file size")
    str_bytes = data[offset : offset + byte_len]
    offset += byte_len
    try:
        if is_unicode:
            s = str_bytes.decode("utf-16le")
        else:
            # Use latin-1 to preserve byte values without loss
            s = str_bytes.decode("latin-1")
    except UnicodeDecodeError as e:
        fail(f"Invalid string encoding: {e}")
    return s, offset

def filetime_to_iso(ft: int) -> str:
    if ft < 0:
        fail("Negative FILETIME encountered")
    # 100-nanosecond intervals since 1601-01-01 UTC
    seconds = ft / 10_000_000.0
    base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    dt = base + datetime.timedelta(seconds=seconds)
    return dt.isoformat()

def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")
    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        fail(f"Cannot open file: {e}")

    try:
        header = parse_header(data)
    except SystemExit:
        raise
    except Exception as e:
        fail(f"Invalid header: {e}")

    offset = 0x4C

    if header["link_flags"] & 0x00000001:  # HasLinkTargetIDList
        try:
            offset = skip_idlist(data, offset)
        except SystemExit:
            raise
        except Exception as e:
            fail(f"Failed to skip IDList: {e}")

    if header["link_flags"] & 0x00000002:  # HasLinkInfo
        try:
            offset = skip_linkinfo(data, offset)
        except SystemExit:
            raise
        except Exception as e:
            fail(f"Failed to skip LinkInfo: {e}")

    is_unicode = bool(header["link_flags"] & 0x00000080)

    # Order of possible string sections
    string_specs = [
        ("name_string", 0x00000004),   # HasName
        ("relative_path", 0x00000008), # HasRelativePath
        ("working_dir", 0x00000010),   # HasWorkingDir
        ("command_line_arguments", 0x00000020), # HasArguments
        ("icon_location", 0x00000040), # HasIconLocation
    ]

    results = {}
    for name, flag in string_specs:
        if header["link_flags"] & flag:
            try:
                s, offset = read_string(data, offset, is_unicode)
                results[name] = s
            except SystemExit:
                raise
            except Exception as e:
                fail(f"Failed to read {name}: {e}")
        else:
            results[name] = None

    if offset > len(data):
        fail("Parsed beyond end of file")

    output = {
        "name_string": results["name_string"],
        "relative_path": results["relative_path"],
        "working_dir": results["working_dir"],
        "command_line_arguments": results["command_line_arguments"],
        "icon_location": results["icon_location"],
        "file_size": header["file_size"],
        "icon_index": header["icon_index"],
        "creation_time": filetime_to_iso(header["creation_time"]),
        "access_time": filetime_to_iso(header["access_time"]),
        "write_time": filetime_to_iso(header["write_time"]),
    }

    print(json.dumps(output))
    sys.exit(0)

if __name__ == "__main__":
    main()