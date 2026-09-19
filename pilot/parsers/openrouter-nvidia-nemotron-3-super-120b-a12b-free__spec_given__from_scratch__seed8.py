import sys
import struct
import json
import locale
from datetime import datetime, timezone, timedelta

def parse_lnk(data: bytes):
    idx = 0
    n = len(data)

    def read_u8():
        nonlocal idx
        if idx + 1 > n:
            raise ValueError("Truncated file")
        v = data[idx]
        idx += 1
        return v

    def read_u16():
        nonlocal idx
        if idx + 2 > n:
            raise ValueError("Truncated file")
        v = struct.unpack_from('<H', data, idx)[0]
        idx += 2
        return v

    def read_u32():
        nonlocal idx
        if idx + 4 > n:
            raise ValueError("Truncated file")
        v = struct.unpack_from('<I', data, idx)[0]
        idx += 4
        return v

    def read_u64():
        nonlocal idx
        if idx + 8 > n:
            raise ValueError("Truncated file")
        v = struct.unpack_from('<Q', data, idx)[0]
        idx += 8
        return v

    def read_s32():
        nonlocal idx
        if idx + 4 > n:
            raise ValueError("Truncated file")
        v = struct.unpack_from('<i', data, idx)[0]
        idx += 4
        return v

    # ---- ShellLinkHeader (76 bytes) ----
    if n < 76:
        raise ValueError("File too small for header")
    header_size = read_u32()
    if header_size != 0x4C:
        raise ValueError(f"Invalid HeaderSize: 0x{header_size:08X}")

    expected_clsid = bytes.fromhex('0114020000000000C000000000000046')
    link_clsid = read_bytes(16)
    if link_clsid != expected_clsid:
        raise ValueError("Invalid LinkCLSID")

    link_flags = read_u32()
    _file_attributes = read_u32()  # ignored
    creation_time = read_u64()
    access_time = read_u64()
    write_time = read_u64()
    file_size = read_u32()
    icon_index = read_s32()  # signed
    _show_command = read_u32()
    hot_key = read_u16()
    reserved1 = read_u16()
    reserved2 = read_u32()
    reserved3 = read_u32()
    # reserved fields should be zero; we ignore mismatches to avoid false positives

    # ---- Optional IDList ----
    if link_flags & 0x00000001:
        while True:
            if idx + 2 > n:
                raise ValueError("Truncated IDList")
            item_size = read_u16()
            if item_size == 0:
                break
            if item_size < 2:
                raise ValueError("Invalid IDList item size")
            if idx + item_size > n:
                raise ValueError("IDList exceeds file size")
            idx += item_size - 2  # skip the item data (size includes the 2-byte length)

    # ---- Optional LinkInfo ----
    if link_flags & 0x00000002:
        if idx + 4 > n:
            raise ValueError("Truncated LinkInfo size")
        link_info_size = read_u32()
        if link_info_size < 0:
            raise ValueError("Negative LinkInfo size")
        if idx + link_info_size > n:
            raise ValueError("LinkInfo exceeds file size")
        idx += link_info_size

    # ---- String sections ----
    is_unicode = bool(link_flags & 0x00000080)
    string_defs = [
        (0x00000004, "name_string"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_dir"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    ]
    result = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": "",
        "access_time": "",
        "write_time": "",
    }

    for flag, key in string_defs:
        if link_flags & flag:
            if idx + 2 > n:
                raise ValueError(f"Truncated string length for {key}")
            char_count = read_u16()
            bytes_per_char = 2 if is_unicode else 1
            str_len = char_count * bytes_per_char
            if idx + str_len > n:
                raise ValueError(f"Truncated string data for {key}")
            raw = data[idx:idx + str_len]
            idx += str_len
            try:
                if is_unicode:
                    s = raw.decode('utf-16-le')
                else:
                    encoding = locale.getpreferredencoding(False)
                    s = raw.decode(encoding)
            except Exception as e:
                raise ValueError(f"Failed to decode {key}: {e}")
            result[key] = s
        else:
            result[key] = None

    # ---- Extra data blocks (terminated by a block size < 4) ----
    while True:
        if idx + 4 > n:
            raise ValueError("Truncated extra data block size")
        block_size = read_u32()
        if block_size < 4:
            # terminal block
            break
        if block_size > n - idx:
            raise ValueError("Extra data block exceeds file size")
        idx += block_size - 4  # skip the rest of the block

    if idx != n:
        raise ValueError("Trailing data after terminal block")

    # ---- Convert FILETIME to ISO 8601 UTC ----
    def filetime_to_iso(ft: int) -> str:
        # FILETIME: 100-ns intervals since 1601-01-01 UTC
        base = datetime(1601, 1, 1, tzinfo=timezone.utc)
        microseconds = ft // 10
        dt = base + timedelta(microseconds=microseconds)
        return dt.isoformat()

    result["creation_time"] = filetime_to_iso(creation_time)
    result["access_time"] = filetime_to_iso(access_time)
    result["write_time"] = filetime_to_iso(write_time)

    return result

def read_bytes(length):
    nonlocal idx
    if idx + length > n:
        raise ValueError("Truncated file")
    b = data[idx:idx+length]
    idx += length
    return b

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Cannot read file: {e}\n")
        sys.exit(1)

    try:
        result = parse_lnk(data)
        print(json.dumps(result))
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()