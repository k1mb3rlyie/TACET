#!/usr/bin/env python3
import sys
import json
import datetime

def read_uint8(buf, off):
    return buf[off]

def read_uint16_le(buf, off):
    return buf[off] | (buf[off+1] << 8)

def read_uint32_le(buf, off):
    return (buf[off] |
            (buf[off+1] << 8) |
            (buf[off+2] << 16) |
            (buf[off+3] << 24))

def read_int32_le(buf, off):
    val = read_uint32_le(buf, off)
    return val - 0x100000000 if val & 0x80000000 else val

def read_uint64_le(buf, off):
    return (buf[off] |
            (buf[off+1] << 8) |
            (buf[off+2] << 16) |
            (buf[off+3] << 24) |
            (buf[off+4] << 32) |
            (buf[off+5] << 40) |
            (buf[off+6] << 48) |
            (buf[off+7] << 56))

def filetime_to_dt(ft):
    # FILETIME: 100-ns intervals since 1601-01-01 UTC
    try:
        seconds = ft / 10_000_000 - 11644473600
        dt = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        raise ValueError("Invalid FILETIME value")

def parse_lnk(data):
    n = len(data)
    if n < 0x4C:
        raise ValueError("File too short for ShellLinkHeader")

    off = 0

    # HeaderSize
    header_size = read_uint32_le(data, off)
    if header_size != 0x4C:
        raise ValueError(f"Invalid HeaderSize: 0x{header_size:08X}")
    off += 4

    # LinkCLSID
    expected_clsid = bytes.fromhex("0114020000000000C000000000000046")
    clsid = data[off:off+16]
    if clsid != expected_clsid:
        raise ValueError("Invalid LinkCLSID")
    off += 16

    # LinkFlags
    link_flags = read_uint32_le(data, off)
    off += 4

    # FileAttributes (ignore)
    off += 4

    # CreationTime
    creation_ft = read_uint64_le(data, off)
    off += 8

    # AccessTime
    access_ft = read_uint64_le(data, off)
    off += 8

    # WriteTime
    write_ft = read_uint64_le(data, off)
    off += 8

    # FileSize (unsigned)
    file_size = read_uint32_le(data, off)
    off += 4

    # IconIndex (signed)
    icon_index = read_int32_le(data, off)
    off += 4

    # ShowCommand (ignore)
    off += 4

    # HotKey (ignore)
    off += 2

    # Reserved1
    reserved1 = read_uint16_le(data, off)
    if reserved1 != 0:
        raise ValueError("Reserved1 must be zero")
    off += 2

    # Reserved2
    reserved2 = read_uint32_le(data, off)
    if reserved2 != 0:
        raise ValueError("Reserved2 must be zero")
    off += 4

    # Reserved3
    reserved3 = read_uint32_le(data, off)
    if reserved3 != 0:
        raise ValueError("Reserved3 must be zero")
    off += 4

    # At this point off == 0x4C
    # Optional IDList
    if link_flags & 0x00000001:
        while True:
            if off + 2 > n:
                raise ValueError("Truncated IDList size field")
            id_size = read_uint16_le(data, off)
            off += 2
            if id_size == 0:
                break
            if id_size < 2:
                raise ValueError("Invalid IDList item size")
            if off + (id_size - 2) > n:
                raise ValueError("Truncated IDList item data")
            off += id_size - 2

    # Optional LinkInfo
    if link_flags & 0x00000002:
        if off + 4 > n:
            raise ValueError("Truncated LinkInfo size")
        link_info_size = read_uint32_le(data, off)
        off += 4
        if link_info_size < 0:
            raise ValueError("Negative LinkInfo size")
        if off + link_info_size > n:
            raise ValueError("Truncated LinkInfo structure")
        off += link_info_size

    # Determine Unicode
    is_unicode = bool(link_flags & 0x00000080)

    # Helper to read a string if flag set
    def read_string_if(flag, name):
        nonlocal off
        if link_flags & flag:
            if off + 2 > n:
                raise ValueError(f"Truncated {name} length")
            chars = read_uint16_le(data, off)
            off += 2
            byte_len = chars * (2 if is_unicode else 1)
            if off + byte_len > n:
                raise ValueError(f"Truncated {name} string")
            raw = data[off:off+byte_len]
            off += byte_len
            try:
                if is_unicode:
                    return raw.decode('utf-16le')
                else:
                    # Use utf-8 with fallback to latin-1 to avoid loss
                    try:
                        return raw.decode('utf-8')
                    except UnicodeDecodeError:
                        return raw.decode('latin-1')
            except Exception as e:
                raise ValueError(f"Failed to decode {name}: {e}")
        else:
            return None

    name_string = read_string_if(0x00000004, "NAME_STRING")
    relative_path = read_string_if(0x00000008, "RELATIVE_PATH")
    working_dir = read_string_if(0x00000010, "WORKING_DIR")
    command_line_arguments = read_string_if(0x00000020, "COMMAND_LINE_ARGUMENTS")
    icon_location = read_string_if(0x00000040, "ICON_LOCATION")

    # Extra data (skip until terminal block)
    while True:
        if off + 4 > n:
            raise ValueError("Truncated extra data block size")
        block_size = read_uint32_le(data, off)
        off += 4
        if block_size < 4:
            # Terminal block
            break
        if off + block_size > n:
            raise ValueError("Truncated extra data block")
        off += block_size

    if off != n:
        raise ValueError("Extra data after terminal block")

    # Convert timestamps
    creation_time = filetime_to_dt(creation_ft)
    access_time = filetime_to_dt(access_ft)
    write_time = filetime_to_dt(write_ft)

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time,
        "access_time": access_time,
        "write_time": write_time,
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
        result = parse_lnk(data)
        json.dump(result, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as e:
        err = {"error": str(e)}
        json.dump(err, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)

if __name__ == "__main__":
    main()