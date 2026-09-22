import sys
import json
from datetime import datetime, timezone, timedelta

def read_uint16(buf, off):
    return buf[off] | (buf[off + 1] << 8)

def read_uint32(buf, off):
    return buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)

def read_int32(buf, off):
    val = read_uint32(buf, off)
    return val - (1 << 32) if val & (1 << 31) else val

def read_uint64(buf, off):
    return (buf[off] |
            (buf[off + 1] << 8) |
            (buf[off + 2] << 16) |
            (buf[off + 3] << 24) |
            (buf[off + 4] << 32) |
            (buf[off + 5] << 40) |
            (buf[off + 6] << 48) |
            (buf[off + 7] << 56))

def filetime_to_datetime(ft):
    # ft: 100-ns intervals since 1601-01-01 UTC
    # Convert to datetime with microsecond precision
    dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
    return dt

def parse_lnk(data):
    if len(data) < 0x4C:
        raise ValueError("File too short for ShellLinkHeader")

    off = 0

    header_size = read_uint32(data, off); off += 4
    if header_size != 0x4C:
        raise ValueError(f"Invalid HeaderSize: 0x{header_size:X}")

    link_clsid = data[off:off+16]; off += 16
    expected_clsid = bytes([0x01,0x14,0x02,0x00,
                            0x00,0x00,0x00,0x00,
                            0xC0,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x46])
    if link_clsid != expected_clsid:
        raise ValueError("Invalid LinkCLSID")

    link_flags = read_uint32(data, off); off += 4
    _file_attributes = read_uint32(data, off); off += 4  # unused

    creation_time = read_uint64(data, off); off += 8
    access_time = read_uint64(data, off); off += 8
    write_time = read_uint64(data, off); off += 8

    file_size = read_uint32(data, off); off += 4  # unsigned
    icon_index = read_int32(data, off); off += 4   # signed
    _show_command = read_uint32(data, off); off += 4  # unused
    hot_key = read_uint16(data, off); off += 2       # unused
    reserved1 = read_uint16(data, off); off += 2
    if reserved1 != 0:
        raise ValueError("Reserved1 must be zero")
    reserved2 = read_uint32(data, off); off += 4
    if reserved2 != 0:
        raise ValueError("Reserved2 must be zero")
    reserved3 = read_uint32(data, off); off += 4
    if reserved3 != 0:
        raise ValueError("Reserved3 must be zero")

    # Optional IDList
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        while True:
            if off + 2 > len(data):
                raise ValueError("IDList truncation while reading size")
            id_size = read_uint16(data, off)
            off += 2
            if id_size == 0:
                break
            if id_size < 2:
                raise ValueError("Invalid IDList item size")
            if off + id_size - 2 > len(data):
                raise ValueError("IDList truncation while reading item data")
            off += id_size - 2

    # Optional LinkInfo
    if link_flags & 0x00000002:  # HasLinkInfo
        if off + 4 > len(data):
            raise ValueError("LinkInfo truncation while reading size")
        link_info_size = read_uint32(data, off)
        off += 4
        if link_info_size < 4:
            raise ValueError("LinkInfo size too small")
        if off + link_info_size > len(data):
            raise ValueError("LinkInfo truncation")
        off += link_info_size

    is_unicode = bool(link_flags & 0x00000080)

    def read_string(flag_bit, var_name):
        nonlocal off
        if link_flags & flag_bit:
            if off + 2 > len(data):
                raise ValueError(f"String size truncation for {var_name}")
            char_count = read_uint16(data, off)
            off += 2
            byte_len = char_count * (2 if is_unicode else 1)
            if off + byte_len > len(data):
                raise ValueError(f"String data truncation for {var_name}")
            str_bytes = data[off:off+byte_len]
            off += byte_len
            try:
                encoding = 'utf-16-le' if is_unicode else 'utf-8'
                return str_bytes.decode(encoding, errors='strict')
            except UnicodeDecodeError as e:
                raise ValueError(f"Failed to decode {var_name}: {e}")
        else:
            return None

    name_string = read_string(0x00000004, "name_string")
    relative_path = read_string(0x00000008, "relative_path")
    working_dir = read_string(0x00000010, "working_dir")
    command_line_arguments = read_string(0x00000020, "command_line_arguments")
    icon_location = read_string(0x00000040, "icon_location")

    # Convert timestamps
    try:
        creation_dt = filetime_to_datetime(creation_time)
        access_dt = filetime_to_datetime(access_time)
        write_dt = filetime_to_datetime(write_time)
    except Exception as e:
        raise ValueError(f"Timestamp conversion error: {e}")

    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_dt.isoformat(timespec='seconds'),
        "access_time": access_dt.isoformat(timespec='seconds'),
        "write_time": write_dt.isoformat(timespec='seconds')
    }
    return result

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"Cannot open file: {e}\n")
        sys.exit(1)

    try:
        result = parse_lnk(data)
    except Exception as e:
        sys.stderr.write(f"Parsing failed: {e}\n")
        sys.exit(1)

    json.dump(result, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")

if __name__ == "__main__":
    main()