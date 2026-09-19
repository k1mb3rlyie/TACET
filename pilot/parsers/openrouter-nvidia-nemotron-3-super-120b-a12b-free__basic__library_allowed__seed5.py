import sys
import json
import struct
from datetime import datetime, timezone, timedelta

def read_uint8(buf, off):
    return struct.unpack_from('<B', buf, off)[0], off + 1

def read_uint16(buf, off):
    return struct.unpack_from('<H', buf, off)[0], off + 2

def read_uint32(buf, off):
    return struct.unpack_from('<I', buf, off)[0], off + 4

def read_int32(buf, off):
    return struct.unpack_from('<i', buf, off)[0], off + 4

def read_uint64(buf, off):
    return struct.unpack_from('<Q', buf, off)[0], off + 8

def filetime_to_dt(ft):
    # ft: 100-nanoseconds since 1601-01-01 UTC
    # Convert to microseconds since 1601-01-01, then to datetime
    microseconds = ft // 10
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)

def parse_lnk(data):
    if len(data) < 0x4C:
        raise ValueError("File too small for a .lnk header")
    if data[0:4] != b'\x4C\x00\x00\x00':
        raise ValueError("Invalid .lnk signature")
    off = 4  # skip signature
    off += 16  # skip LinkCLSID
    link_flags, off = read_uint32(buf=data, off=off)
    # skip FileAttributes (4 bytes)
    off += 4
    creation_time, off = read_uint64(buf=data, off=off)
    access_time, off = read_uint64(buf=data, off=off)
    write_time, off = read_uint64(buf=data, off=off)
    file_size, off = read_uint32(buf=data, off=off)
    icon_index, off = read_int32(buf=data, off=off)
    # skip ShowCommand (4), HotKey (2), Reserved1 (2), Reserved2 (4), Reserved3 (4)
    off += 4 + 2 + 2 + 4 + 4  # total 16 bytes
    # Now off should be 0x4C
    is_unicode = (link_flags & 0x00000080) != 0

    # Helper to read a string block if flag set
    def read_string_if(flag, offset):
        if not (link_flags & flag):
            return None, offset
        if offset + 4 > len(data):
            raise ValueError("String size field out of bounds")
        str_size, offset = read_uint32(buf=data, off=offset)
        if str_size == 0:
            raise ValueError("String size zero")
        if offset + str_size > len(data):
            raise ValueError("String data out of bounds")
        raw = data[offset:offset + str_size]
        offset += str_size
        try:
            if is_unicode:
                s = raw.decode('utf-16-le')
            else:
                s = raw.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Failed to decode string")
        # Remove trailing null terminator(s)
        s = s.rstrip('\x00')
        return s, offset

    # Skip LinkTargetIDList if present
    if link_flags & 0x00000001:  # HasLinkTargetIDList
        if off + 2 > len(data):
            raise ValueError("LinkTargetIDList size out of bounds")
        id_list_size, off = read_uint16(buf=data, off=off)
        if off + id_list_size > len(data):
            raise ValueError("LinkTargetIDList data out of bounds")
        off += id_list_size

    # Skip LinkInfo if present
    if link_flags & 0x00000002:  # HasLinkInfo
        if off + 4 > len(data):
            raise ValueError("LinkInfo size out of bounds")
        info_size, off = read_uint32(buf=data, off=off)
        if info_size < 4:
            raise ValueError("Invalid LinkInfo size")
        if off + (info_size - 4) > len(data):
            raise ValueError("LinkInfo data out of bounds")
        off += (info_size - 4)

    # Read optional string blocks in fixed order
    name_string, off = read_string_if(0x00000004, off)   # HasName
    relative_path, off = read_string_if(0x00000008, off) # HasRelativePath
    working_dir, off = read_string_if(0x00000010, off)   # HasWorkingDir
    command_line_arguments, off = read_string_if(0x00000020, off) # HasArguments
    icon_location, off = read_string_if(0x00000040, off) # HasIconLocation

    # At this point we have successfully parsed all requested fields
    return {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_dt(creation_time).isoformat(),
        "access_time": filetime_to_dt(access_time).isoformat(),
        "write_time": filetime_to_dt(write_time).isoformat()
    }

def main():
    if len(sys.argv) != 2:
        err = {"error": "Usage: python parser.py <path-to-lnk-file>"}
        print(json.dumps(err, separators=(',', ':')))
        sys.exit(0)
    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
        result = parse_lnk(data)
        print(json.dumps(result, separators=(',', ':'), ensure_ascii=False))
    except Exception as e:
        # Log diagnostics to stderr
        sys.stderr.write(f"Error parsing .lnk file: {e}\n")
        err = {"error": "Failed to parse .lnk file"}
        print(json.dumps(err, separators=(',', ':')))
        sys.exit(0)

if __name__ == "__main__":
    main()