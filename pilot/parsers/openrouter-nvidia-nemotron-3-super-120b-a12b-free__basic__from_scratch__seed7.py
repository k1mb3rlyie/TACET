import sys
import struct
import datetime
import json

def filetime_to_iso(ft: int) -> str:
    """Convert Windows FILETIME to ISO 8601 string with UTC offset."""
    EPOCH = 116444736000000000  # 100-ns intervals from 1601-01-01 to 1970-01-01
    if ft < EPOCH:
        # Before 1970, seconds will be negative; datetime handles it.
        pass
    seconds = (ft - EPOCH) // 10000000
    remainder_ns100 = (ft - EPOCH) % 10000000
    microseconds = remainder_ns100 // 10  # 100-ns -> microseconds
    dt = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc) + datetime.timedelta(microseconds=microseconds)
    iso = dt.strftime('%Y-%m-%dT%H:%M:%S%z')
    return iso[:-2] + ':' + iso[-2:]

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        sys.stderr.write("Failed to read file.\n")
        sys.exit(1)

    n = len(data)
    if n < 76:
        sys.stderr.write("File too small to be a valid LNK.\n")
        sys.exit(1)

    try:
        # Header: 16s CLSID + LinkFlags + FileAttributes + CreationTime + AccessTime +
        # WriteTime + FileSize + IconIndex + ShowCommand + HotKey + Reserved1-4
        header_fmt = '<16sIIQQQIIiiHHIII'
        header = struct.unpack_from(header_fmt, data, 0)
        linkflags = header[1]
        creation_time_raw = header[3]
        access_time_raw = header[4]
        write_time_raw = header[5]
        file_size = header[6]
        icon_index = header[7]

        offset = 76  # start after header

        # Optional ItemIDList
        if linkflags & 0x01:  # HasLinkTargetIDList
            if offset + 2 > n:
                raise ValueError("Truncated IDList size")
            idlist_size = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if offset + idlist_size > n:
                raise ValueError("Truncated IDList")
            offset += idlist_size

        # Optional LinkInfo
        if linkflags & 0x02:  # HasLinkInfo
            if offset + 4 > n:
                raise ValueError("Truncated LinkInfo size")
            linkinfosize = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            if offset + linkinfosize > n:
                raise ValueError("Truncated LinkInfo")
            offset += linkinfosize

        is_unicode = bool(linkflags & 0x00008000)  # IsUnicode flag

        def read_string(flag):
            nonlocal offset
            if not (linkflags & flag):
                return None
            if offset + 2 > n:
                raise ValueError("Truncated string length")
            strlen = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            if is_unicode:
                nb = strlen * 2
            else:
                nb = strlen
            if offset + nb > n:
                raise ValueError("Truncated string data")
            if nb == 0:
                return ''
            raw = data[offset:offset + nb]
            offset += nb
            if is_unicode:
                try:
                    return raw.decode('utf-16le')
                except UnicodeDecodeError:
                    raise ValueError("Invalid Unicode string")
            else:
                try:
                    return raw.decode('mbcs')
                except LookupError:
                    # mbcs not available; fallback to latin-1 (should not happen on Windows)
                    return raw.decode('latin-1')

        name_string = read_string(0x04)      # HasName
        relative_path = read_string(0x08)    # HasRelativePath
        working_dir = read_string(0x10)      # HasWorkingDir
        command_line_arguments = read_string(0x20)  # HasArguments
        icon_location = read_string(0x40)    # HasIconLocation

        # Convert timestamps
        creation_time_iso = filetime_to_iso(creation_time_raw)
        access_time_iso = filetime_to_iso(access_time_raw)
        write_time_iso = filetime_to_iso(write_time_raw)

        result = {
            "name_string": name_string,
            "relative_path": relative_path,
            "working_dir": working_dir,
            "command_line_arguments": command_line_arguments,
            "icon_location": icon_location,
            "file_size": file_size,
            "icon_index": icon_index,
            "creation_time": creation_time_iso,
            "access_time": access_time_iso,
            "write_time": write_time_iso,
        }

        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0)

    except (struct.error, ValueError, UnicodeDecodeError) as e:
        sys.stderr.write(f"Parsing failed: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()