import sys
import struct
import json
import datetime

def filetime_to_iso(ft: int) -> str:
    """Convert FILETIME (100-ns since 1601-01-01 UTC) to ISO 8601 with UTC offset."""
    EPOCH_DIFF = 116444736000000000  # 100-ns from 1601-01-01 to 1970-01-01
    try:
        seconds = (ft - EPOCH_DIFF) / 10000000.0
        dt = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise ValueError("FILETIME out of range")
    return dt.isoformat()

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

    if len(data) < 0x4C:
        sys.stderr.write("File too short for header\n")
        sys.exit(1)

    try:
        (HeaderSize, LinkCLSID, LinkFlags, FileAttributes,
         CreationTime, AccessTime, WriteTime,
         FileSize, IconIndex, ShowCommand, HotKey,
         Reserved1, Reserved2, Reserved3) = struct.unpack_from(
            '<I 16s I I Q Q Q I i I H H I I', data, 0)
    except struct.error:
        sys.stderr.write("Failed to unpack header\n")
        sys.exit(1)

    if HeaderSize != 0x4C:
        sys.stderr.write(f"Invalid HeaderSize: 0x{HeaderSize:X}\n")
        sys.exit(1)

    expected_clsid = bytes.fromhex('0114020000000000C000000000000046')
    if LinkCLSID != expected_clsid:
        sys.stderr.write("Invalid LinkCLSID\n")
        sys.exit(1)

    IsUnicode = bool(LinkFlags & 0x00000080)
    offset = 0x4C

    # Skip LinkTargetIDList if present
    if LinkFlags & 0x00000001:
        if offset + 2 > len(data):
            sys.stderr.write("Truncated IDList size field\n")
            sys.exit(1)
        idlist_size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if offset + idlist_size > len(data):
            sys.stderr.write("Truncated IDList data\n")
            sys.exit(1)
        offset += idlist_size

    # Skip LinkInfo if present
    if LinkFlags & 0x00000002:
        if offset + 4 > len(data):
            sys.stderr.write("Truncated LinkInfo size field\n")
            sys.exit(1)
        linkinfosize = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if linkinfosize < 4:
            sys.stderr.write("Invalid LinkInfo size\n")
            sys.exit(1)
        if offset + (linkinfosize - 4) > len(data):
            sys.stderr.write("Truncated LinkInfo data\n")
            sys.exit(1)
        offset += linkinfosize - 4

    # Process optional string sections in order
    sections = [
        ('name_string', 0x00000004),
        ('relative_path', 0x00000008),
        ('working_dir', 0x00000010),
        ('command_line_arguments', 0x00000020),
        ('icon_location', 0x00000040)
    ]

    result = {}
    for key, flag in sections:
        if LinkFlags & flag:
            if offset + 2 > len(data):
                sys.stderr.write(f"Truncated CountCharacters for {key}\n")
                sys.exit(1)
            count_chars = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            byte_count = count_chars * (2 if IsUnicode else 1)
            if offset + byte_count > len(data):
                sys.stderr.write(f"Truncated string data for {key}\n")
                sys.exit(1)
            string_bytes = data[offset:offset + byte_count]
            offset += byte_count
            try:
                if IsUnicode:
                    s = string_bytes.decode('utf-16-le')
                else:
                    s = string_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # Fallback to latin-1 to preserve bytes losslessly
                s = string_bytes.decode('latin-1')
            result[key] = s
        else:
            result[key] = None

    if offset > len(data):
        sys.stderr.write("Parsed beyond file end\n")
        sys.exit(1)

    try:
        result['creation_time'] = filetime_to_iso(CreationTime)
        result['access_time'] = filetime_to_iso(AccessTime)
        result['write_time'] = filetime_to_iso(WriteTime)
    except ValueError as e:
        sys.stderr.write(f"Invalid FILETIME: {e}\n")
        sys.exit(1)

    result['file_size'] = FileSize
    result['icon_index'] = IconIndex

    json.dump(result, sys.stdout, ensure_ascii=False)
    sys.stdout.write('\n')
    sys.exit(0)

if __name__ == '__main__':
    main()