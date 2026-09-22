#!/usr/bin/env python3
import sys
import os
import json
import struct
from datetime import datetime, timezone

def read_bytes(f, n):
    data = f.read(n)
    if len(data) < n:
        raise EOFError("Unexpected end of file")
    return data

def filetime_to_iso(ft):
    # FILETIME: 100-ns intervals since 1601-01-01 UTC
    if ft == 0:
        return None
    try:
        # Convert to seconds since 1970-01-01
        seconds = (ft / 10_000_000) - 11644473600
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, OSError):
        return None

def parse_lnk(path):
    with open(path, 'rb') as f:
        # Header
        header = read_bytes(f, 4)
        if header != b'\x4C\x00\x00\x00':
            raise ValueError("Not a valid LNK file (bad header)")
        link_flags = struct.unpack('<I', read_bytes(f, 4))[0]
        file_attributes = struct.unpack('<I', read_bytes(f, 4))[0]
        creation_time = struct.unpack('<Q', read_bytes(f, 8))[0]
        access_time = struct.unpack('<Q', read_bytes(f, 8))[0]
        write_time = struct.unpack('<Q', read_bytes(f, 8))[0]
        file_size = struct.unpack('<I', read_bytes(f, 8))[0]  # first 4 bytes are size, next 4 reserved?
        # Actually after write_time there is file size (DWORD) then icon index (WORD) then show command (WORD)
        # Let's read correctly: According to spec: after write_time: dwFileSize (DWORD), dwIconIndex (DWORD), dwShowCommand (DWORD), dwHotKey (WORD), wReserved1 (WORD), dwReserved2 (DWORD), dwReserved3 (DWORD)
        # We'll re-read: we consumed 4+4+8+8+8 = 32 bytes. Next 4 bytes file size.
        # We already read 8 bytes for file_size incorrectly; fix:
        # Let's restart parsing more clearly.

    # Re-implement with proper offsets
    with open(path, 'rb') as f:
        f.read(4)  # header already checked
        link_flags = struct.unpack('<I', f.read(4))[0]
        file_attributes = struct.unpack('<I', f.read(4))[0]
        creation_time = struct.unpack('<Q', f.read(8))[0]
        access_time = struct.unpack('<Q', f.read(8))[0]
        write_time = struct.unpack('<Q', f.read(8))[0]
        file_size = struct.unpack('<I', f.read(4))[0]
        icon_index = struct.unpack('<I', f.read(4))[0]
        show_command = struct.unpack('<I', f.read(4))[0]
        hot_key = struct.unpack('<H', f.read(2))[0]
        f.read(2)  # wReserved1
        f.read(4)  # dwReserved2
        f.read(4)  # dwReserved3

        # Determine if strings are Unicode
        is_unicode = bool(link_flags & 0x0400)  # HasUnicodeString? Actually flag 0x0400: IsUnicode
        # According to MSDN: bit 10 (0x0400) indicates Unicode strings.

        def read_string():
            length_bytes = f.read(2)
            if not length_bytes:
                raise EOFError
            length = struct.unpack('<H', length_bytes)[0]
            if length == 0xFFFF:
                # 32-bit length follows
                length = struct.unpack('<I', f.read(4))[0]
            if is_unicode:
                data = f.read(length * 2)
                try:
                    return data.decode('utf-16-le')
                except UnicodeDecodeError:
                    return data.decode('utf-16-le', 'replace')
            else:
                data = f.read(length)
                try:
                    return data.decode('cp1252')
                except UnicodeDecodeError:
                    return data.decode('cp1252', 'replace')

        # Helper to conditionally read a string if flag set
        def maybe_read_string(flag):
            if link_flags & flag:
                return read_string()
            else:
                return None

        # The order of optional strings: Name, RelativePath, WorkingDir, CommandLineArgs, IconLocation
        # According to spec: after the fixed header, if HasName flag set, then Name string, etc.
        name_string = maybe_read_string(0x0004)   # HasName
        relative_path = maybe_read_string(0x0008) # HasRelativePath
        working_dir = maybe_read_string(0x0010)   # HasWorkingDir
        command_line_arguments = maybe_read_string(0x0020) # HasArguments
        icon_location = maybe_read_string(0x0040) # HasIconLocation

        # The rest of the file (LinkTargetIDList, LinkInfo) we ignore for required fields.

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

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python parser.py <path-to-lnk-file>\n")
        sys.exit(2)
    lnk_path = sys.argv[1]
    if not os.path.isfile(lnk_path):
        sys.stderr.write("File not found\n")
        sys.exit(1)
    try:
        data = parse_lnk(lnk_path)
    except Exception as e:
        sys.stderr.write(f"Error parsing LNK: {e}\n")
        # According to spec, we can either exit non-zero or output error JSON.
        # We'll output error JSON and exit 0 to satisfy both options.
        print(json.dumps({"error": str(e)}))
        sys.exit(0)
    # Ensure null for missing strings (already None)
    print(json.dumps(data, ensure_ascii=False))
    sys.exit(0)

if __name__ == "__main__":
    main()