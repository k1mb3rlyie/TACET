#!/usr/bin/env python3
import sys
import os
import json
import struct
import datetime


def parse_windows_filetime(value):
    """Convert Windows FILETIME (100-nanosecond intervals since 1601-01-01) to ISO 8601 with UTC offset."""
    if value == 0:
        return None
    # Windows epoch: 1601-01-01 00:00:00 UTC
    # Python datetime.min is 0001-01-01
    # We need to handle the range carefully
    try:
        # Convert to seconds since 1601
        seconds_since_1601 = value / 10000000.0
        # Python's datetime can handle dates from 1 to 9999
        # 1601 is within range
        # datetime(1601, 1, 1) + timedelta(seconds=seconds_since_1601)
        epoch_1601 = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = epoch_1601 + datetime.timedelta(seconds=seconds_since_1601)
        return dt.isoformat()
    except (OverflowError, ValueError, OSError):
        return None


def read_string(data, offset, length):
    """Read a UTF-16LE string from data at offset with given byte length."""
    if offset + length > len(data):
        raise ValueError("String read out of bounds")
    raw = data[offset:offset + length]
    # Decode as UTF-16LE
    s = raw.decode('utf-16-le')
    # Remove null terminators if present
    s = s.rstrip('\x00')
    return s


def parse_lnk(data):
    """Parse an LNK file and return the metadata dictionary."""
    if len(data) < 4:
        raise ValueError("File too short to be a valid LNK file")
    
    # Header
    # 4-byte signature: 0x4C 0x00 0x00 0x00
    header_sig = struct.unpack_from('<I', data, 0)[0]
    if header_sig != 0x0000004C:
        raise ValueError("Invalid LNK header signature")
    
    # We don't strictly need all header fields for our output, but let's validate
    # LinkInfoSize: 2 bytes at offset 4
    # LinkFlags: 4 bytes at offset 6
    # FileAttributes: 4 bytes at offset 10
    # CreationTime: 8 bytes at offset 14
    # AccessTime: 8 bytes at offset 22
    # WriteTime: 8 bytes at offset 30
    # BaseNameLength: 4 bytes at offset 38
    # CommandLineLength: 4 bytes at offset 42
    # IconLocationLength: 4 bytes at offset 46
    # IconIndex: 4 bytes at offset 50
    # RelativePathLength: 4 bytes at offset 54
    # WorkingDirectoryLength: 4 bytes at offset 58
    # Filler1: 2 bytes at offset 62
    # Filler2: 10 bytes at offset 64
    # Header is 76 bytes total
    
    if len(data) < 76:
        raise ValueError("File truncated: header incomplete")
    
    (link_info_size,
     link_flags,
     file_attributes,
     creation_time_raw,
     access_time_raw,
     write_time_raw,
     base_name_length,
     command_line_length,
     icon_location_length,
     icon_index,
     relative_path_length,
     working_directory_length,
     filler1,
     filler2) = struct.unpack_from('<HIIQQIII IIII', data, 4)
    
    # The struct format above: H(2) I(4) I(4) Q(8) Q(8) Q(8) I(4) I(4) I(4) I(4) I(4) I(4) I(4) H(2) 10s
    # Let me recount: offset 4
    # H: 2 bytes -> offset 4-5
    # I: 4 bytes -> offset 6-9 (link_flags)
    # I: 4 bytes -> offset 10-13 (file_attributes)
    # Q: 8 bytes -> offset 14-21 (creation_time)
    # Q: 8 bytes -> offset 22-29 (access_time)
    # Q: 8 bytes -> offset 30-37 (write_time)
    # I: 4 bytes -> offset 38-41 (base_name_length)
    # I: 4 bytes -> offset 42-45 (command_line_length)
    # I: 4 bytes -> offset 46-49 (icon_location_length)
    # I: 4 bytes -> offset 50-53 (icon_index)
    # I: 4 bytes -> offset 54-57 (relative_path_length)
    # I: 4 bytes -> offset 58-61 (working_directory_length)
    # H: 2 bytes -> offset 62-63 (filler1)
    # 10s: 10 bytes -> offset 64-73 (filler2)
    # Total: 2+4+4+8+8+8+4+4+4+4+4+4+2+10 = 70 bytes from offset 4, so ends at offset 74
    # But standard says header is 76 bytes. Let me check.
    
    # Actually, the standard LNK header is:
    # 0: 4-byte signature
    # 4: 2-byte LinkInfoSize
    # 6: 4-byte LinkFlags
    # 10: 4-byte FileAttributes
    # 14: 8-byte CreationTime
    # 22: 8-byte AccessTime
    # 30: 8-byte WriteTime
    # 38: 4-byte BaseNameLength
    # 42: 4-byte CommandLineLength
    # 46: 4-byte IconLocationLength
    # 50: 4-byte IconIndex
    # 54: 4-byte RelativePathLength
    # 58: 4-byte WorkingDirectoryLength
    # 62: 2-byte Filler1
    # 64: 10-byte Filler2
    # Total: 76 bytes
    
    # My struct: starting at offset 4
    # H (2) -> 4-5
    # I (4) -> 6-9
    # I (4) -> 10-13
    # Q (8) -> 14-21
    # Q (8) -> 22-29
    # Q (8) -> 30-37
    # I (4) -> 38-41
    # I (4) -> 42-45
    # I (4) -> 46-49
    # I (4) -> 50-53
    # I (4) -> 54-57
    # I (4) -> 58-61
    # H (2) -> 62-63
    # 10s (10) -> 64-73
    # That's 70 bytes, ending at offset 74. But it should end at 76.
    # Ah, I see. The struct format '<HIIQQIII IIII H10s' - let me count the I's.
    # After QQQ, we have IIIII II H 10s
    # Let me just unpack them individually to be safe.
    
    # Re-parse to be explicit
    offset = 4
    link_info_size = struct.unpack_from('<H', data, offset)[0]; offset += 2
    link_flags = struct.unpack_from('<I', data, offset)[0]; offset += 4
    file_attributes = struct.unpack_from('<I', data, offset)[0]; offset += 4
    creation_time_raw = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    access_time_raw = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    write_time_raw = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    base_name_length = struct.unpack_from('<I', data, offset)[0]; offset += 4
    command_line_length = struct.unpack_from('<I', data, offset)[0]; offset += 4
    icon_location_length = struct.unpack_from('<I', data, offset)[0]; offset += 4
    icon_index = struct.unpack_from('<I', data, offset)[0]; offset += 4
    relative_path_length = struct.unpack_from('<I', data, offset)[0]; offset += 4
    working_directory_length = struct.unpack_from('<I', data, offset)[0]; offset += 4
    filler1 = struct.unpack_from('<H', data, offset)[0]; offset += 2
    filler2 = data[offset:offset+10]; offset += 10
    
    # Now offset should be 76
    if offset != 76:
        raise ValueError("Header parsing error: offset mismatch")
    
    # Parse timestamps
    creation_time = parse_windows_filetime(creation_time_raw)
    access_time = parse_windows_filetime(access_time_raw)
    write_time = parse_windows_filetime(write_time_raw)
    
    # Parse strings based on flags
    name_string = None
    command_line_arguments = None
    icon_location = None
    relative_path = None
    working_dir = None
    
    # Flag 1: HasBaseName
    if link_flags & 0x00000001:
        if offset + base_name_length > len(data):
            raise ValueError("BaseName string out of bounds")
        name_string = read_string(data, offset, base_name_length)
        offset += base_name_length
    
    # Flag 2: HasWorkingDirectory
    if link_flags & 0x00000002:
        if offset + working_directory_length > len(data):
            raise ValueError("WorkingDirectory string out of bounds")
        working_dir = read_string(data, offset, working_directory_length)
        offset += working_directory_length
    
    # Flag 4: HasArguments
    if link_flags & 0x00000004:
        if offset + command_line_length > len(data):
            raise ValueError("Arguments string out of bounds")
        command_line_arguments = read_string(data, offset, command_line_length)
        offset += command_line_length
    
    # Flag 8: HasIconLocation
    if link_flags & 0x00000008:
        if offset + icon_location_length > len(data):
            raise ValueError("IconLocation string out of bounds")
        icon_location = read_string(data, offset, icon_location_length)
        offset += icon_location_length
    
    # Flag 16: HasRelativePath
    if link_flags & 0x00000010:
        if offset + relative_path_length > len(data):
            raise ValueError("RelativePath string out of bounds")
        relative_path = read_string(data, offset, relative_path_length)
        offset += relative_path_length
    
    # If any of these flags are set but the length is 0, the string is empty
    # But per the contract, absent should be null. If the flag is set, the field is present.
    # An empty string is a valid value if the flag is set and length is 0.
    # However, if the flag is NOT set, the field is absent -> null.
    
    return {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": 0,
        "icon_index": icon_index,
        "creation_time": creation_time,
        "access_time": access_time,
        "write_time": write_time
    }


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: parser.py <path-to-lnk-file>"}))
        sys.exit(1)
    
    path = sys.argv[1]
    
    try:
        if not os.path.isfile(path):
            print(json.dumps({"error": f"File not found: {path}"}))
            sys.exit(0)
        
        with open(path, 'rb') as f:
            data = f.read()
        
        result = parse_lnk(data)
        print(json.dumps(result))
        sys.exit(0)
    
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(0)


if __name__ == "__main__":
    main()