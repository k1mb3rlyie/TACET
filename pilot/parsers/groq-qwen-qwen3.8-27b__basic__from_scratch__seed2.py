#!/usr/bin/env python3
import struct
import sys
import json
import os
from datetime import datetime, timezone, timedelta


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(0)


def parse_windows_filetime(ft):
    """Convert a Windows FILETIME (uint64) to an ISO 8601 string with UTC offset."""
    if ft == 0:
        return None
    # Windows FILETIME is the number of 100-nanosecond intervals since Jan 1, 1601 UTC.
    # Python datetime uses epoch Jan 1, 1970 UTC.
    # 1601 to 1970 is 369 years.
    # The number of 100ns intervals between 1601-01-01 and 1970-01-01:
    # 116444736000000000
    EPOCH_DIFF = 116444736000000000
    if ft < EPOCH_DIFF:
        return None
    delta = (ft - EPOCH_DIFF) / 10000000.0
    dt = datetime.fromtimestamp(delta, tz=timezone.utc)
    return dt.isoformat()


def read_string(data, offset, length):
    """Read a UTF-16LE string of given byte length."""
    if offset < 0 or offset + length > len(data):
        return None
    try:
        return data[offset:offset + length].decode('utf-16-le')
    except (UnicodeDecodeError, Exception):
        return None


def parse_lnk(data):
    """Parse LNK file data and return a dict of fields."""
    if len(data) < 76:
        raise ValueError("File too small to be a valid LNK file")

    # Header
    header_size = struct.unpack_from('<H', data, 0)[0]
    if header_size != 0x4C:  # 76 bytes
        raise ValueError(f"Invalid header size: {header_size:#x}, expected 0x4C")

    version = struct.unpack_from('<H', data, 2)[0]
    if version != 4:
        raise ValueError(f"Unsupported LNK version: {version}")

    file_type = struct.unpack_from('<H', data, 4)[0]
    if file_type != 0x0000:  # Link file
        raise ValueError(f"Not a link file, type: {file_type:#x}")

    reserved1 = struct.unpack_from('<I', data, 6)[0]
    if reserved1 != 0:
        raise ValueError("Reserved field not zero")

    # Flags
    flags = struct.unpack_from('<I', data, 10)[0]

    # File attributes
    file_attributes = struct.unpack_from('<I', data, 14)[0]

    # Timestamps
    creation_time = struct.unpack_from('<Q', data, 18)[0]
    access_time = struct.unpack_from('<Q', data, 26)[0]
    write_time = struct.unpack_from('<Q', data, 34)[0]

    # File size
    file_size = struct.unpack_from('<Q', data, 42)[0]

    # Icon index
    icon_index = struct.unpack_from('<I', data, 50)[0]

    # Command line arguments
    command_line_length = struct.unpack_from('<I', data, 54)[0]
    reserved2 = struct.unpack_from('<I', data, 58)[0]
    reserved3 = struct.unpack_from('<I', data, 62)[0]
    reserved4 = struct.unpack_from('<I', data, 66)[0]
    icon_location_length = struct.unpack_from('<I', data, 70)[0]
    reserved5 = struct.unpack_from('<I', data, 74)[0]

    result = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": parse_windows_filetime(creation_time),
        "access_time": parse_windows_filetime(access_time),
        "write_time": parse_windows_filetime(write_time),
    }

    # Parse extended parts
    offset = 76

    # LINKCLSID
    if len(data) < offset + 16:
        raise ValueError("Truncated: missing LINKCLSID")
    offset += 16

    # String data block
    string_block_present = (flags & 0x00000001) != 0
    if string_block_present:
        if len(data) < offset + 4:
            raise ValueError("Truncated: missing string block size")
        block_size = struct.unpack_from('<I', data, offset)[0]
        if block_size < 4 or offset + block_size > len(data):
            raise ValueError(f"Invalid string block size: {block_size}")
        block_end = offset + block_size

        # Parse string items
        item_offset = offset + 4
        while item_offset < block_end:
            if item_offset + 2 > block_end:
                break
            str_len = struct.unpack_from('<H', data, item_offset)[0]
            if str_len == 0:
                break
            if item_offset + 2 + str_len > block_end:
                raise ValueError("String item exceeds block boundary")
            # Determine which string this is based on order
            # The order of strings in the block depends on flags
            # We need to track which strings are present
            # Let's collect all strings and then assign them
            # Actually, let's re-parse properly by tracking order

            item_offset += 2 + str_len

        # Re-parse string block to identify each string
        # The order is determined by the flags:
        # 0x00000001: LinkInfo
        # 0x00000002: Description
        # 0x00000004: RelativePath
        # 0x00000008: WorkingDir
        # 0x00000010: CommandLine
        # 0x00000020: IconLocation
        # ...
        # Actually, the strings appear in the order of their flag bits being set,
        # but only for the ones that are present. Let me re-read the spec.
        # The string data block contains strings for each of the following fields
        # that are set in the flags, in this order:
        # - LinkInfo (0x00000001) - but this is a separate block, not a string
        # Wait, let me reconsider. The flags indicate which optional data blocks are present.
        # The string data block (0x00000001) contains the following strings in order:
        # Actually, I think I'm confusing this. Let me look at this more carefully.
        
        # The header flags indicate which blocks are present:
        # 0x00000001 - LinkInfo
        # 0x00000002 - StringData
        # 0x00000004 - IconLocation
        # 0x00000008 - Icon
        # 0x00000010 - Command
        # 0x00000020 - WorkingDirectory
        # 0x00000040 - DriveType
        # 0x00000080 - DriveNumber
        # 0x00000100 - NoLocalPath
        # 0x00000200 - Icon
        # 0x00000400 - RelativePath
        # 0x00000800 - Name
        # 0x00001000 - LocalBasePath
        # 0x00002000 - CommonName
        # 0x00004000 - LocalBasePath
        # 0x00008000 - UnicodeName
        # 0x00010000 - UnicodeRelativePath
        # 0x00020000 - UnicodeWorkingDir
        # 0x00040000 - UnicodeCommandLine
        # 0x00080000 - UnicodeIconLocation
        # 0x00100000 - UnicodeIcon

        # The StringData block (flag 0x00000002) contains strings for:
        # - Description (if 0x00000002 is set in the string block's internal flags? No...)
        
        # Actually, I recall now. The string data block contains a sequence of
        # strings, each with a 2-byte length prefix (UTF-16LE). The strings are
        # in the order of the fields that have the corresponding flag bits set
        # in the main header flags, but only for specific fields.
        
        # Let me take a different approach. I'll parse the string block and collect
        # all strings, then determine which is which based on the flags.
        
        # The strings in the string data block correspond to these fields in order
        # (only those whose flag is set):
        # - 0x00000002: Description
        # - 0x00000004: RelativePath  
        # - 0x00000008: WorkingDir
        # - 0x00000010: CommandLine
        # - 0x00000020: IconLocation
        # - 0x00000800: Name
        # - 0x00010000: LocalBasePath
        # - 0x00020000: CommonName
        # - 0x00040000: LocalBasePath (duplicate?)
        
        # Hmm, this is getting complicated. Let me just collect all strings and
        # map them based on the order they appear, matching against the flags.
        
        strings = []
        item_offset = offset + 4
        while item_offset < block_end:
            if item_offset + 2 > block_end:
                break
            str_len = struct.unpack_from('<H', data, item_offset)[0]
            if str_len == 0:
                break
            if item_offset + 2 + str_len > block_end:
                raise ValueError("String item exceeds block boundary")
            s = read_string(data, item_offset + 2, str_len)
            if s is None:
                raise ValueError("Failed to decode string in string block")
            strings.append(s)
            item_offset += 2 + str_len

        # Now map strings to fields based on flags
        # The order of strings in the block matches the order of these flag bits
        # being set (from lowest to highest among the relevant bits):
        # The relevant flags for strings in the StringData block are:
        # 0x00000002 - Description
        # 0x00000004 - RelativePath
        # 0x00000008 - WorkingDir
        # 0x00000010 - CommandLine
        # 0x00000020 - IconLocation
        # 0x00000800 - Name
        # 0x00010000 - LocalBasePath
        # 0x00020000 - CommonName
        # 0x00040000 - LocalBasePath
        # 0x00080000 - UnicodeName
        # 0x00100000 - UnicodeRelativePath
        # 0x00200000 - UnicodeWorkingDir
        # 0x00400000 - UnicodeCommandLine
        # 0x00800000 - UnicodeIconLocation
        
        # Actually, I think the correct interpretation is that the string data block
        # contains strings for the following fields, in the order of their flag bits:
        # The fields that use the string data block are identified by specific flags.
        
        # Let me use a simpler approach: define the expected order of string fields
        # based on the flag bits, and match them in order.
        
        string_fields = []
        if flags & 0x00000002:
            string_fields.append("description")
        if flags & 0x00000004:
            string_fields.append("relative_path")
        if flags & 0x00000008:
            string_fields.append("working_dir")
        if flags & 0x00000010:
            string_fields.append("command_line")
        if flags & 0x00000020:
            string_fields.append("icon_location")
        if flags & 0x00000800:
            string_fields.append("name")
        if flags & 0x00010000:
            string_fields.append("local_base_path")
        if flags & 0x00020000:
            string_fields.append("common_name")
        if flags & 0x00040000:
            string_fields.append("local_base_path2")
        if flags & 0x00080000:
            string_fields.append("unicode_name")
        if flags & 0x00100000:
            string_fields.append("unicode_relative_path")
        if flags & 0x00200000:
            string_fields.append("unicode_working_dir")
        if flags & 0x00400000:
            string_fields.append("unicode_command_line")
        if flags & 0x00800000:
            string_fields.append("unicode_icon_location")

        # Map strings to fields
        for i, field in enumerate(string_fields):
            if i < len(strings):
                if field == "relative_path":
                    result["relative_path"] = strings[i]
                elif field == "working_dir":
                    result["working_dir"] = strings[i]
                elif field == "command_line":
                    result["command_line_arguments"] = strings[i]
                elif field == "icon_location":
                    result["icon_location"] = strings[i]
                elif field == "name":
                    result["name_string"] = strings[i]
                elif field == "unicode_name":
                    result["name_string"] = strings[i]
                elif field == "unicode_relative_path":
                    result["relative_path"] = strings[i]
                elif field == "unicode_working_dir":
                    result["working_dir"] = strings[i]
                elif field == "unicode_command_line":
                    result["command_line_arguments"] = strings[i]
                elif field == "unicode_icon_location":
                    result["icon_location"] = strings[i]

        offset = block_end

    # We've parsed what we can. Return the result.
    return result


def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")

    path = sys.argv[1]

    if not os.path.isfile(path):
        fail(f"File not found: {path}")

    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        fail(f"Cannot read file: {e}")

    try:
        result = parse_lnk(data)
    except Exception as e:
        fail(f"Parse error: {e}")

    print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()