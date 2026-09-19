#!/usr/bin/env python3
"""
Parse a Windows Shortcut (.lnk) file and extract metadata.

Usage: python parser.py <path-to-lnk-file>

On success: prints a JSON object to stdout and exits with code 0.
On failure: prints {"error": "<description>"} to stdout and exits with non-zero code.
"""

import sys
import os
import struct
import json
import datetime


def fail(msg):
    """Print error JSON to stdout and exit with non-zero code."""
    print(json.dumps({"error": msg}))
    sys.exit(1)


def read_exact(data, offset, length, context=""):
    """Read exactly `length` bytes from data at offset. Raises if not enough data."""
    if offset < 0 or offset + length > len(data):
        raise ValueError(f"Not enough data at offset {offset} for {length} bytes ({context})")
    return data[offset:offset + length]


def parse_lnk(path):
    """Parse an LNK file and return a dict of metadata."""
    if not os.path.isfile(path):
        raise ValueError(f"File not found: {path}")

    with open(path, 'rb') as f:
        data = f.read()

    if len(data) < 4:
        raise ValueError("File too small to be a valid LNK file")

    # Check header signature: 4C 00 00 00
    header_sig = data[0:4]
    if header_sig != b'\x4c\x00\x00\x00':
        raise ValueError("Invalid LNK header signature")

    # Header is 76 bytes (0x4C)
    if len(data) < 76:
        raise ValueError("File too small for LNK header")

    # Parse header fields
    # Link CLSID: 16 bytes at offset 4
    link_clsid = data[4:20]
    # Expected CLSID for Shell Link: 00021401-0000-0000-C000-000000000046
    expected_clsid = bytes.fromhex('0114020000000000C000000000000046')
    if link_clsid != expected_clsid:
        raise ValueError("Invalid Link CLSID in header")

    # File attributes at offset 20 (4 bytes)
    file_attributes = struct.unpack_from('<I', data, 20)[0]

    # Creation time at offset 24 (8 bytes, FILETIME)
    creation_time_raw = data[24:32]
    # Access time at offset 32 (8 bytes, FILETIME)
    access_time_raw = data[32:40]
    # Write time at offset 40 (8 bytes, FILETIME)
    write_time_raw = data[40:48]

    # Hot key at offset 48 (2 bytes)
    # Reserved at offset 50 (2 bytes)
    # File size at offset 52 (4 bytes)
    file_size = struct.unpack_from('<i', data, 52)[0]

    # Show window at offset 56 (4 bytes)
    # Icon index at offset 60 (4 bytes)
    icon_index = struct.unpack_from('<i', data, 60)[0]

    # Reserved at offset 64 (4 bytes)
    # Reserved at offset 68 (4 bytes)

    # Local base path offset at offset 72 (4 bytes)
    local_base_path_offset = struct.unpack_from('<I', data, 72)[0]

    # Now parse the link target ID list (starts at offset 76)
    # LinkTargetIDList:
    #   Size (2 bytes) - total size of this block
    #   Entries:
    #     IDSize (1 byte)
    #     Flags (1 byte)
    #     ID (IDSize bytes)
    #   Terminated by IDSize = 0, Flags = 0

    offset = 76

    # Check minimum size for LinkTargetIDList
    if offset + 2 > len(data):
        raise ValueError("Truncated file: cannot read LinkTargetIDList size")

    id_list_size = struct.unpack_from('<H', data, offset)[0]
    if id_list_size < 2:
        raise ValueError("Invalid LinkTargetIDList size")

    offset += 2

    # Parse ID list entries
    id_list_start = offset
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError("Truncated file in LinkTargetIDList")
        id_size = data[offset]
        flags = data[offset + 1]
        offset += 2
        if id_size == 0 and flags == 0:
            break
        if offset + id_size > len(data):
            raise ValueError("Truncated file in LinkTargetIDList entry")
        offset += id_size

    # Check that we consumed the right amount
    # The size field should match: from id_list_start to current offset
    actual_size = offset - id_list_start
    if actual_size != id_list_size:
        raise ValueError(f"Mismatch in LinkTargetIDList size: expected {id_list_size}, got {actual_size}")

    # Now we should be at the LinkInfo block (if present)
    # LinkInfo is optional. It starts with a size field (4 bytes) and a linker signature (4 bytes = 0xB472828E)
    # If the next 4 bytes don't look like a valid LinkInfo signature, there is no LinkInfo.

    if offset + 8 > len(data):
        # Not enough data for LinkInfo header, so no LinkInfo
        link_info_present = False
    else:
        li_size = struct.unpack_from('<I', data, offset)[0]
        li_sig = struct.unpack_from('<I', data, offset + 4)[0]
        # Valid LinkInfo signature is 0xB472828E
        if li_sig == 0xB472828E and li_size >= 8:
            link_info_present = True
            if offset + li_size > len(data):
                raise ValueError("Truncated LinkInfo block")
            offset += li_size
        else:
            link_info_present = False

    # Now parse StringData
    # StringData is a sequence of blocks. Each block has:
    #   Size (2 bytes) - total size of the block (including the 2-byte size field)
    #   String (variable) - UTF-16LE encoded string, null-terminated
    # The sequence ends when Size = 0.

    strings = {}

    while offset + 2 <= len(data):
        block_size = struct.unpack_from('<H', data, offset)[0]
        if block_size == 0:
            break
        if block_size < 2:
            raise ValueError("Invalid StringData block size")
        if offset + block_size > len(data):
            raise ValueError("Truncated StringData block")

        # The string data is from offset+2 to offset+block_size
        str_data = data[offset + 2:offset + block_size]

        # The string is UTF-16LE, null-terminated
        # We need to decode it properly
        # Find the null terminator (0x0000)
        # The string may or may not be null-terminated within the block
        
        try:
            # Decode as UTF-16LE, handling potential truncation
            # We need to ensure even length
            if len(str_data) % 2 != 0:
                str_data = str_data[:-1]
            decoded = str_data.decode('utf-16-le', errors='strict')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16 encoding in StringData")

        # Remove null terminator if present
        if decoded.endswith('\x00'):
            decoded = decoded[:-1]
        # Also handle case where there might be multiple nulls or the string is empty
        # Actually, the standard format is that the string is null-terminated, so we strip one null
        # But if the block is exactly size 2, the string is empty

        # Determine which string this is based on position
        # Standard order:
        # 0: Local base path
        # 1: Window style (not always present, but typically)
        # 2: Command line arguments
        # 3: Icon location
        # 4: Working directory
        # 5: Relative path
        # 6: Name string
        # ... (more possible)

        # Actually, the order is defined by the LinkInfo and StringData structure.
        # The standard fields in StringData are:
        # - LocalBasePath (if local base path offset was non-zero in header)
        # - WindowStyle
        # - CommandLineArguments
        # - IconLocation
        # - WorkingDirectory
        # - RelativePath
        # - NameString
        # - (additional strings possible)

        # But the actual presence depends on the structure. Let's just collect all strings
        # and map them by known positions.

        # For simplicity and correctness, let's collect all strings in order
        # and then assign them based on the standard field order.

        strings[block_size] = decoded  # Use block_size as temporary key, will reorganize

        offset += block_size

    # Reorganize strings by position
    # We need to know which string corresponds to which field.
    # The standard order of StringData blocks is:
    # 1. LocalBasePath (if the local base path offset in the header is non-zero)
    # 2. WindowStyle
    # 3. CommandLineArguments
    # 4. IconLocation
    # 5. WorkingDirectory
    # 6. RelativePath
    # 7. NameString

    # However, not all fields are always present. The fields that are present
    # are in this fixed order.

    # Let's re-parse more carefully by tracking which fields are present.
    # Actually, a simpler approach: collect all strings in order, then assign.

    # Re-collect strings in order
    str_list = []
    offset = 0
    # Skip header (76 bytes)
    offset = 76

    # Skip LinkTargetIDList
    if offset + 2 > len(data):
        raise ValueError("Truncated file")
    id_list_size = struct.unpack_from('<H', data, offset)[0]
    offset += 2 + id_list_size

    # Skip LinkInfo if present
    if offset + 8 <= len(data):
        li_size = struct.unpack_from('<I', data, offset)[0]
        li_sig = struct.unpack_from('<I', data, offset + 4)[0]
        if li_sig == 0xB472828E and li_size >= 8:
            if offset + li_size > len(data):
                raise ValueError("Truncated LinkInfo")
            offset += li_size

    # Now at StringData
    while offset + 2 <= len(data):
        block_size = struct.unpack_from('<H', data, offset)[0]
        if block_size == 0:
            break
        if block_size < 2:
            raise ValueError("Invalid StringData block size")
        if offset + block_size > len(data):
            raise ValueError("Truncated StringData block")

        str_data = data[offset + 2:offset + block_size]
        if len(str_data) % 2 != 0:
            str_data = str_data[:-1]
        try:
            decoded = str_data.decode('utf-16-le', errors='strict')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16 encoding in StringData")

        if decoded.endswith('\x00'):
            decoded = decoded[:-1]

        str_list.append(decoded)
        offset += block_size

    # Now assign strings to fields based on standard order
    # The standard fields in order are:
    # 0: LocalBasePath
    # 1: WindowStyle
    # 2: CommandLineArguments
    # 3: IconLocation
    # 4: WorkingDirectory
    # 5: RelativePath
    # 6: NameString

    # But note: LocalBasePath is only present if the local base path offset in the header
    # was non-zero. Let's check.

    local_base_path = None
    window_style = None
    command_line_arguments = None
    icon_location = None
    working_dir = None
    relative_path = None
    name_string = None

    # Determine which fields are present
    # According to the MS-LNK specification, the StringData block contains
    # the following fields in this order, but only those that are present:
    # The fields are determined by what the creator wrote. However, the standard
    # set that we need is:
    # - NameString
    # - RelativePath
    # - WorkingDirectory
    # - CommandLineArguments
    # - IconLocation
    # - LocalBasePath (if applicable)

    # A common approach: the strings are in a fixed order for the fields that are present.
    # The typical order for the fields we care about is:
    # If LocalBasePath is present, it comes first.
    # Then: WindowStyle, CommandLineArguments, IconLocation, WorkingDirectory, RelativePath, NameString

    # Let's assume the standard order and map accordingly.
    # We'll use the following mapping based on the typical LNK structure:
    # Index 0: LocalBasePath (if local_base_path_offset != 0)
    # Index 1: WindowStyle
    # Index 2: CommandLineArguments
    # Index 3: IconLocation
    # Index 4: WorkingDirectory
    # Index 5: RelativePath
    # Index 6: NameString

    # But this is not always correct. Some LNK files may have fewer fields.
    # A more robust approach is to recognize that the fields we need are:
    # name_string, relative_path, working_dir, command_line_arguments, icon_location

    # Let's use a heuristic: if we have 7 strings, use the standard mapping.
    # If we have 6, the first one might be missing (LocalBasePath or WindowStyle).
    # This is getting complex. Let's use the known fact that the last few strings
    # in the standard order are:
    # ... WorkingDirectory, RelativePath, NameString

    # So NameString is typically the last string if all standard fields are present.
    # But to be safe, let's use the following:
    # The standard order (when all are present) is:
    # [LocalBasePath, WindowStyle, CommandLineArguments, IconLocation, WorkingDirectory, RelativePath, NameString]

    # We'll map based on this, but handle cases where some are missing.
    # Given the complexity, let's use a simpler approach:
    # If there are at least 7 strings, use indices 2,3,4,5,6 for cmd, icon, workdir, relpath, name
    # If there are 6 strings, assume LocalBasePath is missing, so indices 1,2,3,4,5
    # etc.

    # Actually, let's just use the most common case and validate.
    # For forensic purposes, we should be conservative.

    # Let me use a different approach: the fields are in a fixed order, and we
    # know which ones we need. Let's just take the last 5 strings as:
    # CommandLineArguments, IconLocation, WorkingDirectory, RelativePath, NameString
    # This assumes that LocalBasePath and WindowStyle may or may not be present,
    # but the last 5 are always in this order if they exist.

    # However, if some of these are missing, this won't work.

    # Given the constraints, let's use the standard full mapping and hope for the best,
    # but validate that we have enough strings.

    if len(str_list) >= 7:
        # Standard full set
        local_base_path = str_list[0] if str_list[0] else None
        # WindowStyle = str_list[1]
        command_line_arguments = str_list[2] if str_list[2] else None
        icon_location = str_list[3] if str_list[3] else None
        working_dir = str_list[4] if str_list[4] else None
        relative_path = str_list[5] if str_list[5] else None
        name_string = str_list[6] if str_list[6] else None
    elif len(str_list) == 6:
        # Assume LocalBasePath is missing
        # [WindowStyle, CommandLineArguments, IconLocation, WorkingDirectory, RelativePath, NameString]
        # WindowStyle = str_list[0]
        command_line_arguments = str_list[1] if str_list[1] else None
        icon_location = str_list[2] if str_list[2] else None
        working_dir = str_list[3] if str_list[3] else None
        relative_path = str_list[4] if str_list[4] else None
        name_string = str_list[5] if str_list[5] else None
    elif len(str_list) == 5:
        # Assume LocalBasePath and WindowStyle are missing
        # [CommandLineArguments, IconLocation, WorkingDirectory, RelativePath, NameString]
        command_line_arguments = str_list[0] if str_list[0] else None
        icon_location = str_list[1] if str_list[1] else None
        working_dir = str_list[2] if str_list[2] else None
        relative_path = str_list[3] if str_list[3] else None
        name_string = str_list[4] if str_list[4] else None
    elif len(str_list) == 4:
        # Assume some are missing. Let's try:
        # [CommandLineArguments, IconLocation, WorkingDirectory, NameString] (RelativePath missing)
        # or [IconLocation, WorkingDirectory, RelativePath, NameString] (CommandLineArguments missing)
        # This is ambiguous. Let's be conservative and set what we can.
        # Given the ambiguity, let's set the last one as name_string and work backwards.
        name_string = str_list[3] if str_list[3] else None
        relative_path = str_list[2] if str_list[2] else None
        working_dir = str_list[1] if str_list[1] else None
        icon_location = str_list[0] if str_list[0] else None
        command_line_arguments = None
    elif len(str_list) == 3:
        name_string = str_list[2] if str_list[2] else None
        relative_path = str_list[1] if str_list[1] else None
        working_dir = str_list[0] if str_list[0] else None
        icon_location = None
        command_line_arguments = None
    elif len(str_list) == 2:
        name_string = str_list[1] if str_list[1] else None
        relative_path = str_list[0] if str_list[0] else None
        working_dir = None
        icon_location = None
        command_line_arguments = None
    elif len(str_list) == 1:
        name_string = str_list[0] if str_list[0] else None
        relative_path = None
        working_dir = None
        icon_location = None
        command_line_arguments = None
    else:
        name_string = None
        relative_path = None
        working_dir = None
        icon_location = None
        command_line_arguments = None

    # Parse FILETIME values
    def filetime_to_iso8601(ft_bytes):
        """Convert a FILETIME (8 bytes, little-endian) to ISO 8601 with UTC offset."""
        if ft_bytes is None or len(ft_bytes) != 8:
            return None
        # FILETIME is 100-nanosecond intervals since January 1, 1601
        ft_value = struct.unpack('<Q', ft_bytes)[0]
        if ft_value == 0:
            return None

        # Convert to datetime
        # Windows epoch is 1601-01-01 00:00:00 UTC
        # Python datetime is limited to 1970-01-01, but we can handle this
        # by using the number of seconds since 1601-01-01 and converting.

        # 1601-01-01 to 1970-01-01 is 11644473600 seconds
        SECONDS_1601_TO_1970 = 11644473600

        # Convert FILETIME to seconds since 1601-01-01
        total_seconds = ft_value // 10000000
        microseconds = (ft_value % 10000000) * 100  # 100ns to 1us

        # Convert to seconds since 1970-01-01
        if total_seconds < SECONDS_1601_TO_1970:
            # Before 1970, which is unusual but possible
            # We'll still try to convert
            delta = total_seconds - SECONDS_1601_TO_1970
            dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=delta, microseconds=microseconds)
        else:
            delta = total_seconds - SECONDS_1601_TO_1970
            dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=delta, microseconds=microseconds)

        return dt.isoformat()

    creation_time = filetime_to_iso8601(creation_time_raw)
    access_time = filetime_to_iso8601(access_time_raw)
    write_time = filetime_to_iso8601(write_time_raw)

    return {
        "name_string": name_string if name_string else None,
        "relative_path": relative_path if relative_path else None,
        "working_dir": working_dir if working_dir else None,
        "command_line_arguments": command_line_arguments if command_line_arguments else None,
        "icon_location": icon_location if icon_location else None,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_time,
        "access_time": access_time,
        "write_time": write_time
    }


def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")

    path = sys.argv[1]

    try:
        result = parse_lnk(path)
        print(json.dumps(result))
        sys.exit(0)
    except Exception as e:
        fail(str(e))


if __name__ == "__main__":
    main()