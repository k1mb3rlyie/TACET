#!/usr/bin/env python3
"""
Parser for Windows Shortcut (.lnk) files for digital forensics.
"""

import sys
import struct
import json
import os
import re
from datetime import datetime, timezone


def fail(msg):
    """Print error JSON and exit with non-zero code."""
    print(json.dumps({"error": msg}))
    sys.exit(1)


def parse_timestamp(buf, offset):
    """Parse a Windows FILETIME (8 bytes, little-endian) to ISO 8601 UTC."""
    if offset + 8 > len(buf):
        return None
    ft = struct.unpack_from("<Q", buf, offset)[0]
    if ft == 0:
        return None
    # Windows FILETIME is 100-nanosecond intervals since Jan 1, 1601
    # Python datetime uses seconds since Jan 1, 1970
    # Difference between 1601-01-01 and 1970-01-01 is 134774 days
    epoch_delta = 134774 * 24 * 3600
    # Convert to seconds and microseconds
    total_seconds = ft // 10_000_000
    microseconds = (ft % 10_000_000) * 100
    
    # Check if the timestamp is valid
    # The minimum valid FILETIME is 0 (1601-01-01), max is around year 3000
    # Let's check if it's reasonable
    if total_seconds < 0:
        return None
    
    # Convert to Python datetime
    # We need to subtract the epoch delta
    adjusted_seconds = total_seconds - epoch_delta
    
    try:
        dt = datetime.fromtimestamp(adjusted_seconds, tz=timezone.utc)
        # Add microseconds
        if microseconds:
            dt = dt.replace(microsecond=dt.microsecond + microseconds)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def extract_string(buf, offset, max_len, encoding='utf-16-le'):
    """Extract a null-terminated string of specified byte length."""
    if offset + max_len > len(buf):
        return None
    data = buf[offset:offset + max_len]
    
    # For UTF-16-LE, find null character
    try:
        # Look for null terminator (0x00 0x00)
        idx = 0
        while idx < len(data) - 1:
            if data[idx] == 0 and data[idx + 1] == 0:
                break
            idx += 2
        else:
            # No null terminator found, use entire string
            idx = len(data)
        
        if idx == 0:
            return ""  # Empty string
        
        return data[:idx].decode(encoding, errors='strict')
    except (UnicodeDecodeError, IndexError):
        return None


def parse_link_flags(buf, offset):
    """Parse the LinkFlags field (4 bytes)."""
    if offset + 4 > len(buf):
        return None
    flags = struct.unpack_from("<I", buf, offset)[0]
    return flags


def parse_string_buffer(buf, offset, is_unicode):
    """
    Parse a string from the LinkInfo or other sections.
    Returns (string_value, new_offset) or (None, None) on error.
    """
    if offset + 2 > len(buf):
        return None, None
    
    if is_unicode:
        # Length is in characters, each char is 2 bytes
        char_len = struct.unpack_from("<H", buf, offset)[0]
        if char_len == 0:
            return "", offset + 2
        byte_len = char_len * 2
        if offset + 2 + byte_len > len(buf):
            return None, None
        data = buf[offset + 2:offset + 2 + byte_len]
        try:
            s = data.decode('utf-16-le', errors='strict')
            return s, offset + 2 + byte_len
        except UnicodeDecodeError:
            return None, None
    else:
        # Length is in bytes
        byte_len = struct.unpack_from("<H", buf, offset)[0]
        if byte_len == 0:
            return "", offset + 2
        if offset + 2 + byte_len > len(buf):
            return None, None
        data = buf[offset + 2:offset + 2 + byte_len]
        try:
            s = data.decode('cp1252', errors='strict')
            return s, offset + 2 + byte_len
        except (UnicodeDecodeError, LookupError):
            return None, None


def parse_local_base_path(buf, offset):
    """Parse the LocalBasePath structure."""
    if offset + 4 > len(buf):
        return None
    size = struct.unpack_from("<I", buf, offset)[0]
    # Size includes the 4-byte length field itself
    if size < 4:
        return None
    if offset + size > len(buf):
        return None
    
    # The string starts after the 4-byte size field
    str_data = buf[offset + 4:offset + size]
    try:
        # Try UTF-16-LE first
        s = str_data.decode('utf-16-le', errors='strict')
        # Remove trailing null if present
        if s.endswith('\x00'):
            s = s[:-1]
        return s
    except UnicodeDecodeError:
        try:
            s = str_data.decode('cp1252', errors='strict')
            if s.endswith('\x00'):
                s = s[:-1]
            return s
        except (UnicodeDecodeError, LookupError):
            return None


def parse_relative_path(buf, offset):
    """Parse the RelativePath structure."""
    if offset + 6 > len(buf):
        return None
    size = struct.unpack_from("<H", buf, offset)[0]
    flags = struct.unpack_from("<H", buf, offset + 2)[0]
    
    if size < 4:
        return None
    if offset + size > len(buf):
        return None
    
    # String starts at offset + 4 (after size and flags)
    str_data = buf[offset + 4:offset + size]
    try:
        if flags & 0x0001:  # UNICODE flag
            s = str_data.decode('utf-16-le', errors='strict')
        else:
            s = str_data.decode('cp1252', errors='strict')
        if s.endswith('\x00'):
            s = s[:-1]
        return s
    except (UnicodeDecodeError, LookupError):
        return None


def parse_command_line_args(buf, offset):
    """Parse the CommandLine structure."""
    if offset + 4 > len(buf):
        return None
    size = struct.unpack_from("<I", buf, offset)[0]
    if size < 4:
        return None
    if offset + size > len(buf):
        return None
    
    str_data = buf[offset + 4:offset + size]
    try:
        s = str_data.decode('utf-16-le', errors='strict')
        if s.endswith('\x00'):
            s = s[:-1]
        return s
    except UnicodeDecodeError:
        try:
            s = str_data.decode('cp1252', errors='strict')
            if s.endswith('\x00'):
                s = s[:-1]
            return s
        except (UnicodeDecodeError, LookupError):
            return None


def parse_working_dir(buf, offset):
    """Parse the WorkingDirectory structure."""
    if offset + 4 > len(buf):
        return None
    size = struct.unpack_from("<I", buf, offset)[0]
    if size < 4:
        return None
    if offset + size > len(buf):
        return None
    
    str_data = buf[offset + 4:offset + size]
    try:
        s = str_data.decode('utf-16-le', errors='strict')
        if s.endswith('\x00'):
            s = s[:-1]
        return s
    except UnicodeDecodeError:
        try:
            s = str_data.decode('cp1252', errors='strict')
            if s.endswith('\x00'):
                s = s[:-1]
            return s
        except (UnicodeDecodeError, LookupError):
            return None


def parse_icon_location(buf, offset):
    """Parse the IconLocation structure."""
    if offset + 4 > len(buf):
        return None
    size = struct.unpack_from("<I", buf, offset)[0]
    if size < 4:
        return None
    if offset + size > len(buf):
        return None
    
    str_data = buf[offset + 4:offset + size]
    try:
        s = str_data.decode('utf-16-le', errors='strict')
        if s.endswith('\x00'):
            s = s[:-1]
        return s
    except UnicodeDecodeError:
        try:
            s = str_data.decode('cp1252', errors='strict')
            if s.endswith('\x00'):
                s = s[:-1]
            return s
        except (UnicodeDecodeError, LookupError):
            return None


def parse_icon_index(buf, offset):
    """Parse the IconIndex (4 bytes int)."""
    if offset + 4 > len(buf):
        return None
    return struct.unpack_from("<i", buf, offset)[0]


def parse_file_size(buf, offset):
    """Parse the FileSize (8 bytes int64)."""
    if offset + 8 > len(buf):
        return None
    return struct.unpack_from("<q", buf, offset)[0]


def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    if not os.path.isfile(filepath):
        fail(f"File not found: {filepath}")
    
    try:
        with open(filepath, 'rb') as f:
            buf = f.read()
    except (IOError, OSError) as e:
        fail(f"Cannot read file: {e}")
    
    # Check minimum size (header is at least 4+4+4+4+4+4+4+4+4+4+8+8 = 60 bytes)
    if len(buf) < 60:
        fail("File too small to be a valid .lnk file")
    
    # Parse header
    # Signature: 4 bytes (0x00021401)
    signature = struct.unpack_from("<I", buf, 0)[0]
    if signature != 0x00021401:
        fail("Invalid .lnk file signature")
    
    # Link CLSID: 16 bytes (offset 4-19)
    # We'll skip validation of CLSID for now but could check
    
    offset = 20
    
    # LinkFlags: 4 bytes
    link_flags = parse_link_flags(buf, offset)
    if link_flags is None:
        fail("Cannot parse LinkFlags")
    offset += 4
    
    # FileAttributes: 4 bytes
    offset += 4
    
    # CreationTime: 8 bytes
    creation_time = parse_timestamp(buf, offset)
    offset += 8
    
    # AccessTime: 8 bytes
    access_time = parse_timestamp(buf, offset)
    offset += 8
    
    # WriteTime: 8 bytes
    write_time = parse_timestamp(buf, offset)
    offset += 8
    
    # FileSize: 8 bytes
    file_size = parse_file_size(buf, offset)
    offset += 8
    
    # IconIndex: 4 bytes
    icon_index = parse_icon_index(buf, offset)
    offset += 4
    
    # CommandFlags: 4 bytes
    command_flags = struct.unpack_from("<I", buf, offset)[0]
    offset += 4
    
    # Reserved: 4 bytes
    offset += 4
    
    # Now parse optional structures based on flags
    
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    # LF_HAS_NAME: bit 0 (0x0001)
    if link_flags & 0x0001:
        if offset + 4 > len(buf):
            fail("Truncated file: cannot read NameString size")
        size = struct.unpack_from("<I", buf, offset)[0]
        if size < 4:
            fail("Invalid NameString size")
        if offset + size > len(buf):
            fail("Truncated file: NameString extends beyond EOF")
        str_data = buf[offset + 4:offset + size]
        try:
            name_string = str_data.decode('utf-16-le', errors='strict')
            if name_string.endswith('\x00'):
                name_string = name_string[:-1]
        except UnicodeDecodeError:
            try:
                name_string = str_data.decode('cp1252', errors='strict')
                if name_string.endswith('\x00'):
                    name_string = name_string[:-1]
            except (UnicodeDecodeError, LookupError):
                name_string = None
        offset += size
    
    # LF_HAS_RELATIVE_PATH: bit 1 (0x0002)
    if link_flags & 0x0002:
        if offset + 6 > len(buf):
            fail("Truncated file: cannot read RelativePath header")
        size = struct.unpack_from("<H", buf, offset)[0]
        flags = struct.unpack_from("<H", buf, offset + 2)[0]
        if size < 4:
            fail("Invalid RelativePath size")
        if offset + size > len(buf):
            fail("Truncated file: RelativePath extends beyond EOF")
        str_data = buf[offset + 4:offset + size]
        try:
            if flags & 0x0001:
                relative_path = str_data.decode('utf-16-le', errors='strict')
            else:
                relative_path = str_data.decode('cp1252', errors='strict')
            if relative_path.endswith('\x00'):
                relative_path = relative_path[:-1]
        except (UnicodeDecodeError, LookupError):
            relative_path = None
        offset += size
    
    # LF_HAS_WORKING_DIR: bit 2 (0x0004)
    if link_flags & 0x0004:
        if offset + 4 > len(buf):
            fail("Truncated file: cannot read WorkingDir size")
        size = struct.unpack_from("<I", buf, offset)[0]
        if size < 4:
            fail("Invalid WorkingDir size")
        if offset + size > len(buf):
            fail("Truncated file: WorkingDir extends beyond EOF")
        str_data = buf[offset + 4:offset + size]
        try:
            working_dir = str_data.decode('utf-16-le', errors='strict')
            if working_dir.endswith('\x00'):
                working_dir = working_dir[:-1]
        except UnicodeDecodeError:
            try:
                working_dir = str_data.decode('cp1252', errors='strict')
                if working_dir.endswith('\x00'):
                    working_dir = working_dir[:-1]
            except (UnicodeDecodeError, LookupError):
                working_dir = None
        offset += size
    
    # LF_HAS_COMMAND_LINE: bit 3 (0x0008)
    if link_flags & 0x0008:
        if offset + 4 > len(buf):
            fail("Truncated file: cannot read CommandLine size")
        size = struct.unpack_from("<I", buf, offset)[0]
        if size < 4:
            fail("Invalid CommandLine size")
        if offset + size > len(buf):
            fail("Truncated file: CommandLine extends beyond EOF")
        str_data = buf[offset + 4:offset + size]
        try:
            command_line_arguments = str_data.decode('utf-16-le', errors='strict')
            if command_line_arguments.endswith('\x00'):
                command_line_arguments = command_line_arguments[:-1]
        except UnicodeDecodeError:
            try:
                command_line_arguments = str_data.decode('cp1252', errors='strict')
                if command_line_arguments.endswith('\x00'):
                    command_line_arguments = command_line_arguments[:-1]
            except (UnicodeDecodeError, LookupError):
                command_line_arguments = None
        offset += size
    
    # LF_HAS_ICON_LOCATION: bit 4 (0x0010)
    if link_flags & 0x0010:
        if offset + 4 > len(buf):
            fail("Truncated file: cannot read IconLocation size")
        size = struct.unpack_from("<I", buf, offset)[0]
        if size < 4:
            fail("Invalid IconLocation size")
        if offset + size > len(buf):
            fail("Truncated file: IconLocation extends beyond EOF")
        str_data = buf[offset + 4:offset + size]
        try:
            icon_location = str_data.decode('utf-16-le', errors='strict')
            if icon_location.endswith('\x00'):
                icon_location = icon_location[:-1]
        except UnicodeDecodeError:
            try:
                icon_location = str_data.decode('cp1252', errors='strict')
                if icon_location.endswith('\x00'):
                    icon_location = icon_location[:-1]
            except (UnicodeDecodeError, LookupError):
                icon_location = None
        offset += size
    
    # Validate that we haven't gone past the buffer
    if offset > len(buf):
        fail("Offset exceeded file size")
    
    # Build result
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
        "write_time": write_time
    }
    
    print(json.dumps(result, indent=None))
    sys.exit(0)


if __name__ == "__main__":
    main()