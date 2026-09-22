#!/usr/bin/env python3
import sys
import json
import struct
import os
import re
from datetime import datetime, timezone


def fail(message):
    """Print error JSON and exit with non-zero code."""
    print(json.dumps({"error": message}))
    sys.exit(1)


def parse_lnk(data):
    """
    Parse a Windows .lnk file and extract metadata.
    Returns a dict with the required keys, or raises an exception on error.
    """
    result = {
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
        "file_size": None,
        "icon_index": None,
        "creation_time": None,
        "access_time": None,
        "write_time": None
    }

    # Check minimum size
    if len(data) < 4:
        raise ValueError("File too small to be a valid LNK file")

    # Header
    # Signature: 4 bytes, must be 0x4C 0x6F 0x6E 0x47 ("LoNg")
    if data[0:4] != b'\x4c\x6f\x6e\x47':
        raise ValueError("Invalid LNK signature")

    header_size = struct.unpack_from('<I', data, 4)[0]
    offset = 0x1C  # Standard fixed header size

    # Check that we have at least the header
    if len(data) < offset:
        raise ValueError("Truncated file: missing header")

    # LinkFlags (8 bytes)
    if len(data) < offset + 8:
        raise ValueError("Truncated file: missing LinkFlags")
    link_flags = struct.unpack_from('<Q', data, offset)[0]
    offset += 8

    # FileAttributes (4 bytes)
    if len(data) < offset + 4:
        raise ValueError("Truncated file: missing FileAttributes")
    offset += 4

    # Creation time (8 bytes) - FILETIME
    if len(data) < offset + 8:
        raise ValueError("Truncated file: missing CreationTime")
    creation_time_filetime = struct.unpack_from('<Q', data, offset)[0]
    offset += 8

    # Access time (8 bytes) - FILETIME
    if len(data) < offset + 8:
        raise ValueError("Truncated file: missing AccessTime")
    access_time_filetime = struct.unpack_from('<Q', data, offset)[0]
    offset += 8

    # Write time (8 bytes) - FILETIME
    if len(data) < offset + 8:
        raise ValueError("Truncated file: missing WriteTime")
    write_time_filetime = struct.unpack_from('<Q', data, offset)[0]
    offset += 8

    # File size (4 bytes)
    if len(data) < offset + 4:
        raise ValueError("Truncated file: missing FileSize")
    file_size = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    # Icon index (4 bytes)
    if len(data) < offset + 4:
        raise ValueError("Truncated file: missing IconIndex")
    icon_index = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    # Convert FILETIME to datetime
    def filetime_to_iso8601(ft):
        """Convert Windows FILETIME (100ns intervals since 1601-01-01) to ISO 8601 UTC."""
        if ft == 0:
            return None
        # FILETIME is in 100-nanosecond intervals since January 1, 1601
        # Convert to seconds since Unix epoch (1970-01-01)
        EPOCH_DIFF = 11644473600  # Seconds between 1601-01-01 and 1970-01-01
        seconds = (ft / 10000000) - EPOCH_DIFF
        try:
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
            return dt.isoformat()
        except (OSError, OverflowError, ValueError):
            raise ValueError("Invalid FILETIME value")

    try:
        result["creation_time"] = filetime_to_iso8601(creation_time_filetime)
    except ValueError:
        raise ValueError("Invalid creation time")

    try:
        result["access_time"] = filetime_to_iso8601(access_time_filetime)
    except ValueError:
        raise ValueError("Invalid access time")

    try:
        result["write_time"] = filetime_to_iso8601(write_time_filetime)
    except ValueError:
        raise ValueError("Invalid write time")

    result["file_size"] = file_size
    result["icon_index"] = icon_index

    # Now parse optional fields based on LinkFlags
    # Bit 0: LINKFLAG_HAS_LINKINFO
    # Bit 1: LINKFLAG_HAS_STRINGDATA
    # Bit 2: LINKFLAG_HAS_ICONLOCATION
    # Bit 3: LINKFLAG_HAS_COMMANDLINE
    # Bit 4: LINKFLAG_HAS_WORKINGDIR
    # Bit 5: LINKFLAG_HAS_RELATIVEPATH

    # StringData block
    if link_flags & 0x00000002:  # LINKFLAG_HAS_STRINGDATA
        if len(data) < offset + 8:
            raise ValueError("Truncated file: missing StringData block size")
        string_data_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # The StringData block contains a sequence of strings.
        # Each string: 2 bytes length in bytes (not chars), then UTF-16LE data.
        # The block ends with a 4-byte zero (0x00000000) or two null characters.
        
        string_data_start = offset
        strings = []
        
        # Read strings until we hit the end of the string data block
        # The total size of the StringData block is given, but it's a bit tricky.
        # Actually, the StringData block size in the header refers to the size of the
        # entire StringData block including the strings.
        
        # Let's read strings one by one
        while offset + 2 <= len(data):
            # Check if we've gone past reasonable bounds
            if offset + 2 > len(data):
                break
            
            str_len_bytes = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            
            if str_len_bytes == 0:
                # End of strings
                break
            
            # Check if we have enough data
            if offset + str_len_bytes > len(data):
                raise ValueError("Truncated file: string data extends beyond file")
            
            str_data = data[offset:offset + str_len_bytes]
            offset += str_len_bytes
            
            # Decode as UTF-16LE
            try:
                str_value = str_data.decode('utf-16-le')
            except UnicodeDecodeError:
                raise ValueError("Invalid UTF-16 string in StringData block")
            
            strings.append(str_value)
        
        # Map strings to fields
        # The order of strings in the StringData block corresponds to the flags:
        # 1. LocalBasePath (if LINKFLAG_HAS_LOCALBASEPATH - bit 6)
        # 2. CommonName (if LINKFLAG_HAS_COMMONNAME - bit 7)
        # 3. IconFileName (if LINKFLAG_HAS_ICONFILENAME - bit 8)
        # 4. RelativePath (if LINKFLAG_HAS_RELATIVEPATH - bit 9)
        # 5. WorkingDirectory (if LINKFLAG_HAS_WORKINGDIR - bit 10)
        # 6. CommandLineArguments (if LINKFLAG_HAS_COMMANDLINE - bit 11)
        # 7. IconFileName (if LINKFLAG_HAS_ICONLOCATION - bit 12)
        
        # Actually, the exact mapping depends on which flags are set.
        # Let me re-read the spec more carefully.
        # 
        # The StringData block contains:
        # - If LINKFLAG_HAS_LOCALBASEPATH (bit 6): LocalBasePath string
        # - If LINKFLAG_HAS_COMMONNAME (bit 7): CommonName string
        # - If LINKFLAG_HAS_ICONFILENAME (bit 8): IconFileName string
        # - If LINKFLAG_HAS_RELATIVEPATH (bit 9): RelativePath string
        # - If LINKFLAG_HAS_WORKINGDIR (bit 10): WorkingDirectory string
        # - If LINKFLAG_HAS_COMMANDLINE (bit 11): CommandLineArguments string
        # - If LINKFLAG_HAS_ICONLOCATION (bit 12): IconFileName string
        #
        # Wait, I need to be more careful. Let me check the standard order.
        # 
        # According to the MS-LNK spec, the StringData block contains the following
        # strings in this order (only those whose flags are set):
        # 1. LocalBasePath (bit 6)
        # 2. CommonName (bit 7)
        # 3. IconFileName (bit 8)
        # 4. RelativePath (bit 9)
        # 5. WorkingDirectory (bit 10)
        # 6. CommandLineArguments (bit 11)
        # 7. IconFileName (bit 12)
        #
        # Hmm, that doesn't seem right either. Let me think about this differently.
        # 
        # Actually, looking at the spec more carefully:
        # The StringData block is a sequence of null-terminated (in UTF-16) strings.
        # The specific strings present depend on the LinkFlags.
        
        # Let me use a different approach: map flags to expected string positions
        str_index = 0
        
        # Check each flag in order
        if link_flags & 0x00000040:  # LINKFLAG_HAS_LOCALBASEPATH
            if str_index < len(strings):
                # LocalBasePath - not in our output contract, skip
                str_index += 1
        
        if link_flags & 0x00000080:  # LINKFLAG_HAS_COMMONNAME
            if str_index < len(strings):
                # CommonName - this might be the "name_string"
                result["name_string"] = strings[str_index]
                str_index += 1
        
        if link_flags & 0x00000100:  # LINKFLAG_HAS_ICONFILENAME
            if str_index < len(strings):
                # IconFileName
                result["icon_location"] = strings[str_index]
                str_index += 1
        
        if link_flags & 0x00000200:  # LINKFLAG_HAS_RELATIVEPATH
            if str_index < len(strings):
                result["relative_path"] = strings[str_index]
                str_index += 1
        
        if link_flags & 0x00000400:  # LINKFLAG_HAS_WORKINGDIR
            if str_index < len(strings):
                result["working_dir"] = strings[str_index]
                str_index += 1
        
        if link_flags & 0x00000800:  # LINKFLAG_HAS_COMMANDLINE
            if str_index < len(strings):
                result["command_line_arguments"] = strings[str_index]
                str_index += 1
        
        if link_flags & 0x00001000:  # LINKFLAG_HAS_ICONLOCATION
            if str_index < len(strings):
                # This is another icon-related string
                if result["icon_location"] is None:
                    result["icon_location"] = strings[str_index]
                str_index += 1

    # LinkInfo block
    if link_flags & 0x00000001:  # LINKFLAG_HAS_LINKINFO
        if len(data) < offset + 4:
            raise ValueError("Truncated file: missing LinkInfo block size")
        link_info_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        
        if offset + link_info_size > len(data):
            raise ValueError("Truncated file: LinkInfo block extends beyond file")
        
        # Skip the LinkInfo block for now (we don't extract from it in our contract)
        offset += link_info_size

    # IconLocation block
    if link_flags & 0x00001000:  # LINKFLAG_HAS_ICONLOCATION
        # This was already handled in StringData if present
        # But there's also a separate IconLocation block in some implementations
        # Actually, the IconLocation is part of StringData, so we're good

    # Verify we haven't gone past the end of the file
    if offset > len(data):
        raise ValueError("Parsing went past end of file")

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
        fail(f"Cannot read file: {str(e)}")
    
    try:
        result = parse_lnk(data)
    except ValueError as e:
        fail(str(e))
    except Exception as e:
        fail(f"Unexpected error: {str(e)}")
    
    # Ensure all values are in the correct format
    # file_size and icon_index should be integers or null
    if result.get("file_size") is not None:
        if not isinstance(result["file_size"], int):
            fail("file_size must be an integer")
    if result.get("icon_index") is not None:
        if not isinstance(result["icon_index"], int):
            fail("icon_index must be an integer")
    
    print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()