#!/usr/bin/env python3
"""Parse a Windows Shortcut (.lnk) file following MS-SHLLINK specification."""

import json
import struct
import sys
import os
import datetime
from datetime import timezone, timedelta

# Expected LinkCLSID bytes
LINK_CLSID = bytes([
    0x00, 0x02, 0x14, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x46
])

# LinkFlags bits
LINK_FLAGS_HAS_LINK_TARGET_ID_LIST = 0x00000001
LINK_FLAGS_HAS_LINK_INFO = 0x00000002
LINK_FLAGS_HAS_NAME = 0x00000004
LINK_FLAGS_HAS_RELATIVE_PATH = 0x00000008
LINK_FLAGS_HAS_WORKING_DIR = 0x00000010
LINK_FLAGS_HAS_ARGUMENTS = 0x00000020
LINK_FLAGS_HAS_ICON_LOCATION = 0x00000040
LINK_FLAGS_IS_UNICODE = 0x00000080


def error(msg):
    """Print error to stderr and exit with non-zero code."""
    print(json.dumps({"error": msg}), file=sys.stdout)
    sys.exit(1)


def filetime_to_iso(ft):
    """Convert a FILETIME (100-nanosecond intervals since 1601-01-01 UTC) to ISO 8601 with UTC offset.
    
    Returns None if the value is not a valid representable date.
    """
    if ft == 0:
        # Zero is technically valid (1601-01-01 00:00:00 UTC)
        return datetime.datetime(1601, 1, 1, 0, 0, 0, tzinfo=timezone.utc).isoformat()
    
    # Convert to seconds and microseconds from epoch offset
    # 1601-01-01 to 1970-01-01 is 11644473600 seconds
    EPOCH_DIFF = 11644473600 * 10000000  # in 100-ns intervals
    
    # Check if value is too large
    # Max FILETIME is 0x7FFFFFFFFFFFFFFF
    if ft > 0x7FFFFFFFFFFFFFFF:
        return None
    
    try:
        total_100ns = ft
        # Convert to seconds and microseconds
        total_seconds_float = total_100ns / 10000000.0
        seconds = int(total_seconds_float)
        microseconds = int((total_seconds_float - seconds) * 1000000)
        
        # Ensure microseconds is in valid range
        if microseconds < 0:
            microseconds = 0
        elif microseconds > 999999:
            microseconds = 999999
        
        dt = datetime.datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = dt + datetime.timedelta(seconds=seconds, microseconds=microseconds)
        
        # Verify the conversion is reasonable
        if dt.year < 1601 or dt.year > 9999:
            return None
        
        return dt.isoformat()
    except (OverflowError, ValueError, OSError):
        return None


class LnkParser:
    def __init__(self, data):
        self.data = data
        self.pos = 0
    
    def read_bytes(self, count):
        """Read exactly count bytes. Raises if not enough data."""
        if self.pos + count > len(self.data):
            raise ValueError(f"Truncated file: need {count} bytes at offset {self.pos}, only {len(self.data) - self.pos} remain")
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result
    
    def read_uint16(self):
        return struct.unpack('<H', self.read_bytes(2))[0]
    
    def read_uint32(self):
        return struct.unpack('<I', self.read_bytes(4))[0]
    
    def read_int32(self):
        return struct.unpack('<i', self.read_bytes(4))[0]
    
    def read_uint64(self):
        return struct.unpack('<Q', self.read_bytes(8))[0]
    
    def read_uint16(self):
        return struct.unpack('<H', self.read_bytes(2))[0]
    
    def read_int32(self):
        return struct.unpack('<i', self.read_bytes(4))[0]
    
    def read_uint64(self):
        return struct.unpack('<Q', self.read_bytes(8))[0]
    
    def parse(self):
        """Parse the entire LNK file and return a dict of extracted fields."""
        if len(self.data) < 0x4C:
            raise ValueError("File too small to contain ShellLinkHeader")
        
        # Parse ShellLinkHeader (76 bytes)
        header_size = self.read_uint32()
        if header_size != 0x0000004C:
            raise ValueError(f"Invalid HeaderSize: expected 0x4C, got 0x{header_size:08X}")
        
        link_clsid = self.read_bytes(16)
        if link_clsid != LINK_CLSID:
            raise ValueError("Invalid LinkCLSID")
        
        link_flags = self.read_uint32()
        file_attributes = self.read_uint32()
        creation_time = self.read_uint64()
        access_time = self.read_uint64()
        write_time = self.read_uint64()
        file_size = self.read_uint32()
        icon_index = self.read_int32()  # signed
        show_command = self.read_uint32()
        hotkey = self.read_uint16()
        reserved1 = self.read_uint16()
        reserved2 = self.read_uint32()
        reserved3 = self.read_uint32()
        
        # We should be at offset 0x4C now
        if self.pos != 0x4C:
            raise ValueError(f"Header size mismatch: expected pos 0x4C after header, got 0x{self.pos:X}")
        
        # Parse optional structures in order
        # 1. LinkTargetIDList if HasLinkTargetIDList
        if link_flags & LINK_FLAGS_HAS_LINK_TARGET_ID_LIST:
            # IDList: sequence of IDList entries, each:
            #   Count (uint16) - number of elements
            #   For each element: Size (uint8) + data
            #   Terminated by Count = 0
            while True:
                count = self.read_uint16()
                if count == 0:
                    break
                for _ in range(count):
                    size = self.read_bytes(1)[0]
                    if size > 0:
                        self.read_bytes(size)
                # No additional terminator per entry; the count=0 terminates the list
        
        # 2. LinkInfo if HasLinkInfo
        if link_flags & LINK_FLAGS_HAS_LINK_INFO:
            # LinkInfo structure:
            #   LinkInfoSize (uint32)
            #   CvSize (uint32) - size of CVolumeID
            #   CVolumeID structure
            #   LocalBasePath (String)
            #   CommonNetworkRelativePath (String)
            #   CommonRelativePath (String)
            #   DriveType (uint32)
            #   DriveNumber (uint8)
            #   Unused1 (uint8)
            #   Unused2 (uint16)
            
            link_info_size = self.read_uint32()
            if self.pos + link_info_size > len(self.data):
                raise ValueError("LinkInfo extends beyond file")
            
            # Read CvSize
            cv_size = self.read_uint32()
            if self.pos + cv_size > len(self.data):
                raise ValueError("CVolumeID extends beyond file")
            
            # Skip CVolumeID
            self.read_bytes(cv_size)
            
            # Read three strings (each: uint16 count + string bytes)
            # These are ANSI strings in LinkInfo
            for _ in range(3):
                str_len = self.read_uint16()
                if str_len > 0:
                    self.read_bytes(str_len)
            
            # DriveType (uint32)
            drive_type = self.read_uint32()
            # DriveNumber (uint8)
            drive_number = self.read_bytes(1)[0]
            # Unused1 (uint8)
            unused1 = self.read_bytes(1)[0]
            # Unused2 (uint16)
            unused2 = self.read_uint16()
            
            # Verify we've consumed exactly link_info_size bytes from start of LinkInfo
            # We don't track start, but the structure should be consistent.
            # The LinkInfoSize includes all the above.
        
        # 3. StringData sections (only if corresponding flags are set)
        is_unicode = bool(link_flags & LINK_FLAGS_IS_UNICODE)
        
        name_string = None
        relative_path = None
        working_dir = None
        command_line_arguments = None
        icon_location = None
        
        def read_string_data():
            """Read a StringData section. Returns the string or None if flag not set."""
            char_count = self.read_uint16()
            if char_count == 0:
                return ""
            if is_unicode:
                byte_count = char_count * 2
            else:
                byte_count = char_count
            raw = self.read_bytes(byte_count)
            if is_unicode:
                return raw.decode('utf-16-le')
            else:
                return raw.decode('cp1252', errors='replace')
        
        if link_flags & LINK_FLAGS_HAS_NAME:
            name_string = read_string_data()
        
        if link_flags & LINK_FLAGS_HAS_RELATIVE_PATH:
            relative_path = read_string_data()
        
        if link_flags & LINK_FLAGS_HAS_WORKING_DIR:
            working_dir = read_string_data()
        
        if link_flags & LINK_FLAGS_HAS_ARGUMENTS:
            command_line_arguments = read_string_data()
        
        if link_flags & LINK_FLAGS_HAS_ICON_LOCATION:
            icon_location = read_string_data()
        
        # 4. Extra Data blocks
        # Sequence of extra data blocks terminated by TerminalBlock (uint32 < 0x4)
        while self.pos + 4 <= len(self.data):
            marker = struct.unpack('<I', self.data[self.pos:self.pos + 4])[0]
            if marker < 0x00000004:
                # TerminalBlock
                self.pos += 4
                break
            else:
                # ExtraDataBlock:
                #   Size (uint16)
                #   Unknown (uint16)
                #   Data (Size - 4 bytes)
                if self.pos + 4 > len(self.data):
                    break
                block_size = self.read_uint16()
                unknown = self.read_uint16()
                if block_size < 4:
                    raise ValueError(f"Invalid extra data block size: {block_size}")
                data_size = block_size - 4
                if self.pos + data_size > len(self.data):
                    break
                self.read_bytes(data_size)
        
        # Convert timestamps
        creation_time_iso = filetime_to_iso(creation_time)
        access_time_iso = filetime_to_iso(access_time)
        write_time_iso = filetime_to_iso(write_time)
        
        return {
            "name_string": name_string,
            "relative_path": relative_path,
            "working_dir": working_dir,
            "command_line_arguments": command_line_arguments,
            "icon_location": icon_location,
            "file_size": file_size,
            "icon_index": icon_index,
            "creation_time": creation_time_iso,
            "access_time": access_time_iso,
            "write_time": write_time_iso
        }


def main():
    if len(sys.argv) != 2:
        error("Usage: parser.py <path-to-lnk-file>")
    
    filepath = sys.argv[1]
    
    if not os.path.isfile(filepath):
        error(f"File not found: {filepath}")
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except IOError as e:
        error(f"Cannot read file: {e}")
    
    try:
        parser = LnkParser(data)
        result = parser.parse()
    except ValueError as e:
        error(str(e))
    except Exception as e:
        error(f"Parse error: {e}")
    
    print(json.dumps(result))
    sys.exit(0)


if __name__ == '__main__':
    main()