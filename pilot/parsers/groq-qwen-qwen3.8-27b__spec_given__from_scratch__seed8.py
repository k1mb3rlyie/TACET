import sys
import struct
import json
import datetime

def fail(msg):
    print(json.dumps({"error": msg}), file=sys.stdout)
    sys.exit(1)

def filetime_to_iso(ft):
    """Convert FILETIME (100ns intervals since 1601-01-01 UTC) to ISO 8601 with +00:00 offset.
    Returns None if the value is not representable."""
    if ft == 0:
        # This could be a valid timestamp (1601-01-01) but often indicates unset.
        # The spec says "not every 64-bit value maps to a representable date."
        # We'll try to convert it. If it works, we return it.
        # 1601-01-01 is representable.
        pass
    
    # Python's datetime can handle dates from year 1 to 9999.
    # FILETIME 0 = 1601-01-01 00:00:00 UTC
    # Max FILETIME for year 9999: 
    #   (9999 - 1601) years * 365.25 * 24 * 3600 * 10^7 ≈ 3.15e17
    # 2^64 - 1 ≈ 1.8e19, which is way beyond year 9999.
    
    try:
        # Convert 100ns intervals to seconds and microseconds
        total_seconds = ft / 10_000_000.0
        # Use integer arithmetic to avoid floating point issues where possible
        seconds = ft // 10_000_000
        remainder = ft % 10_000_000
        microseconds = remainder * 100
        
        # datetime.datetime.fromtimestamp assumes local time, so we use UTC
        # But fromtimestamp has limits. Let's use datetime.datetime directly.
        # The epoch for datetime is 1970-01-01.
        # FILETIME epoch is 1601-01-01.
        # Difference in seconds:
        # 1970-01-01 - 1601-01-01 = 369 years.
        # Let's compute the offset in 100ns intervals.
        # 369 years... it's easier to just use the known constant.
        # 116444736000000000 is the number of 100ns intervals between 1601-01-01 and 1970-01-01.
        EPOCH_1601_TO_1970 = 116444736000000000
        
        if ft < EPOCH_1601_TO_1970:
            # Before 1970, fromtimestamp might not work correctly on all systems or with negative values in older Python
            # Let's construct the datetime from the delta.
            # We can use datetime.datetime(1601, 1, 1) + timedelta
            base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
            delta = datetime.timedelta(microseconds=ft * 100)
            dt = base + delta
            return dt.isoformat()
        else:
            # Convert to POSIX timestamp
            posix_ft = ft - EPOCH_1601_TO_1970
            posix_seconds = posix_ft // 10_000_000
            posix_microseconds = (posix_ft % 10_000_000) * 100
            
            # Check if it's within datetime range
            if posix_seconds > 253402300799:  # Year 9999
                return None
            
            dt = datetime.datetime.fromtimestamp(posix_seconds, tz=datetime.timezone.utc)
            dt = dt.replace(microsecond=posix_microseconds)
            return dt.isoformat()
            
    except (OverflowError, OSError, ValueError):
        return None

def read_string(data, offset, is_unicode):
    """Read a StringData block. Returns (string, new_offset) or raises exception."""
    if offset + 2 > len(data):
        raise ValueError("Truncated CountCharacters")
    
    count_chars = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    if is_unicode:
        byte_count = count_chars * 2
        if offset + byte_count > len(data):
            raise ValueError("Truncated Unicode string")
        raw = data[offset:offset+byte_count]
        try:
            s = raw.decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-16LE string")
        offset += byte_count
    else:
        # ANSI string. The spec says "CountCharacters characters".
        # In ANSI, each character is 1 byte.
        byte_count = count_chars
        if offset + byte_count > len(data):
            raise ValueError("Truncated ANSI string")
        raw = data[offset:offset+byte_count]
        try:
            s = raw.decode('ascii')
        except UnicodeDecodeError:
            # Try latin-1 as a fallback? Or fail?
            # The spec implies standard ANSI. Let's try to be lenient but strict on structure.
            # Actually, if it's not ASCII, it might be a different codepage.
            # For forensic purposes, failing is safer than guessing the codepage.
            # However, .lnk files often use the system default codepage.
            # Let's try UTF-8 first, then Latin-1?
            # The prompt says "Do not guess". But decoding a byte string is necessary.
            # Let's stick to strict ASCII for non-unicode, or fail.
            # Actually, let's look at the MS-SHLLINK spec. It says "ANSI string".
            # Most likely it's the system default. But without knowing the system, we can't be sure.
            # Let's try to decode as UTF-8, and if that fails, fail.
            try:
                s = raw.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Invalid ANSI string (not ASCII or UTF-8)")
        offset += byte_count
        
    return s, offset

def parse_idlist(data, offset):
    """Parse the IDList. Returns new offset."""
    while True:
        # Each item is a null-terminated string (ANSI or Unicode depending on IsUnicode? 
        # Actually, IDList items are CBString: 16-bit length followed by string.
        # The length is in bytes for ANSI? No, for Unicode it's in chars?
        # MS-SHLLINK: "Each item is a CBString... The length is the number of characters, not bytes."
        # Wait, let's check the spec carefully.
        # "Each item in the list is a null-terminating string... The string is preceded by a 16-bit value that indicates the number of characters in the string, not including the null terminator."
        # If IsUnicode is set, the string is Unicode. Otherwise, ANSI.
        
        if offset + 2 > len(data):
            raise ValueError("Truncated IDList")
        
        char_count = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        
        # The string ends with a null terminator.
        # If char_count is 0, it's the end of the list.
        if char_count == 0:
            # The null terminator is just the 0x00 0x00 (if unicode) or 0x00 (if ansi)?
            # Actually, the CBString for the end is just a 0 length.
            # Does it consume the null terminator bytes?
            # "The list is terminated by a 16-bit value of 0."
            # So if char_count is 0, we stop. The null terminator bytes themselves are not read as a string?
            # Actually, the string data for a 0-length string is empty. But is there a null terminator?
            # The spec says "null-terminating string".
            # If char_count is 0, the string is empty. The null terminator is implicit?
            # Let's look at typical implementations.
            # Usually, the IDList ends with two 0x0000 words.
            # So if char_count is 0, we check if there are more bytes?
            # No, the 16-bit value of 0 IS the terminator.
            # So we stop here.
            return offset
        
        if char_count > 100000: # Sanity check
            raise ValueError("Invalid IDList item length")
            
        if is_unicode:
            byte_count = char_count * 2
            # Plus 2 bytes for null terminator?
            # "The string is followed by a null terminator."
            # So total bytes = char_count * 2 + 2.
            if offset + byte_count + 2 > len(data):
                raise ValueError("Truncated IDList item")
            # We don't need to decode the IDList content for the output, just skip it.
            offset += byte_count + 2
        else:
            byte_count = char_count
            # Plus 1 byte for null terminator.
            if offset + byte_count + 1 > len(data):
                raise ValueError("Truncated IDList item")
            offset += byte_count + 1

def parse_link_info(data, offset):
    """Parse the LinkInfo structure. Returns new offset."""
    # LinkInfo is a complex structure. We just need to skip it.
    # It starts with LinkInfoSize (4 bytes).
    if offset + 4 > len(data):
        raise ValueError("Truncated LinkInfo")
    
    link_info_size = struct.unpack_from('<I', data, offset)[0]
    
    # The size includes the 4 bytes of the size field itself.
    if link_info_size < 4:
        raise ValueError("Invalid LinkInfo size")
        
    if offset + link_info_size > len(data):
        raise ValueError("Truncated LinkInfo data")
        
    offset += link_info_size
    return offset

def main():
    if len(sys.argv) != 2:
        fail("Usage: python parser.py <path-to-lnk-file>")
    
    path = sys.argv[1]
    
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        fail(f"Cannot read file: {e}")
    
    # Minimum size for header
    if len(data) < 0x4C:
        fail("File too small to contain ShellLinkHeader")
    
    offset = 0
    
    # Parse Header
    header_size = struct.unpack_from('<I', data, offset)[0]
    if header_size != 0x4C:
        fail("Invalid HeaderSize")
    offset += 4
    
    # LinkCLSID
    expected_clsid = bytes([
        0x00, 0x02, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    ])
    # Wait, the CLSID is a GUID. The byte order in the file is mixed.
    # The first 3 fields are little-endian, the rest are network order?
    # Actually, in the file, the CLSID is stored as:
    # 4 bytes LE, 2 bytes LE, 2 bytes LE, 8 bytes BE (or just raw bytes).
    # Let's check the provided hex: 00021401-0000-0000-C000-000000000046
    # In memory/file, it should be:
    # 01 14 02 00 (LE of 0x00021401? No, 0x00021401 -> 01 14 02 00)
    # 00 00 (LE of 0x0000)
    # 00 00 (LE of 0x0000)
    # C0 00 00 00 00 00 00 46 (Raw bytes of the last part)
    
    actual_clsid = data[offset:offset+16]
    # Let's construct the expected bytes
    exp = struct.pack('<IHH8s', 0x00021401, 0x0000, 0x0000, bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]))
    if actual_clsid != exp:
        fail("Invalid LinkCLSID")
    offset += 16
    
    # LinkFlags
    link_flags = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    
    # FileAttributes
    file_attributes = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    
    # CreationTime
    creation_time = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    
    # AccessTime
    access_time = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    
    # WriteTime
    write_time = struct.unpack_from('<Q', data, offset)[0]
    offset += 8
    
    # FileSize (unsigned 32-bit)
    file_size = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    
    # IconIndex (signed 32-bit)
    icon_index = struct.unpack_from('<i', data, offset)[0]
    offset += 4
    
    # ShowCommand
    show_command = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    
    # HotKey
    hot_key = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    
    # Reserved1
    reserved1 = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if reserved1 != 0:
        # Spec says "must be zero". Is this a hard failure?
        # "If you cannot read a field correctly, say so."
        # A non-zero reserved field might indicate corruption or non-standard LNK.
        # We'll treat it as an error to be safe.
        fail("Non-zero Reserved1")
        
    # Reserved2
    reserved2 = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    if reserved2 != 0:
        fail("Non-zero Reserved2")
        
    # Reserved3
    reserved3 = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    if reserved3 != 0:
        fail("Non-zero Reserved3")
        
    # Now offset should be 0x4C
    if offset != 0x4C:
        fail("Header parsing offset mismatch")
        
    is_unicode = bool(link_flags & 0x00000080)
    
    # Parse optional structures
    if link_flags & 0x00000001: # HasLinkTargetIDList
        try:
            offset = parse_idlist(data, offset)
        except ValueError as e:
            fail(f"Error parsing IDList: {e}")
            
    if link_flags & 0x00000002: # HasLinkInfo
        try:
            offset = parse_link_info(data, offset)
        except ValueError as e:
            fail(f"Error parsing LinkInfo: {e}")
            
    # Parse StringData sections
    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None
    
    try:
        if link_flags & 0x00000004: # HasName
            name_string, offset = read_string(data, offset, is_unicode)
            
        if link_flags & 0x00000008: # HasRelativePath
            relative_path, offset = read_string(data, offset, is_unicode)
            
        if link_flags & 0x00000010: # HasWorkingDir
            working_dir, offset = read_string(data, offset, is_unicode)
            
        if link_flags & 0x00000020: # HasArguments
            command_line_arguments, offset = read_string(data, offset, is_unicode)
            
        if link_flags & 0x00000040: # HasIconLocation
            icon_location, offset = read_string(data, offset, is_unicode)
            
    except ValueError as e:
        fail(f"Error parsing StringData: {e}")
        
    # Parse Extra Data
    # Sequence of blocks terminated by a 32-bit value less than 4.
    while offset + 4 <= len(data):
        dw_extra_size = struct.unpack_from('<I', data, offset)[0]
        
        if dw_extra_size < 4:
            # Terminal block
            # The block is just the 4 bytes?
            # "terminated by a TerminalBlock: a 32-bit value less than 0x00000004."
            # So we read the 4 bytes, see it's < 4, and stop.
            offset += 4
            break
        else:
            # Extra data block size
            # The size includes the 4 bytes of the size field?
            # MS-SHLLINK: "The size of the extra data block, including the ExtraDataSize field."
            if dw_extra_size < 4:
                # This case is handled above as terminal.
                pass
            if offset + dw_extra_size > len(data):
                fail("Truncated Extra Data block")
            offset += dw_extra_size
    else:
        # Loop finished without break, meaning we ran out of data without finding a terminal block?
        # Or we reached exactly the end of data?
        # If offset == len(data), we need to check if the last 4 bytes were a terminal block.
        # If the loop condition `offset + 4 <= len(data)` failed, it means there are less than 4 bytes left.
        # If there are 0 bytes left, we are good?
        # The spec says the file ends with a terminal block.
        # So if we reach the end of the file, the last 4 bytes should have been a terminal block.
        # If we have 0-3 bytes left, it's malformed.
        if offset != len(data):
            fail("Malformed Extra Data termination")
            
    # Convert timestamps
    def ft_to_iso(ft):
        if ft == 0:
            # 1601-01-01T00:00:00+00:00
            return "1601-01-01T00:00:00+00:00"
        # We need to handle the conversion carefully.
        # Using the method from filetime_to_iso
        try:
            return filetime_to_iso(ft)
        except Exception:
            return None
            
    creation_iso = ft_to_iso(creation_time)
    access_iso = ft_to_iso(access_time)
    write_iso = ft_to_iso(write_time)
    
    if creation_iso is None:
        fail("Unrepresentable CreationTime")
    if access_iso is None:
        fail("Unrepresentable AccessTime")
    if write_iso is None:
        fail("Unrepresentable WriteTime")
        
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": creation_iso,
        "access_time": access_iso,
        "write_time": write_iso
    }
    
    print(json.dumps(result))
    sys.exit(0)

if __name__ == "__main__":
    main()