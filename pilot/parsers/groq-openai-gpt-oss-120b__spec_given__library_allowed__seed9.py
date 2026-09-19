#!/usr/bin/env python3
import sys
import struct
import json
import datetime

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def error(msg: str):
    """Print error JSON and exit with code 0."""
    json.dump({"error": msg}, sys.stdout, ensure_ascii=False)
    sys.stdout.flush()
    sys.exit(0)


def read_uint(data, offset, fmt):
    """Read unsigned integer of given struct format at offset."""
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError("unexpected end of file")
    return struct.unpack_from(fmt, data, offset)[0], offset + size


def filetime_to_iso(ft: int) -> str:
    """Convert Windows FILETIME to ISO‑8601 string with UTC offset."""
    if ft == 0:
        # Zero is sometimes used for “not set”; treat as epoch start
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    else:
        try:
            dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(
                microseconds=ft // 10
            )
        except OverflowError as e:
            raise ValueError("FILETIME out of range") from e
    return dt.isoformat()


def read_string(data, offset, is_unicode):
    """Read a counted string (CountCharacters + characters)."""
    count, offset = read_uint(data, offset, "<H")
    byte_len = count * (2 if is_unicode else 1)
    if offset + byte_len > len(data):
        raise ValueError("truncated string data")
    raw = data[offset : offset + byte_len]
    offset += byte_len
    if is_unicode:
        try:
            s = raw.decode("utf-16le")
        except UnicodeDecodeError:
            s = raw.decode("utf-16le", errors="replace")
    else:
        # ANSI – best effort using Windows‑1252 fallback
        try:
            s = raw.decode("cp1252")
        except UnicodeDecodeError:
            s = raw.decode("cp1252", errors="replace")
    return s, offset


# ----------------------------------------------------------------------
# Main parsing routine
# ----------------------------------------------------------------------
def parse_lnk(path: str):
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 0x4C:
        raise ValueError("file too short for ShellLinkHeader")

    # ---- ShellLinkHeader ------------------------------------------------
    hdr_size, off = read_uint(data, 0, "<I")
    if hdr_size != 0x4C:
        raise ValueError("invalid HeaderSize")

    link_clsid = data[off : off + 16]
    off += 16
    expected_clsid = bytes.fromhex("01140200-0000-0000-C000-000000000046".replace("-", ""))
    if link_clsid != expected_clsid:
        raise ValueError("invalid LinkCLSID")

    link_flags, off = read_uint(data, off, "<I")
    file_attrs, off = read_uint(data, off, "<I")
    creation_ft, off = read_uint(data, off, "<Q")
    access_ft, off = read_uint(data, off, "<Q")
    write_ft, off = read_uint(data, off, "<Q")
    file_size, off = read_uint(data, off, "<I")
    icon_index, off = read_uint(data, off, "<i")  # signed
    show_cmd, off = read_uint(data, off, "<I")
    hotkey, off = read_uint(data, off, "<H")
    # Reserved fields (must be zero)
    reserved1, off = read_uint(data, off, "<H")
    reserved2, off = read_uint(data, off, "<I")
    reserved3, off = read_uint(data, off, "<I")
    if any([reserved1, reserved2, reserved3]):
        raise ValueError("non‑zero reserved fields")

    # ---- Optional structures --------------------------------------------
    # LinkTargetIDList
    if link_flags & 0x00000001:
        # first 2 bytes = IDListSize
        idlist_size, off = read_uint(data, off, "<H")
        if off + idlist_size > len(data):
            raise ValueError("truncated IDList")
        off += idlist_size  # skip

    # LinkInfo
    if link_flags & 0x00000002:
        linkinfo_size, off = read_uint(data, off, "<I")
        if linkinfo_size < 4:
            raise ValueError("invalid LinkInfoSize")
        if off + (linkinfo_size - 4) > len(data):
            raise ValueError("truncated LinkInfo")
        off += linkinfo_size - 4  # already consumed 4 bytes for size

    # ---- StringData ------------------------------------------------------
    is_unicode = bool(link_flags & 0x00000080)

    def maybe_read(flag_bit):
        return bool(link_flags & flag_bit)

    name_string = None
    relative_path = None
    working_dir = None
    command_line_arguments = None
    icon_location = None

    if maybe_read(0x00000004):  # HasName
        name_string, off = read_string(data, off, is_unicode)
    if maybe_read(0x00000008):  # HasRelativePath
        relative_path, off = read_string(data, off, is_unicode)
    if maybe_read(0x00000010):  # HasWorkingDir
        working_dir, off = read_string(data, off, is_unicode)
    if maybe_read(0x00000020):  # HasArguments
        command_line_arguments, off = read_string(data, off, is_unicode)
    if maybe_read(0x00000040):  # HasIconLocation
        icon_location, off = read_string(data, off, is_unicode)

    # ---- Build result ----------------------------------------------------
    result = {
        "name_string": name_string,
        "relative_path": relative_path,
        "working_dir": working_dir,
        "command_line_arguments": command_line_arguments,
        "icon_location": icon_location,
        "file_size": file_size,
        "icon_index": icon_index,
        "creation_time": filetime_to_iso(creation_ft),
        "access_time": filetime_to_iso(access_ft),
        "write_time": filetime_to_iso(write_ft),
    }
    return result


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def main():
    if len(sys.argv) != 2:
        error("usage: python parser.py <path-to-lnk-file>")

    path = sys.argv[1]
    try:
        out = parse_lnk(path)
        json.dump(out, sys.stdout, ensure_ascii=False)
        sys.stdout.flush()
        sys.exit(0)
    except Exception as exc:
        # Any parsing problem results in an error JSON
        error(str(exc))


if __name__ == "__main__":
    main()