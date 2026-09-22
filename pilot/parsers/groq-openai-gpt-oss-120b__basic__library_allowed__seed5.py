#!/usr/bin/env python3
import sys
import struct
import json
import datetime

HEADER_SIZE = 0x4C  # 76 bytes
LINK_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'


def read_exact(f, n):
    data = f.read(n)
    if len(data) != n:
        raise ValueError(f'Unexpected end of file while reading {n} bytes')
    return data


def filetime_to_iso(ft):
    if ft == 0:
        return None
    # FILETIME is number of 100‑ns intervals since 1601‑01‑01 UTC
    us = ft // 10
    dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
    return dt.isoformat()


def read_string(f, is_unicode):
    # 2‑byte character count, then characters (UTF‑16LE or ANSI)
    char_count_bytes = read_exact(f, 2)
    (char_count,) = struct.unpack('<H', char_count_bytes)
    if is_unicode:
        raw = read_exact(f, char_count * 2)
        return raw.decode('utf-16le', errors='replace')
    else:
        raw = read_exact(f, char_count)
        return raw.decode('utf-8', errors='replace')


def parse_lnk(path):
    with open(path, 'rb') as f:
        # ---- Header ---------------------------------------------------------
        header = read_exact(f, HEADER_SIZE)
        (hdr_size,) = struct.unpack_from('<I', header, 0)
        if hdr_size != HEADER_SIZE:
            raise ValueError('Invalid header size')
        if header[4:20] != LINK_CLSID:
            raise ValueError('Invalid LinkCLSID GUID')

        (link_flags,) = struct.unpack_from('<I', header, 20)
        # File attributes (ignored for output)
        # timestamps
        (creation_time,) = struct.unpack_from('<Q', header, 28)
        (access_time,) = struct.unpack_from('<Q', header, 36)
        (write_time,) = struct.unpack_from('<Q', header, 44)
        (file_size,) = struct.unpack_from('<I', header, 52)
        (icon_index,) = struct.unpack_from('<I', header, 56)

        # ---- Optional sections before string data ---------------------------
        # LinkTargetIDList
        if link_flags & 0x00000001:
            idlist_size_bytes = read_exact(f, 2)
            (idlist_size,) = struct.unpack('<H', idlist_size_bytes)
            # size includes the 2‑byte size field itself
            to_skip = idlist_size - 2
            if to_skip < 0:
                raise ValueError('Invalid IDList size')
            f.seek(to_skip, 1)

        # LinkInfo
        if link_flags & 0x00000002:
            info_size_bytes = read_exact(f, 4)
            (info_size,) = struct.unpack('<I', info_size_bytes)
            if info_size < 4:
                raise ValueError('Invalid LinkInfo size')
            f.seek(info_size - 4, 1)

        # ---- StringData -----------------------------------------------------
        is_unicode = bool(link_flags & 0x00000080)

        def get_string(flag):
            if link_flags & flag:
                return read_string(f, is_unicode)
            return None

        name_string = get_string(0x00000004)
        relative_path = get_string(0x00000008)
        working_dir = get_string(0x00000010)
        command_line_arguments = get_string(0x00000020)
        icon_location = get_string(0x00000040)

        # ---- Build result ---------------------------------------------------
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
            "write_time": filetime_to_iso(write_time)
        }
        return result


def main():
    if len(sys.argv) != 2:
        sys.stderr.write('Usage: python parser.py <path-to-lnk-file>\n')
        sys.exit(1)

    path = sys.argv[1]
    try:
        data = parse_lnk(path)
        json.dump(data, sys.stdout, ensure_ascii=False)
        sys.stdout.write('\n')
        sys.exit(0)
    except Exception as e:
        err = {"error": str(e)}
        json.dump(err, sys.stdout, ensure_ascii=False)
        sys.stdout.write('\n')
        sys.exit(0)


if __name__ == '__main__':
    main()