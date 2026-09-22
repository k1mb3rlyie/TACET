from __future__ import annotations

import datetime as _dt
import os
import platform
import struct
import sys
import time

from harness.lnkbuild import build, default_corpus

# 60 s is the real test. Set VCS_SLEEP to a smaller number only to check the script
# runs; a short interval still detects substitution but is weaker evidence, so the
# figure in any write-up should come from a full 60 s run.
SLEEP_SECONDS = int(os.environ.get("VCS_SLEEP", "60"))

CASES = [
    ("A", "0xFFFFFFFFFFFFFFFF  (damaged / out of range)", 0xFFFFFFFFFFFFFFFF),
    ("B", "0                   (UNSET -- ordinary files)", 0),
]


def env_banner() -> None:
    try:
        import importlib.metadata as md
        ver = md.version("pylnk3")
    except Exception:
        ver = "unknown"
    now = _dt.datetime.now().astimezone()
    print("=" * 74)
    print("ENVIRONMENT")
    print("=" * 74)
    print(f"  OS              : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"  Python          : {sys.version.split()[0]} ({platform.python_implementation()})")
    print(f"  pylnk3          : {ver}")
    print(f"  Local timezone  : {now.tzname()} (UTC{now.strftime('%z')})")
    print()


def filetime_bytes(raw_value: int) -> tuple[bytes, int]:
    """Write raw_value into a generated shortcut file's write_time field, then read
    those 8 bytes back out at the offset the specification puts them."""
    data, gt = build(default_corpus()[0])
    off = gt.by_name("write_time").offset
    b = bytearray(data)
    struct.pack_into("<Q", b, off, raw_value)
    return bytes(b[off:off + 8]), off


def convert(raw8: bytes):
    """Convert with pylnk3's own routine -- the code path under test."""
    from pylnk3 import convert_time_to_unix
    value = struct.unpack("<Q", raw8)[0]
    clock = _dt.datetime.now()
    try:
        return convert_time_to_unix(value), None, clock
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", clock


def main() -> None:
    env_banner()

    prepared = []
    for tag, label, raw in CASES:
        raw8, off = filetime_bytes(raw)
        prepared.append((tag, label, raw8, off))

    print("=" * 74)
    print("TEST  --  identical bytes converted twice, 60 s apart")
    print("=" * 74)
    print(f"  write_time field offset in header: 0x{prepared[0][3]:02x} (8 bytes)")
    print()

    first = {}
    for tag, label, raw8, _ in prepared:
        v, err, clock = convert(raw8)
        first[tag] = (v, err, clock)
        shown = f"RAISED {err}" if err else repr(v)
        print(f"  Case {tag}  write_time = {label}")
        print(f"           bytes {raw8.hex(' ')}")
        print(f"           Read 1: {shown}")
        print(f"                   system clock at read: {clock}")
        print()

    print(f"  waiting {SLEEP_SECONDS} s ...\n")
    time.sleep(SLEEP_SECONDS)

    for tag, label, raw8, _ in prepared:
        v1, err1, clock1 = first[tag]
        v2, err2, clock2 = convert(raw8)
        shown = f"RAISED {err2}" if err2 else repr(v2)
        print(f"  Case {tag}  Read 2: {shown}")
        print(f"                   system clock at read: {clock2}")

        print(f"  Case {tag}  VERDICT: ", end="")
        if err1 and err2:
            print("raised both times -- correct, loud failure on this platform.")
        elif err1 or err2:
            print("raised once and not the other -- inconsistent, investigate.")
        elif v1 == v2:
            print(f"STABLE at {v1!r} -- a fixed fallback, not the clock.")
            if v1.year == 1601:
                print("            (1601 is the FILETIME epoch: recognisably 'unset'.)")
        else:
            drift = abs((v2 - v1).total_seconds())
            elapsed = abs((clock2 - clock1).total_seconds())
            off1 = abs((v1 - clock1).total_seconds())
            off2 = abs((v2 - clock2).total_seconds())
            print(f"value MOVED {drift:.0f} s across {elapsed:.0f} s of wall clock.")
            print(f"            offset from system clock: read 1 {off1:.0f} s, read 2 {off2:.0f} s")
            if abs(drift - elapsed) < 5 and off1 < 5 and off2 < 5:
                print("            >> CLOCK SUBSTITUTION CONFIRMED.")
                print("            The value returned is the time of EXAMINATION, not a")
                print("            timestamp from the file. No error is raised.")
            else:
                print("            Moves but does not track the clock 1:1 -- investigate")
                print("            before claiming substitution.")
        print()


if __name__ == "__main__":
    main()