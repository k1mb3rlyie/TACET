#refuting clock is out of range
from __future__ import annotations

import datetime as _dt
import io
import platform
import struct
import sys
import time

from harness.lnkbuild import build, default_corpus, from_filetime

SLEEP_SECONDS = 60


def env_banner() -> None:
    try:
        import importlib.metadata as md
        ver = md.version("pylnk3")
    except Exception:
        ver = "unknown"
    print("=" * 74)
    print("ENVIRONMENT  (record this verbatim)")
    print("=" * 74)
    print(f"  OS              : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"  Python          : {sys.version.split()[0]} ({platform.python_implementation()})")
    print(f"  pylnk3          : {ver}")
    print(f"  Local timezone  : {_dt.datetime.now().astimezone().tzname()} "
          f"(UTC{_dt.datetime.now().astimezone().strftime('%z')})")
    print()


def make_bad_file() -> bytes:
    """Valid LNK with write_time set to 0xFFFFFFFFFFFFFFFF (~year 58000)."""
    data, gt = build(default_corpus()[0])
    f = gt.by_name("write_time")
    b = bytearray(data)
    struct.pack_into("<Q", b, f.offset, 0xFFFFFFFFFFFFFFFF)
    return bytes(b)


def parse_once(data: bytes):
    import pylnk3
    clock_before = _dt.datetime.now()
    try:
        lnk = pylnk3.Lnk(io.BytesIO(data))
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", clock_before
    return lnk.modification_time, None, clock_before


def main() -> None:
    env_banner()
    data = make_bad_file()

    print("=" * 74)
    print("TEST  --  identical bytes parsed twice, 60 s apart")
    print("=" * 74)

    v1, err1, clock1 = parse_once(data)
    if err1:
        print(f"  Read 1: RAISED  {err1}")
        print(f"\n  Correct behaviour. No clock substitution on this platform.")
        print(f"  Record the environment banner above alongside this result.")
        return

    print(f"  Read 1: returned {v1!r}")
    print(f"          system clock at read: {clock1}")
    print(f"\n  waiting {SLEEP_SECONDS} s ...\n")
    time.sleep(SLEEP_SECONDS)

    v2, err2, clock2 = parse_once(data)
    if err2:
        print(f"  Read 2: RAISED {err2}  <- inconsistent with read 1, investigate")
        return
    print(f"  Read 2: returned {v2!r}")
    print(f"          system clock at read: {clock2}")

    print()
    print("=" * 74)
    print("VERDICT")
    print("=" * 74)

    if v1 == v2:
        print("  Value is STABLE across reads.")
        print("  Not clock substitution. It is some fixed fallback -- a clamp to")
        print("  datetime.max, an epoch default, or a wrapped value. Decode it and")
        print("  classify accordingly; still a silent failure, different category.")
        return

    drift = abs((v2 - v1).total_seconds())
    elapsed = abs((clock2 - clock1).total_seconds())
    print(f"  Value MOVED by {drift:.0f} s across {elapsed:.0f} s of wall clock.")
    print(f"  Offset from system clock at read 1: "
          f"{abs((v1 - clock1).total_seconds()):.0f} s")
    print(f"  Offset from system clock at read 2: "
          f"{abs((v2 - clock2).total_seconds()):.0f} s")
    print()
    if abs(drift - elapsed) < 5:
        print("  >> CLOCK SUBSTITUTION CONFIRMED.")
        print()
        print("  The parser returns the time of EXAMINATION in place of an")
        print("  unparseable evidence timestamp, with no error and no signal.")
        print("  In a report this reads as file activity on the day the examiner")
        print("  ran the tool. Category: default_substitution, not timestamp.")
    else:
        print("  Value moves but does not track the clock 1:1. Investigate before")
        print("  claiming substitution -- it may be a partial or scaled fallback.")


if __name__ == "__main__":
    main()
