from __future__ import annotations

import copy
import struct
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any

from .lnkbuild import GroundTruth, FieldTruth, HEADER_SIZE


class Expect(str, Enum):
    VALUE = "EXPECT_VALUE"
    ERROR = "EXPECT_ERROR"
    ABSENT = "EXPECT_ABSENT"


@dataclass
class Perturbation:
   
    pert_id: str
    level: int                 # 0, 1, 2
    family: str                # short label used for taxonomy roll-up
    target_field: str
    expect: Expect
    expected_value: Any = None
    rationale: str = ""        # why this is the correct behaviour, in words

    def to_json(self) -> dict:
        d = asdict(self)
        d["expect"] = self.expect.value
        return d


@dataclass
class Sample:
    sample_id: str
    data: bytes
    truth: GroundTruth
    perturbation: Perturbation


def _clone_truth(gt: GroundTruth) -> GroundTruth:
    return copy.deepcopy(gt)


def _set_field(gt: GroundTruth, name: str, value: Any) -> None:
    f = gt.by_name(name)
    if f is not None:
        f.value = value



def level0(data: bytes, gt: GroundTruth) -> list[Sample]:

    skip = {"link_clsid", "header_size", "terminal_block", "hotkey", "reserved1",
            "reserved2", "reserved3"}
    out: list[Sample] = []
    for f in gt.fields:
        if f.name in skip or f.name.endswith("__count"):
            continue
        expect = Expect.ABSENT if f.value is None else Expect.VALUE
        out.append(Sample(
            f"{gt.sample_id}::L0.{f.name}", data, _clone_truth(gt),
            Perturbation(
                f"L0.{f.name}", 0, "none", f.name, expect,
                expected_value=f.value,
                rationale="Unmodified file. This field must read back exactly as "
                          "constructed.",
            )))
    return out



def level1(data: bytes, gt: GroundTruth) -> list[Sample]:
    out: list[Sample] = []


    tb = gt.by_name("terminal_block")
    if tb and tb.offset >= 0:
        t = _clone_truth(gt)
        _set_field(t, "terminal_block", None)
        out.append(Sample(
            f"{gt.sample_id}::L1.no_terminal", data[: tb.offset], t,
            Perturbation(
                "L1.no_terminal", 1, "truncation", "terminal_block", Expect.ERROR,
                rationale="EXTRA_DATA is unterminated. A conformant parser reaches EOF "
                          "looking for the terminal block and must signal.",
            )))


    for attr, bit in [("name_string", 0x04), ("working_dir", 0x10)]:
        f = gt.by_name(attr)
        cf = gt.by_name(f"{attr}__count")
        if not f or not cf or f.offset < 0:
            continue
        b = bytearray(data)
        flags = struct.unpack_from("<I", b, 0x14)[0]
        struct.pack_into("<I", b, 0x14, flags & ~bit)
        del b[cf.offset: f.offset + f.size]       
        shift = (f.offset + f.size) - cf.offset
        t = _clone_truth(gt)
        _set_field(t, "link_flags", flags & ~bit)
        _set_field(t, attr, None)
        _set_field(t, f"{attr}__count", None)
        for other in t.fields:                       
            if other.offset > f.offset:
                other.offset -= shift
        t.total_size -= shift
        out.append(Sample(
            f"{gt.sample_id}::L1.remove_{attr}", bytes(b), t,
            Perturbation(
                f"L1.remove_{attr}", 1, "absent_field", attr, Expect.ABSENT,
                expected_value=None,
                rationale=f"{attr} removed cleanly and its flag cleared. The file is "
                          f"well-formed. Correct behaviour is to report the field absent "
                          f"-- reporting an empty string instead conflates 'not present' "
                          f"with 'present and empty', which in a report reads as a "
                          f"positive finding about the file.",
            )))

    for attr in ("relative_path", "icon_location"):
        cf = gt.by_name(f"{attr}__count")
        if not cf or cf.offset < 0:
            continue
        b = bytearray(data)
        struct.pack_into("<H", b, cf.offset, 0)
        t = _clone_truth(gt)
        _set_field(t, f"{attr}__count", 0)
        _set_field(t, attr, "")
        out.append(Sample(
            f"{gt.sample_id}::L1.zero_count_{attr}", bytes(b), t,
            Perturbation(
                f"L1.zero_count_{attr}", 1, "structure_desync", attr, Expect.ERROR,
                rationale="Count says zero but the character bytes are still present, so "
                          "every subsequent section is misaligned. A parser that reads on "
                          "and returns plausible values for later fields has desynced "
                          "silently.",
            )))

    #truncate mid-string.
    f = gt.by_name("relative_path")
    if f and f.offset >= 0 and f.size > 8:
        cut = f.offset + (f.size // 2) | 1  # odd cut: splits a UTF-16 code unit
        out.append(Sample(
            f"{gt.sample_id}::L1.truncate_mid_string", data[:cut], _clone_truth(gt),
            Perturbation(
                "L1.truncate_mid_string", 1, "truncation", "relative_path", Expect.ERROR,
                rationale="File ends mid-string, on an odd byte so the final UTF-16 unit "
                          "is split. Decoding must fail, not silently drop the byte.",
            )))

    return out

def level2(data: bytes, gt: GroundTruth) -> list[Sample]:
    out: list[Sample] = []

    for attr in ("working_dir", "command_line_arguments", "relative_path"):
        cf = gt.by_name(f"{attr}__count")
        if not cf or cf.offset < 0:
            continue
        b = bytearray(data)
        struct.pack_into("<H", b, cf.offset, 0x7FFF)
        out.append(Sample(
            f"{gt.sample_id}::L2.overlong_count_{attr}", bytes(b), _clone_truth(gt),
            Perturbation(
                f"L2.overlong_count_{attr}", 2, "bounds_violation", attr, Expect.ERROR,
                rationale="Declared length (32767 chars) exceeds bytes remaining. Must "
                          "signal. Clamping to what is available and returning a "
                          "truncated string is the classic silent bounds absorption.",
            )))
        break  

    for tname in ("write_time", "creation_time"):
        f = gt.by_name(tname)
        if not f:
            continue
        b = bytearray(data)
        struct.pack_into("<Q", b, f.offset, 0xFFFFFFFFFFFFFFFF)
        t = _clone_truth(gt)
        _set_field(t, tname, 0xFFFFFFFFFFFFFFFF)
        out.append(Sample(
            f"{gt.sample_id}::L2.max_filetime_{tname}", bytes(b), t,
            Perturbation(
                f"L2.max_filetime_{tname}", 2, "timestamp", tname, Expect.ERROR,
                rationale="FILETIME 0xFFFF...FF is ~58000 AD, outside datetime range. "
                          "Must signal or report the raw integer. Silently substituting "
                          "epoch, now(), or a wrapped date is a timestamp misread.",
            )))
        break

    f = gt.by_name("icon_index")
    if f:
        b = bytearray(data)
        struct.pack_into("<i", b, f.offset, -7)
        t = _clone_truth(gt)
        _set_field(t, "icon_index", -7)
        out.append(Sample(
            f"{gt.sample_id}::L2.negative_icon_index", bytes(b), t,
            Perturbation(
                "L2.negative_icon_index", 2, "sign_confusion", "icon_index",
                Expect.VALUE, expected_value=-7,
                rationale="IconIndex is a signed 32-bit integer. -7 read as unsigned "
                          "gives 4294967289: plausible, wrong, silent.",
            )))

    f = gt.by_name("working_dir")
    if f and f.offset >= 0 and f.size >= 4:
        b = bytearray(data)
        struct.pack_into("<H", b, f.offset, 0xD800)
        out.append(Sample(
            f"{gt.sample_id}::L2.lone_surrogate", bytes(b), _clone_truth(gt),
            Perturbation(
                "L2.lone_surrogate", 2, "encoding", "working_dir", Expect.ERROR,
                rationale="Unpaired high surrogate is not valid UTF-16. Decoding with "
                          "errors='ignore' or 'replace' hides evidence tampering, which "
                          "is precisely the forensic failure case.",
            )))

    b = bytearray(data)
    struct.pack_into("<I", b, 0x00, 0x5C)
    out.append(Sample(
        f"{gt.sample_id}::L2.bad_header_size", bytes(b), _clone_truth(gt),
        Perturbation(
            "L2.bad_header_size", 2, "structure_desync", "header_size", Expect.ERROR,
            rationale="HeaderSize must be 0x4C. A parser that ignores the field and "
                      "hardcodes 76 gets the right answer for the wrong reason and will "
                      "not flag a tampered file.",
        )))

    b = bytearray(data)
    b[0x04] = (b[0x04] + 1) & 0xFF
    out.append(Sample(
        f"{gt.sample_id}::L2.bad_clsid", bytes(b), _clone_truth(gt),
        Perturbation(
            "L2.bad_clsid", 2, "magic", "link_clsid", Expect.ERROR,
            rationale="LinkCLSID no longer matches. The file is not a shell link and "
                      "must be rejected before any field is interpreted.",
        )))

    return out


def all_levels(data: bytes, gt: GroundTruth, max_level: int = 2) -> list[Sample]:
    out = level0(data, gt)
    if max_level >= 1:
        out += level1(data, gt)
    if max_level >= 2:
        out += level2(data, gt)
    return out
