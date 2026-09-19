
from __future__ import annotations

import datetime as _dt
import struct
from dataclasses import dataclass, field, asdict
from typing import Any

LINK_CLSID = bytes.fromhex("01140200000000000C0000000000046".replace("0C0", "C0", 1))
#to avoid transcription error:
LINK_CLSID = bytes(
    [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
     0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
)

HEADER_SIZE = 0x4C
FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)

# LinkFlags
F_HAS_IDLIST = 0x00000001
F_HAS_LINKINFO = 0x00000002
F_HAS_NAME = 0x00000004
F_HAS_RELPATH = 0x00000008
F_HAS_WORKDIR = 0x00000010
F_HAS_ARGS = 0x00000020
F_HAS_ICON = 0x00000040
F_IS_UNICODE = 0x00000080

STRING_SECTIONS = [
    ("name_string", F_HAS_NAME),
    ("relative_path", F_HAS_RELPATH),
    ("working_dir", F_HAS_WORKDIR),
    ("command_line_arguments", F_HAS_ARGS),
    ("icon_location", F_HAS_ICON),
]


HEADER_FIELDS: dict[str, tuple[int, int, str]] = {
    "header_size": (0x00, 4, "<I"),
    "link_clsid": (0x04, 16, None),
    "link_flags": (0x14, 4, "<I"),
    "file_attributes": (0x18, 4, "<I"),
    "creation_time": (0x1C, 8, "<Q"),
    "access_time": (0x24, 8, "<Q"),
    "write_time": (0x2C, 8, "<Q"),
    "file_size": (0x34, 4, "<I"),
    "icon_index": (0x3C - 4, 4, "<i"),  # 0x38
    "show_command": (0x3C, 4, "<I"),
    "hotkey": (0x40, 2, "<H"),
    "reserved1": (0x42, 2, "<H"),
    "reserved2": (0x44, 4, "<I"),
    "reserved3": (0x48, 4, "<I"),
}


def to_filetime(dt: _dt.datetime) -> int:
    """
    Datetime -> Windows FILETIME (100ns intervals since 1601-01-01 UTC).

    Integer arithmetic throughout. The obvious implementation,
    int(delta.total_seconds() * 10_000_000), routes through a float64, and modern
    FILETIMEs need ~18 significant digits where float64 carries ~15-16. It happens
    to be exact for many values, which is worse than being reliably wrong.
    """
    if dt.tzinfo is None:
        raise ValueError(
            "naive datetime passed to to_filetime. Attach a timezone explicitly -- "
            "silently assuming UTC is exactly the bug this harness exists to catch."
        )
    dt = dt.astimezone(_dt.timezone.utc)
    delta = dt - FILETIME_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def from_filetime(ft: int) -> _dt.datetime | None:
    
    if ft <= 0:
        return None
    try:
        return FILETIME_EPOCH + _dt.timedelta(microseconds=ft // 10)
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class FieldTruth:
    
    name: str
    value: Any
    offset: int
    size: int
    kind: str          
    semantic: str      
    optional: bool = False


@dataclass
class GroundTruth:
    
    sample_id: str
    total_size: int
    fields: list[FieldTruth] = field(default_factory=list)

    def by_name(self, name: str) -> FieldTruth | None:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def expected_dict(self) -> dict[str, Any]:
        return {f.name: f.value for f in self.fields}

    def to_json(self) -> dict:
        return {
            "sample_id": self.sample_id,
            "total_size": self.total_size,
            "fields": [asdict(f) for f in self.fields],
        }


@dataclass
class LnkSpec:
   
    sample_id: str
    name_string: str | None = "Quarterly report shortcut"
    relative_path: str | None = r"..\..\Documents\q3.docx"
    working_dir: str | None = r"C:\Users\analyst\Documents"
    command_line_arguments: str | None = None
    icon_location: str | None = r"C:\Windows\System32\shell32.dll"
    file_attributes: int = 0x00000020  # FILE_ATTRIBUTE_ARCHIVE
    creation_time: _dt.datetime = _dt.datetime(2026, 3, 14, 9, 15, 30, tzinfo=_dt.timezone.utc)
    access_time: _dt.datetime = _dt.datetime(2026, 4, 2, 17, 45, 1, tzinfo=_dt.timezone.utc)
    write_time: _dt.datetime = _dt.datetime(2026, 3, 29, 11, 2, 44, tzinfo=_dt.timezone.utc)
    file_size: int = 48_812
    icon_index: int = 3
    show_command: int = 1  # SW_SHOWNORMAL
    hotkey: int = 0


def build(spec: LnkSpec) -> tuple[bytes, GroundTruth]:
   
    flags = F_IS_UNICODE
    present = []
    for attr, bit in STRING_SECTIONS:
        if getattr(spec, attr) is not None:
            flags |= bit
            present.append(attr)

    ct, at, wt = (to_filetime(t) for t in
                  (spec.creation_time, spec.access_time, spec.write_time))

    header = bytearray(HEADER_SIZE)
    struct.pack_into("<I", header, 0x00, HEADER_SIZE)
    header[0x04:0x14] = LINK_CLSID
    struct.pack_into("<I", header, 0x14, flags)
    struct.pack_into("<I", header, 0x18, spec.file_attributes)
    struct.pack_into("<Q", header, 0x1C, ct)
    struct.pack_into("<Q", header, 0x24, at)
    struct.pack_into("<Q", header, 0x2C, wt)
    struct.pack_into("<I", header, 0x34, spec.file_size)
    struct.pack_into("<i", header, 0x38, spec.icon_index)
    struct.pack_into("<I", header, 0x3C, spec.show_command)
    struct.pack_into("<H", header, 0x40, spec.hotkey)
    # 0x42, 0x44, 0x48 stay zero (Reserved1/2/3)

    gt = GroundTruth(sample_id=spec.sample_id, total_size=0)
    gt.fields += [
        FieldTruth("header_size", HEADER_SIZE, 0x00, 4, "u32", "length"),
        FieldTruth("link_clsid", LINK_CLSID.hex(), 0x04, 16, "raw", "guid"),
        FieldTruth("link_flags", flags, 0x14, 4, "u32", "flags"),
        FieldTruth("file_attributes", spec.file_attributes, 0x18, 4, "u32", "flags"),
        FieldTruth("creation_time", ct, 0x1C, 8, "u64", "timestamp"),
        FieldTruth("access_time", at, 0x24, 8, "u64", "timestamp"),
        FieldTruth("write_time", wt, 0x2C, 8, "u64", "timestamp"),
        FieldTruth("file_size", spec.file_size, 0x34, 4, "u32", "integer"),
        FieldTruth("icon_index", spec.icon_index, 0x38, 4, "i32", "integer"),
        FieldTruth("show_command", spec.show_command, 0x3C, 4, "u32", "integer"),
        FieldTruth("hotkey", spec.hotkey, 0x40, 2, "u16", "integer"),
    ]

    body = bytearray()
    cursor = HEADER_SIZE
    for attr in present:
        text: str = getattr(spec, attr)
        encoded = text.encode("utf-16-le")
        count = len(text) 
        gt.fields.append(
            FieldTruth(f"{attr}__count", count, cursor, 2, "count", "length", optional=True)
        )
        gt.fields.append(
            FieldTruth(attr, text, cursor + 2, len(encoded), "utf16", "string", optional=True)
        )
        body += struct.pack("<H", count) + encoded
        cursor += 2 + len(encoded)


    for attr, _bit in STRING_SECTIONS:
        if getattr(spec, attr) is None:
            gt.fields.append(
                FieldTruth(attr, None, -1, 0, "utf16", "string", optional=True)
            )

    # EXTRA_DATA: a TerminalBlock (u32 < 0x00000004) closes the file. Required by
    # MS-SHLLINK; omitting it makes conformant parsers run off the end.
    gt.fields.append(
        FieldTruth("terminal_block", 0, cursor, 4, "u32", "length")
    )
    body += struct.pack("<I", 0)

    data = bytes(header + body)
    gt.total_size = len(data)
    return data, gt


def default_corpus(n: int = 5) -> list[LnkSpec]:
    """A small spread of shapes: all-sections, minimal, unicode-heavy, long, edge values."""
    base = _dt.datetime(2026, 1, 5, 8, 0, 0, tzinfo=_dt.timezone.utc)
    specs = [
        LnkSpec(sample_id="lnk_full"),
        LnkSpec(
            sample_id="lnk_minimal",
            name_string=None, relative_path=r"target.exe",
            working_dir=None, command_line_arguments=None, icon_location=None,
            file_size=0, icon_index=0,
        ),
        LnkSpec(
            sample_id="lnk_unicode",
            name_string="Raport kwartalny \u2014 wersja ostateczna \u00e9\u00e8\u00fc",
            relative_path="..\\\u6587\u66f8\\\u5831\u544a.docx",
            working_dir="C:\\Users\\\u0410\u043d\u0430\u043b\u0438\u0442\u0438\u043a\\Documents",
            command_line_arguments="--mode=\u5b89\u5168",
        ),
        LnkSpec(
            sample_id="lnk_long",
            name_string="A" * 900,
            command_line_arguments="-flag " * 120,
            file_size=0xFFFFFFF0,
        ),
        LnkSpec(
            sample_id="lnk_edge",
            creation_time=base, access_time=base, write_time=base,
            file_size=0, icon_index=-1, show_command=7, hotkey=0x0541,
            command_line_arguments="",  # present but empty: the optional-vs-empty trap
        ),
    ]
    return specs[:n]
