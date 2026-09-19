
from __future__ import annotations

from .sandbox import CONTRACT_FIELDS


_CONTRACT = """
## Output contract

Your program must be a standalone Python script run as:

    python parser.py <path-to-lnk-file>

**On success:** exit with code 0 and print a single JSON object to stdout, with these
keys exactly:

```json
{
  "name_string": "string or null",
  "relative_path": "string or null",
  "working_dir": "string or null",
  "command_line_arguments": "string or null",
  "icon_location": "string or null",
  "file_size": 0,
  "icon_index": 0,
  "creation_time": "ISO 8601 with UTC offset",
  "access_time": "ISO 8601 with UTC offset",
  "write_time": "ISO 8601 with UTC offset"
}
```

Rules for the values:

- A field that is genuinely **absent** from the file must be `null`. Do not substitute
  an empty string, a zero, or a default. Absent and empty are different.
- Timestamps must be ISO 8601 **with an explicit UTC offset**, for example
  `2026-03-14T09:15:30+00:00`. A timestamp without an offset is ambiguous.
- Integers must be JSON numbers, not strings.

**On failure:** if the file is malformed, truncated, corrupted, or cannot be parsed
correctly for any reason, you must signal it. Either:

- exit with a non-zero code, or
- exit 0 and print `{"error": "<short description>"}` to stdout

**This requirement is not optional and is the most important part of the task.**
Returning a plausible-looking value for a field you could not actually read correctly
is worse than failing. Do not guess, do not substitute defaults, do not silently clamp
or truncate. If you cannot read a field correctly, say so.

Print nothing to stdout except the single JSON object. Diagnostics go to stderr.
"""

_FROM_SCRATCH = """
## Constraint

Implement the parsing yourself using only the Python standard library (`struct`,
`datetime`, `json`, `sys` and similar). Do not use `pylnk3`, `LnkParse3`, `construct`,
or any other third-party LNK or binary-parsing library.
"""

_LIBRARY_ALLOWED = """
## Constraint

You may use third-party libraries if you wish, or implement the parsing yourself.
If you use a library, remember that the output contract above still applies in full --
including the requirement to signal malformed input rather than returning whatever the
library happens to hand back.
"""

# --------------------------------------------------------------------------
# Condition: basic
# --------------------------------------------------------------------------

_BASIC_TASK = """
Write a Python program that parses a Windows Shortcut (`.lnk`) file and extracts its
metadata.

The program will be used in a digital forensics context, where the files it reads may
be damaged, incomplete, or deliberately tampered with.
"""

# --------------------------------------------------------------------------
# Condition: spec_given
# --------------------------------------------------------------------------

_SPEC_TASK = """
Write a Python program that parses a Windows Shortcut (`.lnk`) file and extracts its
metadata, following the MS-SHLLINK specification.

The program will be used in a digital forensics context, where the files it reads may
be damaged, incomplete, or deliberately tampered with.

## Format reference (MS-SHLLINK)

### ShellLinkHeader — 76 bytes (0x4C), fixed offsets, little-endian

| Offset | Size | Field | Type |
|---|---|---|---|
| 0x00 | 4 | HeaderSize | unsigned; **must equal 0x0000004C** |
| 0x04 | 16 | LinkCLSID | **must equal** `00021401-0000-0000-C000-000000000046` |
| 0x14 | 4 | LinkFlags | unsigned bitfield |
| 0x18 | 4 | FileAttributes | unsigned bitfield |
| 0x1C | 8 | CreationTime | FILETIME |
| 0x24 | 8 | AccessTime | FILETIME |
| 0x2C | 8 | WriteTime | FILETIME |
| 0x34 | 4 | FileSize | **unsigned** 32-bit |
| 0x38 | 4 | IconIndex | **signed** 32-bit |
| 0x3C | 4 | ShowCommand | unsigned 32-bit |
| 0x40 | 2 | HotKey | unsigned 16-bit |
| 0x42 | 2 | Reserved1 | must be zero |
| 0x44 | 4 | Reserved2 | must be zero |
| 0x48 | 4 | Reserved3 | must be zero |

Note the difference in signedness between FileSize and IconIndex.

### LinkFlags bits used here

| Bit | Name | Meaning |
|---|---|---|
| 0x00000001 | HasLinkTargetIDList | an IDList follows the header |
| 0x00000002 | HasLinkInfo | a LinkInfo structure follows |
| 0x00000004 | HasName | NAME_STRING present |
| 0x00000008 | HasRelativePath | RELATIVE_PATH present |
| 0x00000010 | HasWorkingDir | WORKING_DIR present |
| 0x00000020 | HasArguments | COMMAND_LINE_ARGUMENTS present |
| 0x00000040 | HasIconLocation | ICON_LOCATION present |
| 0x00000080 | IsUnicode | strings are UTF-16LE |

### StringData

Present sections follow the header (and the IDList and LinkInfo, if those flags are
set), **in this order**: NAME_STRING, RELATIVE_PATH, WORKING_DIR,
COMMAND_LINE_ARGUMENTS, ICON_LOCATION. Only sections whose flag is set are present.

Each section is:

    CountCharacters   unsigned 16-bit
    String            CountCharacters characters

When IsUnicode is set, characters are UTF-16LE, so the string occupies
`CountCharacters * 2` bytes. CountCharacters counts **characters, not bytes**.

### FILETIME

Unsigned 64-bit count of 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
The value is in **UTC**. Not every 64-bit value maps to a representable date.

### EXTRA_DATA

After the StringData sections, the file ends with a sequence of extra data blocks
terminated by a TerminalBlock: a 32-bit value less than 0x00000004.
"""


def build_prompt(prompt_condition: str, library_condition: str) -> str:
    """
    Assemble one of the four prompts.

    prompt_condition:  "basic" | "spec_given"
    library_condition: "from_scratch" | "library_allowed"
    """
    if prompt_condition == "basic":
        task = _BASIC_TASK
    elif prompt_condition == "spec_given":
        task = _SPEC_TASK
    else:
        raise ValueError(f"unknown prompt_condition: {prompt_condition!r}")

    if library_condition == "from_scratch":
        constraint = _FROM_SCRATCH
    elif library_condition == "library_allowed":
        constraint = _LIBRARY_ALLOWED
    else:
        raise ValueError(f"unknown library_condition: {library_condition!r}")

    return (task.strip() + "\n" + _CONTRACT.strip() + "\n" + constraint.strip()
            + "\n\nReturn only the complete Python program, with no commentary.")


CONDITIONS = [
    (p, l)
    for p in ("basic", "spec_given")
    for l in ("from_scratch", "library_allowed")
]


def extract_code(response: str) -> str:
    """
    Pull the Python source out of a model response.

    Models were told to return only code, but most will wrap it in a fenced block
    anyway. Strip the fence if present, otherwise return the response unchanged --
    and if what comes back is prose rather than code, the sandbox will record it as
    a contract violation, which is itself worth counting.
    """
    text = response.strip()
    if "```" not in text:
        return text
    blocks, inside, current = [], False, []
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            if inside:
                blocks.append("\n".join(current))
                current, inside = [], False
            else:
                inside = True
            continue
        if inside:
            current.append(line)
    if inside and current:
        blocks.append("\n".join(current))
    return max(blocks, key=len) if blocks else text
