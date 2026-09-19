# TACET

**T**ool-generated **A**rtefact parsers: **C**orrectness **E**valuation under **T**ampering

*Tacet* is the instruction in a musical score telling an instrument not to play —
literally, "it is silent." A parser that stays silent exactly when it should speak is
what this measures.

A test harness for forensic artefact parsers. It generates Windows Shortcut (`.lnk`)
files with byte-exact known contents, damages them in controlled ways, and grades a
parser on whether it **fails loudly** (raises, exits non-zero, signals an error) or
**fails quietly** (returns a plausible wrong value with no indication anything went
wrong).

The distinction matters in forensics. A parser that crashes is recoverable — the
examiner sees an error and investigates. A parser that returns a confident wrong value
puts that value in a report.

---

## Findings in pylnk3 0.4.3

Testing turned up two correctness defects in a widely used library. Both were reported
before publication and a fix was offered.

**The parser can invent a timestamp.** When a `FILETIME` cannot be converted to a date,
`pylnk3` returned the current system time rather than signalling an error. Parsing
identical bytes sixty seconds apart returned two values sixty seconds apart. On Windows
this fires not only for corrupted timestamps but for **unset** ones — FILETIME `0`,
which is common in ordinary shortcut files, and which appears in two of the library's
own test fixtures.

**`IconIndex` was read as unsigned.** MS-SHLLINK defines it as a signed 32-bit integer,
so `-1` was reported as `4294967295` with no error.

Reproduce the first in three lines:

```python
from datetime import datetime
from pylnk3 import convert_time_to_unix
 
print("returned    :", convert_time_to_unix(0xFFFFFFFFFFFFFFFF))
print("system clock:", datetime.now())
```

On unpatched pylnk3 0.4.3 under Windows, both print the same value. Or run the full
demonstration, which parses identical bytes a minute apart and reports whether the
answer moved:

```bash
python verify_clock_substitution.py
```

|                               |                                                             |
| ----------------------------- | ----------------------------------------------------------- |
| Issue: timestamp substitution | [strayge/pylnk#47](https://github.com/strayge/pylnk/issues/47) |
| Issue: IconIndex sign         | [strayge/pylnk#48](https://github.com/strayge/pylnk/issues/48) |
| Fix, with tests               | [strayge/pylnk#49](https://github.com/strayge/pylnk/pull/49)   |

---

## Quick start

Python 3.11+. The harness itself is standard library only; `pylnk3` is needed only for
the reference baseline.

```bash
git clone https://github.com/k1mb3rlyie/TACET.git
cd TACET/pilot
pip install pylnk3
python run_pilot.py
```

`run_pilot.py` runs `pylnk3` through the full perturbation matrix and prints a summary —
106 trials across 5 generated files and 12 perturbations.

---

## How it works

Ground truth is **constructive**, not parser-derived. Shortcut files are generated from
MS-SHLLINK, so every field value and byte offset is known because the harness wrote
them.

This is the design decision everything else rests on. The obvious approach — run two
reference parsers and investigate disagreements — breaks down on damaged input.
Perturbed files lie outside the domain any parser was validated against, and independent
implementations of the same public specification tend to share failure modes, so they
can agree on the same wrong answer. The `IconIndex` defect above was invisible while
`pylnk3` was being used as an oracle.

Each perturbation therefore carries its own expected outcome, derived from the
modification itself:

| Expectation       | Meaning                                         | A silent failure is                   |
| ----------------- | ----------------------------------------------- | ------------------------------------- |
| `EXPECT_VALUE`  | file stays well-formed with a new correct value | returning any other value             |
| `EXPECT_ERROR`  | file is now malformed                           | returning anything without signalling |
| `EXPECT_ABSENT` | field is legitimately gone                      | reporting it present                  |

Outcomes are graded as `CORRECT`, `EXPLICIT_FAILURE`, `SILENT_PLAUSIBLE`,
`SILENT_DEGENERATE`, `OVER_STRICT`, `NO_OUTPUT` or `TIMEOUT`, with silent failures
classified into eight categories. `SILENT_PLAUSIBLE` — a value an examiner would
transcribe without hesitating — is reported separately from `SILENT_DEGENERATE`, since
pooling them overstates the result.

---
