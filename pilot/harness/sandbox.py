from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .classify import ParserResult

DEFAULT_TIMEOUT = 10          
MAX_OUTPUT_BYTES = 1_000_000  


CONTRACT_FIELDS = [
    "name_string", "relative_path", "working_dir", "command_line_arguments",
    "icon_location", "file_size", "icon_index",
    "creation_time", "access_time", "write_time",
]


@dataclass
class RunRecord:
    """Raw execution detail, kept alongside the graded Trial for auditing."""
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    wall_seconds: float
    json_parse_ok: bool
    raw_error_key: str | None = None


def _minimal_env() -> dict:
    keep = ("PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC",
            "TEMP", "TMP", "LANG", "LC_ALL", "LD_LIBRARY_PATH",
            "VIRTUAL_ENV", "PYTHONPATH",
            "APPDATA", "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
            "PROGRAMFILES", "PROGRAMDATA", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    env["NO_PROXY"] = "*"
    return env


def run_generated_parser(
    parser_source: str,
    sample_bytes: bytes,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    python_exe: str | None = None,
) -> tuple[ParserResult, RunRecord]:
    """
    Write the generated source to a temp dir, run it against the sample, grade the
    output against the contract, and return both a ParserResult and the raw record.
    """
    import time

    python_exe = python_exe or sys.executable
    workdir = Path(tempfile.mkdtemp(prefix="tacet_"))
    try:
        parser_path = workdir / "parser.py"
        sample_path = workdir / "sample.lnk"
        parser_path.write_text(parser_source, encoding="utf-8")
        sample_path.write_bytes(sample_bytes)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                [python_exe, str(parser_path), str(sample_path)],
                cwd=workdir,
                env=_minimal_env(),
                capture_output=True,
                timeout=timeout,
                # never let a generated parser block waiting on input
                stdin=subprocess.DEVNULL,
            )
            elapsed = time.monotonic() - start
            stdout = proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            stderr = proc.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            exit_code = proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as e:
            elapsed = time.monotonic() - start
            stdout = (e.stdout or b"")[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
            stderr = (e.stderr or b"")[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
            exit_code, timed_out = None, True

        return _grade_output(stdout, stderr, exit_code, timed_out, elapsed)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _grade_output(stdout, stderr, exit_code, timed_out, elapsed):
    """Map raw process output onto the ParserResult the classifier expects."""
    rec = RunRecord(exit_code=exit_code, stdout=stdout, stderr=stderr,
                    timed_out=timed_out, wall_seconds=elapsed, json_parse_ok=False)

    if timed_out:
        return ParserResult(signalled=False, timed_out=True,
                            produced_output=bool(stdout.strip())), rec

    if not stdout.strip():
        return ParserResult(
            signalled=exit_code not in (0, None),
            signal_detail=f"exit {exit_code}; empty stdout; stderr: {stderr[:200]}",
            produced_output=False,
        ), rec

    try:
        payload = json.loads(stdout)
        rec.json_parse_ok = True
    except json.JSONDecodeError as e:
        return ParserResult(
            signalled=exit_code not in (0, None),
            signal_detail=f"exit {exit_code}; stdout not JSON ({e}); "
                          f"first 120 chars: {stdout[:120]!r}",
        ), rec

    if not isinstance(payload, dict):
        return ParserResult(
            signalled=exit_code not in (0, None),
            signal_detail=f"exit {exit_code}; JSON is {type(payload).__name__}, "
                          f"expected object",
        ), rec

    if "error" in payload and payload["error"]:
        rec.raw_error_key = str(payload["error"])[:200]
        return ParserResult(signalled=True,
                            signal_detail=f'error key: {rec.raw_error_key}'), rec

    if exit_code not in (0, None):
        return ParserResult(
            signalled=True,
            signal_detail=f"exit {exit_code} with JSON body; stderr: {stderr[:200]}",
        ), rec

    fields, naive = {}, set()
    for k in CONTRACT_FIELDS:
        if k not in payload:
            continue
        v = payload[k]
        if k.endswith("_time") and isinstance(v, str):
            v, was_naive = _parse_iso(v)
            if was_naive:
                naive.add(k)
        fields[k] = v

    return ParserResult(signalled=False, fields=fields,
                        naive_timestamps=naive), rec


def _parse_iso(s: str):
    """
    Parse an ISO 8601 timestamp, reporting whether it carried a UTC offset.

    A timestamp without an offset is under-specified, not wrong -- the same
    distinction made for pylnk3 in NOTES.md section 4. Recorded, not penalised.
    """
    import datetime as dt
    txt = s.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(txt)
    except ValueError:
        return s, False        
    return parsed, parsed.tzinfo is None
