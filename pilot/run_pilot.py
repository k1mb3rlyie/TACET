from __future__ import annotations

import datetime as _dt
import io
import json
import sys
from collections import Counter
from pathlib import Path

from harness.lnkbuild import build, default_corpus, from_filetime, to_filetime
from harness.perturb import all_levels
from harness.classify import (
    ParserResult, Trial, Outcome, classify, evaluate_kill_criteria,
)

PYLNK3_MAP = {
    "name_string": "description",
    "relative_path": "relative_path",
    "working_dir": "work_dir",
    "command_line_arguments": "arguments",
    "icon_location": "icon",
    "file_size": "file_size",
    "icon_index": "icon_index",
    "creation_time": "creation_time",
    "access_time": "access_time",
    "write_time": "modification_time",
}

UNSCORED = {"link_flags", "file_attributes", "show_command"}


def _coerce(v):
    """
    Reduce parser output to comparable primitives.

    Datetimes are passed through UNTOUCHED, tzinfo and all. The previous version
    did `v.replace(tzinfo=utc)` on naive values, which asserts "this is UTC" about
    a value the parser never made that claim for. On a UTC host that assumption is
    invisibly right; on UTC+1 it is invisibly wrong by an hour. Timezone handling
    belongs in one place -- normalise_timestamps -- not scattered through coercion.
    """
    if isinstance(v, _dt.datetime):
        return v
    if isinstance(v, (str, int, float, bool, type(None))):
        return v
    if isinstance(v, bytes):
        return v.hex()
    return str(v)[:200]


def pylnk3_adapter(data: bytes) -> ParserResult:
    import pylnk3
    try:
        lnk = pylnk3.Lnk(io.BytesIO(data))
    except Exception as e:
        return ParserResult(signalled=True,
                            signal_detail=f"{type(e).__name__}: {e}")

    fields, naive = {}, set()
    for gt_name, attr in PYLNK3_MAP.items():
        try:
            v = _coerce(getattr(lnk, attr))
        except Exception:
            continue
        if isinstance(v, _dt.datetime) and v.tzinfo is None:
            naive.add(gt_name)
        fields[gt_name] = v
    return ParserResult(signalled=False, fields=fields, naive_timestamps=naive)


def _to_whole_seconds(ft: int) -> int:
    """Round-to-nearest whole second, in ticks. Must be applied to BOTH sides --
    flooring one side and not the other loses a full second at the boundary."""
    return (ft + 5_000_000) // 10_000_000 * 10_000_000


def normalise_timestamps(result: ParserResult, truth, pert) -> ParserResult:

    for name in ("creation_time", "access_time", "write_time"):
        v = result.fields.get(name)
        if isinstance(v, _dt.datetime):
            if v.tzinfo is None:
                v = v.astimezone()          
            result.fields[name] = _to_whole_seconds(to_filetime(v))
        tf = truth.by_name(name)
        if tf is not None and isinstance(tf.value, int):
            tf.value = _to_whole_seconds(tf.value)
        if pert.target_field == name and isinstance(pert.expected_value, int):
            pert.expected_value = _to_whole_seconds(pert.expected_value)
    return result


NAIVE_TS: list = []


def run(adapter, *, model="reference", prompt_condition="n/a",
        library_condition="library_allowed", max_level=2) -> list[Trial]:
    trials: list[Trial] = []
    for spec in default_corpus():
        data, gt = build(spec)
        for sample in all_levels(data, gt, max_level=max_level):
            result = adapter(sample.data)
            NAIVE_TS.extend(result.naive_timestamps)
            result = normalise_timestamps(result, sample.truth, sample.perturbation)
            if sample.perturbation.target_field in UNSCORED:
                continue
            trials.append(classify(
                result, sample.perturbation, sample.truth,
                parser_id=f"{model}::{library_condition}",
                model=model, prompt_condition=prompt_condition,
                library_condition=library_condition, artefact="lnk",
                attribution="imported_library",
            ))
    return trials


def summarise(trials: list[Trial]) -> None:
    outcomes = Counter(t.outcome.value for t in trials)
    print(f"\n{'OUTCOME':<22}{'N':>5}   {'%':>6}")
    print("-" * 36)
    total = len(trials)
    for name, n in outcomes.most_common():
        print(f"{name:<22}{n:>5}   {100*n/total:>5.1f}%")
    print("-" * 36)
    print(f"{'TOTAL':<22}{total:>5}")

    silent = [t for t in trials if t.outcome in
              (Outcome.SILENT_PLAUSIBLE, Outcome.SILENT_DEGENERATE)]
    if silent:
        print(f"\nSILENT FAILURES BY TAXONOMY CATEGORY")
        print("-" * 52)
        for cat, n in Counter(t.category.value for t in silent).most_common():
            print(f"  {cat:<26}{n:>4}")

    if NAIVE_TS:
        print(f"\nTIMEZONE-UNLABELLED TIMESTAMPS (reported, not scored as failures)")
        print("-" * 78)
        print(f"  {len(NAIVE_TS)} timestamp reads returned a naive datetime.")
        print(f"  Host zone: {_dt.datetime.now().astimezone().tzname()}. On a UTC host this")
        print(f"  is invisible; elsewhere the reported instant shifts by the UTC offset.")

    plausible = [t for t in trials if t.outcome is Outcome.SILENT_PLAUSIBLE]
    if plausible:
        print(f"\nPLAUSIBLE SILENT FAILURES (the dangerous ones)")
        print("-" * 78)
        for t in plausible[:12]:
            obs = repr(t.observed)
            obs = obs[:34] + "..." if len(obs) > 37 else obs
            print(f"  {t.pert_id:<30} {t.category.value:<20} -> {obs}")
        if len(plausible) > 12:
            print(f"  ... and {len(plausible)-12} more")


if __name__ == "__main__":
    print("=" * 78)
    print("PILOT HARNESS SELF-TEST  --  parser under test: pylnk3 (library baseline)")
    print("=" * 78)
    trials = run(pylnk3_adapter)
    summarise(trials)

    verdict = evaluate_kill_criteria(trials)
    print("\n" + "=" * 78)
    print("KILL-CRITERION EVALUATION")
    print("=" * 78)
    for k, v in verdict.items():
        print(f"  {k:<38} {v}")

    out = Path("results")
    out.mkdir(exist_ok=True)
    (out / "trials_pylnk3.json").write_text(
        json.dumps([t.to_json() for t in trials], indent=2, default=str))
    (out / "verdict_pylnk3.json").write_text(
        json.dumps(verdict, indent=2, default=str))
    print(f"\nWrote {len(trials)} trials to results/trials_pylnk3.json")
