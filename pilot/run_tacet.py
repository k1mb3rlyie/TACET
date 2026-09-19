from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness.classify import Outcome, Category, classify, _wilson
from harness.lnkbuild import build, default_corpus
from harness.perturb import all_levels
from harness.prompts import CONDITIONS, build_prompt, extract_code
from harness.providers import (ProviderError, call as provider_call,
                               check as check_keys, show_models)
from harness.sandbox import CONTRACT_FIELDS, run_generated_parser

PARSER_DIR = Path("parsers")
RESULT_DIR = Path("results")
TRIALS_PATH = RESULT_DIR / "tacet_trials.jsonl"

SEEDS = 5
TIMEOUT = 10


MODELS = [
    "groq:openai/gpt-oss-120b",                      # OpenAI lineage, 120B
    "gemini:gemini-3.8-flash",                       # Google lineage
    "openrouter:deepseek/deepseek-v4-flash-0731:free",   # DeepSeek lineage
]


DEFAULT_MAX_TOKENS = 16384


def call_model(model: str, prompt: str, max_tokens: int = DEFAULT_MAX_TOKENS,
               retries: int = 5, timeout: float = 300.0) -> str:
    """Send `prompt` to `model`, return the raw response text."""
    return provider_call(model, prompt, max_tokens=max_tokens, verbose=True,
                         max_retries=retries, timeout=timeout)


def mock_model(model: str, prompt: str) -> str:
    """
    Stub generator for exercising the pipeline without API access.

    Returns one of three deliberately flawed parsers, so `evaluate` and `report`
    produce realistic-looking output. These are NOT findings — they are fixtures.
    Any run whose trials came from mock mode is tagged `mock=true` in the JSONL.
    """
    variants = [_MOCK_SWALLOWS_ERRORS, _MOCK_UNSIGNED_ICON, _MOCK_DECENT]
    return "```python\n" + random.choice(variants) + "\n```"


#generation
_FORBIDDEN = ':/\\*?"<>| '


def _slug(text: str) -> str:
    for ch in _FORBIDDEN:
        text = text.replace(ch, "-")
    while "--" in text:
        text = text.replace("--", "-")
    return text.strip("-")


def parser_id(model: str, prompt_cond: str, lib_cond: str, seed: int) -> str:
    return f"{_slug(model)}__{prompt_cond}__{lib_cond}__seed{seed}"


MIN_PARSER_CHARS = 150


def _looks_like_code(source: str) -> str | None:
    """
    Reject non-code before it reaches the cache.

    A cached empty file is worse than a failure: `generate` skips anything already on
    disk, so a zero-byte parser silently becomes a permanent hole in the matrix and
    re-running will never fill it. Returns a reason string if the source is unusable,
    None if it is fine.
    """
    text = (source or "").strip()
    if not text:
        return "empty response"
    if len(text) < MIN_PARSER_CHARS:
        return f"too short ({len(text)} chars)"
    if "import" not in text and "def " not in text:
        return "no import or def — probably prose, not code"
    return None


def generate(models: list[str], seeds: int, mock: bool, sleep: float,
             max_tokens: int = DEFAULT_MAX_TOKENS,
             retries: int = 5, timeout: float = 300.0) -> None:
    PARSER_DIR.mkdir(exist_ok=True)
    caller = mock_model if mock else call_model
    total = len(models) * len(CONDITIONS) * seeds
    done = skipped = failed = 0

    print(f"Generating {total} parsers "
          f"({len(models)} models x {len(CONDITIONS)} conditions x {seeds} seeds)")
    if mock:
        print("*** MOCK MODE — stub parsers, no API calls, results are fixtures ***")
    print()

    for model in models:
        for prompt_cond, lib_cond in CONDITIONS:
            prompt = build_prompt(prompt_cond, lib_cond)
            for seed in range(seeds):
                pid = parser_id(model, prompt_cond, lib_cond, seed)
                path = PARSER_DIR / f"{pid}.py"
                if path.exists():
                    skipped += 1
                    continue
                try:
                    response = (caller(model, prompt) if mock
                                else caller(model, prompt, max_tokens,
                                            retries, timeout))
                    source = extract_code(response)
                    bad = _looks_like_code(source)
                    if bad:
                        failed += 1
                        print(f"  [{done + skipped + failed:>3}/{total}] {pid}  "
                              f"REJECTED: {bad} (not cached — re-run to retry)")
                        if sleep and not mock:
                            time.sleep(sleep)
                        continue
                    path.write_text(source, encoding="utf-8")
                    (PARSER_DIR / f"{pid}.meta.json").write_text(json.dumps({
                        "parser_id": pid, "model": model,
                        "prompt_condition": prompt_cond,
                        "library_condition": lib_cond, "seed": seed,
                        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "mock": mock,
                        "response_chars": len(response),
                        "code_chars": len(source),
                    }, indent=2))
                    done += 1
                    print(f"  [{done + skipped + failed:>3}/{total}] {pid}  "
                          f"{len(source)} chars")
                except Exception as e:
                    failed += 1
                    print(f"  [{done + skipped + failed:>3}/{total}] {pid}  "
                          f"FAILED: {type(e).__name__}: {str(e)[:70]}")
                if sleep and not mock:
                    time.sleep(sleep)

    print(f"\ngenerated {done}, skipped {skipped} (cached), failed {failed}")
    if failed:
        print("Re-run the same command to retry only the failures.")



def _scorable(sample) -> bool:
    """
    Drop trials that ask a parser about a field the prompt never told it to return.

    The output contract lists ten fields. link_flags, file_attributes and
    show_command are not among them, so a compliant parser omits them — and scoring
    that omission as a wrong answer manufactures silent failures out of nothing.
    Five samples x three phantom fields = fifteen fabricated failures per parser,
    which is exactly the suspicious count of 15 seen in the first real run.

    EXPECT_ERROR trials are always kept: there the measurement is whether the parser
    signalled on a damaged file, and the damaged field may legitimately be one the
    contract never asks about (HeaderSize, CLSID, the terminal block).
    """
    from harness.perturb import Expect
    if sample.perturbation.expect is Expect.ERROR:
        return True
    return sample.perturbation.target_field in CONTRACT_FIELDS


def _load_done() -> set:
    if not TRIALS_PATH.exists():
        return set()
    done = set()
    with TRIALS_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
                done.add((r["parser_id"], r["sample_id"], r["pert_id"]))
            except Exception:
                continue
    return done


def evaluate(timeout: float, limit: int | None) -> None:
    RESULT_DIR.mkdir(exist_ok=True)
    parsers = sorted(PARSER_DIR.glob("*.py")) if PARSER_DIR.exists() else []
    if not parsers:
        print("No parsers in parsers/. Run `generate` first.")
        return

    already = _load_done()
    if already:
        print(f"Resuming — {len(already)} trials already recorded.\n")

    matrix = []
    for spec in default_corpus():
        data, gt = build(spec)
        matrix.extend(all_levels(data, gt))

    print(f"{len(parsers)} parsers x {len(matrix)} trials = "
          f"{len(parsers) * len(matrix)} total\n")

    written = 0
    with TRIALS_PATH.open("a", encoding="utf-8") as out:
        for i, path in enumerate(parsers, 1):
            pid = path.stem
            meta_path = PARSER_DIR / f"{pid}.meta.json"
            meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
            source = path.read_text(encoding="utf-8")

            pending = [s for s in matrix
                       if _scorable(s)
                       and (pid, s.truth.sample_id, s.perturbation.pert_id) not in already]
            if not pending:
                print(f"  [{i:>3}/{len(parsers)}] {pid}  (complete)")
                continue

            counts = Counter()
            for sample in pending:
                result, record = run_generated_parser(
                    source, sample.data, timeout=timeout)
                trial = classify(
                    result, sample.perturbation, sample.truth,
                    parser_id=pid,
                    model=meta.get("model", "unknown"),
                    prompt_condition=meta.get("prompt_condition", "unknown"),
                    library_condition=meta.get("library_condition", "unknown"),
                    artefact="lnk",
                    attribution="unknown",
                )
                row = trial.to_json()
                row["mock"] = meta.get("mock", False)
                row["exit_code"] = record.exit_code
                row["wall_seconds"] = round(record.wall_seconds, 3)
                row["naive_timestamp"] = sample.perturbation.target_field in \
                    result.naive_timestamps
                out.write(json.dumps(row, default=str) + "\n")
                counts[trial.outcome.value] += 1
                written += 1
            out.flush()

            sp = counts.get("SILENT_PLAUSIBLE", 0)
            print(f"  [{i:>3}/{len(parsers)}] {pid}  "
                  f"{len(pending)} trials, {sp} silent-plausible")

            if limit and written >= limit:
                print(f"\nStopping at --limit {limit}. Re-run to continue.")
                break

    print(f"\nwrote {written} trials to {TRIALS_PATH}")


def _cluster_bootstrap(by_parser: dict, n_boot: int = 2000) -> tuple[float, float]:

    parsers = list(by_parser.values())
    if not parsers:
        return (0.0, 1.0)
    rng = random.Random(20260918)
    rates = []
    for _ in range(n_boot):
        draw = [parsers[rng.randrange(len(parsers))] for _ in parsers]
        k = sum(d[0] for d in draw)
        n = sum(d[1] for d in draw)
        rates.append(k / n if n else 0.0)
    rates.sort()
    return (rates[int(0.025 * n_boot)], rates[int(0.975 * n_boot)])


def report(threshold: float, min_l0: float = 0.5) -> None:
    if not TRIALS_PATH.exists():
        print("No trials. Run `evaluate` first.")
        return
    rows = [json.loads(l) for l in TRIALS_PATH.open(encoding="utf-8") if l.strip()]
    if not rows:
        print("Trials file is empty.")
        return

    mock_rows = sum(1 for r in rows if r.get("mock"))
    print("=" * 76)
    print(f"TACET REPORT  —  {len(rows):,} trials, "
          f"{len({r['parser_id'] for r in rows})} parsers")
    if mock_rows:
        print(f"*** {mock_rows:,} trials came from MOCK parsers — fixtures, not findings ***")
    print("=" * 76)

    print(f"\n{'OUTCOME':<22}{'N':>7}{'%':>8}")
    print("-" * 38)
    outcomes = Counter(r["outcome"] for r in rows)
    for name, n in outcomes.most_common():
        print(f"{name:<22}{n:>7,}{100 * n / len(rows):>7.1f}%")

    l0 = defaultdict(lambda: [0, 0])
    for r in rows:
        if r["level"] == 0:
            c = l0[r["parser_id"]]
            c[1] += 1
            if r["outcome"] == "CORRECT":
                c[0] += 1
    competence = {pid: (c[0] / c[1] if c[1] else 0.0) for pid, c in l0.items()}
    competent = {pid for pid, acc in competence.items() if acc >= min_l0}
    excluded = sorted(set(competence) - competent,
                      key=lambda pid: competence[pid])

    print(f"\n{'COMPETENCE GATE — Level 0 (undamaged files)':<46}")
    print("-" * 76)
    print(f"  threshold                 {100*min_l0:.0f}% of pristine fields correct")
    print(f"  parsers passing           {len(competent)} / {len(competence)}")
    if excluded:
        print(f"  excluded from headline    {len(excluded)}")
        for pid in excluded[:10]:
            oc = Counter(r["outcome"] for r in rows if r["parser_id"] == pid)
            top = ", ".join(f"{k}={v}" for k, v in oc.most_common(3))
            print(f"    {100*competence[pid]:>5.1f}%  {pid[:44]:<44} {top}")
        if len(excluded) > 10:
            print(f"    ... and {len(excluded) - 10} more")
        print("\n  A parser here is broken, not safe. Report the exclusion count and")
        print("  the threshold in the paper — reviewers will ask, and the honest")
        print("  version of this number is the defensible one.")

    scratch = [r for r in rows if r["library_condition"] == "from_scratch"
               and r["parser_id"] in competent]
    by_parser = defaultdict(lambda: [0, 0])
    for r in scratch:
        c = by_parser[r["parser_id"]]
        c[1] += 1
        if r["outcome"] == "SILENT_PLAUSIBLE":
            c[0] += 1
    k = sum(c[0] for c in by_parser.values())
    n = sum(c[1] for c in by_parser.values())
    rate = k / n if n else 0.0
    naive_wilson = _wilson(k, n)
    cluster = _cluster_bootstrap(by_parser)

    all_scratch = [r for r in rows if r["library_condition"] == "from_scratch"]
    all_k = sum(1 for r in all_scratch if r["outcome"] == "SILENT_PLAUSIBLE")
    print(f"\n{'HEADLINE — from_scratch, competent parsers only':<46}")
    print("-" * 76)
    print(f"  silent-plausible          {k:,} / {n:,}  =  {100*rate:.2f}%")
    print(f"  naive binomial 95% CI     ({100*naive_wilson[0]:.2f}%, "
          f"{100*naive_wilson[1]:.2f}%)   <- overstates precision")
    print(f"  cluster bootstrap 95% CI  ({100*cluster[0]:.2f}%, "
          f"{100*cluster[1]:.2f}%)   <- report this one")
    print(f"  parsers (clusters)        {len(by_parser)}")
    if len(all_scratch) != n:
        ungated = all_k / len(all_scratch) if all_scratch else 0.0
        print(f"\n  without the gate          {all_k:,} / {len(all_scratch):,}  =  "
              f"{100*ungated:.2f}%   <- diluted by broken parsers")

    silent = [r for r in rows if r["outcome"] in
              ("SILENT_PLAUSIBLE", "SILENT_DEGENERATE")]
    cats = Counter(r["category"] for r in silent if r["category"] != "-")
    print(f"\n{'SILENT FAILURES BY CATEGORY':<46}")
    print("-" * 76)
    for cat, cnt in cats.most_common():
        print(f"  {cat:<30}{cnt:>6,}")
    if not cats:
        print("  (none)")

    for dim, label in (("model", "BY MODEL"),
                       ("prompt_condition", "BY PROMPT CONDITION"),
                       ("library_condition", "BY LIBRARY CONDITION")):
        print(f"\n{label}")
        print("-" * 76)
        print(f"  {'':<26}{'trials':>8}{'silent':>8}{'rate':>9}{'explicit':>10}")
        groups = defaultdict(list)
        for r in rows:
            groups[r[dim]].append(r)
        for key in sorted(groups):
            g = groups[key]
            sp = sum(1 for r in g if r["outcome"] == "SILENT_PLAUSIBLE")
            ex = sum(1 for r in g if r["outcome"] == "EXPLICIT_FAILURE")
            print(f"  {str(key):<26}{len(g):>8,}{sp:>8,}"
                  f"{100*sp/len(g):>8.1f}%{100*ex/len(g):>9.1f}%")

    naive_ts = sum(1 for r in rows if r.get("naive_timestamp"))
    if naive_ts:
        print(f"\nTIMEZONE-UNLABELLED TIMESTAMPS (reported, not scored)")
        print("-" * 76)
        print(f"  {naive_ts:,} timestamp reads returned no UTC offset despite the "
              f"prompt requiring one.")

    print("\n" + "=" * 76)
    print("KILL CRITERIA")
    print("=" * 76)
    lo, hi = cluster
    n_cats = len(cats)
    kill_rate = hi < threshold
    inconclusive = lo < threshold <= hi
    print(f"  rule 1  silent-plausible < {100*threshold:.0f}%     "
          f"upper bound {100*hi:.2f}%  ->  "
          f"{'KILL' if kill_rate else 'inconclusive' if inconclusive else 'pass'}")
    print(f"  rule 2  fewer than 3 categories    observed {n_cats}  ->  "
          f"{'KILL' if n_cats < 3 else 'pass'}")
    decision = ("KILL" if (kill_rate or (n_cats < 3 and not inconclusive))
                else "INCONCLUSIVE — INCREASE N" if inconclusive else "CONTINUE")
    print(f"\n  DECISION: {decision}")
    if mock_rows:
        print("\n  (meaningless while mock trials are present — "
              "delete results/tacet_trials.jsonl before the real run)")

    RESULT_DIR.mkdir(exist_ok=True)
    (RESULT_DIR / "tacet_summary.json").write_text(json.dumps({
        "trials": len(rows), "parsers": len({r["parser_id"] for r in rows}),
        "mock_trials": mock_rows,
        "competence_gate": {"min_l0": min_l0, "passing": len(competent),
                            "total": len(competence), "excluded": excluded},
        "from_scratch": {"silent_plausible": k, "n": n, "rate": rate,
                         "cluster_95ci": cluster, "naive_95ci": naive_wilson},
        "categories": dict(cats), "outcomes": dict(outcomes),
        "decision": decision,
    }, indent=2, default=str))
    print(f"\nwrote {RESULT_DIR / 'tacet_summary.json'}")

_MOCK_SWALLOWS_ERRORS = '''
import json, struct, sys, datetime
d = open(sys.argv[1], "rb").read()
def g(fmt, off, default=0):
    try: return struct.unpack_from(fmt, d, off)[0]
    except Exception: return default
def ft(v):
    try: return (datetime.datetime(1601,1,1) +
                 datetime.timedelta(microseconds=v//10)).isoformat()
    except Exception: return datetime.datetime.now().isoformat()
print(json.dumps({"name_string":"", "relative_path":"", "working_dir":"",
    "command_line_arguments":"", "icon_location":"",
    "file_size": g("<I",0x34), "icon_index": g("<I",0x38),
    "creation_time": ft(g("<Q",0x1C)), "access_time": ft(g("<Q",0x24)),
    "write_time": ft(g("<Q",0x2C))}))
'''

_MOCK_UNSIGNED_ICON = '''
import json, struct, sys, datetime
d = open(sys.argv[1], "rb").read()
if len(d) < 76 or struct.unpack_from("<I", d, 0)[0] != 0x4C:
    print(json.dumps({"error": "bad header"})); sys.exit(0)
def ft(v):
    try: return (datetime.datetime(1601,1,1,tzinfo=datetime.timezone.utc) +
                 datetime.timedelta(microseconds=v//10)).isoformat()
    except Exception: sys.exit(3)
print(json.dumps({"name_string": None, "relative_path": None, "working_dir": None,
    "command_line_arguments": None, "icon_location": None,
    "file_size": struct.unpack_from("<I", d, 0x34)[0],
    "icon_index": struct.unpack_from("<I", d, 0x38)[0],
    "creation_time": ft(struct.unpack_from("<Q", d, 0x1C)[0]),
    "access_time": ft(struct.unpack_from("<Q", d, 0x24)[0]),
    "write_time": ft(struct.unpack_from("<Q", d, 0x2C)[0])}))
'''

_MOCK_DECENT = '''
import json, struct, sys, datetime
d = open(sys.argv[1], "rb").read()
def die(m): print(json.dumps({"error": m})); sys.exit(0)
if len(d) < 80: die("truncated")
if struct.unpack_from("<I", d, 0)[0] != 0x4C: die("bad HeaderSize")
if d[4:20] != bytes([1,20,2,0,0,0,0,0,192,0,0,0,0,0,0,70]): die("bad CLSID")
def ft(v):
    try: return (datetime.datetime(1601,1,1,tzinfo=datetime.timezone.utc) +
                 datetime.timedelta(microseconds=v//10)).isoformat()
    except Exception: die("FILETIME out of range")
flags = struct.unpack_from("<I", d, 0x14)[0]
out = {"file_size": struct.unpack_from("<I", d, 0x34)[0],
       "icon_index": struct.unpack_from("<i", d, 0x38)[0],
       "creation_time": ft(struct.unpack_from("<Q", d, 0x1C)[0]),
       "access_time": ft(struct.unpack_from("<Q", d, 0x24)[0]),
       "write_time": ft(struct.unpack_from("<Q", d, 0x2C)[0])}
pos = 0x4C
for name, bit in (("name_string",4), ("relative_path",8), ("working_dir",0x10),
                  ("command_line_arguments",0x20), ("icon_location",0x40)):
    if not flags & bit:
        out[name] = None; continue
    if pos + 2 > len(d): die("truncated in StringData")
    cnt = struct.unpack_from("<H", d, pos)[0]; pos += 2
    if pos + cnt*2 > len(d): die("declared length exceeds file")
    try: out[name] = d[pos:pos+cnt*2].decode("utf-16-le")
    except UnicodeDecodeError: die("invalid UTF-16")
    pos += cnt*2
print(json.dumps(out))
'''


# ==========================================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="TACET driver")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="ask models for parsers (cached, resumable)")
    g.add_argument("--models", nargs="+", default=MODELS)
    g.add_argument("--seeds", type=int, default=SEEDS)
    g.add_argument("--mock", action="store_true",
                   help="stub parsers, no API calls — do this first")
    g.add_argument("--sleep", type=float, default=0.0,
                   help="seconds between calls, for rate limits")
    g.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS,
                   help="raise for reasoning models that think before writing")
    g.add_argument("--retries", type=int, default=5,
                   help="attempts per parser; drop to 1-2 with a flaky provider")
    g.add_argument("--timeout", type=float, default=300.0,
                   help="seconds per request before giving up")

    e = sub.add_parser("evaluate", help="run cached parsers over the matrix")
    e.add_argument("--timeout", type=float, default=TIMEOUT)
    e.add_argument("--limit", type=int, default=None,
                   help="stop after N trials (resumable)")

    m = sub.add_parser("models", help="list what each provider serves right now")
    m.add_argument("--providers", nargs="+", default=None)

    c = sub.add_parser("check", help="verify keys and model IDs before spending quota")
    c.add_argument("--models", nargs="+", default=MODELS)

    r = sub.add_parser("report", help="summarise and apply kill criteria")
    r.add_argument("--threshold", type=float, default=0.05)
    r.add_argument("--min-l0", type=float, default=0.5,
                   help="minimum Level-0 accuracy for a parser to count (0..1)")

    a = ap.parse_args()
    if a.cmd == "generate":
        generate(a.models, a.seeds, a.mock, a.sleep, a.max_tokens,
                 a.retries, a.timeout)
    elif a.cmd == "evaluate":
        evaluate(a.timeout, a.limit)
    elif a.cmd == "models":
        show_models(a.providers)
    elif a.cmd == "check":
        sys.exit(0 if check_keys(a.models) else 1)
    else:
        report(a.threshold, a.min_l0)


if __name__ == "__main__":
    main()
