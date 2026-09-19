from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

TRIALS = Path("results/tacet_trials.jsonl")


def load():
    if not TRIALS.exists():
        raise SystemExit("No trials. Run `python run_tacet.py evaluate` first.")
    return [json.loads(l) for l in TRIALS.open(encoding="utf-8") if l.strip()]


def verdict(l0_acc: float, silent: int, explicit: int, no_out: int, n: int) -> str:
    if no_out > n * 0.5:
        return "DEAD          never produced output"
    if l0_acc < 0.25:
        return "BROKEN        cannot read undamaged files"
    if l0_acc < 0.5:
        return "UNRELIABLE    fails on undamaged files"
    if silent == 0 and explicit > 0:
        return "SAFE          reads clean, signals on damaged"
    if silent == 0:
        return "SAFE?         no silent failures, few signals either"
    return f"LEAKY         {silent} silent failures"


def overview(rows):
    by = defaultdict(list)
    for r in rows:
        by[r["parser_id"]].append(r)

    print(f"{'PARSER':<52}{'L0':>6}{'silent':>8}{'expl':>6}  VERDICT")
    print("-" * 118)

    tally = Counter()
    for pid in sorted(by):
        g = by[pid]
        l0 = [r for r in g if r["level"] == 0]
        acc = sum(1 for r in l0 if r["outcome"] == "CORRECT") / len(l0) if l0 else 0.0
        silent = sum(1 for r in g if r["outcome"] == "SILENT_PLAUSIBLE")
        expl = sum(1 for r in g if r["outcome"] == "EXPLICIT_FAILURE")
        no_out = sum(1 for r in g if r["outcome"] in ("NO_OUTPUT", "TIMEOUT"))
        v = verdict(acc, silent, expl, no_out, len(g))
        tally[v.split()[0]] += 1
        short = pid.replace("groq-", "").replace("gemini-", "").replace("openrouter-", "")
        print(f"{short[:50]:<52}{100*acc:>5.0f}%{silent:>8}{expl:>6}  {v}")

    print("-" * 118)
    for k, n in tally.most_common():
        print(f"  {k:<14}{n:>3}")

    if tally.get("BROKEN") or tally.get("DEAD") or tally.get("UNRELIABLE"):
        print("\n  Parsers marked BROKEN, DEAD or UNRELIABLE score zero silent failures")
        print("  because they fail at everything, not because they are careful. Leaving")
        print("  them in the headline understates the silent-failure rate. The report's")
        print("  competence gate excludes them; say so explicitly in the paper.")


def detail(rows, needle: str):
    hits = sorted({r["parser_id"] for r in rows if needle.lower() in r["parser_id"].lower()})
    if not hits:
        raise SystemExit(f"No parser matching {needle!r}")
    for pid in hits[:3]:
        g = [r for r in rows if r["parser_id"] == pid]
        print(f"\n{'=' * 78}\n{pid}\n{'=' * 78}")
        print("  outcomes:", dict(Counter(r["outcome"] for r in g)))

        l0 = [r for r in g if r["level"] == 0]
        bad = [r for r in l0 if r["outcome"] != "CORRECT"]
        print(f"\n  Level 0 (undamaged): {len(l0) - len(bad)}/{len(l0)} correct")
        for r in bad[:8]:
            print(f"    {r['pert_id']:<28} {r['outcome']:<18} "
                  f"expected={str(r['expected'])[:22]!r} got={str(r['observed'])[:22]!r}")

        sil = [r for r in g if r["outcome"] == "SILENT_PLAUSIBLE"]
        if sil:
            print(f"\n  Silent failures ({len(sil)}):")
            for r in sil[:10]:
                print(f"    {r['pert_id']:<28} {r['category']:<22} "
                      f"got={str(r['observed'])[:26]!r}")

        src = Path("parsers") / f"{pid}.py"
        if src.exists():
            text = src.read_text(encoding="utf-8", errors="replace")
            print(f"\n  Source: {len(text)} chars, {text.count(chr(10))} lines")
            swallows = text.count("except") - text.count("raise")
            print(f"    except blocks: {text.count('except')}, "
                  f"raise statements: {text.count('raise')}, "
                  f"sys.exit: {text.count('sys.exit')}")
            if swallows > 2:
                print(f"    -> {swallows} more excepts than raises: likely swallowing errors")
            print(f"    IconIndex read: "
                  f"{'signed <i' if '<i' in text else 'unsigned <I' if '<I' in text else 'unclear'}")


def why(needle: str | None):
    """
    Run parsers against the UNDAMAGED corpus and print exactly what they say.

    When a parser rejects a pristine file, the reason is in its own output, not in
    any statistic. This runs it and shows you.
    """
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    from harness.lnkbuild import build, default_corpus
    from harness.sandbox import run_generated_parser

    files = sorted(Path("parsers").glob("*.py"))
    if needle:
        files = [f for f in files if needle.lower() in f.stem.lower()]
    if not files:
        raise SystemExit("No parsers matched.")

    data, _gt = build(default_corpus()[0])          
    print(f"Running {len(files)} parser(s) against the UNDAMAGED lnk_full sample.\n")

    reasons = Counter()
    for f in files:
        res, rec = run_generated_parser(f.read_text(encoding="utf-8", errors="replace"),
                                        data, timeout=15)
        short = f.stem.replace("groq-", "").replace("gemini-", "")[:46]
        if not res.signalled and res.fields:
            print(f"  OK       {short}")
            reasons["accepted"] += 1
            continue
        msg = (rec.stdout.strip() or rec.stderr.strip() or "(no output)")
        msg = " ".join(msg.split())[:110]
        print(f"  REJECTS  {short}")
        print(f"           {msg}")
        key = msg.lower()
        for probe in ("idlist", "id list", "linkinfo", "link info", "shell item",
                      "target", "traceback", "no such", "import", "argv"):
            if probe in key:
                reasons[probe] += 1
                break
        else:
            reasons["other"] += 1

    print("\n" + "-" * 70)
    for k, v in reasons.most_common():
        print(f"  {k:<14}{v:>4}")
    if reasons.get("idlist", 0) + reasons.get("linkinfo", 0) > 2:
        print("\n  Parsers are demanding a LinkTargetIDList or LinkInfo structure.")
        print("  Real .lnk files almost always carry both; the synthetic corpus has")
        print("  neither. Those parsers are not over-strict -- the corpus is")
        print("  unrealistic. This needs fixing in lnkbuild.py before any number")
        print("  from this run means anything.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--parser", default=None, help="substring of a parser_id")
    ap.add_argument("--why", action="store_true",
                    help="run parsers on an undamaged file and show why they reject")
    a = ap.parse_args()
    if a.why:
        why(a.parser)
    else:
        rows = load()
        detail(rows, a.parser) if a.parser else overview(rows)
