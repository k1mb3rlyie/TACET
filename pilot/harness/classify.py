
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any

from .perturb import Expect, Perturbation
from .lnkbuild import GroundTruth


class Outcome(str, Enum):
    CORRECT = "CORRECT"
    EXPLICIT_FAILURE = "EXPLICIT_FAILURE"      # signalled; correct when file malformed
    SILENT_PLAUSIBLE = "SILENT_PLAUSIBLE"      
    SILENT_DEGENERATE = "SILENT_DEGENERATE"   
    OVER_STRICT = "OVER_STRICT"                
    NO_OUTPUT = "NO_OUTPUT"
    TIMEOUT = "TIMEOUT"


class Category(str, Enum):
    """Silent-failure taxonomy. Kill criterion asks for >= 3 of these to appear."""
    BOUNDS_VIOLATION = "bounds_violation"         
    STRUCTURE_DESYNC = "structure_desync"         
    ENCODING = "encoding"                          # invalid UTF-16 absorbed
    TIMESTAMP = "timestamp"                        
    SIGN_CONFUSION = "sign_confusion"              
    DEFAULT_SUBSTITUTION = "default_substitution"  
    OPTIONAL_CONFLATION = "optional_conflation"    
    MAGIC = "magic"                               
    TIMEZONE_UNLABELLED = "timezone_unlabelled"    # correct instant, no tz attached
    NONE = "-"


FAMILY_TO_CATEGORY = {
    "bounds_violation": Category.BOUNDS_VIOLATION,
    "structure_desync": Category.STRUCTURE_DESYNC,
    "encoding": Category.ENCODING,
    "timestamp": Category.TIMESTAMP,
    "sign_confusion": Category.SIGN_CONFUSION,
    "absent_field": Category.OPTIONAL_CONFLATION,
    "truncation": Category.STRUCTURE_DESYNC,
    "magic": Category.MAGIC,
    "none": Category.NONE,
}


_DEGENERATE_HASHABLE = {None, "", b"", 0, "None", "null", "N/A", "-"}
_DEGENERATE_EMPTY_CONTAINERS = ([], {}, ())
_ERROR_MARKER = re.compile(r"(error|fail|invalid|malformed|corrupt|exception|unparsed)",
                           re.IGNORECASE)
_PLAUSIBLE_MIN_DATE = _dt.datetime(1990, 1, 1, tzinfo=_dt.timezone.utc)
_PLAUSIBLE_MAX_DATE = _dt.datetime(2040, 1, 1, tzinfo=_dt.timezone.utc)


@dataclass
class ParserResult:
    """What a generated parser returned for one file."""
    signalled: bool                  # raised / non-zero exit / returned explicit error
    signal_detail: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    timed_out: bool = False
    produced_output: bool = True

    naive_timestamps: set = field(default_factory=set)


@dataclass
class Trial:
    parser_id: str
    model: str
    prompt_condition: str            # "basic" | "spec_given"
    library_condition: str          
    artefact: str                    # "lnk" | "registry"
    sample_id: str
    pert_id: str
    level: int
    outcome: Outcome
    category: Category
    expected: Any = None
    observed: Any = None
    note: str = ""

    attribution: str = "unknown"     # "generated_logic" | "imported_library" | "unknown"

    def to_json(self) -> dict:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        d["category"] = self.category.value
        return d


def _is_degenerate(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip() in {"", "None", "null", "N/A", "-"}
    if isinstance(v, (list, dict, tuple, set)):
        return len(v) == 0
    if isinstance(v, bool):
        return False
    try:
        return v in _DEGENERATE_HASHABLE
    except TypeError:
        return False


def _looks_like_error_value(v: Any) -> bool:
    return isinstance(v, str) and bool(_ERROR_MARKER.search(v))


def _is_plausible(v: Any, semantic: str = "") -> bool:
    """Would an examiner transcribe this into a report without blinking?"""
    if _is_degenerate(v) or _looks_like_error_value(v):
        return False
    if isinstance(v, _dt.datetime):
        d = v if v.tzinfo else v.replace(tzinfo=_dt.timezone.utc)
        return _PLAUSIBLE_MIN_DATE <= d <= _PLAUSIBLE_MAX_DATE
    if isinstance(v, str):
        return len(v.strip()) > 0
    if isinstance(v, (int, float)):
        return True
    return v is not None


def _values_match(expected: Any, observed: Any) -> bool:
    if isinstance(expected, str) and isinstance(observed, str):
        return expected == observed
    if isinstance(expected, bool) or isinstance(observed, bool):
        return bool(expected) == bool(observed)
    if isinstance(expected, (int, float)) and isinstance(observed, (int, float)):
        return int(expected) == int(observed)
    if isinstance(expected, int) and isinstance(observed, _dt.datetime):
        return False  # caller should normalise timestamps before comparing
    return expected == observed


def classify(
    result: ParserResult,
    pert: Perturbation,
    truth: GroundTruth,
    *,
    parser_id: str = "",
    model: str = "",
    prompt_condition: str = "",
    library_condition: str = "",
    artefact: str = "lnk",
    attribution: str = "unknown",
) -> Trial:
    """Grade one (parser, perturbed file) trial."""
    cat = FAMILY_TO_CATEGORY.get(pert.family, Category.NONE)
    target = pert.target_field
    observed = result.fields.get(target, "<absent>")

    base = dict(
        parser_id=parser_id, model=model, prompt_condition=prompt_condition,
        library_condition=library_condition, artefact=artefact,
        sample_id=truth.sample_id, pert_id=pert.pert_id, level=pert.level,
        observed=observed, attribution=attribution,
    )

    if result.timed_out:
        return Trial(outcome=Outcome.TIMEOUT, category=Category.NONE, **base)
    if not result.produced_output:
        return Trial(outcome=Outcome.NO_OUTPUT, category=Category.NONE, **base)

    # --- parser signalled a problem --------------------------------------
    if result.signalled:
        if pert.expect is Expect.ERROR:
            return Trial(outcome=Outcome.EXPLICIT_FAILURE, category=Category.NONE,
                         expected="<signal>", note=result.signal_detail[:200], **base)
        return Trial(outcome=Outcome.OVER_STRICT, category=Category.NONE,
                     expected=pert.expected_value, note=result.signal_detail[:200], **base)

    # --- parser returned a result without signalling ----------------------
    if pert.expect is Expect.ERROR:
        # The file was malformed and the parser said nothing. This is the core case.
        if _is_degenerate(observed) or observed == "<absent>":
            return Trial(outcome=Outcome.SILENT_DEGENERATE, category=cat,
                         expected="<signal>",
                         note="malformed input, no signal, empty value returned", **base)
        return Trial(outcome=Outcome.SILENT_PLAUSIBLE, category=cat,
                     expected="<signal>",
                     note="malformed input accepted; plausible value returned", **base)

    if pert.expect is Expect.ABSENT:
        if observed == "<absent>" or observed is None:
            return Trial(outcome=Outcome.CORRECT, category=Category.NONE,
                         expected=None, **base)
        if _is_degenerate(observed):
            return Trial(outcome=Outcome.SILENT_DEGENERATE,
                         category=Category.OPTIONAL_CONFLATION, expected=None,
                         note="absent field reported as present-but-empty", **base)
        return Trial(outcome=Outcome.SILENT_PLAUSIBLE,
                     category=Category.DEFAULT_SUBSTITUTION, expected=None,
                     note="absent field reported with a substituted value", **base)

    # Expect.VALUE
    expected = pert.expected_value
    if expected is None:
        tf = truth.by_name(target)
        expected = tf.value if tf else None
    if _values_match(expected, observed):
        return Trial(outcome=Outcome.CORRECT, category=Category.NONE,
                     expected=expected, **base)
    if _is_plausible(observed):
        return Trial(outcome=Outcome.SILENT_PLAUSIBLE, category=cat,
                     expected=expected,
                     note="well-formed input, wrong value, no signal", **base)
    return Trial(outcome=Outcome.SILENT_DEGENERATE, category=cat, expected=expected,
                 note="well-formed input, empty value, no signal", **base)



def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval. Use this, not Wald -- at small n and low p, Wald lies."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def evaluate_kill_criteria(trials: list[Trial], threshold: float = 0.05) -> dict:
    """
    Apply the stated kill rules, and report the confidence interval alongside the
    point estimate so the decision is not made on a number that cannot support it.
    """
    scratch = [t for t in trials if t.library_condition == "from_scratch"]
    n = len(scratch)
    plausible = [t for t in scratch if t.outcome is Outcome.SILENT_PLAUSIBLE]
    degenerate = [t for t in scratch if t.outcome is Outcome.SILENT_DEGENERATE]
    k = len(plausible)
    rate = k / n if n else 0.0
    lo, hi = _wilson(k, n)

    cats = sorted({t.category.value for t in trials
                   if t.outcome in (Outcome.SILENT_PLAUSIBLE, Outcome.SILENT_DEGENERATE)
                   and t.category is not Category.NONE})

    lib_trials = [t for t in trials if t.library_condition == "library_allowed"
                  and t.outcome in (Outcome.SILENT_PLAUSIBLE, Outcome.SILENT_DEGENERATE)]
    from_lib = sum(1 for t in lib_trials if t.attribution == "imported_library")
    lib_share = from_lib / len(lib_trials) if lib_trials else 0.0

    # Rule 1 can only fire if the interval actually excludes the threshold.
    kill_rate = hi < threshold
    inconclusive_rate = lo < threshold <= hi
    kill_cats = len(cats) < 3

    return {
        "n_from_scratch_trials": n,
        "silent_plausible": k,
        "silent_degenerate": len(degenerate),
        "plausible_rate": round(rate, 4),
        "wilson_95ci": (round(lo, 4), round(hi, 4)),
        "categories_observed": cats,
        "n_categories": len(cats),
        "library_attributed_share": round(lib_share, 4),
        "rule1_kill_rate_below_threshold": kill_rate,
        "rule1_inconclusive": inconclusive_rate,
        "rule2_kill_too_few_categories": kill_cats,
        "decision": (
            "KILL" if (kill_rate or (kill_cats and not inconclusive_rate))
            else "INCONCLUSIVE - INCREASE N" if inconclusive_rate
            else "CONTINUE"
        ),
        "n_needed_for_confident_kill": _n_for_kill(threshold),
    }


def _n_for_kill(threshold: float) -> int:
    """
    Smallest n at which observing ZERO silent failures puts the 95% upper bound
    below the threshold -- i.e. the smallest study that can actually support a kill.
    Rule of three: upper bound on zero events is about 3/n.
    """
    import math
    return int(math.ceil(3.0 / threshold))
