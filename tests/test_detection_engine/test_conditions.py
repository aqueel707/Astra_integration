"""
tests/test_detection_engine/test_conditions.py
───────────────────────────────────────────────
Guards for the Sigma condition language.

Two defects lived here for the project's whole life, both silent:

  B3  `and` conditions intersected set(LogEntry). LogEntry is a Pydantic model
      with __eq__ and no __hash__, so every such rule raised TypeError, which
      the pipeline caught, printed and skipped — the rule simply never fired.

  B4  `not` was never implemented. `selection and not filter` fell through to
      "return the first selection's matches", discarding the exclusion, so the
      rule fired on exactly the events it was written to suppress.

Both failed silently, which is why they survived. These tests assert the
semantics directly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.detection_engine.sigma_parser import evaluate_rule, parse_sigma_rule
from core.log_engine.schemas import LogEntry


def _log(**kw) -> LogEntry:
    base = dict(
        session_id="s1",
        source="windows_event",
        message="event",
        timestamp=datetime.now(timezone.utc),
    )
    base.update(kw)
    return LogEntry(**base)


def _rule(condition: str, extra_selection: str = "") -> str:
    return f"""
title: Test Rule
level: high
logsource:
  product: windows
detection:
  selection:
    username: admin
  filter:
    hostname: WKST-TRUSTED
{extra_selection}
  condition: {condition}
"""


# ══════════════════════════════════════════════════════════════════════════
# B3 — `and`
# ══════════════════════════════════════════════════════════════════════════

def test_and_condition_does_not_raise_and_intersects():
    """Previously raised TypeError: unhashable type: 'LogEntry'."""
    rule = parse_sigma_rule(_rule("selection and filter"))
    logs = [
        _log(id="a", username="admin", hostname="WKST-TRUSTED"),   # both
        _log(id="b", username="admin", hostname="WKST-OTHER"),     # selection only
        _log(id="c", username="guest", hostname="WKST-TRUSTED"),   # filter only
    ]
    matched = [l.id for group in evaluate_rule(rule, logs) for l in group]
    assert matched == ["a"]


# ══════════════════════════════════════════════════════════════════════════
# B4 — `not`
# ══════════════════════════════════════════════════════════════════════════

def test_not_excludes_rather_than_being_ignored():
    """The canonical Sigma idiom. Previously matched b AND a."""
    rule = parse_sigma_rule(_rule("selection and not filter"))
    logs = [
        _log(id="a", username="admin", hostname="WKST-TRUSTED"),   # excluded
        _log(id="b", username="admin", hostname="WKST-OTHER"),     # kept
        _log(id="c", username="guest", hostname="WKST-OTHER"),     # not selected
    ]
    matched = [l.id for group in evaluate_rule(rule, logs) for l in group]
    assert matched == ["b"], "the exclusion was discarded"


def test_bare_not_is_relative_to_the_candidate_pool():
    rule = parse_sigma_rule(_rule("not selection"))
    logs = [
        _log(id="a", username="admin"),
        _log(id="b", username="guest"),
    ]
    matched = [l.id for group in evaluate_rule(rule, logs) for l in group]
    assert matched == ["b"]


def test_parentheses_group_correctly():
    extra = "  second:\n    process_name: evil.exe\n"
    rule = parse_sigma_rule(_rule("(selection or second) and not filter", extra))
    logs = [
        _log(id="a", username="admin", hostname="WKST-OTHER"),                    # selection
        _log(id="b", process_name="evil.exe", hostname="WKST-OTHER"),             # second
        _log(id="c", username="admin", hostname="WKST-TRUSTED"),                  # filtered out
        _log(id="d", username="guest", hostname="WKST-OTHER"),                    # neither
    ]
    matched = sorted(l.id for group in evaluate_rule(rule, logs) for l in group)
    assert matched == ["a", "b"]


def test_or_still_works():
    extra = "  second:\n    process_name: evil.exe\n"
    rule = parse_sigma_rule(_rule("selection or second", extra))
    logs = [
        _log(id="a", username="admin"),
        _log(id="b", process_name="evil.exe"),
        _log(id="c", username="guest"),
    ]
    matched = sorted(l.id for group in evaluate_rule(rule, logs) for l in group)
    assert matched == ["a", "b"]


# ══════════════════════════════════════════════════════════════════════════
# Unusable conditions must be REJECTED, never reinterpreted
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "condition",
    [
        "selection and",             # dangling operator
        "and selection",             # leading operator
        "(selection",                # unbalanced
        "selection)",                # unbalanced
        "nonexistent_selection",     # undefined name
        "selection and ghost",       # undefined name in a compound
        "1 of them",                 # valid Sigma, not implemented here
        "all of them",               # valid Sigma, not implemented here
    ],
)
def test_unusable_conditions_are_rejected_at_parse_time(condition):
    """/detection/rules/validate must refuse what the evaluator cannot honour.

    Previously these all fell through to "return the first selection", so the
    rule saved cleanly and then behaved as something the author never wrote.
    """
    with pytest.raises(ValueError):
        parse_sigma_rule(_rule(condition))


def test_aggregation_suffix_is_still_stripped():
    rule = parse_sigma_rule(_rule("selection | count(hostname) > 2"))
    assert rule.aggregation is not None
    now = datetime.now(timezone.utc)
    logs = [_log(id=str(i), username="admin", hostname="H1", timestamp=now + timedelta(seconds=i))
            for i in range(4)]
    assert evaluate_rule(rule, logs), "aggregation rule stopped firing"
