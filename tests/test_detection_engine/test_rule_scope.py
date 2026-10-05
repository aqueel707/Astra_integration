"""
tests/test_detection_engine/test_rule_scope.py
───────────────────────────────────────────────
Guards for the rule-scoping optimisation.

_run_sigma used to evaluate EVERY rule against the ENTIRE buffer (capped at
5000) on every batch, then discard matches that did not include a new log —
roughly 99% recomputation late in a session, on the event loop.

It now picks the smallest sufficient scope per rule. That is only a valid
optimisation if it does not change what fires, which is what these assert:
a stateless rule must still fire exactly once per matching log, and an
aggregation rule must still see far enough back to cross batch boundaries.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.detection_engine.pipeline import DetectionPipeline
from core.log_engine.schemas import LogEntry

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _log(i: int, *, user="admin", ip="10.0.0.5", offset=0) -> LogEntry:
    return LogEntry(
        id=f"log-{i}",
        session_id="s1",
        source="windows_event",
        message="failed logon",
        username=user,
        source_ip=ip,
        timestamp=BASE + timedelta(seconds=offset),
    )


STATELESS = """
title: Admin activity
level: high
detection:
  selection:
    username: admin
  condition: selection
"""

WINDOWED = """
title: Brute force
level: high
detection:
  selection:
    username: admin
  timeframe: 5m
  condition: selection | count(source_ip) > 5
"""


def _pipeline(rule_yaml: str) -> DetectionPipeline:
    p = DetectionPipeline(session_id="s1", enable_anomaly=False, enable_correlation=False)
    p.rule_manager.add_rule_from_yaml(rule_yaml)
    return p


def test_stateless_rule_fires_once_per_log_across_batches():
    """No duplicates from re-scanning, and no misses from scoping too narrowly."""
    p = _pipeline(STATELESS)

    first = p.process_logs([_log(1, offset=0), _log(2, offset=1)])
    second = p.process_logs([_log(3, offset=2)])
    third = p.process_logs([_log(4, user="guest", offset=3)])   # no match

    assert len(first) == 2
    assert len(second) == 1, "a later batch re-emitted or missed matches"
    assert len(third) == 0


def test_aggregation_window_still_spans_batches():
    """The count must reach back across batches, or brute-force never fires.

    This is the case narrowing the scope could plausibly break: six logs
    arriving in two batches of three, inside one 5-minute window.
    """
    p = _pipeline(WINDOWED)

    assert p.process_logs([_log(i, offset=i * 10) for i in range(3)]) == []

    fired = p.process_logs([_log(i, offset=i * 10) for i in range(3, 7)])
    assert fired, "aggregation rule stopped firing across a batch boundary"


def test_logs_outside_the_timeframe_are_excluded():
    """Scope is the rule's own window, so stale logs cannot inflate a count."""
    p = _pipeline(WINDOWED)

    # Five hits, then a long gap. The old logs fall outside the 5m window.
    p.process_logs([_log(i, offset=i) for i in range(5)])
    late = p.process_logs([_log(99, offset=6000)])

    assert late == [], "logs outside the rule's timeframe were counted"


def test_scope_selection_is_minimal():
    """A stateless rule must be handed only the new logs."""
    p = _pipeline(STATELESS)
    rule = p.rule_manager.active_rules()[0]

    all_logs = [_log(i, offset=i) for i in range(50)]
    only_new = all_logs[-2:]

    assert p._scope_for_rule(rule, all_logs, only_new) == only_new


def test_aggregation_without_timeframe_keeps_full_history():
    p = _pipeline("""
title: Total count
detection:
  selection:
    username: admin
  condition: selection | count(source_ip) > 2
""")
    rule = p.rule_manager.active_rules()[0]
    all_logs = [_log(i, offset=i) for i in range(10)]
    assert p._scope_for_rule(rule, all_logs, all_logs[-1:]) == all_logs
