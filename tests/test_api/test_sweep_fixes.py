"""
tests/test_api/test_sweep_fixes.py
───────────────────────────────────
Guards for the defects found by the full-repo sweep.

  #1  MitreMapper.record_detection had no true-positive filter, and the driver
      called it for every alert carrying a technique id — including ones the
      pipeline had marked False. A false positive therefore marked its
      technique detected, inflated mitre_coverage_pct, and recorded a dwell
      time that improved MTTD. All of it persisted into the Score row. The API
      read path was fixed earlier; this is the write path.

  #2  rule_yaml had no max_length (a 3 MB rule was accepted) and there was no
      cap on rules per session, though every rule is re-parsed and evaluated
      against each log batch.

  #4  The rule listing had no LIMIT.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from core.log_engine.schemas import AlertSchema
from core.mitre.mapper import MitreMapper


BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _step(technique_id="T1059", **kw):
    from core.attack_engine.techniques.base import AttackStep

    defaults = dict(
        step_number=1, phase="execution", technique_id=technique_id,
        technique_name="Command Interpreter", tactic="execution",
        description="ran something", timestamp=BASE, success=True,
    )
    defaults.update(kw)
    return AttackStep(**defaults)


def _alert(technique_id, verdict, at=BASE + timedelta(seconds=30)):
    return AlertSchema(
        id=str(uuid.uuid4()), session_id="s1", detection_type="sigma",
        title="alert", description="d", severity="high",
        technique_id=technique_id, is_true_positive=verdict, timestamp=at,
    )


# ══════════════════════════════════════════════════════════════════════════
# #1 — coverage must count confirmed detections only
# ══════════════════════════════════════════════════════════════════════════

def test_false_positive_does_not_mark_a_technique_detected():
    m = MitreMapper("s1")
    m.record_step(_step("T1059"))
    m.record_detection(_alert("T1059", False))

    summary = m.coverage_summary()
    assert summary["techniques_detected"] == [], "a false positive counted as coverage"
    assert summary["techniques_detected_count"] == 0
    assert summary["coverage_pct"] == 0
    assert summary["techniques_missed"] == ["T1059"]


def test_untriaged_alert_does_not_count():
    m = MitreMapper("s1")
    m.record_step(_step("T1059"))
    m.record_detection(_alert("T1059", None))
    assert m.coverage_summary()["techniques_detected_count"] == 0


def test_true_positive_still_counts():
    """The filter must not break the case it is meant to allow."""
    m = MitreMapper("s1")
    m.record_step(_step("T1059"))
    m.record_detection(_alert("T1059", True))

    summary = m.coverage_summary()
    assert summary["techniques_detected"] == ["T1059"]
    assert summary["techniques_detected_count"] == 1
    assert summary["coverage_pct"] == 100


def test_false_positive_does_not_record_dwell_time():
    """An FP used to set first_detected_at, flattering MTTD."""
    m = MitreMapper("s1")
    m.record_step(_step("T1059"))
    m.record_detection(_alert("T1059", False, at=BASE + timedelta(seconds=5)))
    m.record_detection(_alert("T1059", True, at=BASE + timedelta(seconds=600)))

    rec = m._techniques["T1059"]
    assert rec.dwell_time_sec == pytest.approx(600.0), (
        f"dwell time {rec.dwell_time_sec} came from the false positive"
    )


# ══════════════════════════════════════════════════════════════════════════
# #2 — rule input bounds
# ══════════════════════════════════════════════════════════════════════════

def test_oversized_rule_yaml_is_rejected():
    from api.schemas.detection import MAX_RULE_YAML_CHARS, RuleCreate

    ok = "title: x\ndetection:\n  selection:\n    a: b\n  condition: selection"
    RuleCreate(name="fine", rule_yaml=ok)

    with pytest.raises(ValidationError):
        RuleCreate(name="huge", rule_yaml="a" * (MAX_RULE_YAML_CHARS + 1))


def test_oversized_description_is_rejected():
    from api.schemas.detection import MAX_RULE_DESC_CHARS, RuleCreate

    with pytest.raises(ValidationError):
        RuleCreate(
            name="x",
            rule_yaml="title: x\ndetection:\n  selection:\n    a: b\n  condition: selection",
            description="d" * (MAX_RULE_DESC_CHARS + 1),
        )


def test_update_is_bounded_too():
    """The update path was unbounded even after create was fixed."""
    from api.schemas.detection import MAX_RULE_YAML_CHARS, RuleUpdate

    with pytest.raises(ValidationError):
        RuleUpdate(rule_yaml="a" * (MAX_RULE_YAML_CHARS + 1))


@pytest.mark.asyncio
async def test_rules_per_session_are_capped(make_client, sqlite_db, two_users, monkeypatch):
    import api.routers.detection as detection

    monkeypatch.setattr(detection, "MAX_RULES_PER_SESSION", 2)

    alice, alice_session = two_users["alice"]
    client = make_client(alice)
    body = {
        "name": "r",
        "session_id": alice_session.id,
        "rule_yaml": "title: r\ndetection:\n  selection:\n    username: admin\n  condition: selection",
    }

    assert (await client.post("/detection/rules", json=body)).status_code == 201
    assert (await client.post("/detection/rules", json=body)).status_code == 201

    over = await client.post("/detection/rules", json=body)
    assert over.status_code == 409, over.text


@pytest.mark.asyncio
async def test_rule_listing_is_bounded(make_client, two_users):
    """A limit above the ceiling must be refused rather than silently honoured."""
    alice, _ = two_users["alice"]
    client = make_client(alice)

    assert (await client.get("/detection/rules?limit=10")).status_code == 200
    assert (await client.get("/detection/rules?limit=99999")).status_code == 422
