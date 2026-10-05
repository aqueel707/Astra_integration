"""
tests/test_api/test_progress_modes.py
──────────────────────────────────────
Guards for the progress endpoints.

Three defects, all of which made the skills radar wrong:

  B7   Pentester runs write different quantities, on a different scale, into
       the SOC-shaped Score columns. /progress/skills averaged both modes
       together, so one pentester run made a user's chart meaningless.

  scale  detection_rate is stored as a 0.0-1.0 fraction but the radar chart
       expects 0-100, so SOC detection rendered as ~0.7 out of 100 for every
       session the project has ever scored. Independent of the mode mixing.

  B9b  The Float columns are nullable, so sum() over a row written outside the
       ORM raised TypeError.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio

from db.models import Score, Session as SessionModel


def _score(session_id, *, mode=None, detection_rate=0.8, coverage=60.0, **kw):
    details = {"mode": mode} if mode else {}
    return Score(
        id=str(uuid.uuid4()),
        session_id=session_id,
        total_score=kw.get("total_score", 70.0),
        grade="good",
        detection_rate=detection_rate,
        mean_time_to_detect_sec=kw.get("mttd", 120.0),
        false_positive_rate=kw.get("fp", 0.1),
        containment_score=kw.get("containment", 55.0),
        report_quality_score=kw.get("report", 65.0),
        mitre_coverage_pct=coverage,
        details=details,
    )


async def _extra_session(sqlite_db, user_id) -> str:
    sid = str(uuid.uuid4())
    async with sqlite_db() as s:
        s.add(SessionModel(id=sid, user_id=user_id, scenario_id="silver_pixel",
                           role="red_team", difficulty="medium", status="completed"))
        await s.commit()
    return sid


@pytest.mark.asyncio
async def test_detection_rate_is_scaled_to_the_chart(make_client, sqlite_db, two_users):
    """0.8 stored as a fraction must surface as 80, not 0.8."""
    alice, alice_session = two_users["alice"]
    async with sqlite_db() as s:
        s.add(_score(alice_session.id, detection_rate=0.8))
        await s.commit()

    body = (await make_client(alice).get("/progress/skills")).json()
    assert body["detection"] == pytest.approx(80.0)


@pytest.mark.asyncio
async def test_pentester_scores_excluded_from_soc_skills(make_client, sqlite_db, two_users):
    """A pentester run must not drag the SOC averages."""
    alice, alice_session = two_users["alice"]
    pentester_session = await _extra_session(sqlite_db, alice.id)

    async with sqlite_db() as s:
        s.add(_score(alice_session.id, detection_rate=0.8, coverage=60.0))
        # Pentester shape: stealth 0-100 in detection_rate, minutes in mttd.
        s.add(_score(pentester_session, mode="pentester",
                     detection_rate=95.0, mttd=2700.0, coverage=42.8))
        await s.commit()

    body = (await make_client(alice).get("/progress/skills")).json()

    # Only the SOC row counts: 0.8 -> 80. Averaging both would give ~4790.
    assert body["detection"] == pytest.approx(80.0)
    assert body["coverage"] == pytest.approx(60.0)


@pytest.mark.asyncio
async def test_skills_survives_null_columns(make_client, sqlite_db, two_users):
    """Nullable Float columns must not raise TypeError in sum()."""
    alice, alice_session = two_users["alice"]
    async with sqlite_db() as s:
        row = _score(alice_session.id)
        row.report_quality_score = None
        row.containment_score = None
        row.mean_time_to_detect_sec = None
        s.add(row)
        await s.commit()

    resp = await make_client(alice).get("/progress/skills")
    assert resp.status_code == 200
    assert resp.json()["report"] == 0


@pytest.mark.asyncio
async def test_summary_survives_null_columns(make_client, sqlite_db, two_users):
    alice, alice_session = two_users["alice"]
    async with sqlite_db() as s:
        row = _score(alice_session.id)
        row.total_score = None
        row.mitre_coverage_pct = None
        s.add(row)
        await s.commit()

    resp = await make_client(alice).get("/progress/summary")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_trends_reports_the_real_mode(make_client, sqlite_db, two_users):
    """Session.config is never populated, so trends tagged everything 'soc'."""
    alice, _ = two_users["alice"]
    pentester_session = await _extra_session(sqlite_db, alice.id)
    async with sqlite_db() as s:
        s.add(_score(pentester_session, mode="pentester"))
        await s.commit()

    rows = (await make_client(alice).get("/progress/trends")).json()
    assert rows and rows[0]["mode"] == "pentester"


@pytest.mark.asyncio
async def test_technique_lookup_on_unseeded_matrix(make_client, two_users, monkeypatch):
    """A matrix file with no 'techniques' key must 404, not 500."""
    import api.routers.mitre as mitre

    monkeypatch.setattr(mitre, "_mitre_cache", {"version": "unseeded"})
    alice, _ = two_users["alice"]

    resp = await make_client(alice).get("/mitre/technique/T1059")
    assert resp.status_code == 404
