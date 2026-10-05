"""
tests/test_api/test_coverage_scoring.py
────────────────────────────────────────
Guard for the ATT&CK coverage calculation.

Coverage counted an alert as a detection when is_true_positive was True OR
None — and None means "not yet triaged". So coverage rose with raw alert
volume, and the analyst who triaged nothing scored highest: the metric
rewarded the opposite of the skill the exercise teaches.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio

from db.models import Alert, AttackEvent


@pytest_asyncio.fixture
async def session_with_alerts(sqlite_db, two_users):
    """Three techniques executed; one confirmed, one untriaged, one dismissed."""
    _, alice_session = two_users["alice"]

    def _event(n, tid):
        return AttackEvent(
            id=str(uuid.uuid4()), session_id=alice_session.id,
            phase="execution", step_number=n, technique_id=tid,
            technique_name=f"Technique {tid}", tactic="execution",
            description="step",
        )

    def _alert(tid, verdict):
        return Alert(
            id=str(uuid.uuid4()), session_id=alice_session.id,
            detection_type="sigma", title=f"alert {tid}", description="d",
            severity="high", technique_id=tid, is_true_positive=verdict,
        )

    async with sqlite_db() as s:
        s.add_all([
            _event(1, "T1059"), _event(2, "T1110"), _event(3, "T1041"),
            _alert("T1059", True),    # confirmed detection
            _alert("T1110", None),    # untriaged  -> must NOT count
            _alert("T1041", False),   # dismissed  -> must NOT count
        ])
        await s.commit()

    return alice_session


@pytest.mark.asyncio
async def test_untriaged_alerts_do_not_count_as_detections(
    make_client, two_users, session_with_alerts
):
    alice, _ = two_users["alice"]
    resp = await make_client(alice).get(f"/mitre/coverage/{session_with_alerts.id}")
    assert resp.status_code == 200

    body = resp.json()
    assert body["techniques_detected"] == ["T1059"]
    assert sorted(body["techniques_missed"]) == ["T1041", "T1110"]

    # One of three techniques confirmed detected.
    assert body["coverage_pct"] == pytest.approx(33.3, abs=0.1)


@pytest.mark.asyncio
async def test_triaging_an_alert_raises_coverage(
    make_client, sqlite_db, two_users, session_with_alerts
):
    """The metric should reward triage, which is the point of the exercise."""
    from sqlalchemy import select

    alice, _ = two_users["alice"]
    client = make_client(alice)

    before = (await client.get(f"/mitre/coverage/{session_with_alerts.id}")).json()

    async with sqlite_db() as s:
        untriaged = (
            await s.execute(select(Alert).where(Alert.technique_id == "T1110"))
        ).scalar_one()
        alert_id = untriaged.id

    resp = await client.patch(
        f"/alerts/{alert_id}/triage",
        json={"triage_status": "true_positive", "is_true_positive": True},
    )
    assert resp.status_code == 200

    after = (await client.get(f"/mitre/coverage/{session_with_alerts.id}")).json()
    assert after["coverage_pct"] > before["coverage_pct"]
    assert sorted(after["techniques_detected"]) == ["T1059", "T1110"]
