"""
Alert endpoints — query alerts and triage them.

Routes:
    GET  /alerts                       — list alerts (filter by session_id, severity, status)
    GET  /alerts/{alert_id}            — get a single alert
    PATCH /alerts/{alert_id}/triage    — triage an alert (mark TP/FP, add notes)
    GET  /alerts/stats/{session_id}    — alert statistics for a session

Auth: every route requires a valid token and is scoped to the caller. Alerts
have no user_id of their own — they belong to a session, which has the owner —
so ownership resolves Alert -> Session -> user. As elsewhere in this API we
return 404 (not 403) for "not yours", so an id's existence is never confirmed
to a non-owner.
"""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.firebase_auth import get_current_user
from api.ownership import verify_alert_owner, verify_session_owner
from api.schemas.detection import AlertResponse, AlertTriage
from db import crud
from db.models import Alert, Session as SessionModel, User

router = APIRouter()


# ─── List ────────────────────────────────────────────────────────────────────
@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    session_id: str | None = None,
    severity: str | None = None,
    triage_status: str | None = None,
    limit: int = Query(100, le=500),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the caller's alerts, optionally narrowed to one of their sessions."""
    if session_id:
        # 404s if the session isn't theirs, so this can't read another user's alerts.
        await verify_session_owner(db, session_id, current_user)
        alerts = await crud.get_alerts(
            db,
            session_id=session_id,
            severity=severity,
            triage_status=triage_status,
            limit=limit,
        )
    else:
        # Most recent across the caller's OWN sessions. This previously spanned
        # every user's sessions, which leaked hostnames, IPs, usernames and
        # evidence blobs to anyone who asked.
        stmt = (
            select(Alert)
            .join(SessionModel, Alert.session_id == SessionModel.id)
            .where(SessionModel.user_id == current_user.id)
            .order_by(Alert.timestamp.desc())
            .limit(limit)
        )
        if severity:
            stmt = stmt.where(Alert.severity == severity)
        if triage_status:
            stmt = stmt.where(Alert.triage_status == triage_status)
        result = await db.execute(stmt)
        alerts = list(result.scalars().all())

    return alerts


# ─── Get one ─────────────────────────────────────────────────────────────────
@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch one alert from a session the caller owns."""
    return await verify_alert_owner(db, alert_id, current_user)


# ─── Triage ──────────────────────────────────────────────────────────────────
@router.patch("/{alert_id}/triage", response_model=AlertResponse)
async def triage_alert(
    alert_id: str,
    body: AlertTriage,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Triage an alert — mark it as investigating / true positive / false positive,
    and add analyst notes.

    Triage feeds `is_true_positive`, which drives detection rate, MITRE coverage
    and leaderboard position — so this must only ever touch the caller's own
    alerts.
    """
    await verify_alert_owner(db, alert_id, current_user)

    await crud.triage_alert(
        db,
        alert_id=alert_id,
        triage_status=body.triage_status,
        analyst_notes=body.analyst_notes,
        is_true_positive=body.is_true_positive,
    )

    # Reload to return fresh state
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    return result.scalar_one()


# ─── Stats ───────────────────────────────────────────────────────────────────
@router.get("/stats/{session_id}")
async def alert_stats(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return alert statistics for a session the caller owns."""
    await verify_session_owner(db, session_id, current_user)

    alerts = await crud.get_alerts(db, session_id=session_id, limit=10_000)

    if not alerts:
        return {
            "session_id": session_id,
            "total": 0,
            "by_severity": {},
            "by_status": {},
            "by_detection_type": {},
            "true_positives": 0,
            "false_positives": 0,
            "pending_triage": 0,
        }

    by_severity = Counter(a.severity for a in alerts)
    by_status = Counter(a.triage_status for a in alerts)
    by_detection_type = Counter(a.detection_type for a in alerts)
    tp = sum(1 for a in alerts if a.is_true_positive is True)
    fp = sum(1 for a in alerts if a.is_true_positive is False)
    pending = sum(1 for a in alerts if a.triage_status == "new")

    return {
        "session_id": session_id,
        "total": len(alerts),
        "by_severity": dict(by_severity),
        "by_status": dict(by_status),
        "by_detection_type": dict(by_detection_type),
        "true_positives": tp,
        "false_positives": fp,
        "pending_triage": pending,
    }
