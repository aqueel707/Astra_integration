"""
api/routers/progress.py
────────────────────────
Progress endpoints — feeds the Progress page on the dashboard.

Routes:
    GET /progress/users                          — list users with completed sessions
    GET /progress/{user_id}/summary              — top-level stats (totals, avgs)
    GET /progress/{user_id}/trends               — score time series + mode breakdown
    GET /progress/{user_id}/skills               — avg sub-scores across sessions
    GET /progress/{user_id}/tactics              — per-tactic detection rates
    GET /progress/{user_id}/activity             — last 30 days of session counts
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from db.models import Score, Session as SessionModel, User

router = APIRouter()


# ════════════════════════════════════════════════════════════════════════════
# /progress/users  — list of users
# ════════════════════════════════════════════════════════════════════════════
@router.get("/users")
async def list_users(db: AsyncSession = Depends(get_db)):
    """List users who have at least one scored session."""
    stmt = (
        select(User.id, User.username)
        .join(SessionModel, SessionModel.user_id == User.id)
        .join(Score, Score.session_id == SessionModel.id)
        .distinct()
    )
    result = await db.execute(stmt)
    users = [{"id": row.id, "username": row.username} for row in result.all()]
    if not users:
        # Fallback — return all users so the picker has at least one option
        all_users = await db.execute(select(User.id, User.username))
        users = [{"id": row.id, "username": row.username} for row in all_users.all()]
    return users


# ════════════════════════════════════════════════════════════════════════════
# /progress/{user_id}/summary
# ════════════════════════════════════════════════════════════════════════════
@router.get("/{user_id}/summary")
async def user_summary(user_id: str, db: AsyncSession = Depends(get_db)):
    """Top-level stats for a user."""
    stmt = (
        select(Score)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
    )
    result = await db.execute(stmt)
    scores = result.scalars().all()

    if not scores:
        return {
            "user_id": user_id,
            "total_sessions": 0,
            "avg_score": 0.0,
            "best_score": 0.0,
            "avg_coverage": 0.0,
        }

    return {
        "user_id": user_id,
        "total_sessions": len(scores),
        "avg_score": round(sum(s.total_score for s in scores) / len(scores), 1),
        "best_score": round(max(s.total_score for s in scores), 1),
        "avg_coverage": round(
            sum(s.mitre_coverage_pct for s in scores) / len(scores), 1
        ),
    }


# ════════════════════════════════════════════════════════════════════════════
# /progress/{user_id}/trends
# ════════════════════════════════════════════════════════════════════════════
@router.get("/{user_id}/trends")
async def user_trends(user_id: str, db: AsyncSession = Depends(get_db)):
    """Score over time, with mode tag for each session."""
    stmt = (
        select(Score, SessionModel)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
        .order_by(Score.created_at.asc())
        .limit(50)
    )
    result = await db.execute(stmt)
    rows = []
    for score, session in result.all():
        # Try to read mode from session.metadata (or fallback to 'soc')
        mode = "soc"
        meta = getattr(session, "config", None)
        if isinstance(meta, dict):
            mode = meta.get("mode", "soc")

        rows.append({
            "session_id": session.id,
            "scenario": session.scenario_id,
            "score": float(score.total_score),
            "grade": score.grade,
            "coverage": float(score.mitre_coverage_pct),
            "mode": mode,
            "date": score.created_at.isoformat() if score.created_at else None,
        })
    return rows


# ════════════════════════════════════════════════════════════════════════════
# /progress/{user_id}/skills  — avg sub-scores
# ════════════════════════════════════════════════════════════════════════════
@router.get("/{user_id}/skills")
async def user_skills(user_id: str, db: AsyncSession = Depends(get_db)):
    """Average of each sub-score across the user's sessions."""
    stmt = (
        select(Score)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
    )
    result = await db.execute(stmt)
    scores = result.scalars().all()

    if not scores:
        return {"detection": 0, "mttd": 0, "fp_rate": 0, "containment": 0, "report": 0, "coverage": 0}

    n = len(scores)
    return {
        "detection":   round(sum(s.detection_rate              for s in scores) / n, 1),
        "mttd":        round(sum(_mttd_to_score(s.mean_time_to_detect_sec) for s in scores) / n, 1),
        "fp_rate":     round(sum(_fp_to_score(s.false_positive_rate) for s in scores) / n, 1),
        "containment": round(sum(s.containment_score           for s in scores) / n, 1),
        "report":      round(sum(s.report_quality_score        for s in scores) / n, 1),
        "coverage":    round(sum(s.mitre_coverage_pct          for s in scores) / n, 1),
    }


# ════════════════════════════════════════════════════════════════════════════
# /progress/{user_id}/tactics
# ════════════════════════════════════════════════════════════════════════════
@router.get("/{user_id}/tactics")
async def user_tactics(user_id: str, db: AsyncSession = Depends(get_db)):
    """Per-tactic detection rates aggregated across sessions."""
    stmt = (
        select(Score)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
    )
    result = await db.execute(stmt)
    scores = result.scalars().all()

    # Aggregate by-tactic from each score's details
    tactic_used: dict[str, int] = defaultdict(int)
    tactic_detected: dict[str, int] = defaultdict(int)

    for score in scores:
        details = score.details or {}
        by_tactic = details.get("by_tactic") or details.get("mitre", {}).get("by_tactic", {})
        if not isinstance(by_tactic, dict):
            continue
        for tactic, stats in by_tactic.items():
            if isinstance(stats, dict):
                tactic_used[tactic] += int(stats.get("used", 0))
                tactic_detected[tactic] += int(stats.get("detected", 0))

    return {
        tactic: {
            "used": tactic_used[tactic],
            "detected": tactic_detected[tactic],
            "detection_rate": (tactic_detected[tactic] / tactic_used[tactic]) if tactic_used[tactic] else 0.0,
            "sessions_seen": len(scores),
        }
        for tactic in sorted(tactic_used.keys())
    }


# ════════════════════════════════════════════════════════════════════════════
# /progress/{user_id}/activity
# ════════════════════════════════════════════════════════════════════════════
@router.get("/{user_id}/activity")
async def user_activity(user_id: str, db: AsyncSession = Depends(get_db)):
    """Sessions per day for the last 30 days, broken down by mode."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    stmt = (
        select(Score, SessionModel)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
        .where(Score.created_at >= cutoff)
    )
    result = await db.execute(stmt)

    counts: dict[tuple[str, str], int] = defaultdict(int)  # (date, mode) -> count
    for score, session in result.all():
        if not score.created_at:
            continue
        date_str = score.created_at.date().isoformat()
        meta = getattr(session, "config", None) or {}
        mode = meta.get("mode", "soc") if isinstance(meta, dict) else "soc"
        counts[(date_str, mode)] += 1

    return [
        {"date": d, "mode": m, "count": c}
        for (d, m), c in sorted(counts.items())
    ]


# ─── Internal helpers (mirror scorer logic) ─────────────────────────────────
def _mttd_to_score(mttd_sec: float) -> float:
    """Lower MTTD = higher score. Mirrors scorer's _mttd_to_score."""
    if mttd_sec <= 0:
        return 100.0
    if mttd_sec <= 60:
        return 100.0
    if mttd_sec <= 600:
        return 80.0
    if mttd_sec <= 1800:
        return 50.0
    return 20.0


def _fp_to_score(fp_rate: float) -> float:
    """Lower FP rate = higher score."""
    if fp_rate <= 0:
        return 100.0
    if fp_rate >= 0.5:
        return 0.0
    return max(0.0, 100.0 - fp_rate * 200.0)
