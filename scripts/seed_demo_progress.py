"""
scripts/seed_demo_progress.py
──────────────────────────────
Generate ~50 fake completed sessions across a few demo users so the
Progress page has meaningful data to display.

Usage:
    python scripts/seed_demo_progress.py          # adds to existing data
    python scripts/seed_demo_progress.py --reset  # wipes existing demo data first

Demo users created:
    alice  — strong SOC analyst, weak pentester
    bob    — strong pentester, learning purple team
    charlie — purple specialist, well-rounded

Each user gets 12-20 sessions across the past 30 days, with realistic
score progression (gradually improving over time).
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.engine import get_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from db.models import Score, Session as SessionModel, User


# ════════════════════════════════════════════════════════════════════════════
# Demo profile shaping
# ════════════════════════════════════════════════════════════════════════════
DEMO_PROFILES = [
    {
        "username": "alice",
        "preferred_mode": "soc",
        "skill_curve": (55, 88),  # starts at 55, ends at 88
        "session_count": 18,
        "scenarios": ["ransomware", "phishing_chain", "insider_threat", "apt_espionage"],
    },
    {
        "username": "bob",
        "preferred_mode": "pentester",
        "skill_curve": (50, 80),
        "session_count": 14,
        "scenarios": ["apt_espionage", "supply_chain", "phishing_chain"],
    },
    {
        "username": "charlie",
        "preferred_mode": "purple",
        "skill_curve": (60, 85),
        "session_count": 16,
        "scenarios": ["ransomware", "apt_espionage", "supply_chain", "phishing_chain"],
    },
]

ALL_TACTICS = [
    "reconnaissance", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]


def _grade_for(score: float) -> str:
    if score >= 90: return "excellent"
    if score >= 75: return "good"
    if score >= 60: return "average"
    if score >= 40: return "needs_improvement"
    return "poor"


def _generate_session(profile: dict, session_idx: int) -> tuple[dict, dict]:
    """Generate a (session, score) pair for a user at a given progression point."""
    total_sessions = profile["session_count"]
    progress = session_idx / max(total_sessions - 1, 1)

    # Skill curve — linear with some noise
    s_lo, s_hi = profile["skill_curve"]
    base_score = s_lo + (s_hi - s_lo) * progress
    score = max(20, min(100, base_score + random.gauss(0, 6)))

    # Date — distributed across last 30 days
    days_ago = int((1 - progress) * 30) + random.randint(0, 2)
    when = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=random.randint(0, 23))

    # Mode — mostly preferred but with some variety
    if random.random() < 0.75:
        mode = profile["preferred_mode"]
    else:
        mode = random.choice(["soc", "pentester", "purple"])

    scenario = random.choice(profile["scenarios"])
    session_id = str(uuid.uuid4())

    # Coverage scales with score
    coverage_pct = max(0, min(100, score * 0.65 + random.gauss(0, 8)))

    # Sub-scores — also scale with skill but with personality bias
    if profile["preferred_mode"] == "soc":
        detection_rate = min(100, score * 1.05 + random.gauss(0, 5))
        fp_rate_score = min(100, score * 0.95)
        containment = min(100, score * 0.7)
    elif profile["preferred_mode"] == "pentester":
        detection_rate = min(100, score * 0.85 + random.gauss(0, 5))
        fp_rate_score = min(100, score * 0.85)
        containment = min(100, score * 1.0)
    else:  # purple
        detection_rate = min(100, score * 0.95)
        fp_rate_score = min(100, score * 0.92)
        containment = min(100, score * 0.85)

    mttd_sec = max(10, 600 - (score * 5) + random.gauss(0, 60))
    fp_rate = max(0, min(0.5, (100 - fp_rate_score) / 200))

    # Build a per-tactic breakdown (roughly correlated with overall score)
    by_tactic = {}
    for tactic in ALL_TACTICS:
        used = random.randint(1, 4)
        # Detection rate correlated with score
        detect_prob = min(0.95, score / 100 + random.gauss(0, 0.15))
        detected = sum(1 for _ in range(used) if random.random() < detect_prob)
        by_tactic[tactic] = {"used": used, "detected": detected}

    session_dict = {
        "id": session_id,
        "scenario_id": scenario,
        "difficulty": random.choice(["easy", "medium", "hard"]),
        "status": "completed",
        "session_metadata": {"mode": mode, "demo": True},
        "started_at": when,
        "completed_at": when + timedelta(minutes=random.randint(5, 25)),
    }

    score_dict = {
        "id": str(uuid.uuid4()),
        "session_id": session_id,
        "total_score": round(score, 1),
        "grade": _grade_for(score),
        "detection_rate": round(detection_rate, 2),
        "mean_time_to_detect_sec": round(mttd_sec, 1),
        "false_positive_rate": round(fp_rate, 3),
        "containment_score": round(containment, 1),
        "report_quality_score": round(min(100, score * 0.9 + random.gauss(0, 8)), 1),
        "mitre_techniques_used": sum(t["used"] for t in by_tactic.values()),
        "mitre_techniques_detected": sum(t["detected"] for t in by_tactic.values()),
        "mitre_coverage_pct": round(coverage_pct, 1),
        "details": {
            "mode": mode,
            "by_tactic": by_tactic,
            "demo": True,
        },
        "created_at": when + timedelta(minutes=random.randint(5, 25)),
    }

    return session_dict, score_dict


# ════════════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════════════
async def seed(reset: bool = False):
    engine = get_engine()
    SessionFactory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionFactory() as db:  # type: AsyncSession
        if reset:
            print("[demo-seed] Clearing existing demo sessions...")
            # Delete demo scores first (FK), then sessions, then users
            demo_scores = await db.execute(
                select(Score).where(Score.details.contains({"demo": True}))
            )
            for s in demo_scores.scalars().all():
                await db.delete(s)
            demo_sessions = await db.execute(
                select(SessionModel).where(SessionModel.config.contains({"demo": True}))
            )
            for s in demo_sessions.scalars().all():
                await db.delete(s)
            await db.commit()
            print("[demo-seed] Cleared.")

        # Ensure demo users exist
        for profile in DEMO_PROFILES:
            existing = await db.execute(
                select(User).where(User.username == profile["username"])
            )
            user = existing.scalar_one_or_none()
            if user is None:
                user = User(
                    id=str(uuid.uuid4()),
                    username=profile["username"],
                    display_name=profile["username"].title(),
                )
                db.add(user)
                await db.flush()
                print(f"[demo-seed] Created user: {profile['username']}")
            profile["_user_id"] = user.id

        await db.commit()

        # Generate sessions per user
        total_sessions = 0
        for profile in DEMO_PROFILES:
            print(f"[demo-seed] Generating {profile['session_count']} sessions for {profile['username']}...")
            for i in range(profile["session_count"]):
                sess_dict, score_dict = _generate_session(profile, i)

                # Map dashboard mode to DB role
                _mode_to_role = {"soc": "blue_team", "pentester": "red_team", "purple": "full_spectrum"}
                _mode = sess_dict["session_metadata"].get("mode", "soc")
                session_obj = SessionModel(
                    id=sess_dict["id"],
                    user_id=profile["_user_id"],
                    scenario_id=sess_dict["scenario_id"],
                    role=_mode_to_role.get(_mode, "blue_team"),
                    difficulty=sess_dict["difficulty"],
                    status=sess_dict["status"],
                    config=sess_dict["session_metadata"],  # store mode + demo flag in config
                    started_at=sess_dict["started_at"],
                    ended_at=sess_dict["completed_at"],
                )
                db.add(session_obj)

                score_obj = Score(
                    id=score_dict["id"],
                    session_id=score_dict["session_id"],
                    total_score=score_dict["total_score"],
                    grade=score_dict["grade"],
                    detection_rate=score_dict["detection_rate"],
                    mean_time_to_detect_sec=score_dict["mean_time_to_detect_sec"],
                    false_positive_rate=score_dict["false_positive_rate"],
                    containment_score=score_dict["containment_score"],
                    report_quality_score=score_dict["report_quality_score"],
                    mitre_techniques_used=score_dict["mitre_techniques_used"],
                    mitre_techniques_detected=score_dict["mitre_techniques_detected"],
                    mitre_coverage_pct=score_dict["mitre_coverage_pct"],
                    details=score_dict["details"],
                    created_at=score_dict["created_at"],
                )
                db.add(score_obj)
                total_sessions += 1

        await db.commit()
        print(f"[demo-seed] Done — created {total_sessions} demo sessions across {len(DEMO_PROFILES)} users.")
        print(f"[demo-seed] Visit http://localhost:8050/progress to see the charts.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="Clear existing demo data first")
    args = parser.parse_args()
    asyncio.run(seed(reset=args.reset))


if __name__ == "__main__":
    main()
