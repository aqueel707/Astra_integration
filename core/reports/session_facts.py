"""
core/reports/session_facts.py
──────────────────────────────
For a given session, extract the "ground truth" facts a good report should mention:
- MITRE technique IDs that were used
- MITRE technique IDs that were detected (vs undetected)
- Hostnames that appeared in attack steps
- Notable processes / commands / IPs / usernames from logs and alerts
- Tactic phases reached
- Numeric metrics (alerts fired, MTTD, etc.)

These facts are then matched against the student's submitted report text by the
evaluator to produce a Specificity score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Alert, AttackEvent, LogEntry, Score, Session as SessionModel


# Pattern for valid MITRE technique IDs: T1234 or T1234.001
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
# IPv4 / IPv6 (loose)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Likely hostname (alphanumerics + hyphens, 3+ chars, has a hyphen or capital — to avoid plain words)
_HOSTNAME_HINT = re.compile(r"\b[A-Z][A-Z0-9\-]{2,}[A-Z0-9]\b")


@dataclass
class SessionFacts:
    """The ground-truth facts about a session that a report should reference."""
    session_id: str
    scenario: str
    mode: str
    role: str  # blue_team / red_team / full_spectrum

    # MITRE
    techniques_used: set[str] = field(default_factory=set)
    techniques_detected: set[str] = field(default_factory=set)
    techniques_missed: set[str] = field(default_factory=set)
    tactics_reached: set[str] = field(default_factory=set)

    # IOCs from attack events + logs + alerts
    hostnames: set[str] = field(default_factory=set)
    ip_addresses: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)
    processes: set[str] = field(default_factory=set)

    # Metrics
    total_alerts: int = 0
    total_attack_steps: int = 0
    coverage_pct: float = 0.0
    mttd_sec: float = 0.0

    # Raw stats useful for scoring
    duration_sec: int = 0


async def collect_session_facts(session_id: str, db: AsyncSession) -> SessionFacts | None:
    """Pull all relevant data about a session and aggregate into a SessionFacts object."""
    sess_result = await db.execute(
        select(SessionModel).where(SessionModel.id == session_id)
    )
    session = sess_result.scalar_one_or_none()
    if session is None:
        return None

    # Mode lives in config.mode (or default to mapping role -> mode)
    config = session.config or {}
    role_to_mode = {"blue_team": "soc", "red_team": "pentester", "full_spectrum": "purple"}
    mode = config.get("mode") or role_to_mode.get(session.role, "soc")

    facts = SessionFacts(
        session_id=session.id,
        scenario=session.scenario_id,
        mode=mode,
        role=session.role,
    )

    # Duration
    if session.started_at and session.ended_at:
        facts.duration_sec = int((session.ended_at - session.started_at).total_seconds())

    # Attack events (technique IDs, target hosts)
    ae_result = await db.execute(
        select(AttackEvent).where(AttackEvent.session_id == session_id)
    )
    attack_events = ae_result.scalars().all()
    facts.total_attack_steps = len(attack_events)

    for ae in attack_events:
        if ae.technique_id:
            facts.techniques_used.add(ae.technique_id.upper())
        if ae.tactic:
            facts.tactics_reached.add(ae.tactic)
        if ae.source_host:
            facts.hostnames.add(ae.source_host)
        if ae.target_host:
            facts.hostnames.add(ae.target_host)

    # Alerts (detected techniques, hostnames, processes from evidence)
    al_result = await db.execute(
        select(Alert).where(Alert.session_id == session_id)
    )
    alerts = al_result.scalars().all()
    facts.total_alerts = len(alerts)

    for al in alerts:
        if al.technique_id:
            facts.techniques_detected.add(al.technique_id.upper())
        if al.hostname:
            facts.hostnames.add(al.hostname)
        if al.username:
            facts.usernames.add(al.username)
        if al.source_ip:
            facts.ip_addresses.add(al.source_ip)
        if al.destination_ip:
            facts.ip_addresses.add(al.destination_ip)

    # Sample of log entries — pull the malicious ones (richer detail)
    lg_result = await db.execute(
        select(LogEntry)
        .where(LogEntry.session_id == session_id)
        .where(LogEntry.is_malicious == True)  # noqa: E712
        .limit(50)
    )
    logs = lg_result.scalars().all()

    for lg in logs:
        if lg.hostname:
            facts.hostnames.add(lg.hostname)
        if lg.username:
            facts.usernames.add(lg.username)
        if lg.source_ip:
            facts.ip_addresses.add(lg.source_ip)
        if lg.destination_ip:
            facts.ip_addresses.add(lg.destination_ip)
        if lg.process_name:
            facts.processes.add(lg.process_name)

    # Score (for MTTD / coverage)
    sc_result = await db.execute(
        select(Score).where(Score.session_id == session_id)
    )
    score = sc_result.scalar_one_or_none()
    if score:
        facts.coverage_pct = score.mitre_coverage_pct or 0.0
        facts.mttd_sec = score.mean_time_to_detect_sec or 0.0

    facts.techniques_missed = facts.techniques_used - facts.techniques_detected

    # Filter out trivial / noisy entries
    facts.processes = {p for p in facts.processes if p and len(p) > 2}
    facts.usernames = {u for u in facts.usernames if u and not u.lower() in ("none", "system", "")}
    facts.hostnames = {h for h in facts.hostnames if h and len(h) > 1}

    return facts


# ════════════════════════════════════════════════════════════════════════════
# TEXT-EXTRACTION helpers for the evaluator
# ════════════════════════════════════════════════════════════════════════════
def extract_mitre_ids(text: str) -> set[str]:
    """Pull all MITRE technique IDs cited in a text."""
    return {m.group().upper() for m in _MITRE_RE.finditer(text or "")}


def extract_ips(text: str) -> set[str]:
    """Pull plausible IP addresses from text."""
    return set(_IP_RE.findall(text or ""))


def text_contains_any(text: str, terms: set[str], case_sensitive: bool = False) -> set[str]:
    """Return the subset of `terms` that appear in `text`."""
    if not text:
        return set()
    haystack = text if case_sensitive else text.lower()
    matched = set()
    for t in terms:
        needle = t if case_sensitive else t.lower()
        if needle and needle in haystack:
            matched.add(t)
    return matched
