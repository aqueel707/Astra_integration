"""
api/schemas/report.py
──────────────────────
Pydantic models for the reports API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ════════════════════════════════════════════════════════════════════════════
# Templates
# ════════════════════════════════════════════════════════════════════════════
class SectionTemplate(BaseModel):
    id: str
    title: str
    prompt: str
    placeholder: str
    required: bool
    min_words: int


class ReportTemplateOut(BaseModel):
    id: str
    name: str
    description: str
    audience: str
    sections: list[SectionTemplate]


# ════════════════════════════════════════════════════════════════════════════
# Drafts
# ════════════════════════════════════════════════════════════════════════════
class DraftIn(BaseModel):
    """Submitted by the dashboard when the student saves a draft."""
    report_type: str = Field(..., description="incident or pentest")
    content: dict[str, str] = Field(default_factory=dict, description="section_id → text")
    title: Optional[str] = None


class DraftOut(BaseModel):
    """Returned after a draft save."""
    report_id: str
    session_id: str
    report_type: str
    content: dict[str, str]
    submitted: bool
    updated_at: Optional[datetime]


# ════════════════════════════════════════════════════════════════════════════
# Submission + scoring
# ════════════════════════════════════════════════════════════════════════════
class DimensionFeedback(BaseModel):
    score: float
    weight: float
    feedback: list[str] = Field(default_factory=list)
    matched: dict[str, Any] = Field(default_factory=dict)
    missing: dict[str, Any] = Field(default_factory=dict)


class ReportScoreOut(BaseModel):
    overall_score: float
    grade: str
    dimensions: dict[str, DimensionFeedback]
    summary_feedback: list[str]


class SubmissionResultOut(BaseModel):
    """Returned after the student clicks Submit."""
    report_id: str
    session_id: str
    report_type: str
    score: ReportScoreOut
    submitted_at: datetime


# ════════════════════════════════════════════════════════════════════════════
# Session facts (for the helpful side panel during writing)
# ════════════════════════════════════════════════════════════════════════════
class SessionFactsOut(BaseModel):
    """What the student should know about the session before writing."""
    session_id: str
    scenario: str
    mode: str

    techniques_used: list[str]
    techniques_detected: list[str]
    techniques_missed: list[str]
    tactics_reached: list[str]

    hostnames: list[str]
    ip_addresses: list[str]
    usernames: list[str]
    processes: list[str]

    total_alerts: int
    total_attack_steps: int
    coverage_pct: float
    mttd_sec: float
    duration_sec: int


# ════════════════════════════════════════════════════════════════════════════
# Retrieval
# ════════════════════════════════════════════════════════════════════════════
class ReportOut(BaseModel):
    """Full report for retrieval."""
    report_id: str
    session_id: str
    user_id: str
    report_type: str
    title: str
    content: dict[str, str]
    submitted: bool
    overall_score: Optional[float]
    grade: Optional[str]
    feedback: Optional[dict]
    created_at: datetime
    updated_at: Optional[datetime]
