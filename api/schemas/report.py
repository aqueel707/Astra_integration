"""
api/schemas/report.py
──────────────────────
Pydantic models for the reports API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


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
# Bounds for submitted report bodies. The evaluator runs several regex passes
# over the concatenated sections synchronously on the event loop, so an
# unbounded body is a denial-of-service vector, not just a storage concern.
# The title bound also matches the Report.title column (String(256)), which
# previously turned an over-long title into a database error.
MAX_SECTIONS = 40
MAX_SECTION_CHARS = 20_000
MAX_TITLE_CHARS = 200


class DraftIn(BaseModel):
    """Submitted by the dashboard when the student saves a draft."""
    report_type: str = Field(..., description="incident or pentest")
    content: dict[str, str] = Field(default_factory=dict, description="section_id → text")
    title: Optional[str] = Field(None, max_length=MAX_TITLE_CHARS)

    @field_validator("content")
    @classmethod
    def _bound_content(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > MAX_SECTIONS:
            raise ValueError(f"too many sections (max {MAX_SECTIONS})")
        for key, text in v.items():
            if len(text) > MAX_SECTION_CHARS:
                raise ValueError(
                    f"section '{key}' exceeds {MAX_SECTION_CHARS} characters"
                )
        return v


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
