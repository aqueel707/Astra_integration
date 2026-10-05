"""
Pydantic schemas for the detection API endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# Bounds for rule input. A Sigma rule is a small YAML document — real ones are
# well under a kilobyte. Unbounded, rule_yaml was accepted at megabytes, then
# yaml.safe_load-ed, stored in a Text column, and re-parsed and evaluated
# against every log batch for the life of the session.
MAX_RULE_YAML_CHARS = 20_000
MAX_RULE_DESC_CHARS = 2_000


# ─── Rule schemas ────────────────────────────────────────────────────────────
class RuleCreate(BaseModel):
    """Body for creating a new user detection rule."""
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=MAX_RULE_DESC_CHARS)
    severity: str = Field("medium", pattern="^(info|low|medium|high|critical)$")
    rule_yaml: str = Field(..., min_length=10, max_length=MAX_RULE_YAML_CHARS)
    session_id: Optional[str] = None  # If None, rule is global


class RuleUpdate(BaseModel):
    """Body for updating a rule (all fields optional)."""
    name: Optional[str] = Field(None, max_length=128)
    description: Optional[str] = Field(None, max_length=MAX_RULE_DESC_CHARS)
    severity: Optional[str] = Field(None, pattern="^(info|low|medium|high|critical)$")
    rule_yaml: Optional[str] = Field(None, min_length=10, max_length=MAX_RULE_YAML_CHARS)
    enabled: Optional[bool] = None


class RuleResponse(BaseModel):
    """Response shape for a rule."""
    id: str
    name: str
    description: Optional[str]
    severity: str
    rule_yaml: str
    is_default: bool
    enabled: bool
    true_positives: int = 0
    false_positives: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}


class RuleValidationResult(BaseModel):
    """Returned when validating a rule before saving."""
    valid: bool
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    error: Optional[str] = None
    parsed: Optional[dict[str, Any]] = None


# ─── Alert schemas (response only — alerts are created by the engine) ────────
class AlertResponse(BaseModel):
    """Response shape for an alert."""
    id: str
    session_id: str
    detection_type: str
    rule_id: Optional[str]
    title: str
    description: str
    severity: str
    technique_id: Optional[str]
    tactic: Optional[str]
    hostname: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    username: Optional[str]
    evidence: Optional[dict[str, Any]]
    triage_status: str
    is_true_positive: Optional[bool]
    timestamp: datetime
    triaged_at: Optional[datetime]
    analyst_notes: Optional[str]

    model_config = {"from_attributes": True}


class AlertTriage(BaseModel):
    """Body for triaging an alert."""
    triage_status: str = Field(
        ...,
        pattern="^(new|investigating|true_positive|false_positive|escalated|resolved)$",
    )
    analyst_notes: Optional[str] = None
    is_true_positive: Optional[bool] = None
