"""Block 8 — Report writing & evaluation."""

from core.reports.evaluator import (
    DimensionScore,
    ReportScore,
    evaluate_report,
)
from core.reports.session_facts import SessionFacts, collect_session_facts
from core.reports.templates import (
    INCIDENT_REPORT,
    PENTEST_REPORT,
    ReportSection,
    ReportTemplate,
    get_template,
    templates_for_mode,
)

__all__ = [
    "ReportTemplate", "ReportSection",
    "INCIDENT_REPORT", "PENTEST_REPORT",
    "templates_for_mode", "get_template",
    "SessionFacts", "collect_session_facts",
    "DimensionScore", "ReportScore", "evaluate_report",
]
