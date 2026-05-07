"""
core/reports/evaluator.py
──────────────────────────
Score a submitted report against the session's actual facts.

Five scoring dimensions (each 0-100):
  Structure   (20%) — required sections present, min word count met
  Specificity (30%) — actual MITRE IDs, hostnames, IOCs from session cited
  Coverage    (25%) — meaningful fraction of session events mentioned
  Vocabulary  (15%) — appropriate domain terminology used
  Clarity     (10%) — sentence/paragraph structure (basic heuristic)

Returns a structured ReportScore the dashboard can render with itemized feedback,
so students learn what to improve.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from core.reports.session_facts import (
    SessionFacts,
    extract_mitre_ids,
    text_contains_any,
)
from core.reports.templates import ReportTemplate


# Component weights — sum to 1.0
_WEIGHTS = {
    "structure":   0.20,
    "specificity": 0.30,
    "coverage":    0.25,
    "vocabulary":  0.15,
    "clarity":     0.10,
}


@dataclass
class DimensionScore:
    """Score + human-readable feedback for one of the 5 dimensions."""
    score: float                                 # 0-100
    weight: float                                # contribution to overall (0-1)
    feedback: list[str] = field(default_factory=list)
    matched: dict[str, Any] = field(default_factory=dict)  # what was found
    missing: dict[str, Any] = field(default_factory=dict)  # what should have been there


@dataclass
class ReportScore:
    """Final scored report, ready to persist or render."""
    overall_score: float                         # 0-100
    grade: str                                   # excellent / good / etc.
    dimensions: dict[str, DimensionScore] = field(default_factory=dict)
    summary_feedback: list[str] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════
def _word_count(text: str) -> int:
    return len(re.findall(r"\b\w+\b", text or ""))


def _sentence_count(text: str) -> int:
    if not text:
        return 0
    return len(re.findall(r"[.!?]+(?:\s|$)", text))


def _grade(score: float) -> str:
    if score >= 85: return "excellent"
    if score >= 70: return "good"
    if score >= 55: return "average"
    if score >= 40: return "needs_improvement"
    return "poor"


# ════════════════════════════════════════════════════════════════════════════
# DIMENSION 1 — STRUCTURE
# ════════════════════════════════════════════════════════════════════════════
def _score_structure(content: dict[str, str], template: ReportTemplate) -> DimensionScore:
    """Required sections present and meet min word count."""
    n_required = sum(1 for s in template.sections if s.required)
    if n_required == 0:
        return DimensionScore(100.0, _WEIGHTS["structure"])

    matched_sections = []
    short_sections = []
    missing_sections = []

    for section in template.sections:
        text = (content.get(section.id) or "").strip()
        wc = _word_count(text)
        if not text:
            if section.required:
                missing_sections.append(section.title)
            continue
        if wc < section.min_words:
            short_sections.append((section.title, wc, section.min_words))
            continue
        matched_sections.append(section.title)

    # Score: full credit per fully-met section, half credit for short ones
    full_credit = len(matched_sections)
    half_credit = len(short_sections) * 0.5
    score = ((full_credit + half_credit) / n_required) * 100.0
    score = max(0.0, min(100.0, score))

    feedback = []
    if matched_sections:
        feedback.append(f"✓ {len(matched_sections)}/{n_required} sections fully addressed")
    if short_sections:
        for title, wc, mw in short_sections:
            feedback.append(f"⚠ '{title}' is too brief ({wc} words; aim for {mw}+)")
    if missing_sections:
        for title in missing_sections:
            feedback.append(f"✗ Missing required section: '{title}'")

    return DimensionScore(
        score=score,
        weight=_WEIGHTS["structure"],
        feedback=feedback,
        matched={"sections": matched_sections},
        missing={"sections": missing_sections, "short": [t for t, _, _ in short_sections]},
    )


# ════════════════════════════════════════════════════════════════════════════
# DIMENSION 2 — SPECIFICITY
# ════════════════════════════════════════════════════════════════════════════
def _score_specificity(content: dict[str, str], facts: SessionFacts) -> DimensionScore:
    """Cites actual MITRE IDs, hostnames, IPs, processes from THIS session."""
    full_text = "\n".join(content.values())

    # MITRE IDs cited in report that match session
    cited_mitre = extract_mitre_ids(full_text)
    relevant_mitre = cited_mitre & facts.techniques_used

    # Hostnames mentioned
    cited_hosts = text_contains_any(full_text, facts.hostnames)
    cited_ips = text_contains_any(full_text, facts.ip_addresses)
    cited_users = text_contains_any(full_text, facts.usernames)
    cited_procs = text_contains_any(full_text, facts.processes)

    # Score components
    sub_scores: list[float] = []

    # MITRE: ratio of session techniques cited (cap at 1.0)
    if facts.techniques_used:
        mitre_ratio = len(relevant_mitre) / len(facts.techniques_used)
        sub_scores.append(min(1.0, mitre_ratio * 1.5) * 100)  # 67%+ cited = full credit
    else:
        sub_scores.append(50.0)  # neutral if no techniques in session somehow

    # Hostnames
    if facts.hostnames:
        host_ratio = len(cited_hosts) / max(1, len(facts.hostnames))
        sub_scores.append(min(1.0, host_ratio * 1.5) * 100)
    # IPs
    if facts.ip_addresses:
        ip_ratio = len(cited_ips) / max(1, len(facts.ip_addresses))
        sub_scores.append(min(1.0, ip_ratio * 1.5) * 100)
    # Usernames
    if facts.usernames:
        sub_scores.append(min(1.0, len(cited_users) / max(1, len(facts.usernames))) * 100)
    # Processes
    if facts.processes:
        sub_scores.append(min(1.0, len(cited_procs) / max(1, len(facts.processes)) * 1.5) * 100)

    score = sum(sub_scores) / len(sub_scores) if sub_scores else 0.0

    feedback = []
    if relevant_mitre:
        feedback.append(f"✓ Cited {len(relevant_mitre)} MITRE technique(s) from this session")
    not_cited = facts.techniques_used - relevant_mitre
    if not_cited and len(not_cited) <= 3:
        feedback.append(f"✗ Missing MITRE IDs: {', '.join(sorted(not_cited))}")
    elif not_cited:
        feedback.append(f"✗ Missing {len(not_cited)} MITRE IDs from session")
    if cited_hosts:
        feedback.append(f"✓ Referenced {len(cited_hosts)} affected host(s)")
    elif facts.hostnames:
        feedback.append("✗ No hostnames from the session were cited")
    if cited_procs and len(cited_procs) >= 2:
        feedback.append(f"✓ Referenced specific processes ({len(cited_procs)})")

    return DimensionScore(
        score=max(0.0, min(100.0, score)),
        weight=_WEIGHTS["specificity"],
        feedback=feedback,
        matched={
            "mitre": sorted(relevant_mitre),
            "hostnames": sorted(cited_hosts),
            "processes": sorted(cited_procs),
        },
        missing={"mitre_not_cited": sorted(not_cited)},
    )


# ════════════════════════════════════════════════════════════════════════════
# DIMENSION 3 — COVERAGE
# ════════════════════════════════════════════════════════════════════════════
def _score_coverage(content: dict[str, str], facts: SessionFacts) -> DimensionScore:
    """Reasonable share of what happened is mentioned."""
    full_text = "\n".join(content.values()).lower()
    score_components = []
    feedback = []

    # Tactics mentioned
    if facts.tactics_reached:
        tactics_in_text = sum(1 for t in facts.tactics_reached if t.replace("-", " ") in full_text)
        ratio = tactics_in_text / len(facts.tactics_reached)
        score_components.append(min(1.0, ratio * 1.3) * 100)
        if ratio < 0.5:
            feedback.append(
                f"⚠ Only {tactics_in_text}/{len(facts.tactics_reached)} attack tactics discussed"
            )

    # Total length proportional to session complexity
    total_words = _word_count("\n".join(content.values()))
    expected_words = max(300, facts.total_attack_steps * 50)
    length_ratio = total_words / expected_words
    length_score = min(1.0, length_ratio) * 100
    score_components.append(length_score)
    if length_ratio < 0.6:
        feedback.append(f"⚠ Report is short ({total_words} words; expected ≥{expected_words})")
    elif length_ratio >= 0.9:
        feedback.append(f"✓ Report length appropriate ({total_words} words)")

    # Did they discuss BOTH detection successes AND gaps?
    has_detected_lang = any(w in full_text for w in ("detected", "alerted", "caught", "identified"))
    has_undetected_lang = any(w in full_text for w in ("missed", "evaded", "undetected", "slipped", "gap"))
    if has_detected_lang and has_undetected_lang:
        score_components.append(100.0)
        feedback.append("✓ Discussed both detected and undetected activity")
    elif has_detected_lang or has_undetected_lang:
        score_components.append(60.0)
    else:
        score_components.append(20.0)
        feedback.append("✗ Report doesn't analyze detection effectiveness")

    score = sum(score_components) / len(score_components)

    return DimensionScore(
        score=max(0.0, min(100.0, score)),
        weight=_WEIGHTS["coverage"],
        feedback=feedback,
        matched={"total_words": total_words, "expected": expected_words},
    )


# ════════════════════════════════════════════════════════════════════════════
# DIMENSION 4 — VOCABULARY
# ════════════════════════════════════════════════════════════════════════════
def _score_vocabulary(content: dict[str, str], template: ReportTemplate) -> DimensionScore:
    """Domain-appropriate terminology."""
    feedback = []
    section_scores = []

    for section in template.sections:
        text = (content.get(section.id) or "").lower()
        if not text or not section.vocab:
            continue
        hits = sum(1 for term in section.vocab if term.lower() in text)
        ratio = hits / len(section.vocab)
        section_scores.append(min(1.0, ratio * 1.5) * 100)

    if not section_scores:
        return DimensionScore(50.0, _WEIGHTS["vocabulary"])

    score = sum(section_scores) / len(section_scores)
    if score >= 75:
        feedback.append("✓ Strong use of domain terminology")
    elif score >= 50:
        feedback.append("⚠ Some sections lack expected technical vocabulary")
    else:
        feedback.append("✗ Report is too informal for the audience")

    return DimensionScore(score=score, weight=_WEIGHTS["vocabulary"], feedback=feedback)


# ════════════════════════════════════════════════════════════════════════════
# DIMENSION 5 — CLARITY
# ════════════════════════════════════════════════════════════════════════════
def _score_clarity(content: dict[str, str]) -> DimensionScore:
    """Basic sentence-level clarity heuristics. Cheap, but catches one-line dumps."""
    full_text = "\n".join(content.values())
    if not full_text.strip():
        return DimensionScore(0.0, _WEIGHTS["clarity"], feedback=["No content to evaluate"])

    words = _word_count(full_text)
    sentences = max(1, _sentence_count(full_text))
    avg_words_per_sentence = words / sentences

    feedback = []
    score_parts: list[float] = []

    # Sweet spot 12-22 words/sentence
    if 12 <= avg_words_per_sentence <= 22:
        score_parts.append(100.0)
    elif 8 <= avg_words_per_sentence < 12 or 22 < avg_words_per_sentence <= 30:
        score_parts.append(70.0)
    elif avg_words_per_sentence < 8:
        score_parts.append(40.0)
        feedback.append("⚠ Sentences are very short — explain in more detail")
    else:
        score_parts.append(50.0)
        feedback.append("⚠ Some sentences run long — break them up")

    # Has at least some paragraph structure
    paragraph_count = len([p for p in re.split(r"\n\n+", full_text) if p.strip()])
    if paragraph_count >= 4:
        score_parts.append(100.0)
    elif paragraph_count >= 2:
        score_parts.append(70.0)
    else:
        score_parts.append(40.0)
        feedback.append("⚠ Use paragraph breaks for readability")

    # Discourage report being mostly bullet markers (>70% of lines start with -, *, etc.)
    lines = [l.strip() for l in full_text.split("\n") if l.strip()]
    bullet_ratio = sum(1 for l in lines if re.match(r"^[-*•●]|\d+\.", l)) / max(1, len(lines))
    if bullet_ratio > 0.7 and len(lines) > 8:
        score_parts.append(50.0)
        feedback.append("⚠ Heavy bullet-list use — mix in narrative prose")
    else:
        score_parts.append(100.0)

    score = sum(score_parts) / len(score_parts)
    return DimensionScore(score=score, weight=_WEIGHTS["clarity"], feedback=feedback)


# ════════════════════════════════════════════════════════════════════════════
# Main entry point
# ════════════════════════════════════════════════════════════════════════════
def evaluate_report(
    content: dict[str, str],
    template: ReportTemplate,
    facts: SessionFacts,
) -> ReportScore:
    """
    Score a student's submitted report.

    Args:
        content: dict mapping section_id → submitted text
        template: the report template that was used
        facts: ground-truth facts about the session
    """
    dims = {
        "structure":   _score_structure(content, template),
        "specificity": _score_specificity(content, facts),
        "coverage":    _score_coverage(content, facts),
        "vocabulary":  _score_vocabulary(content, template),
        "clarity":     _score_clarity(content),
    }

    overall = sum(d.score * d.weight for d in dims.values())

    summary = []
    if overall >= 85:
        summary.append("Excellent professional report.")
    elif overall >= 70:
        summary.append("Solid report with room for refinement.")
    elif overall >= 55:
        summary.append("Acceptable report; key details missing.")
    elif overall >= 40:
        summary.append("Report needs significant improvement.")
    else:
        summary.append("Report is incomplete or off-target.")

    return ReportScore(
        overall_score=round(overall, 1),
        grade=_grade(overall),
        dimensions=dims,
        summary_feedback=summary,
    )
