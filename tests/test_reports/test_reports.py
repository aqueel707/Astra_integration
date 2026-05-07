"""
Tests for Block 8 — Report writing and evaluation.
"""

from __future__ import annotations

import pytest

from core.reports.evaluator import evaluate_report
from core.reports.session_facts import SessionFacts, extract_mitre_ids, text_contains_any
from core.reports.templates import (
    INCIDENT_REPORT,
    PENTEST_REPORT,
    get_template,
    templates_for_mode,
)


# ════════════════════════════════════════════════════════════════════════════
# Templates
# ════════════════════════════════════════════════════════════════════════════
class TestTemplates:
    def test_incident_template_well_formed(self):
        assert INCIDENT_REPORT.id == "incident"
        assert len(INCIDENT_REPORT.sections) >= 5
        for section in INCIDENT_REPORT.sections:
            assert section.id
            assert section.title
            assert section.prompt
            assert section.min_words > 0

    def test_pentest_template_well_formed(self):
        assert PENTEST_REPORT.id == "pentest"
        assert len(PENTEST_REPORT.sections) >= 5

    def test_section_ids_unique_within_template(self):
        for tmpl in (INCIDENT_REPORT, PENTEST_REPORT):
            ids = [s.id for s in tmpl.sections]
            assert len(ids) == len(set(ids)), f"duplicate section IDs in {tmpl.id}"

    def test_templates_for_mode(self):
        soc = templates_for_mode("soc")
        assert len(soc) == 1
        assert soc[0].id == "incident"

        pen = templates_for_mode("pentester")
        assert len(pen) == 1
        assert pen[0].id == "pentest"

        purple = templates_for_mode("purple")
        assert len(purple) == 2
        assert {t.id for t in purple} == {"incident", "pentest"}

    def test_get_template(self):
        assert get_template("incident") is INCIDENT_REPORT
        assert get_template("pentest") is PENTEST_REPORT
        assert get_template("nonexistent") is None


# ════════════════════════════════════════════════════════════════════════════
# Text extraction helpers
# ════════════════════════════════════════════════════════════════════════════
class TestExtractors:
    def test_extract_mitre_ids_basic(self):
        text = "The attacker used T1059.001 and T1486 to encrypt files."
        ids = extract_mitre_ids(text)
        assert ids == {"T1059.001", "T1486"}

    def test_extract_mitre_ids_empty(self):
        assert extract_mitre_ids("") == set()
        assert extract_mitre_ids("no techniques here") == set()

    def test_extract_mitre_ids_case_insensitive(self):
        ids = extract_mitre_ids("see t1078 for details")
        assert "T1078" in ids

    def test_extract_mitre_ignores_garbage(self):
        # Should not match "T123" (too short) or "T12345" (too long without dot)
        ids = extract_mitre_ids("T123 T12345 T1059")
        assert ids == {"T1059"}

    def test_text_contains_any(self):
        text = "The breach affected ws-01 and FILE-SRV-02."
        assert text_contains_any(text, {"WS-01", "DC-01"}) == {"WS-01"}
        assert text_contains_any(text, {"FILE-SRV-02"}) == {"FILE-SRV-02"}

    def test_text_contains_any_empty(self):
        assert text_contains_any("", {"a", "b"}) == set()
        assert text_contains_any("hello", set()) == set()


# ════════════════════════════════════════════════════════════════════════════
# SessionFacts (just construction — DB collection tested separately)
# ════════════════════════════════════════════════════════════════════════════
class TestSessionFacts:
    def test_construction(self):
        facts = SessionFacts(
            session_id="abc",
            scenario="ransomware",
            mode="soc",
            role="blue_team",
        )
        assert facts.techniques_used == set()
        assert facts.total_alerts == 0


# ════════════════════════════════════════════════════════════════════════════
# Evaluator — the meat of Block 8
# ════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def good_facts():
    """A reasonably rich SessionFacts to score against."""
    return SessionFacts(
        session_id="test-1",
        scenario="ransomware",
        mode="soc",
        role="blue_team",
        techniques_used={"T1566.001", "T1059.001", "T1486", "T1547.001"},
        techniques_detected={"T1059.001", "T1486"},
        techniques_missed={"T1566.001", "T1547.001"},
        tactics_reached={"initial-access", "execution", "persistence", "impact"},
        hostnames={"WS-01", "FILE-SRV-02"},
        ip_addresses={"192.0.2.45"},
        usernames={"jsmith"},
        processes={"powershell.exe", "cmd.exe"},
        total_alerts=5,
        total_attack_steps=8,
        coverage_pct=50.0,
        mttd_sec=120.0,
        duration_sec=600,
    )


@pytest.fixture
def empty_facts():
    return SessionFacts(
        session_id="empty",
        scenario="ransomware",
        mode="soc",
        role="blue_team",
    )


class TestEvaluator:

    def test_empty_report_scores_low(self, good_facts):
        result = evaluate_report({}, INCIDENT_REPORT, good_facts)
        assert result.overall_score < 30
        assert result.grade in ("poor", "needs_improvement")

    def test_strong_report_scores_high(self, good_facts):
        # A report that hits all the marks
        content = {
            "executive_summary": (
                "On 2025-04-29 at 10:23, our SOC detected ransomware activity on WS-01 "
                "indicating active intrusion. The activity was identified at 10:23:14 via "
                "Sigma alert. Two hosts were affected (WS-01 and FILE-SRV-02). "
                "Containment is in progress with affected systems isolated."
            ),
            "incident_timeline": (
                "10:23:14 — Initial alert: Suspicious PowerShell execution observed on WS-01 (T1059.001).\n\n"
                "10:23:47 — User account jsmith identified as compromised credential vector. "
                "Multiple powershell.exe invocations with encoded commands traced back to this user.\n\n"
                "10:25:02 — File encryption activity detected on FILE-SRV-02 (T1486). "
                "Mass file modifications observed via Sigma rule. The technique chain progressed "
                "rapidly from initial execution to impact within 90 seconds."
            ),
            "indicators_of_compromise": (
                "The investigation identified the following indicators of compromise. "
                "Hostnames: WS-01, FILE-SRV-02. "
                "Processes: powershell.exe with encoded payload, cmd.exe spawning anomalous children. "
                "Source IP: 192.0.2.45. "
                "Username: jsmith — credentials confirmed compromised."
            ),
            "attack_analysis": (
                "The attacker began with spearphishing (T1566.001) targeting jsmith, then executed "
                "an encoded PowerShell payload (T1059.001) to establish presence on WS-01. They "
                "established persistence via registry run keys (T1547.001) before pivoting to "
                "FILE-SRV-02 where ransomware was deployed (T1486). The kill chain demonstrated "
                "a textbook progression through MITRE ATT&CK tactics: initial-access through impact."
            ),
            "response_actions": (
                "Several response steps were taken to contain the incident: "
                "1. Isolated WS-01 and FILE-SRV-02 from the network within 5 minutes. "
                "2. Disabled compromised user account jsmith. "
                "3. Initiated forensic imaging on both affected hosts. "
                "4. Notified the incident response team and senior leadership. "
                "5. Reviewed authentication logs for evidence of further lateral movement."
            ),
            "lessons_learned": (
                "Detection gaps identified: T1566.001 (spearphishing) was not caught by current rules. "
                "T1547.001 (registry persistence) was also missed. "
                "Recommendations: deploy a Sigma rule to detect inbound emails with macro attachments, "
                "and tune EDR to alert on registry run-key modifications. The MTTD of 120 seconds was "
                "acceptable but could improve with better baseline detection rules."
            ),
        }
        result = evaluate_report(content, INCIDENT_REPORT, good_facts)
        # Should be strong
        assert result.overall_score >= 70, f"got {result.overall_score}: {result.summary_feedback}"
        assert result.grade in ("good", "excellent")

    def test_structure_dimension_catches_short_sections(self, good_facts):
        content = {
            "executive_summary": "Short.",
            "incident_timeline": "Brief.",
            "indicators_of_compromise": "Few.",
        }
        result = evaluate_report(content, INCIDENT_REPORT, good_facts)
        struct = result.dimensions["structure"]
        assert struct.score < 50

    def test_specificity_dimension_rewards_mitre_citations(self, good_facts):
        no_mitre = {"executive_summary": "We saw bad stuff happen on the server. " * 10}
        with_mitre = {
            "executive_summary": (
                "We detected attacks corresponding to T1566.001, T1059.001, T1486, and T1547.001. "
                "All four techniques from this session were observed. " * 3
            )
        }
        no_mitre_score = evaluate_report(no_mitre, INCIDENT_REPORT, good_facts)
        with_mitre_score = evaluate_report(with_mitre, INCIDENT_REPORT, good_facts)
        assert (with_mitre_score.dimensions["specificity"].score
                > no_mitre_score.dimensions["specificity"].score)

    def test_specificity_rewards_hostname_citation(self, good_facts):
        # Same length, only one references hostnames
        without = {"executive_summary": "An attack happened. " * 30}
        with_hosts = {
            "executive_summary": (
                "An attack on WS-01 and FILE-SRV-02 was observed during the engagement. "
                "Both hosts were compromised via lateral movement. " * 5
            )
        }
        s_without = evaluate_report(without, INCIDENT_REPORT, good_facts).dimensions["specificity"]
        s_with    = evaluate_report(with_hosts, INCIDENT_REPORT, good_facts).dimensions["specificity"]
        assert s_with.score > s_without.score

    def test_clarity_penalizes_only_bullets(self, good_facts):
        bullets = {
            "executive_summary": "\n".join(["- " + ("event " * 5)] * 10),
            "incident_timeline": "\n".join(["- t" + str(i) for i in range(15)]),
        }
        prose = {
            "executive_summary": (
                "On April 29th, our security operations center detected ransomware activity. "
                "The incident began with phishing and progressed through several stages of the attack chain. "
                "Containment efforts are currently underway across all affected systems."
            ),
            "incident_timeline": (
                "The first indicator appeared at 10:23 when an alert fired on WS-01. "
                "Within 90 seconds, the attacker had executed a PowerShell payload and moved laterally. "
                "By 10:25, file encryption activity was detected on FILE-SRV-02. "
                "Containment was initiated immediately upon detection of the impact phase."
            ),
        }
        bs = evaluate_report(bullets, INCIDENT_REPORT, good_facts).dimensions["clarity"]
        ps = evaluate_report(prose, INCIDENT_REPORT, good_facts).dimensions["clarity"]
        assert ps.score > bs.score

    def test_overall_score_in_valid_range(self, good_facts):
        content = {"executive_summary": "x " * 200}
        result = evaluate_report(content, INCIDENT_REPORT, good_facts)
        assert 0 <= result.overall_score <= 100

    def test_dimension_scores_in_valid_range(self, good_facts):
        content = {"executive_summary": "T1059.001 occurred on WS-01. " * 30}
        result = evaluate_report(content, INCIDENT_REPORT, good_facts)
        for name, dim in result.dimensions.items():
            assert 0 <= dim.score <= 100, f"{name} out of range: {dim.score}"
            assert 0 <= dim.weight <= 1

    def test_weights_sum_to_one(self, good_facts):
        content = {"executive_summary": "x"}
        result = evaluate_report(content, INCIDENT_REPORT, good_facts)
        total_weight = sum(d.weight for d in result.dimensions.values())
        assert abs(total_weight - 1.0) < 0.001

    def test_pentest_template_evaluable(self, good_facts):
        # Just make sure pentest reports score without crashing
        content = {
            "engagement_summary": (
                "This engagement targeted client X with the objective of demonstrating "
                "ransomware risk. Testing was conducted over 4 hours." * 2
            ),
            "kill_chain_walkthrough": (
                "Step 1: T1566.001 phishing email sent to jsmith. "
                "Step 2: T1059.001 PowerShell execution on WS-01. "
                "Step 3: T1547.001 persistence established. "
                "Step 4: T1486 ransomware deployed on FILE-SRV-02." * 3
            ),
        }
        result = evaluate_report(content, PENTEST_REPORT, good_facts)
        assert result.overall_score > 0
        assert result.grade in ("excellent", "good", "average", "needs_improvement", "poor")

    def test_with_empty_facts_does_not_crash(self, empty_facts):
        content = {"executive_summary": "x " * 100}
        result = evaluate_report(content, INCIDENT_REPORT, empty_facts)
        # Should not crash; specificity will be neutral (no facts to match)
        assert 0 <= result.overall_score <= 100

    def test_feedback_provided(self, good_facts):
        content = {"executive_summary": "x " * 50}
        result = evaluate_report(content, INCIDENT_REPORT, good_facts)
        # At least some dimension should provide feedback
        assert any(len(d.feedback) > 0 for d in result.dimensions.values())
        assert result.summary_feedback

    def test_grade_thresholds(self, good_facts):
        # A high-scoring report should grade higher than a near-empty one
        empty = evaluate_report({}, INCIDENT_REPORT, good_facts)
        rich = evaluate_report({s.id: "T1059.001 on WS-01 detected. " * 50
                                for s in INCIDENT_REPORT.sections},
                                INCIDENT_REPORT, good_facts)
        grade_order = ["poor", "needs_improvement", "average", "good", "excellent"]
        assert grade_order.index(rich.grade) >= grade_order.index(empty.grade)
