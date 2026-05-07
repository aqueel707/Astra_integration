"""
core/reports/templates.py
──────────────────────────
Definition of report templates for each mode.

Each template is a list of Sections. A Section has:
  - id:           internal identifier (used as form field name)
  - title:        display title
  - prompt:       instruction shown to the student
  - placeholder:  hint text inside the textarea
  - required:     must this section have content?
  - min_words:    soft floor for the section to count toward Structure score
  - vocab:        terms expected for this section (Vocabulary scoring)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class ReportSection:
    id: str
    title: str
    prompt: str
    placeholder: str = ""
    required: bool = True
    min_words: int = 50
    vocab: list[str] = field(default_factory=list)


@dataclass
class ReportTemplate:
    id: str
    name: str
    description: str
    audience: str  # who reads this?
    sections: list[ReportSection]


# ════════════════════════════════════════════════════════════════════════════
# INCIDENT REPORT — for SOC Analyst & Purple Team modes
# ════════════════════════════════════════════════════════════════════════════
INCIDENT_REPORT = ReportTemplate(
    id="incident",
    name="Incident Response Report",
    description="Document the incident from the defender's perspective. Cite specific evidence.",
    audience="SOC manager / IT leadership",
    sections=[
        ReportSection(
            id="executive_summary",
            title="Executive Summary",
            prompt=(
                "In 3-5 sentences, summarize what happened, when it was detected, "
                "what was affected, and the current containment status. Write for a non-technical reader."
            ),
            placeholder=(
                "On <date>, our SOC detected suspicious activity on <hostname> indicating "
                "<attack type>. The activity was identified at <time> via <detection mechanism>. "
                "<N> hosts were affected. Containment is <status>."
            ),
            min_words=40,
            vocab=["detected", "incident", "affected", "containment", "scope"],
        ),
        ReportSection(
            id="incident_timeline",
            title="Incident Timeline",
            prompt=(
                "List the key events in chronological order. Include timestamps, the action observed, "
                "and the source (which log, which alert). Cite specific MITRE ATT&CK technique IDs (e.g., T1059.001)."
            ),
            placeholder=(
                "10:23:14 — Initial alert: Suspicious PowerShell execution on WS-01 (T1059.001)\n"
                "10:23:47 — Lateral movement attempt observed (T1021.002)\n"
                "10:25:02 — File encryption activity detected (T1486)\n"
                "..."
            ),
            min_words=80,
            vocab=["timeline", "alert", "technique", "observed"],
        ),
        ReportSection(
            id="indicators_of_compromise",
            title="Indicators of Compromise (IOCs)",
            prompt=(
                "List specific IOCs observed: hostnames, IP addresses, processes, usernames, file paths, "
                "or command lines that indicate compromise. Pull these from the actual logs you reviewed."
            ),
            placeholder=(
                "Hostnames: WS-01, FILE-SRV-02\n"
                "Processes: powershell.exe -enc <base64>\n"
                "IP addresses: 192.0.2.45\n"
                "Usernames: jsmith (compromised account)"
            ),
            min_words=30,
            vocab=["ioc", "indicator", "hostname", "process", "address"],
        ),
        ReportSection(
            id="attack_analysis",
            title="Attack Analysis",
            prompt=(
                "Walk through what the attacker did, mapping each step to the MITRE ATT&CK framework. "
                "Reference specific technique IDs from the matrix."
            ),
            placeholder=(
                "The attacker began with reconnaissance (T1595), then gained initial access via spearphishing (T1566.001). "
                "After execution of a malicious payload (T1059.001), they established persistence via..."
            ),
            min_words=60,
            vocab=["attacker", "tactic", "technique", "mitre", "kill chain"],
        ),
        ReportSection(
            id="response_actions",
            title="Response Actions Taken",
            prompt=(
                "Describe the response steps taken (or that should have been taken) to contain "
                "and remediate the incident. Reference specific affected systems."
            ),
            placeholder=(
                "1. Isolated affected workstations from the network\n"
                "2. Disabled compromised user account jsmith\n"
                "3. Initiated forensic imaging on WS-01\n"
                "4. Notified incident response team\n"
                "5. Reviewed authentication logs for further compromise"
            ),
            min_words=50,
            vocab=["isolated", "contained", "remediated", "response", "blocked"],
        ),
        ReportSection(
            id="lessons_learned",
            title="Lessons Learned & Recommendations",
            prompt=(
                "What detection gaps were identified? What rules or processes should be improved? "
                "Be specific about which techniques weren't caught and how to detect them in the future."
            ),
            placeholder=(
                "Detection gaps:\n"
                "- T1027 (Obfuscated files) was not detected by current Sigma rules.\n"
                "Recommendations:\n"
                "- Add Sigma rule for base64-encoded PowerShell commands\n"
                "- Tune brute force threshold from 10 to 5 attempts\n"
                "- Implement continuous EDR monitoring on file servers"
            ),
            min_words=40,
            vocab=["gap", "recommendation", "detection", "improve", "rule"],
        ),
    ],
)


# ════════════════════════════════════════════════════════════════════════════
# PENTEST REPORT — for Pentester & Purple Team modes
# ════════════════════════════════════════════════════════════════════════════
PENTEST_REPORT = ReportTemplate(
    id="pentest",
    name="Penetration Test Report",
    description="Document your engagement from the attacker's perspective. Map findings to MITRE ATT&CK.",
    audience="Engagement client / blue team",
    sections=[
        ReportSection(
            id="engagement_summary",
            title="Engagement Summary",
            prompt=(
                "Summarize the engagement: scope, objective, dates, methodology used, and the "
                "high-level outcome (was the objective achieved?)."
            ),
            placeholder=(
                "This engagement targeted <client>'s <environment> with the objective of "
                "<objective>. Testing was conducted over <duration>. The objective was achieved by "
                "exploiting <technique chain>. <N> critical findings were identified."
            ),
            min_words=40,
            vocab=["engagement", "scope", "objective", "achieved", "methodology"],
        ),
        ReportSection(
            id="executive_summary",
            title="Executive Summary",
            prompt=(
                "Non-technical summary for executives. What's the business risk? Severity rating. "
                "Top 2-3 most critical findings."
            ),
            placeholder=(
                "We successfully gained access to the target environment within <time>. "
                "Critical risk findings include: (1) ..., (2) ..., (3) ..."
            ),
            min_words=40,
            vocab=["risk", "critical", "finding", "business impact"],
        ),
        ReportSection(
            id="kill_chain_walkthrough",
            title="Attack Path / Kill Chain",
            prompt=(
                "Walk through the attack chain step-by-step. For each step: technique used (with MITRE T-id), "
                "command/method, target host, success/failure, evidence. Be specific."
            ),
            placeholder=(
                "Step 1 — Reconnaissance (T1595.002)\n"
                "  Method: nmap scan against 192.0.2.0/24\n"
                "  Result: Identified web-srv-01 (192.0.2.10) running outdated CMS\n\n"
                "Step 2 — Initial Access (T1190)\n"
                "  Method: Exploited known CVE in CMS\n"
                "  Result: Reverse shell as www-data on web-srv-01\n..."
            ),
            min_words=120,
            vocab=["technique", "exploit", "executed", "compromised", "access"],
        ),
        ReportSection(
            id="findings",
            title="Findings & Vulnerabilities",
            prompt=(
                "List each technical finding. Include: title, severity (critical/high/medium/low), "
                "affected system, evidence, and the MITRE technique it relates to."
            ),
            placeholder=(
                "Finding 1 — Unrestricted PowerShell Execution (Critical, T1059.001)\n"
                "  Affected: WS-01\n"
                "  Evidence: Successfully executed `powershell.exe -enc ...` without any AV/EDR alert\n\n"
                "Finding 2 — Weak Domain Service Account (High, T1078)\n"
                "  ..."
            ),
            min_words=80,
            vocab=["finding", "severity", "vulnerability", "affected", "evidence"],
        ),
        ReportSection(
            id="defenses_observed",
            title="Defenses Observed",
            prompt=(
                "Which of your techniques were detected by the SOC? Which slipped through? "
                "What does this tell you about the maturity of the blue team's detection?"
            ),
            placeholder=(
                "Detected: T1059.001 (PowerShell encoded command alerted within 30 seconds)\n"
                "Undetected: T1027 (Obfuscated files), T1078 (Valid accounts)\n\n"
                "The SOC has solid coverage of execution-phase techniques but lacks visibility into..."
            ),
            min_words=50,
            vocab=["detected", "undetected", "evasion", "alert", "coverage"],
        ),
        ReportSection(
            id="recommendations",
            title="Recommendations",
            prompt=(
                "Provide remediation recommendations for each finding. Prioritize critical and high severity items. "
                "Be specific about controls or detection rules that would mitigate the issue."
            ),
            placeholder=(
                "1. Restrict PowerShell execution policy to AllSigned for non-admin users (mitigates T1059.001)\n"
                "2. Enforce MFA on all domain accounts to mitigate credential theft (T1078)\n"
                "3. Deploy a Sigma rule for base64-encoded command detection\n"
                "4. ..."
            ),
            min_words=50,
            vocab=["recommend", "mitigate", "remediate", "control", "policy"],
        ),
    ],
)


# ════════════════════════════════════════════════════════════════════════════
# Mode → templates mapping
# ════════════════════════════════════════════════════════════════════════════
TEMPLATES_BY_MODE: dict[str, list[ReportTemplate]] = {
    "soc":       [INCIDENT_REPORT],
    "pentester": [PENTEST_REPORT],
    "purple":    [INCIDENT_REPORT, PENTEST_REPORT],   # Purple writes both
}


def templates_for_mode(mode: str) -> list[ReportTemplate]:
    """Return the report templates a given mode should produce."""
    return TEMPLATES_BY_MODE.get(mode, [INCIDENT_REPORT])


def get_template(template_id: str) -> ReportTemplate | None:
    """Look up a template by its id."""
    for t in (INCIDENT_REPORT, PENTEST_REPORT):
        if t.id == template_id:
            return t
    return None
