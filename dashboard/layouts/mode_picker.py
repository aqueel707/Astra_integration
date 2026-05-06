"""
dashboard/layouts/mode_picker.py
─────────────────────────────────
Landing page — the user picks a training mode before anything else.

Three modes, each with its own focus:

  🛡  SOC Analyst   — defend; detect attacks; tune Sigma rules
  ⚔  Pentester     — attack; reach objectives; stay stealthy
  🟣 Purple Team   — both; attack first, then audit your own work

Selecting a mode stores it in dcc.Store(id="active-mode") and routes the
user to the launcher with mode-filtered scenarios.
"""

from __future__ import annotations

from dash import dcc, html


# ─── Mode definitions ───────────────────────────────────────────────────────
MODES = [
    {
        "id": "soc",
        "label": "SOC Analyst",
        "tagline": "Defend the network",
        "icon": "🛡",
        "color": "soc",
        "description": (
            "Watch attacks unfold in real-time. Triage logs, tune Sigma rules, "
            "and identify malicious behavior before it does damage."
        ),
        "skills": ["Log triage", "Detection engineering", "Alert investigation", "MITRE ATT&CK mapping"],
        "metrics": ["Detection rate", "Mean time to detect", "False positive rate", "MITRE coverage"],
    },
    {
        "id": "pentester",
        "label": "Pentester",
        "tagline": "Breach the target",
        "icon": "⚔",
        "color": "pentester",
        "description": (
            "Plan and execute multi-stage attacks. Move through the kill chain "
            "while staying below the SOC's detection threshold."
        ),
        "skills": ["Attack planning", "Technique selection", "OPSEC / stealth", "Persistence design"],
        "metrics": ["Stealth score", "Phases reached", "Persistence achieved", "Time to objective"],
    },
    {
        "id": "purple",
        "label": "Purple Team",
        "tagline": "Bridge attack & defense",
        "icon": "🟣",
        "color": "purple",
        "description": (
            "Run a full kill chain, then switch hats and audit your own attack "
            "as the defender. Develop both perspectives in a single session."
        ),
        "skills": ["Attack-side planning", "Detection auditing", "Cross-team translation", "Gap analysis"],
        "metrics": ["Combined attack/defense score", "Self-detection rate", "Coverage gaps identified"],
    },
]


def _mode_card(mode: dict) -> html.Div:
    """Render a single large mode-selection card."""
    return dcc.Link(
        html.Div(
            [
                # Icon + accent bar
                html.Div(
                    [
                        html.Span(mode["icon"], className="mode-icon"),
                        html.Span(mode["tagline"].upper(), className="mode-tagline"),
                    ],
                    className="mode-card-header",
                ),

                # Title
                html.H3(mode["label"], className="mode-card-title"),

                # Description
                html.P(mode["description"], className="mode-card-desc"),

                # Skills you'll practice
                html.Div(
                    [
                        html.Div("Skills", className="mode-card-section-label"),
                        html.Div(
                            [
                                html.Span(s, className="mode-skill-pill")
                                for s in mode["skills"]
                            ],
                            className="mode-card-pills",
                        ),
                    ],
                    className="mode-card-section",
                ),

                # Scored on
                html.Div(
                    [
                        html.Div("Scored on", className="mode-card-section-label"),
                        html.Ul(
                            [html.Li(m, className="mode-metric-item") for m in mode["metrics"]],
                            className="mode-metric-list",
                        ),
                    ],
                    className="mode-card-section",
                ),

                # CTA arrow
                html.Div(
                    [
                        html.Span("Begin Training"),
                        html.Span("→", className="mode-cta-arrow"),
                    ],
                    className="mode-card-cta",
                ),
            ],
            className=f"mode-card mode-card-{mode['color']}",
            id={"type": "mode-card", "mode": mode["id"]},
        ),
        href=f"/launch/{mode['id']}",
        className="mode-card-link",
    )


def layout():
    """Top-level layout for the mode picker."""
    return html.Div(
        [
            html.Div(
                [
                    html.H1("Choose Your Training Mode", className="picker-heading"),
                    html.P(
                        "Each mode trains different skills using the same attack scenarios. "
                        "Switch between them to develop a complete security mindset.",
                        className="picker-subheading",
                    ),
                ],
                className="picker-header",
            ),

            html.Div(
                [_mode_card(m) for m in MODES],
                className="mode-picker-grid",
            ),
        ],
        className="mode-picker-page",
    )
