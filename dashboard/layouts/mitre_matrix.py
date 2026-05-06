"""
dashboard/layouts/mitre_matrix.py
──────────────────────────────────
ATT&CK matrix heatmap.

For a given session, shows all techniques organized by tactic, color-coded:
  - Gray:   not used
  - Amber:  used by the attack but NOT detected
  - Green:  used AND detected (success!)
  - Red:    used and missed (a real blind spot)

Header has a session selector — defaults to the most recent session.
"""

from __future__ import annotations

from dash import dcc, html


# Tactic columns in the order they appear in the kill chain
_TACTIC_ORDER = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Dev"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Esc"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "C2"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]


def layout():
    return html.Div(
        [
            dcc.Store(id="matrix-store", data={}),
            dcc.Store(id="matrix-tactic-order", data=_TACTIC_ORDER),

            html.Div(
                [
                    html.H2("ATT&CK Coverage Matrix", className="page-heading"),
                    html.Div(
                        [
                            dcc.Dropdown(
                                id="matrix-session-picker",
                                placeholder="Select a session...",
                                clearable=False,
                                className="astra-select",
                                style={"minWidth": "280px"},
                            ),
                        ],
                    ),
                ],
                className="live-header",
            ),

            # Legend
            html.Div(
                [
                    html.Span(
                        [
                            html.Span(className="legend-swatch", style={"background": "var(--severity-medium)"}),
                            "Used (undetected)",
                        ],
                        className="legend-item",
                    ),
                    html.Span(
                        [
                            html.Span(className="legend-swatch", style={"background": "var(--status-good)"}),
                            "Detected",
                        ],
                        className="legend-item",
                    ),
                    html.Span(
                        [
                            html.Span(className="legend-swatch", style={"background": "var(--severity-critical)"}),
                            "Missed (blind spot)",
                        ],
                        className="legend-item",
                    ),
                ],
                className="matrix-legend",
                style={
                    "display": "flex",
                    "gap": "20px",
                    "marginBottom": "20px",
                    "fontFamily": "var(--font-ui)",
                    "fontSize": "12px",
                    "color": "var(--text-secondary)",
                },
            ),

            html.Div(
                id="matrix-grid-container",
                children=[
                    html.Div(
                        [
                            html.Div("⊞", className="empty-state-icon"),
                            "Select a session to view its ATT&CK coverage",
                        ],
                        className="empty-state",
                    ),
                ],
            ),
        ],
    )
