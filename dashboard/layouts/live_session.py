"""
dashboard/layouts/live_session.py
──────────────────────────────────
The active-session view. Adapts its framing based on which mode the
user picked on the home page.

Routes here:
  /launch/<mode>   — show the launcher form (scenario/difficulty pickers)
  /live            — show the live grid (after launch)
"""

from __future__ import annotations

from dash import dcc, html

from dashboard.layouts.mode_picker import MODES


# Index modes by id for fast lookup
_MODE_BY_ID = {m["id"]: m for m in MODES}


# ─── Kill chain phases ──────────────────────────────────────────────────────
_KILL_CHAIN_PHASES = [
    ("01", "Recon"),
    ("02", "Initial Access"),
    ("03", "Execution"),
    ("04", "Persistence"),
    ("05", "Lateral Movement"),
    ("06", "Exfiltration"),
    ("07", "Impact"),
]


# ─── Scenarios with mode tagging ────────────────────────────────────────────
ALL_SCENARIOS = [
    {
        "id": "ransomware",
        "label": "Ransomware Attack",
        "description": "Multi-stage ransomware: phishing → execution → persistence → encryption",
        "modes": ["soc", "purple"],
    },
    {
        "id": "apt_espionage",
        "label": "APT Espionage Campaign",
        "description": "Slow, stealthy long-term intrusion focused on data theft",
        "modes": ["soc", "pentester", "purple"],
    },
    {
        "id": "insider_threat",
        "label": "Insider Threat",
        "description": "Malicious insider exfiltrating data through legitimate channels",
        "modes": ["soc", "purple"],
    },
    {
        "id": "phishing_chain",
        "label": "Phishing Chain",
        "description": "Email-based initial access leading to credential theft",
        "modes": ["soc", "pentester", "purple"],
    },
    {
        "id": "supply_chain",
        "label": "Supply Chain Compromise",
        "description": "Compromise via trusted third-party software",
        "modes": ["pentester", "purple"],
    },
]

_DIFFICULTIES = [
    {"label": "Easy — clear signals, lots of logs", "value": "easy"},
    {"label": "Medium — realistic noise/signal mix", "value": "medium"},
    {"label": "Hard — quiet attacker, heavy noise", "value": "hard"},
]


def get_scenarios_for_mode(mode_id: str) -> list[dict]:
    return [s for s in ALL_SCENARIOS if mode_id in s["modes"]]


def _stat_block(label: str, value_id: str, severity: str = "") -> html.Div:
    return html.Div(
        [
            html.P(label, className="stat-label"),
            html.P("0", id=value_id, className="stat-value"),
        ],
        className=f"stat-block {severity}",
    )


def _kill_chain_strip() -> html.Div:
    return html.Div(
        [
            html.Div(
                [
                    html.Div(num, className="kc-phase-number"),
                    html.Div(name, className="kc-phase-name"),
                ],
                className="kc-phase",
            )
            for num, name in _KILL_CHAIN_PHASES
        ],
        className="kill-chain",
        id="kill-chain-strip",
    )


def _log_stream_card() -> html.Div:
    return html.Div(
        [
            html.Div(
                [
                    html.H3("Event Stream", className="astra-card-title"),
                    html.Span(id="log-stream-count", children="0 events", className="astra-card-meta"),
                ],
                className="astra-card-header",
            ),
            html.Div(
                [
                    html.Div(
                        [
                            html.Span("Time"),
                            html.Span("Source"),
                            html.Span("Severity"),
                            html.Span("Message"),
                            html.Span("Host"),
                        ],
                        className="log-table-header",
                    ),
                    html.Div(
                        id="log-stream-body",
                        className="log-table-body",
                        children=[
                            html.Div(
                                [html.Div("⌂", className="empty-state-icon"), "Waiting for log stream..."],
                                className="empty-state",
                            ),
                        ],
                    ),
                ],
                className="log-table-container",
            ),
        ],
        className="astra-card",
    )


def _alerts_card() -> html.Div:
    return html.Div(
        [
            html.Div(
                [
                    html.H3("Alerts", className="astra-card-title"),
                    html.Span(id="alerts-count", children="0", className="astra-card-meta"),
                ],
                className="astra-card-header",
            ),
            html.Div(
                id="alerts-stream",
                className="alerts-stream",
                children=[
                    html.Div(
                        [html.Div("◇", className="empty-state-icon"), "No alerts yet"],
                        className="empty-state",
                    ),
                ],
            ),
        ],
        className="astra-card",
    )


def _score_panel() -> html.Div:
    return html.Div(
        [
            html.Div(
                [
                    html.H3("Performance Score", className="astra-card-title"),
                    html.Span(id="score-meta", className="astra-card-meta"),
                ],
                className="astra-card-header",
            ),
            html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div("0", id="score-number", className="score-number"),
                                    html.Div("—", id="score-grade", className="score-grade"),
                                ],
                                style={"display": "flex", "alignItems": "center", "gap": "32px", "flex": "1"},
                            ),
                            html.Div(
                                [
                                    html.Div("Recent trajectory", className="subscore-label"),
                                    dcc.Graph(
                                        id="score-sparkline-chart",
                                        config={"displayModeBar": False, "responsive": True},
                                        style={"width": "200px", "height": "60px"},
                                    ),
                                ],
                                style={"minWidth": "220px"},
                            ),
                        ],
                        className="score-hero",
                    ),
                    html.Div(id="score-subscores", className="score-breakdown"),
                ],
            ),
        ],
        className="astra-card",
    )


def _mode_banner(mode: dict) -> html.Div:
    accent = {"soc": "#00d9ff", "pentester": "#ef4444", "purple": "#a855f7"}.get(mode["id"], "#00d9ff")
    return html.Div(
        [
            html.Div(
                [
                    html.Span(mode["icon"], className="launcher-mode-icon"),
                    html.Div(
                        [
                            html.Div(mode["label"], className="launcher-mode-label"),
                            html.Div(mode["tagline"], className="launcher-mode-tagline"),
                        ],
                        className="launcher-mode-text",
                    ),
                ],
                className="launcher-mode-info",
            ),
            dcc.Link("← Change Mode", href="/", className="launcher-change-mode"),
        ],
        className="launcher-mode-banner",
        style={"--mode-accent": accent, "borderLeftColor": accent},
    )


def _launcher_form(mode: dict) -> html.Div:
    """Mode-aware launcher: scenarios filtered to the chosen mode."""
    scenarios = get_scenarios_for_mode(mode["id"])
    scenario_options = [
        {"label": s["label"], "value": s["id"]} for s in scenarios
    ]
    default_scenario = scenarios[0]["id"] if scenarios else None

    button_label = {
        "soc": "▶ Begin Defense",
        "pentester": "⚔ Begin Engagement",
        "purple": "◆ Begin Exercise",
    }.get(mode["id"], "▶ Launch Session")

    return html.Div(
        [
            _mode_banner(mode),
            html.Div(
                [
                    html.Div(
                        [
                            html.H3("Configure Session", className="astra-card-title"),
                            html.Span("STEP 2", className="astra-card-meta"),
                        ],
                        className="astra-card-header",
                    ),
                    html.Div(
                        [
                            html.Label("Attack Scenario", className="astra-label"),
                            dcc.Dropdown(
                                id="launcher-scenario",
                                options=scenario_options,
                                value=default_scenario,
                                clearable=False,
                                className="astra-select",
                            ),
                            html.Div(
                                id="scenario-description",
                                className="scenario-description",
                                children=(scenarios[0]["description"] if scenarios else ""),
                            ),
                            html.Div(style={"height": "20px"}),
                            html.Label("Difficulty", className="astra-label"),
                            dcc.Dropdown(
                                id="launcher-difficulty",
                                options=_DIFFICULTIES,
                                value="medium",
                                clearable=False,
                                className="astra-select",
                            ),
                            html.Div(style={"height": "24px"}),
                            html.Button(
                                button_label,
                                id="launch-button",
                                className="btn-astra btn-primary-astra",
                                n_clicks=0,
                            ),
                            html.Div(id="launch-status", className="launch-status"),

                            # hidden field carrying the mode id
                            dcc.Store(id="launcher-mode", data=mode["id"]),
                        ],
                    ),
                ],
                className="astra-card",
                style={"maxWidth": "640px"},
            ),
        ],
    )


def layout(mode_id: str | None = None):
    """Render the live session page for a given mode."""
    mode = _MODE_BY_ID.get(mode_id or "soc", _MODE_BY_ID["soc"])

    return html.Div(
        [
            dcc.Interval(id="live-tick", interval=1000, n_intervals=0, disabled=True),
            dcc.Store(id="live-logs-store", data=[]),
            dcc.Store(id="live-alerts-store", data=[]),
            dcc.Store(id="live-stats-store", data={
                "logs_count": 0, "alerts_count": 0, "coverage_pct": 0.0,
                "score": 0.0, "current_phase": -1, "completed_phases": [],
            }),

            html.Div(
                [
                    html.H2(f"{mode['label']} — Live Session", className="page-heading"),
                    html.Div(id="session-info-row", className="session-info-row"),
                ],
                className="live-header",
            ),

            html.Div(
                [
                    _stat_block("Events", "stat-logs", ""),
                    _stat_block("Alerts", "stat-alerts", "severity-high"),
                    # Coverage donut (replaces plain stat block)
                    html.Div(
                        [
                            html.P("MITRE Coverage", className="stat-label"),
                            dcc.Graph(
                                id="stat-coverage-donut",
                                config={"displayModeBar": False, "responsive": True},
                                style={"width": "100%", "height": "140px"},
                            ),
                            # Hidden span — retained for compatibility with old callbacks
                            html.Span("0", id="stat-coverage", style={"display": "none"}),
                        ],
                        className="stat-block status-good",
                        style={"padding": "12px 16px"},
                    ),
                    _stat_block("Score", "stat-score", ""),
                ],
                className="stat-grid",
            ),

            html.Div("Kill Chain Progress", className="section-heading"),
            _kill_chain_strip(),

            html.Div(
                id="live-main-area",
                children=[_launcher_form(mode)],
            ),
        ],
    )
