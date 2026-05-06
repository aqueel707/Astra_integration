"""
dashboard/layouts/progress.py
──────────────────────────────
The Progress page — a user's training journey at a glance.

Sections:
  1. User picker + summary header (total sessions, avg score, best score)
  2. Score trend over time (line chart by mode)
  3. Skills radar (avg sub-scores across all sessions)
  4. Tactic mastery heatmap (MITRE detection rate per tactic)
  5. Activity calendar (last 30 days)
"""

from __future__ import annotations

from dash import dcc, html


def _summary_stat(label: str, value_id: str, severity: str = "") -> html.Div:
    return html.Div(
        [
            html.P(label, className="stat-label"),
            html.P("—", id=value_id, className="stat-value"),
        ],
        className=f"stat-block {severity}",
    )


def _chart_card(title: str, graph_id: str, subtitle: str = "") -> html.Div:
    """Standard card wrapper around a Plotly graph."""
    header_children = [html.H3(title, className="astra-card-title")]
    if subtitle:
        header_children.append(html.Span(subtitle, className="astra-card-meta"))

    return html.Div(
        [
            html.Div(header_children, className="astra-card-header"),
            dcc.Graph(
                id=graph_id,
                config={
                    "displayModeBar": False,
                    "responsive": True,
                },
                style={"width": "100%"},
            ),
        ],
        className="astra-card",
    )


def layout():
    return html.Div(
        [
            # Hidden state
            dcc.Store(id="progress-data-store", data={}),
            dcc.Interval(id="progress-tick", interval=30_000, n_intervals=0),

            # Header
            html.Div(
                [
                    html.Div(
                        [
                            html.H2("Progress", className="page-heading"),
                            html.P(
                                "Track your improvement across sessions and modes.",
                                style={
                                    "color": "var(--text-secondary)",
                                    "fontSize": "13px",
                                    "margin": "4px 0 0 0",
                                },
                            ),
                        ],
                    ),
                    html.Div(
                        [
                            html.Label("User", className="astra-label", style={"marginBottom": "4px"}),
                            dcc.Dropdown(
                                id="progress-user-picker",
                                options=[],
                                placeholder="Loading users...",
                                clearable=False,
                                className="astra-select",
                                style={"minWidth": "220px"},
                            ),
                        ],
                        style={"minWidth": "240px"},
                    ),
                ],
                className="live-header",
            ),

            # Top stat blocks
            html.Div(
                [
                    _summary_stat("Total Sessions", "progress-stat-sessions"),
                    _summary_stat("Avg Score", "progress-stat-avg"),
                    _summary_stat("Best Score", "progress-stat-best", "status-good"),
                    _summary_stat("Avg Coverage", "progress-stat-coverage"),
                ],
                className="stat-grid",
            ),

            # Charts grid - 2 cols on top (trend + radar), full width below (heatmap, activity)
            html.Div("Score & Skills", className="section-heading"),
            html.Div(
                [
                    _chart_card("Score over Time", "progress-chart-trend", "by mode"),
                    _chart_card("Skills Profile", "progress-chart-radar", "avg sub-scores"),
                ],
                className="progress-grid-2col",
            ),

            html.Div("ATT&CK Mastery", className="section-heading"),
            _chart_card("Tactic Mastery", "progress-chart-heatmap", "% detected per tactic"),

            html.Div("Training Cadence", className="section-heading"),
            _chart_card("Activity", "progress-chart-activity", "last 30 days"),
        ],
    )
