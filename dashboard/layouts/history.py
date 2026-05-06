"""
dashboard/layouts/history.py
─────────────────────────────
Past sessions browser.

Shows a table of recently completed sessions with score, scenario, duration,
and a "view debrief" link to drill in.
"""

from __future__ import annotations

from dash import dcc, html


def layout():
    return html.Div(
        [
            dcc.Store(id="history-store", data=[]),
            dcc.Interval(id="history-tick", interval=8000, n_intervals=0),

            html.Div(
                [
                    html.H2("Session History", className="page-heading"),
                    html.Span(id="history-count", className="astra-card-meta"),
                ],
                className="live-header",
            ),

            html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Span("Session"),
                                    html.Span("Scenario"),
                                    html.Span("Score"),
                                    html.Span("Coverage"),
                                    html.Span("Duration"),
                                    html.Span("Completed"),
                                ],
                                className="log-table-header",
                                style={"gridTemplateColumns": "120px 1fr 90px 90px 100px 160px"},
                            ),
                            html.Div(
                                id="history-table-body",
                                className="log-table-body",
                                children=[
                                    html.Div(
                                        [
                                            html.Div("◰", className="empty-state-icon"),
                                            "No completed sessions yet — launch one from the Live tab",
                                        ],
                                        className="empty-state",
                                    ),
                                ],
                            ),
                        ],
                        className="log-table-container",
                        style={"maxHeight": "70vh"},
                    ),
                ],
                className="astra-card",
            ),
        ],
    )
