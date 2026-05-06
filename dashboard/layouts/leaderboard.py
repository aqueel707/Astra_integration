"""
dashboard/layouts/leaderboard.py
─────────────────────────────────
Top-scoring sessions across all users.
"""

from __future__ import annotations

from dash import dcc, html


def layout():
    return html.Div(
        [
            dcc.Store(id="leaderboard-store", data=[]),
            dcc.Interval(id="leaderboard-tick", interval=15000, n_intervals=0),

            html.Div(
                [
                    html.H2("Leaderboard", className="page-heading"),
                    html.Span(
                        id="leaderboard-meta",
                        children="Top-ranked completed sessions",
                        className="astra-card-meta",
                    ),
                ],
                className="live-header",
            ),

            html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Span("Rank"),
                                    html.Span("User"),
                                    html.Span("Scenario"),
                                    html.Span("Score"),
                                    html.Span("Grade"),
                                    html.Span("Coverage"),
                                ],
                                className="log-table-header",
                                style={"gridTemplateColumns": "60px 160px 1fr 100px 120px 100px"},
                            ),
                            html.Div(
                                id="leaderboard-body",
                                className="log-table-body",
                                children=[
                                    html.Div(
                                        [
                                            html.Div("✦", className="empty-state-icon"),
                                            "No scored sessions yet",
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
