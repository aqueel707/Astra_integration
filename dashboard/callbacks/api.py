"""
dashboard/callbacks/api.py
───────────────────────────
REST API callbacks for non-realtime pages (history, leaderboard, MITRE matrix).

These poll the backend periodically and render results.
"""

from __future__ import annotations

import logging

import httpx
from dash import Input, Output, State, html, no_update

from dashboard.components.renderers import (
    render_history_row,
    render_leaderboard_row,
    render_mitre_matrix,
)


logger = logging.getLogger("astra.dashboard.api")


def _safe_get(url: str, timeout: float = 3.0) -> dict | list | None:
    """GET an endpoint; return parsed JSON or None on error."""
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.debug(f"API call failed [{url}]: {e}")
        return None


def _safe_post(url: str, json: dict, timeout: float = 5.0) -> dict | None:
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(url, json=json)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.debug(f"API POST failed [{url}]: {e}")
        return None


def register(app):
    """Register all API-driven callbacks."""

    # ── History page ────────────────────────────────────────────────────
    @app.callback(
        Output("history-table-body", "children"),
        Output("history-count", "children"),
        Input("history-tick", "n_intervals"),
        State("api-base", "data"),
    )
    def refresh_history(_n, api_base):
        # The API returns Score records sorted by created_at desc; we'll join with sessions client-side.
        # For now we use leaderboard as a stand-in since both surface scored sessions.
        data = _safe_get(f"{api_base}/scoring/leaderboard?limit=50")
        if not data:
            return (
                [
                    html.Div(
                        [
                            html.Div("◰", className="empty-state-icon"),
                            "No completed sessions yet",
                        ],
                        className="empty-state",
                    )
                ],
                "0 sessions",
            )

        rows = [render_history_row({
            "session_id": e.get("session_id", ""),
            "scenario_id": e.get("scenario_id", ""),
            "total_score": e.get("total_score", 0),
            "grade": e.get("grade", "—"),
            "mitre_coverage_pct": e.get("mitre_coverage_pct", 0),
            "duration_sec": 0,  # not in leaderboard endpoint; would need /sessions/{id}
            "created_at": e.get("created_at", ""),
        }) for e in data]
        return rows, f"{len(data)} sessions"

    # ── Leaderboard page ────────────────────────────────────────────────
    @app.callback(
        Output("leaderboard-body", "children"),
        Input("leaderboard-tick", "n_intervals"),
        State("api-base", "data"),
    )
    def refresh_leaderboard(_n, api_base):
        data = _safe_get(f"{api_base}/scoring/leaderboard?limit=20")
        if not data:
            return [html.Div(
                [html.Div("✦", className="empty-state-icon"), "No scored sessions yet"],
                className="empty-state",
            )]
        return [render_leaderboard_row(e) for e in data]

    # ── MITRE matrix page ───────────────────────────────────────────────
    @app.callback(
        Output("matrix-session-picker", "options"),
        Input("url", "pathname"),
        State("api-base", "data"),
    )
    def populate_matrix_session_picker(pathname, api_base):
        if not pathname or not pathname.startswith("/matrix"):
            return no_update
        data = _safe_get(f"{api_base}/scoring/leaderboard?limit=50") or []
        return [
            {"label": f"{e.get('session_id','')[:12]} — {e.get('scenario_id','?')} ({e.get('total_score',0):.0f})",
             "value": e.get("session_id", "")}
            for e in data
        ]

    @app.callback(
        Output("matrix-grid-container", "children"),
        Input("matrix-session-picker", "value"),
        State("api-base", "data"),
        State("matrix-tactic-order", "data"),
    )
    def render_matrix_for_session(session_id, api_base, tactic_order):
        if not session_id:
            return html.Div(
                [html.Div("⊞", className="empty-state-icon"),
                 "Select a session to view its ATT&CK coverage"],
                className="empty-state",
            )
        cov = _safe_get(f"{api_base}/mitre/coverage/{session_id}")
        if not cov:
            return html.Div(
                [html.Div("⚠", className="empty-state-icon"),
                 f"Could not load coverage for session {session_id[:12]}"],
                className="empty-state",
            )
        # tactic_order arrives as list of [id, name] from the Store
        order = [tuple(t) for t in (tactic_order or [])]
        return render_mitre_matrix(cov, order, enterprise_techniques=None)
