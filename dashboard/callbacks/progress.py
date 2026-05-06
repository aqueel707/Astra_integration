"""
dashboard/callbacks/progress.py
────────────────────────────────
Callbacks for the Progress page.

Flow:
  1. On page load → /progress/users populates user picker
  2. User selected → fire 5 parallel API calls → store data in dcc.Store
  3. Store data → render summary stats + 4 charts
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from dash import Input, Output, State, no_update

from dashboard.components.charts import (
    activity_calendar_chart,
    empty_chart,
    score_trend_chart,
    skills_radar_chart,
    tactic_heatmap_chart,
)


logger = logging.getLogger("astra.dashboard.progress")


def _fetch(url: str, timeout: float = 4.0) -> Any:
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.debug(f"Progress fetch failed [{url}]: {e}")
        return None


def register(app):
    """Register all progress page callbacks."""

    # ── User picker population (on page load) ────────────────────────────
    @app.callback(
        Output("progress-user-picker", "options"),
        Output("progress-user-picker", "value"),
        Input("url", "pathname"),
        State("api-base", "data"),
    )
    def populate_user_picker(pathname, api_base):
        if not pathname or not pathname.startswith("/progress"):
            return no_update, no_update
        users = _fetch(f"{api_base}/progress/users") or []
        if not users:
            return [], None
        options = [{"label": u["username"], "value": u["id"]} for u in users]
        # Default to first user
        return options, users[0]["id"]

    # ── Fetch all progress data when user changes ────────────────────────
    @app.callback(
        Output("progress-data-store", "data"),
        Input("progress-user-picker", "value"),
        Input("progress-tick", "n_intervals"),
        State("api-base", "data"),
    )
    def fetch_progress(user_id, _n, api_base):
        if not user_id:
            return {}
        return {
            "summary":  _fetch(f"{api_base}/progress/{user_id}/summary")  or {},
            "trends":   _fetch(f"{api_base}/progress/{user_id}/trends")   or [],
            "skills":   _fetch(f"{api_base}/progress/{user_id}/skills")   or {},
            "tactics":  _fetch(f"{api_base}/progress/{user_id}/tactics")  or {},
            "activity": _fetch(f"{api_base}/progress/{user_id}/activity") or [],
        }

    # ── Render summary stat blocks ───────────────────────────────────────
    @app.callback(
        Output("progress-stat-sessions", "children"),
        Output("progress-stat-avg",      "children"),
        Output("progress-stat-best",     "children"),
        Output("progress-stat-coverage", "children"),
        Input("progress-data-store", "data"),
    )
    def render_summary(data):
        if not data or not data.get("summary"):
            return "—", "—", "—", "—"
        s = data["summary"]
        return (
            str(s.get("total_sessions", 0)),
            f"{s.get('avg_score', 0):.0f}",
            f"{s.get('best_score', 0):.0f}",
            f"{s.get('avg_coverage', 0):.0f}%",
        )

    # ── Render score trend chart ─────────────────────────────────────────
    @app.callback(
        Output("progress-chart-trend", "figure"),
        Input("progress-data-store", "data"),
    )
    def render_trend(data):
        if not data:
            return empty_chart("Select a user")
        trends = data.get("trends") or []
        # Map to the shape charts.py expects
        rows = [
            {"date": t.get("date", ""), "score": t.get("score", 0), "mode": t.get("mode", "soc")}
            for t in trends
        ]
        return score_trend_chart(rows)

    # ── Render skills radar ──────────────────────────────────────────────
    @app.callback(
        Output("progress-chart-radar", "figure"),
        Input("progress-data-store", "data"),
    )
    def render_radar(data):
        if not data:
            return empty_chart("Select a user")
        skills = data.get("skills") or {}
        return skills_radar_chart(skills)

    # ── Render tactic heatmap ────────────────────────────────────────────
    @app.callback(
        Output("progress-chart-heatmap", "figure"),
        Input("progress-data-store", "data"),
    )
    def render_heatmap(data):
        if not data:
            return empty_chart("Select a user")
        tactics = data.get("tactics") or {}
        return tactic_heatmap_chart(tactics)

    # ── Render activity calendar ─────────────────────────────────────────
    @app.callback(
        Output("progress-chart-activity", "figure"),
        Input("progress-data-store", "data"),
    )
    def render_activity(data):
        if not data:
            return empty_chart("Select a user")
        activity = data.get("activity") or []
        return activity_calendar_chart(activity)
