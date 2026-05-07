"""
dashboard/app.py
─────────────────
ASTRA Dashboard — entry point.

Routes:
  /                  → mode picker (3 cards)
  /launch/<mode>     → launcher for that mode
  /live              → active live session view (after launch)
  /history           → past sessions
  /leaderboard       → top scores
  /matrix            → ATT&CK matrix
"""

from __future__ import annotations

import os

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, State, dcc, html

from dashboard.layouts import history, leaderboard, live_session, mitre_matrix, mode_picker, progress, report_writer
from dashboard.layouts.main import navbar


# ─── App initialization ─────────────────────────────────────────────────────
app = dash.Dash(
    __name__,
    external_stylesheets=[
        # Bootstrap reboot only - we provide our own theme
        "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap-reboot.min.css",
        # IBM Plex - distinctive, engineered personality
        "https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@300;400;500;600;700&display=swap",
    ],
    suppress_callback_exceptions=True,
    title="ASTRA — Cyber Range",
    update_title=None,
    meta_tags=[
        {"name": "viewport", "content": "width=device-width, initial-scale=1"},
    ],
)

API_BASE = os.getenv("ASTRA_API_BASE", "http://localhost:8000")
WS_BASE = os.getenv("ASTRA_WS_BASE", "ws://localhost:8000")


app.layout = html.Div(
    [
        dcc.Location(id="url", refresh=False),
        dcc.Store(id="active-session", storage_type="session"),
        dcc.Store(id="active-mode", storage_type="session"),  # NEW — selected mode
        dcc.Store(id="api-base", data=API_BASE),
        dcc.Store(id="ws-base", data=WS_BASE),

        navbar(),
        html.Div(id="page-content", className="page-container"),

        html.Footer(
            [
                html.Span("ASTRA", className="footer-brand"),
                html.Span(" / ", className="footer-sep"),
                html.Span(id="footer-status", children="● connected", className="footer-status"),
                html.Span(" / ", className="footer-sep"),
                html.Span("v0.1.0", className="footer-version"),
            ],
            className="footer",
        ),
    ],
    className="app-root",
)


@app.callback(
    Output("page-content", "children"),
    Output("active-mode", "data"),
    Input("url", "pathname"),
    State("active-mode", "data"),
)
def render_page(pathname: str, current_mode):
    """Route based on pathname; persist mode selection."""
    if pathname is None or pathname == "/":
        return mode_picker.layout(), current_mode

    if pathname.startswith("/launch/"):
        mode = pathname.removeprefix("/launch/").strip("/")
        if mode in {"soc", "pentester", "purple"}:
            return live_session.layout(mode), mode
        return mode_picker.layout(), current_mode

    if pathname.startswith("/live"):
        # Use whichever mode is in session storage; fall back to soc
        return live_session.layout(current_mode or "soc"), current_mode

    if pathname.startswith("/report/"):
        # /report/<session_id> or /report/<session_id>/<report_type>
        parts = pathname.removeprefix("/report/").strip("/").split("/")
        session_id = parts[0] if parts else None
        report_type = parts[1] if len(parts) > 1 else "incident"
        if session_id:
            return report_writer.layout(session_id, report_type), current_mode
        return html.Div("Missing session id"), current_mode
    if pathname.startswith("/progress"):
        return progress.layout(), current_mode
    if pathname.startswith("/history"):
        return history.layout(), current_mode
    if pathname.startswith("/leaderboard"):
        return leaderboard.layout(), current_mode
    if pathname.startswith("/matrix"):
        return mitre_matrix.layout(), current_mode

    return html.Div(
        [
            html.H1("404", className="error-code"),
            html.P("This page doesn't exist.", className="error-msg"),
            dcc.Link("Back to home", href="/", className="error-link"),
        ],
        className="error-page",
    ), current_mode


# ─── Wire up callbacks ──────────────────────────────────────────────────────
from dashboard.callbacks import api as api_callbacks  # noqa: E402, F401
from dashboard.callbacks import streaming as streaming_callbacks  # noqa: E402, F401

from dashboard.callbacks import progress as progress_callbacks  # noqa: E402, F401

from dashboard.callbacks import report_writer as report_writer_callbacks  # noqa: E402, F401

api_callbacks.register(app)
streaming_callbacks.register(app)
progress_callbacks.register(app)
report_writer_callbacks.register(app)


# ─── Scenario description sync (small UX touch) ─────────────────────────────
@app.callback(
    Output("scenario-description", "children"),
    Input("launcher-scenario", "value"),
    prevent_initial_call=True,
)
def sync_scenario_description(scenario_id):
    """When user changes scenario, show its description."""
    from dashboard.layouts.live_session import ALL_SCENARIOS
    for s in ALL_SCENARIOS:
        if s["id"] == scenario_id:
            return s["description"]
    return ""


def main():
    debug = os.getenv("ASTRA_DASHBOARD_DEBUG", "false").lower() == "true"
    port = int(os.getenv("ASTRA_DASHBOARD_PORT", "8050"))
    app.run(host="0.0.0.0", port=port, debug=debug)


if __name__ == "__main__":
    main()
