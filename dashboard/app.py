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

Auth (Phase 1):
  Firebase email/password gate wraps every route. No token in
  dcc.Store(id="auth-token") → render_page() returns the auth view (sign
  in / create account) and the navbar is hidden.

  firebase-auth.js is an ES module. Dash auto-loads assets/ files as PLAIN
  scripts, which cannot parse `import` (that was the "import declarations
  may only appear at top level of a module" error). Fix: we DISABLE Dash's
  auto-include for that one file (assets_ignore) and instead inject it as
  <script type="module"> via index_string, so the browser parses it
  correctly. Every other asset still auto-loads as before.
"""

from __future__ import annotations

import os

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, State, dcc, html

from dashboard.layouts import history, leaderboard, live_session, mitre_matrix, mode_picker, progress, report_writer
from dashboard.layouts import pentester as pentester_layouts
from dashboard.layouts.main import navbar


# ─── App initialization ─────────────────────────────────────────────────────
app = dash.Dash(
    __name__,
    external_stylesheets=[
        "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap-reboot.min.css",
        "https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@300;400;500;600;700&display=swap",
    ],
    suppress_callback_exceptions=True,
    title="ASTRA — Cyber Range",
    update_title=None,
    meta_tags=[
        {"name": "viewport", "content": "width=device-width, initial-scale=1"},
    ],
    # Stop Dash auto-including firebase-auth.js as a plain <script>. We inject
    # it as a module below. Regex matches the filename Dash would otherwise add.
    assets_ignore=r"firebase-auth\.js",
)

API_BASE = os.getenv("ASTRA_API_BASE", "http://localhost:8000")
# Render's fromService:host gives just the hostname; prepend https:// if missing
if API_BASE and not API_BASE.startswith(("http://", "https://")):
    API_BASE = f"https://{API_BASE}"
WS_BASE = os.getenv("ASTRA_WS_BASE", "")
# If WS_BASE not set explicitly, derive from API_BASE (http -> ws, https -> wss)
if not WS_BASE:
    if API_BASE.startswith("https://"):
        WS_BASE = "wss://" + API_BASE[len("https://"):]
    elif API_BASE.startswith("http://"):
        WS_BASE = "ws://" + API_BASE[len("http://"):]
    else:
        WS_BASE = "ws://localhost:8000"

# Inject firebase-auth.js as an ES module. {%...%} are Dash index_string
# placeholders and must be preserved exactly. Dash still serves the static
# file at /assets/firebase-auth.js even though it no longer auto-includes it.
app.index_string = """<!DOCTYPE html>
<html>
  <head>
    {%metas%}
    <title>{%title%}</title>
    {%favicon%}
    {%css%}
  </head>
  <body>
    {%app_entry%}
    <footer>
      {%config%}
      {%scripts%}
      {%renderer%}
      <script type="module" src="/assets/firebase-auth.js"></script>
    </footer>
  </body>
</html>"""


# ─── Auth view (sign in + create account) ───────────────────────────────────
def _field(label: str, input_id: str, **kw) -> html.Div:
    """A labelled field. Password fields get a reveal toggle.

    Every id here is a contract with assets/firebase-auth.js — that module
    reads them by getElementById and by the .auth-reveal / data-for pair.
    """
    is_password = kw.get("type") == "password"
    control = [dcc.Input(id=input_id, className="auth-input", **kw)]
    if is_password:
        control.append(
            html.Button(
                "Show",
                className="auth-reveal",
                **{"data-for": input_id, "aria-label": "Show password"},
                n_clicks=0,
                type="button",
            )
        )
    return html.Div(
        [
            html.Label(label, htmlFor=input_id, className="auth-label"),
            html.Div(control, className="auth-control"),
        ],
        className="auth-field",
    )


def auth_layout() -> html.Div:
    """Sign-in / create-account screen.

    Two panes: the left states what the account is for, the right is the form.
    The IDs are the contract with firebase-auth.js — auth-error, auth-notice,
    auth-resend, auth-forgot, the auth-panel-* wrappers and the .auth-tab
    buttons with data-mode. Tab switching and panel visibility stay pure
    client-side, with no Dash callback.
    """
    signin_panel = html.Div(
        [
            _field("Email", "login-email", type="email",
                   placeholder="you@domain.com", autoComplete="username"),
            _field("Password", "login-password", type="password",
                   placeholder="Your password", autoComplete="current-password"),
            html.Div(
                html.Button("Reset password", id="auth-forgot",
                            className="auth-link", n_clicks=0, type="button"),
                className="auth-row-end",
            ),
            html.Button("Sign in", id="login-submit", n_clicks=0, className="auth-btn"),
        ],
        id="auth-panel-signin",
        className="auth-panel",
    )

    signup_panel = html.Div(
        [
            _field("Email", "signup-email", type="email",
                   placeholder="you@domain.com", autoComplete="username"),
            _field("Password", "signup-password", type="password",
                   placeholder="At least 6 characters", autoComplete="new-password"),
            # The API refuses other providers after the Firebase account already
            # exists, so say it up front rather than letting someone find out
            # from a 403 they cannot act on.
            html.Div(
                [
                    html.Span("Accepted providers", className="auth-hint-label"),
                    html.Span("Gmail · DuckDuckGo · Proton · Tuta · iCloud",
                              className="auth-hint-value"),
                ],
                className="auth-hint",
            ),
            html.Button("Create account", id="signup-submit", n_clicks=0, className="auth-btn"),
        ],
        id="auth-panel-signup",
        className="auth-panel",
        style={"display": "none"},
    )

    form_pane = html.Div(
        [
            html.Div(
                [
                    html.Button("Sign in", className="auth-tab is-active",
                                n_clicks=0, type="button", **{"data-mode": "signin"}),
                    html.Button("Create account", className="auth-tab",
                                n_clicks=0, type="button", **{"data-mode": "signup"}),
                ],
                className="auth-tabs",
                role="tablist",
            ),
            signin_panel,
            signup_panel,
            html.Div(id="auth-error", className="auth-error", role="alert"),
            html.Div(id="auth-notice", className="auth-notice", role="status"),
            html.Button("Resend verification", id="auth-resend",
                        className="auth-resend", n_clicks=0, type="button"),
        ],
        className="auth-form-pane",
    )

    intro_pane = html.Div(
        [
            html.Div(
                [
                    html.Span("ASTRA", className="auth-brand"),
                    html.Span("CYBER RANGE", className="auth-brand-sub"),
                ],
                className="auth-brand-wrap",
            ),
            html.P(
                "Multi-stage attack scenarios, scored against MITRE ATT&CK. "
                "Hunt the intrusion in a live log stream, or plan it move by move.",
                className="auth-intro-lede",
            ),
            html.Ul(
                [
                    html.Li("Detection scored technique by technique"),
                    html.Li("Live log triage under real time pressure"),
                    html.Li("Branching red-team engagements"),
                ],
                className="auth-intro-list",
            ),
            html.Div(
                [html.Span(className="auth-dot"), "Secure access · Firebase"],
                className="auth-intro-foot",
            ),
        ],
        className="auth-intro-pane",
    )

    return html.Div(
        html.Div([intro_pane, form_pane], className="auth-card"),
        className="auth-page",
    )


def landing_layout() -> html.Iframe:
    """Full-viewport marketing landing, served as a self-contained static
    asset (assets/landing.html) inside an overlay iframe. The iframe covers
    the whole viewport (including the Dash footer) so the landing reads as a
    standalone page. Its CTAs navigate the top window to /signin."""
    return html.Iframe(
        src="/assets/landing.html",
        # allow-same-origin removed: combined with allow-scripts it lets the
        # framed document reach out and remove its own sandbox attribute,
        # so the restriction was decorative. The landing page needs neither.
        sandbox="allow-scripts allow-top-navigation allow-top-navigation-by-user-activation",
        style={
            "position": "fixed", "top": 0, "left": 0,
            "width": "100vw", "height": "100vh",
            "border": "0", "zIndex": 1000, "background": "var(--bg-base)",
        },
    )


app.layout = html.Div(
    [
        dcc.Location(id="url", refresh=False),
        dcc.Store(id="active-session", storage_type="session"),
        dcc.Store(id="active-mode", storage_type="session"),
        dcc.Store(id="api-base", data=API_BASE),
        dcc.Store(id="ws-base", data=WS_BASE),
        dcc.Store(id="auth-token", storage_type="session"),

        html.Div(id="navbar-slot"),
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
    Output("navbar-slot", "children"),
    Input("url", "pathname"),
    Input("auth-token", "data"),
    State("active-mode", "data"),
)
def render_page(pathname: str, token, current_mode):
    """Route based on pathname; persist mode. Auth gate: no token → auth view,
    navbar hidden (navbar is static markup, hiding it has no side effects).

    auth-token is an Input (not State) so a successful Firebase sign-in,
    which writes the token via the clientside relay, immediately re-fires
    this callback and swaps the auth view for the dashboard. As State it
    was only read on URL change, so login appeared to 'do nothing' until
    a manual reload."""
    if not token:
        # Auth form lives only at /signin; every other route shows the
        # landing page. Landing CTAs navigate (_top) to /signin.
        if pathname == "/signin":
            return auth_layout(), current_mode, None
        return landing_layout(), current_mode, None

    nav = navbar()

    # Logged in but sitting on the landing / sign-in route (e.g. just
    # finished signing in) -> send to the mode picker.
    if pathname in (None, "/", "/signin"):
        return mode_picker.layout(), current_mode, nav

    if pathname == "/launch/pentester":
        return pentester_layouts.picker_layout(), "pentester", nav

    if pathname.startswith("/pentester/brief/"):
        scenario_id = pathname.removeprefix("/pentester/brief/").strip("/")
        if scenario_id:
            return pentester_layouts.brief_layout(scenario_id), "pentester", nav
        return pentester_layouts.picker_layout(), "pentester", nav

    if pathname.startswith("/pentester/engagement/"):
        parts = pathname.removeprefix("/pentester/engagement/").strip("/").split("/")
        session_id = parts[0] if parts else None
        scenario_id = parts[1] if len(parts) > 1 else ""
        if session_id:
            return pentester_layouts.engagement_layout(session_id, scenario_id), "pentester", nav
        return pentester_layouts.picker_layout(), "pentester", nav

    if pathname.startswith("/launch/"):
        mode = pathname.removeprefix("/launch/").strip("/")
        from dashboard.layouts.mode_picker import MODES
        _mode_obj = next((m for m in MODES if m["id"] == mode), None)
        if _mode_obj is None or _mode_obj.get("coming_soon"):
            return mode_picker.layout(), current_mode, nav
        return live_session.layout(mode), mode, nav

    if pathname.startswith("/live"):
        return live_session.layout(current_mode or "soc"), current_mode, nav

    if pathname.startswith("/report/"):
        parts = pathname.removeprefix("/report/").strip("/").split("/")
        session_id = parts[0] if parts else None
        report_type = parts[1] if len(parts) > 1 else "incident"
        if session_id:
            return report_writer.layout(session_id, report_type), current_mode, nav
        return html.Div("Missing session id"), current_mode, nav
    if pathname.startswith("/progress"):
        return progress.layout(), current_mode, nav
    if pathname.startswith("/history"):
        return history.layout(), current_mode, nav
    if pathname.startswith("/leaderboard"):
        return leaderboard.layout(), current_mode, nav
    if pathname.startswith("/matrix"):
        return mitre_matrix.layout(), current_mode, nav

    return html.Div(
        [
            html.H1("404", className="error-code"),
            html.P("This page doesn't exist.", className="error-msg"),
            dcc.Link("Back to home", href="/", className="error-link"),
        ],
        className="error-page",
    ), current_mode, nav


# ─── Wire up callbacks ──────────────────────────────────────────────────────
from dashboard.callbacks import api as api_callbacks  # noqa: E402, F401
from dashboard.callbacks import streaming as streaming_callbacks  # noqa: E402, F401

from dashboard.callbacks import progress as progress_callbacks  # noqa: E402, F401

from dashboard.callbacks import report_writer as report_writer_callbacks  # noqa: E402, F401
from dashboard.callbacks import pentester as pentester_callbacks  # noqa: E402, F401

api_callbacks.register(app)
streaming_callbacks.register(app)
progress_callbacks.register(app)
report_writer_callbacks.register(app)
pentester_callbacks.register(app)


@app.callback(
    Output("scenario-description", "children"),
    Input("launcher-scenario", "value"),
    prevent_initial_call=True,
)
def sync_scenario_description(scenario_id):
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


# Security headers (wired in by fix_wire_security_headers.py)
from security_headers import apply_to_flask
apply_to_flask(app.server)        # Dash's underlying Flask app
