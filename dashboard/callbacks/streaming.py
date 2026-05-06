"""
dashboard/callbacks/streaming.py
─────────────────────────────────
Callbacks for the Live Session page — launches a session and updates the UI
live as logs/alerts come in.

Architecture note:
  Dash callbacks can't hold long-running websockets directly. So we use a
  background worker (started when the user clicks "Launch") that subscribes
  to the streaming backend and pushes events into a thread-safe deque per
  session. The dcc.Interval ('live-tick') fires every second to drain the
  deque into the dcc.Store, which triggers the rendering callbacks.

  In practice the user starts a session by hitting POST /attacks/run/...,
  the backend does the simulation, and we poll the API for current state
  while also subscribing to the streaming backend for real-time events.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

import httpx
from dash import Input, Output, State, html, no_update

from dashboard.components.renderers import (
    render_alert_card,
    render_kill_chain,
    render_log_row,
    render_score_breakdown,
)


logger = logging.getLogger("astra.dashboard.streaming")


# ════════════════════════════════════════════════════════════════════════════
# THREAD-SAFE EVENT BUFFER per session
# ════════════════════════════════════════════════════════════════════════════
class _SessionBuffer:
    """Bounded thread-safe buffers for logs / alerts / status / scores."""
    def __init__(self, maxlen: int = 500):
        self.logs: deque = deque(maxlen=maxlen)
        self.alerts: deque = deque(maxlen=200)
        self.attack_status: dict[str, Any] = {}
        self.score: dict[str, Any] = {}
        self.lock = threading.Lock()
        self.subscriber_task: asyncio.Task | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.stop_event = threading.Event()


_buffers: dict[str, _SessionBuffer] = {}
_buffers_lock = threading.Lock()


def _get_buffer(session_id: str) -> _SessionBuffer:
    with _buffers_lock:
        if session_id not in _buffers:
            _buffers[session_id] = _SessionBuffer()
        return _buffers[session_id]


# ════════════════════════════════════════════════════════════════════════════
# BACKGROUND SUBSCRIBER — one per active session
# ════════════════════════════════════════════════════════════════════════════
def _start_subscriber(session_id: str):
    """Spawn a thread that subscribes to streaming for this session."""
    buf = _get_buffer(session_id)
    if buf.subscriber_task is not None:
        return  # already running

    def _run():
        # Each thread needs its own event loop
        loop = asyncio.new_event_loop()
        buf.loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_subscribe_loop(session_id, buf))
        finally:
            loop.close()

    t = threading.Thread(target=_run, daemon=True, name=f"astra-sub-{session_id[:8]}")
    t.start()
    buf.subscriber_task = t  # not actually a Task, but the slot is fine


async def _subscribe_loop(session_id: str, buf: _SessionBuffer):
    """Subscribe to all relevant streams for this session and fan out into the buffer."""
    try:
        from streaming.backend import get_backend
        from streaming.channels import StreamType, channel_for, deserialize
    except ImportError:
        logger.warning("streaming module not importable from dashboard")
        return

    backend = get_backend()
    channels = [
        channel_for(session_id, StreamType.LOGS),
        channel_for(session_id, StreamType.ALERTS),
        channel_for(session_id, StreamType.ATTACK_STATUS),
        channel_for(session_id, StreamType.SCORES),
    ]

    try:
        async for channel, raw in backend.subscribe(*channels):
            if buf.stop_event.is_set():
                break
            try:
                msg = deserialize(raw)
            except Exception:
                continue
            stream_name = msg.get("stream") or channel.split(":")[-1]
            payload = msg.get("payload", {})
            with buf.lock:
                if stream_name == "logs":
                    buf.logs.append(payload)
                elif stream_name == "alerts":
                    buf.alerts.append(payload)
                elif stream_name == "attack_status":
                    buf.attack_status = payload
                elif stream_name == "scores":
                    buf.score = payload
    except Exception as e:
        logger.exception(f"subscriber crashed for session={session_id}: {e}")


# ════════════════════════════════════════════════════════════════════════════
# CALLBACKS
# ════════════════════════════════════════════════════════════════════════════
def register(app):
    """Register live-session callbacks."""

    # ── Launch button → start session via API ───────────────────────────
    @app.callback(
        Output("active-session", "data"),
        Output("live-tick", "disabled"),
        Output("launch-status", "children"),
        Output("live-main-area", "children"),
        Input("launch-button", "n_clicks"),
        State("launcher-scenario", "value"),
        State("launcher-difficulty", "value"),
        State("api-base", "data"),
        prevent_initial_call=True,
    )
    def launch_session(n_clicks, scenario, difficulty, api_base):
        if not n_clicks or not scenario:
            return no_update, no_update, no_update, no_update

        # Generate a session ID locally (the API will accept whatever we give it)
        session_id = str(uuid.uuid4())

        # Start the subscriber BEFORE the simulation starts — so we don't miss events
        _start_subscriber(session_id)

        # Tell the backend to run the scenario
        # Note: this is fire-and-forget; the backend will publish events to streaming
        try:
            with httpx.Client(timeout=5.0) as client:
                client.post(
                    f"{api_base}/attacks/run/{scenario}",
                    json={"session_id": session_id, "difficulty": difficulty, "stream": True},
                )
        except Exception as e:
            return no_update, no_update, html.Div(
                f"⚠ Failed to launch: {e}",
                style={"color": "var(--severity-critical)", "marginTop": "12px"},
            ), no_update

        # Replace launcher form with the live grid
        live_grid = _build_live_grid(session_id, scenario, difficulty)
        return session_id, False, html.Div(
            f"✓ Session {session_id[:8]} launched — {scenario} / {difficulty}",
            style={"color": "var(--status-good)", "marginTop": "12px"},
        ), live_grid

    # ── Live tick → drain buffer into Stores ────────────────────────────
    @app.callback(
        Output("live-logs-store", "data"),
        Output("live-alerts-store", "data"),
        Output("live-stats-store", "data"),
        Input("live-tick", "n_intervals"),
        State("active-session", "data"),
        State("live-stats-store", "data"),
        prevent_initial_call=True,
    )
    def drain_buffer(_n, session_id, prev_stats):
        if not session_id:
            return no_update, no_update, no_update
        buf = _get_buffer(session_id)
        with buf.lock:
            logs = list(buf.logs)
            alerts = list(buf.alerts)
            attack_status = dict(buf.attack_status)
            score = dict(buf.score)

        # Build stats
        coverage = score.get("mitre_coverage_pct", prev_stats.get("coverage_pct", 0)) if score else prev_stats.get("coverage_pct", 0)
        score_value = score.get("total_score", prev_stats.get("score", 0)) if score else prev_stats.get("score", 0)

        # Phase tracking from attack_status
        phase_name = (attack_status.get("current_phase") or "").lower()
        phase_idx = _phase_to_index(phase_name)
        completed = attack_status.get("phases_completed", [])
        completed_idx = [_phase_to_index(p.lower()) for p in completed if _phase_to_index(p.lower()) >= 0]

        stats = {
            "logs_count": len(logs),
            "alerts_count": len(alerts),
            "coverage_pct": coverage,
            "score": score_value,
            "current_phase": phase_idx,
            "completed_phases": completed_idx,
            "score_full": score,
        }
        return logs, alerts, stats

    # ── Render log table ─────────────────────────────────────────────────
    @app.callback(
        Output("log-stream-body", "children"),
        Output("log-stream-count", "children"),
        Input("live-logs-store", "data"),
    )
    def render_logs(logs):
        if not logs:
            return [
                html.Div(
                    [html.Div("⌂", className="empty-state-icon"), "Waiting for log stream..."],
                    className="empty-state",
                )
            ], "0 events"
        # Show newest first, cap at 200 in the DOM for perf
        recent = list(reversed(logs))[:200]
        return [render_log_row(l) for l in recent], f"{len(logs)} events"

    # ── Render alerts feed ───────────────────────────────────────────────
    @app.callback(
        Output("alerts-stream", "children"),
        Output("alerts-count", "children"),
        Input("live-alerts-store", "data"),
    )
    def render_alerts(alerts):
        if not alerts:
            return [
                html.Div(
                    [html.Div("◇", className="empty-state-icon"), "No alerts yet"],
                    className="empty-state",
                )
            ], "0"
        recent = list(reversed(alerts))[:50]
        return [render_alert_card(a) for a in recent], str(len(alerts))

    # ── Update stat blocks + kill chain + score panel ───────────────────
    @app.callback(
        Output("stat-logs", "children"),
        Output("stat-alerts", "children"),
        Output("stat-coverage", "children"),
        Output("stat-score", "children"),
        Output("kill-chain-strip", "children"),
        Output("score-number", "children"),
        Output("score-grade", "children"),
        Output("score-grade", "className"),
        Output("score-subscores", "children"),
        Input("live-stats-store", "data"),
    )
    def render_stats(stats):
        if not stats:
            return ("0", "0", "0%", "0", no_update, "0", "—", "score-grade", [])

        kc = render_kill_chain(stats.get("current_phase", -1), stats.get("completed_phases", []))

        score_full = stats.get("score_full") or {}
        grade = score_full.get("grade", "—")
        score_val = stats.get("score", 0)

        return (
            str(stats.get("logs_count", 0)),
            str(stats.get("alerts_count", 0)),
            f"{stats.get('coverage_pct', 0):.0f}%",
            f"{score_val:.0f}",
            kc,
            f"{score_val:.0f}",
            grade.upper().replace("_", " "),
            f"score-grade {grade.lower()}",
            render_score_breakdown(score_full),
        )

    # ── Coverage donut + score sparkline (live) ──────────────────────────
    @app.callback(
        Output("stat-coverage-donut", "figure"),
        Output("score-sparkline-chart", "figure"),
        Input("live-stats-store", "data"),
        State("api-base", "data"),
        State("active-mode", "data"),
    )
    def render_donut_and_sparkline(stats, api_base, mode):
        from dashboard.components.charts import coverage_donut, score_sparkline, empty_chart
        if not stats:
            return empty_chart("0%", height=140), empty_chart("", height=60)
        coverage_pct = float(stats.get("coverage_pct", 0))
        # The score_full dict contains MITRE detail
        score_full = stats.get("score_full") or {}
        mitre = score_full.get("details", {}).get("mitre", {})
        detected = mitre.get("techniques_detected", 0) if isinstance(mitre, dict) else 0
        used     = mitre.get("techniques_used", 0)     if isinstance(mitre, dict) else 0
        donut = coverage_donut(coverage_pct, detected=detected, total=used)

        # For sparkline, fetch recent scores. Cheap polling:
        history = []
        try:
            import httpx
            with httpx.Client(timeout=2.0) as client:
                r = client.get(f"{api_base}/scoring/leaderboard?limit=10")
                r.raise_for_status()
                # Reverse so oldest first
                history = [e.get("total_score", 0) for e in reversed(r.json())]
        except Exception:
            pass
        spark = score_sparkline(history, current=stats.get("score"))
        return donut, spark

    # ── Abort button ─────────────────────────────────────────────────────
    @app.callback(
        Output("active-session", "data", allow_duplicate=True),
        Output("live-tick", "disabled", allow_duplicate=True),
        Output("live-main-area", "children", allow_duplicate=True),
        Input("abort-button", "n_clicks"),
        State("active-session", "data"),
        State("api-base", "data"),
        prevent_initial_call=True,
    )
    def abort_session(n_clicks, session_id, api_base):
        if not n_clicks or not session_id:
            return no_update, no_update, no_update
        # Tell backend to stop
        try:
            with httpx.Client(timeout=3.0) as client:
                client.post(f"{api_base}/attacks/abort", json={"session_id": session_id})
        except Exception:
            pass
        # Stop the subscriber
        buf = _get_buffer(session_id)
        buf.stop_event.set()
        # Reset to launcher form
        from dashboard.layouts.live_session import _launcher_form
        return None, True, _launcher_form()


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════
def _phase_to_index(phase_name: str) -> int:
    """Map phase name strings to kill chain indices."""
    mapping = {
        "reconnaissance": 0, "recon": 0,
        "delivery": 1, "initial_access": 1, "initial-access": 1,
        "exploitation": 2, "execution": 2,
        "installation": 3, "persistence": 3,
        "command_and_control": 4, "lateral_movement": 4, "lateral-movement": 4,
        "actions_on_objectives": 5, "exfiltration": 5,
        "impact": 6,
    }
    return mapping.get(phase_name.lower(), -1)


def _build_live_grid(session_id: str, scenario: str, difficulty: str):
    """Build the live grid that replaces the launcher form once a session starts."""
    from dashboard.layouts.live_session import _alerts_card, _log_stream_card, _score_panel

    return html.Div(
        [
            html.Div(
                [
                    html.Span(
                        f"▶ {scenario} / {difficulty} / {session_id[:8]}",
                        style={
                            "fontFamily": "var(--font-mono)",
                            "color": "var(--text-secondary)",
                            "fontSize": "13px",
                        },
                    ),
                    html.Button(
                        "■ Abort Session",
                        id="abort-button",
                        className="btn-astra btn-danger-astra",
                        n_clicks=0,
                    ),
                ],
                style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "center",
                    "marginBottom": "16px",
                },
            ),
            html.Div(
                [
                    _log_stream_card(),
                    _alerts_card(),
                ],
                className="live-grid",
            ),
            html.Div(style={"height": "20px"}),
            _score_panel(),
        ],
    )
