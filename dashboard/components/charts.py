"""
dashboard/components/charts.py
───────────────────────────────
Plotly chart builders. All charts share the dark SOC console palette
defined in our CSS so visualizations feel native.

Public API:
    score_trend_chart(rows)
    skills_radar_chart(avg_subscores)
    tactic_heatmap_chart(per_tactic_stats)
    activity_calendar_chart(rows_by_day)
    coverage_donut(coverage_pct)
    score_sparkline(history)
    empty_chart(message)
"""

from __future__ import annotations

from typing import Any

import plotly.graph_objects as go


# ─── Theme constants (must mirror astra.css palette) ────────────────────────
COLORS = {
    "bg": "#080809",
    "card": "#131318",
    "elevated": "#101013",
    "border": "#25252e",
    "border_subtle": "#1a1a22",
    "text_primary": "#e6e6ea",
    "text_secondary": "#95959e",
    "text_tertiary": "#5d5d68",
    "accent": "#d4ff5e",
    "accent_dim": "#9bbf3d",
    "good": "#a3e87a",
    "warn": "#d9a13a",
    "bad": "#e85a5a",
    "soc": "#d4ff5e",
    "pentester": "#ff7a7a",
    "purple": "#c490ff",
}

FONT_MONO = "IBM Plex Mono, Menlo, Consolas, monospace"
FONT_UI = "IBM Plex Sans, -apple-system, sans-serif"


def _base_layout(**overrides) -> dict:
    """Base Plotly layout for all charts — paperless transparent dark."""
    layout = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT_UI, size=12, color=COLORS["text_secondary"]),
        margin=dict(l=40, r=20, t=30, b=40),
        hoverlabel=dict(
            bgcolor=COLORS["elevated"],
            bordercolor=COLORS["border"],
            font_family=FONT_MONO,
            font_size=12,
            font_color=COLORS["text_primary"],
        ),
        xaxis=dict(
            showgrid=True,
            gridcolor=COLORS["border_subtle"],
            zerolinecolor=COLORS["border"],
            tickfont=dict(family=FONT_MONO, size=10, color=COLORS["text_tertiary"]),
            linecolor=COLORS["border"],
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor=COLORS["border_subtle"],
            zerolinecolor=COLORS["border"],
            tickfont=dict(family=FONT_MONO, size=10, color=COLORS["text_tertiary"]),
            linecolor=COLORS["border"],
        ),
        showlegend=True,
        legend=dict(
            font=dict(family=FONT_UI, size=11, color=COLORS["text_secondary"]),
            bgcolor="rgba(0,0,0,0)",
            bordercolor="rgba(0,0,0,0)",
        ),
    )
    layout.update(overrides)
    return layout


# ════════════════════════════════════════════════════════════════════════════
# 1. SCORE TREND — line chart over time, colored by mode
# ════════════════════════════════════════════════════════════════════════════
def score_trend_chart(rows: list[dict]) -> go.Figure:
    """
    rows: [{date: ISO, score: 0-100, mode: 'soc'|'pentester'|'purple', scenario: str}, ...]
    Sorted oldest → newest.
    """
    if not rows:
        return empty_chart("No completed sessions yet")

    # Group by mode for line series
    by_mode: dict[str, list[tuple[str, float]]] = {}
    for r in rows:
        mode = r.get("mode", "soc")
        by_mode.setdefault(mode, []).append((r.get("date", ""), r.get("score", 0)))

    fig = go.Figure()

    for mode, pts in by_mode.items():
        if not pts:
            continue
        x_vals = [p[0] for p in pts]
        y_vals = [p[1] for p in pts]
        fig.add_trace(go.Scatter(
            x=x_vals,
            y=y_vals,
            mode="lines+markers",
            name=mode.upper(),
            line=dict(color=COLORS.get(mode, COLORS["accent"]), width=2),
            marker=dict(size=8, line=dict(width=1, color=COLORS["bg"])),
            hovertemplate="<b>%{y:.1f}</b> on %{x}<extra>%{fullData.name}</extra>",
        ))

    fig.update_layout(**_base_layout(
        height=320,
        title=dict(
            text="Score over time",
            font=dict(family=FONT_UI, size=13, color=COLORS["text_primary"]),
            x=0, xanchor="left", y=0.95,
        ),
        yaxis=dict(
            title="Score",
            range=[0, 105],
            showgrid=True,
            gridcolor=COLORS["border_subtle"],
            tickfont=dict(family=FONT_MONO, size=10, color=COLORS["text_tertiary"]),
            linecolor=COLORS["border"],
        ),
        xaxis=dict(
            showgrid=False,
            tickfont=dict(family=FONT_MONO, size=10, color=COLORS["text_tertiary"]),
            linecolor=COLORS["border"],
        ),
        hovermode="x unified",
    ))
    return fig


# ════════════════════════════════════════════════════════════════════════════
# 2. SKILLS RADAR — avg sub-scores across all sessions
# ════════════════════════════════════════════════════════════════════════════
def skills_radar_chart(avg_subscores: dict[str, float]) -> go.Figure:
    """
    avg_subscores: {detection: 75, mttd: 82, fp_rate: 95, containment: 60, report: 70, coverage: 45}
    """
    expected_keys = ["detection", "mttd", "fp_rate", "containment", "report", "coverage"]
    labels = ["Detection", "MTTD", "False Positives", "Containment", "Report Quality", "Coverage"]
    values = [avg_subscores.get(k, 0) for k in expected_keys]

    if max(values) == 0:
        return empty_chart("No score data yet")

    # Close the loop by repeating the first point
    values_closed = values + [values[0]]
    labels_closed = labels + [labels[0]]

    fig = go.Figure()

    fig.add_trace(go.Scatterpolar(
        r=values_closed,
        theta=labels_closed,
        fill="toself",
        fillcolor="rgba(212, 255, 94, 0.15)",
        line=dict(color=COLORS["accent"], width=2),
        marker=dict(size=8, color=COLORS["accent"]),
        hovertemplate="<b>%{theta}</b>: %{r:.0f}<extra></extra>",
        name="Average",
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT_UI, size=12, color=COLORS["text_secondary"]),
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(
                visible=True,
                range=[0, 100],
                gridcolor=COLORS["border_subtle"],
                linecolor=COLORS["border"],
                tickfont=dict(family=FONT_MONO, size=9, color=COLORS["text_tertiary"]),
                tickmode="linear",
                tick0=0,
                dtick=25,
            ),
            angularaxis=dict(
                gridcolor=COLORS["border_subtle"],
                linecolor=COLORS["border"],
                tickfont=dict(family=FONT_UI, size=11, color=COLORS["text_secondary"]),
            ),
        ),
        showlegend=False,
        margin=dict(l=60, r=60, t=30, b=30),
        height=360,
        title=dict(
            text="Skills profile",
            font=dict(family=FONT_UI, size=13, color=COLORS["text_primary"]),
            x=0, xanchor="left", y=0.97,
        ),
    )
    return fig


# ════════════════════════════════════════════════════════════════════════════
# 3. TACTIC HEATMAP — MITRE tactic mastery
# ════════════════════════════════════════════════════════════════════════════
def tactic_heatmap_chart(per_tactic: dict[str, dict[str, float]]) -> go.Figure:
    """
    per_tactic: {
        "reconnaissance": {"detection_rate": 0.4, "sessions_seen": 12},
        "initial-access":  {"detection_rate": 0.7, "sessions_seen": 18},
        ...
    }

    Renders a 1-column heatmap (one row per tactic) showing detection rate.
    """
    if not per_tactic:
        return empty_chart("No tactic data yet")

    tactics = list(per_tactic.keys())
    rates = [per_tactic[t].get("detection_rate", 0) * 100 for t in tactics]
    counts = [per_tactic[t].get("sessions_seen", 0) for t in tactics]

    # Pretty labels
    pretty_labels = [t.replace("-", " ").replace("_", " ").title() for t in tactics]

    fig = go.Figure(go.Heatmap(
        z=[rates],
        x=pretty_labels,
        y=["Detection rate"],
        colorscale=[
            [0.0, COLORS["bad"]],
            [0.5, COLORS["warn"]],
            [1.0, COLORS["good"]],
        ],
        zmin=0,
        zmax=100,
        showscale=True,
        colorbar=dict(
            title=dict(text="%", font=dict(family=FONT_MONO, color=COLORS["text_secondary"])),
            tickfont=dict(family=FONT_MONO, color=COLORS["text_tertiary"], size=10),
            outlinecolor=COLORS["border"],
            outlinewidth=1,
            len=0.7,
        ),
        text=[[f"{r:.0f}% ({c})" for r, c in zip(rates, counts)]],
        texttemplate="%{text}",
        textfont=dict(family=FONT_MONO, color=COLORS["bg"], size=10),
        hovertemplate="<b>%{x}</b><br>Detection rate: %{z:.1f}%<extra></extra>",
    ))

    fig.update_layout(**_base_layout(
        height=200,
        title=dict(
            text="Tactic mastery (detection rate per ATT&CK tactic)",
            font=dict(family=FONT_UI, size=13, color=COLORS["text_primary"]),
            x=0, xanchor="left", y=0.95,
        ),
        xaxis=dict(
            tickangle=-30,
            tickfont=dict(family=FONT_UI, size=10, color=COLORS["text_secondary"]),
            showgrid=False,
        ),
        yaxis=dict(
            tickfont=dict(family=FONT_UI, size=11, color=COLORS["text_primary"]),
            showgrid=False,
        ),
    ))
    return fig


# ════════════════════════════════════════════════════════════════════════════
# 4. ACTIVITY CALENDAR — sessions per day, last 30 days, colored by mode
# ════════════════════════════════════════════════════════════════════════════
def activity_calendar_chart(rows_by_day: list[dict]) -> go.Figure:
    """
    rows_by_day: [{date: ISO, mode: str, count: int}, ...] for last 30 days.
    """
    if not rows_by_day:
        return empty_chart("No activity yet")

    # Group by mode
    by_mode: dict[str, dict[str, int]] = {}
    all_dates = set()
    for r in rows_by_day:
        date = r.get("date", "")
        mode = r.get("mode", "soc")
        count = r.get("count", 0)
        by_mode.setdefault(mode, {})[date] = count
        all_dates.add(date)

    sorted_dates = sorted(all_dates)

    fig = go.Figure()
    for mode in ["soc", "pentester", "purple"]:
        if mode not in by_mode:
            continue
        counts = [by_mode[mode].get(d, 0) for d in sorted_dates]
        fig.add_trace(go.Bar(
            x=sorted_dates,
            y=counts,
            name=mode.upper(),
            marker=dict(color=COLORS.get(mode, COLORS["accent"])),
            hovertemplate="<b>%{x}</b>: %{y} session(s)<extra>%{fullData.name}</extra>",
        ))

    fig.update_layout(**_base_layout(
        height=240,
        barmode="stack",
        title=dict(
            text="Training activity (last 30 days)",
            font=dict(family=FONT_UI, size=13, color=COLORS["text_primary"]),
            x=0, xanchor="left", y=0.95,
        ),
        xaxis=dict(
            type="category",
            tickfont=dict(family=FONT_MONO, size=9, color=COLORS["text_tertiary"]),
            showgrid=False,
            linecolor=COLORS["border"],
        ),
        yaxis=dict(
            title="Sessions",
            tickfont=dict(family=FONT_MONO, size=10, color=COLORS["text_tertiary"]),
            gridcolor=COLORS["border_subtle"],
        ),
    ))
    return fig


# ════════════════════════════════════════════════════════════════════════════
# 5. COVERAGE DONUT — for the live session view
# ════════════════════════════════════════════════════════════════════════════
def coverage_donut(coverage_pct: float, detected: int = 0, total: int = 0) -> go.Figure:
    """A single-value donut chart for MITRE coverage on the live page."""
    pct = max(0.0, min(100.0, float(coverage_pct or 0)))
    remaining = 100.0 - pct

    # Pick color based on coverage
    if pct >= 70:
        color = COLORS["good"]
    elif pct >= 40:
        color = COLORS["warn"]
    else:
        color = COLORS["bad"]

    fig = go.Figure(go.Pie(
        values=[pct, remaining],
        labels=["Detected", "Missed"],
        hole=0.7,
        marker=dict(colors=[color, COLORS["border"]], line=dict(color=COLORS["bg"], width=2)),
        textinfo="none",
        hovertemplate="<b>%{label}</b>: %{value:.1f}%<extra></extra>",
        sort=False,
        direction="clockwise",
        rotation=-90,  # Start from top
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        margin=dict(l=0, r=0, t=0, b=0),
        height=140,
        annotations=[
            dict(
                text=f"<b>{pct:.0f}%</b>",
                x=0.5, y=0.55, xref="paper", yref="paper",
                showarrow=False,
                font=dict(family=FONT_MONO, size=24, color=COLORS["text_primary"]),
            ),
            dict(
                text=f"{detected}/{total}" if total else "coverage",
                x=0.5, y=0.38, xref="paper", yref="paper",
                showarrow=False,
                font=dict(family=FONT_MONO, size=10, color=COLORS["text_tertiary"]),
            ),
        ],
    )
    return fig


# ════════════════════════════════════════════════════════════════════════════
# 6. SCORE SPARKLINE — mini line chart showing this session vs recent
# ════════════════════════════════════════════════════════════════════════════
def score_sparkline(history: list[float], current: float | None = None) -> go.Figure:
    """
    history: list of recent session scores (last 5–10), oldest first.
    current: optionally highlight the current session score as a marker.
    """
    if not history:
        return empty_chart("No history", height=60)

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        y=history,
        mode="lines",
        line=dict(color=COLORS["accent"], width=2, shape="spline"),
        fill="tozeroy",
        fillcolor="rgba(212, 255, 94, 0.10)",
        showlegend=False,
        hovertemplate="Score: %{y:.0f}<extra></extra>",
    ))

    if current is not None:
        fig.add_trace(go.Scatter(
            x=[len(history)],
            y=[current],
            mode="markers",
            marker=dict(size=10, color=COLORS["accent"], line=dict(color=COLORS["bg"], width=2)),
            showlegend=False,
            hovertemplate="<b>Now</b>: %{y:.0f}<extra></extra>",
        ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=10, b=10),
        height=60,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False, range=[0, 105]),
    )
    return fig


# ════════════════════════════════════════════════════════════════════════════
# Empty state
# ════════════════════════════════════════════════════════════════════════════
def empty_chart(message: str = "No data", height: int = 280) -> go.Figure:
    """Empty placeholder figure with a centered message."""
    fig = go.Figure()
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        height=height,
        margin=dict(l=0, r=0, t=0, b=0),
        annotations=[dict(
            text=message,
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(family=FONT_MONO, size=12, color=COLORS["text_tertiary"]),
        )],
    )
    return fig
