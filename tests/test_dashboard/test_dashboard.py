"""
Tests for dashboard renderers (Block 7).

Pure render-function tests — exercise the layouts and renderers without
spinning up a Dash server.
"""

from __future__ import annotations

import pytest

from dashboard.components.renderers import (
    render_alert_card,
    render_history_row,
    render_kill_chain,
    render_leaderboard_row,
    render_log_row,
    render_mitre_matrix,
    render_score_breakdown,
)
from dashboard.layouts.history import layout as history_layout
from dashboard.layouts.leaderboard import layout as leaderboard_layout
from dashboard.layouts.live_session import layout as live_layout
from dashboard.layouts.main import navbar
from dashboard.layouts.mitre_matrix import layout as mitre_layout


# ════════════════════════════════════════════════════════════════════════════
# LAYOUT SMOKE TESTS — every page should at least render to a Div
# ════════════════════════════════════════════════════════════════════════════
class TestLayouts:
    def test_navbar_renders(self):
        nav = navbar()
        assert nav is not None
        assert "astra-nav" in (nav.className or "")

    def test_live_layout_renders(self):
        lo = live_layout()
        assert lo is not None

    def test_history_layout_renders(self):
        lo = history_layout()
        assert lo is not None

    def test_leaderboard_layout_renders(self):
        lo = leaderboard_layout()
        assert lo is not None

    def test_mitre_layout_renders(self):
        lo = mitre_layout()
        assert lo is not None


# ════════════════════════════════════════════════════════════════════════════
# LOG ROW
# ════════════════════════════════════════════════════════════════════════════
class TestRenderLogRow:
    def test_basic_log(self):
        log = {
            "timestamp": "2025-04-29T10:30:00Z",
            "source": "windows_event",
            "severity": "info",
            "message": "User logged in",
            "hostname": "WS-01",
            "is_malicious": False,
        }
        row = render_log_row(log)
        assert "log-row" in row.className
        assert "malicious" not in row.className

    def test_malicious_log_gets_marker(self):
        log = {
            "timestamp": "2025-04-29T10:30:00Z",
            "source": "windows_event",
            "severity": "high",
            "message": "Suspicious command",
            "hostname": "WS-01",
            "is_malicious": True,
        }
        row = render_log_row(log)
        assert "malicious" in row.className

    def test_missing_fields_default_gracefully(self):
        log = {"timestamp": "2025-04-29T10:30:00Z"}
        row = render_log_row(log)
        assert row is not None  # should not crash


# ════════════════════════════════════════════════════════════════════════════
# ALERT CARD
# ════════════════════════════════════════════════════════════════════════════
class TestRenderAlertCard:
    def test_critical_alert(self):
        alert = {
            "timestamp": "2025-04-29T10:30:05Z",
            "severity": "critical",
            "title": "Ransomware Detected",
            "technique_id": "T1486",
            "hostname": "FILE-SRV",
            "rule_name": "ransomware_pattern",
        }
        card = render_alert_card(alert)
        assert "severity-critical" in card.className

    def test_alert_with_no_mitre_id(self):
        alert = {
            "timestamp": "2025-04-29T10:30:05Z",
            "severity": "low",
            "title": "Unusual login",
            "hostname": "WS-01",
        }
        card = render_alert_card(alert)
        assert card is not None  # works even without technique_id


# ════════════════════════════════════════════════════════════════════════════
# KILL CHAIN
# ════════════════════════════════════════════════════════════════════════════
class TestRenderKillChain:
    def test_seven_phases(self):
        cells = render_kill_chain(0, [])
        assert len(cells) == 7

    def test_active_phase_marked(self):
        cells = render_kill_chain(2, [0, 1])
        # phase 2 should be active
        assert "active" in cells[2].className
        # phases 0,1 should be completed
        assert "completed" in cells[0].className
        assert "completed" in cells[1].className
        # phase 5 should be neither
        assert "active" not in cells[5].className
        assert "completed" not in cells[5].className

    def test_no_active_phase(self):
        cells = render_kill_chain(-1, [])
        for c in cells:
            assert "active" not in c.className
            assert "completed" not in c.className


# ════════════════════════════════════════════════════════════════════════════
# SCORE BREAKDOWN
# ════════════════════════════════════════════════════════════════════════════
class TestRenderScoreBreakdown:
    def test_with_full_score(self):
        score = {
            "mitre_coverage_pct": 33.3,
            "details": {"sub_scores": {
                "detection_score": 100,
                "mttd_score": 80,
                "fp_score": 100,
                "containment_score": 50,
                "report_score": 75,
            }},
        }
        items = render_score_breakdown(score)
        assert len(items) == 6  # 5 sub-scores + coverage

    def test_with_empty_score(self):
        items = render_score_breakdown({})
        assert items == []


# ════════════════════════════════════════════════════════════════════════════
# MITRE MATRIX
# ════════════════════════════════════════════════════════════════════════════
class TestRenderMitreMatrix:
    def test_empty_coverage_shows_empty_state(self):
        matrix = render_mitre_matrix(
            {"techniques_used": [], "techniques_detected": [], "techniques_missed": []},
            [("execution", "Execution")],
        )
        # The empty state has class "empty-state"
        assert "empty-state" in (matrix.className or "")

    def test_with_techniques_renders_grid(self):
        cov = {
            "techniques_used": ["T1059.001", "T1486"],
            "techniques_detected": ["T1059.001"],
            "techniques_missed": ["T1486"],
            "by_tactic": {"execution": {"used": 2, "detected": 1}},
        }
        matrix = render_mitre_matrix(cov, [("execution", "Execution")])
        assert "matrix-grid" in matrix.className


# ════════════════════════════════════════════════════════════════════════════
# HISTORY / LEADERBOARD ROWS
# ════════════════════════════════════════════════════════════════════════════
class TestHistoryAndLeaderboard:
    def test_history_row(self):
        session = {
            "session_id": "abc12345",
            "scenario_id": "ransomware",
            "total_score": 75.5,
            "grade": "good",
            "mitre_coverage_pct": 50.0,
            "duration_sec": 600,
            "created_at": "2025-04-29T10:00:00Z",
        }
        row = render_history_row(session)
        assert "log-row" in row.className

    def test_leaderboard_row(self):
        entry = {
            "rank": 1,
            "username": "alice",
            "scenario_id": "ransomware",
            "total_score": 92.0,
            "grade": "excellent",
            "mitre_coverage_pct": 80.0,
        }
        row = render_leaderboard_row(entry)
        assert "log-row" in row.className


# ════════════════════════════════════════════════════════════════════════════
# MODE PICKER (Block 7.1)
# ════════════════════════════════════════════════════════════════════════════
class TestModePicker:
    def test_picker_layout_renders(self):
        from dashboard.layouts.mode_picker import layout
        lo = layout()
        assert lo is not None
        assert "mode-picker-page" in (lo.className or "")

    def test_three_modes_defined(self):
        from dashboard.layouts.mode_picker import MODES
        assert len(MODES) == 3
        ids = {m["id"] for m in MODES}
        assert ids == {"soc", "pentester", "purple"}

    def test_each_mode_has_required_fields(self):
        from dashboard.layouts.mode_picker import MODES
        for m in MODES:
            assert "id" in m
            assert "label" in m
            assert "icon" in m
            assert "description" in m
            assert "skills" in m
            assert "metrics" in m


class TestScenarioModeFiltering:
    def test_soc_has_scenarios(self):
        from dashboard.layouts.live_session import get_scenarios_for_mode
        sc = get_scenarios_for_mode("soc")
        assert len(sc) > 0
        for s in sc:
            assert "soc" in s["modes"]

    def test_pentester_has_scenarios(self):
        from dashboard.layouts.live_session import get_scenarios_for_mode
        sc = get_scenarios_for_mode("pentester")
        assert len(sc) > 0
        for s in sc:
            assert "pentester" in s["modes"]

    def test_purple_has_all_scenarios(self):
        from dashboard.layouts.live_session import get_scenarios_for_mode, ALL_SCENARIOS
        sc = get_scenarios_for_mode("purple")
        # Purple should see scenarios that include purple in modes
        assert len(sc) >= 3
        for s in sc:
            assert "purple" in s["modes"]


class TestModeAwareLayouts:
    def test_soc_launcher_renders(self):
        from dashboard.layouts.live_session import layout
        lo = layout("soc")
        assert lo is not None

    def test_pentester_launcher_renders(self):
        from dashboard.layouts.live_session import layout
        lo = layout("pentester")
        assert lo is not None

    def test_purple_launcher_renders(self):
        from dashboard.layouts.live_session import layout
        lo = layout("purple")
        assert lo is not None

    def test_invalid_mode_falls_back_to_soc(self):
        from dashboard.layouts.live_session import layout
        lo = layout("nonexistent_mode")
        assert lo is not None  # should not crash


# ════════════════════════════════════════════════════════════════════════════
# CHARTS (Block 7.2)
# ════════════════════════════════════════════════════════════════════════════
class TestCharts:
    def test_score_trend_with_data(self):
        from dashboard.components.charts import score_trend_chart
        fig = score_trend_chart([
            {"date": "2026-04-29", "score": 65, "mode": "soc"},
            {"date": "2026-04-30", "score": 72, "mode": "soc"},
        ])
        assert len(fig.data) == 1  # one mode = one trace
        assert fig.data[0].name == "SOC"

    def test_score_trend_multiple_modes(self):
        from dashboard.components.charts import score_trend_chart
        fig = score_trend_chart([
            {"date": "2026-04-29", "score": 65, "mode": "soc"},
            {"date": "2026-04-30", "score": 72, "mode": "pentester"},
        ])
        assert len(fig.data) == 2

    def test_score_trend_empty_returns_placeholder(self):
        from dashboard.components.charts import score_trend_chart
        fig = score_trend_chart([])
        # empty_chart returns a fig with annotations and no data traces
        assert len(fig.data) == 0

    def test_skills_radar_renders(self):
        from dashboard.components.charts import skills_radar_chart
        fig = skills_radar_chart({
            "detection": 80, "mttd": 70, "fp_rate": 90,
            "containment": 65, "report": 75, "coverage": 60,
        })
        assert len(fig.data) == 1
        # Radar has 7 points (6 metrics + closing point)
        assert len(fig.data[0].r) == 7

    def test_skills_radar_empty(self):
        from dashboard.components.charts import skills_radar_chart
        fig = skills_radar_chart({"detection": 0, "mttd": 0, "fp_rate": 0, "containment": 0, "report": 0, "coverage": 0})
        assert len(fig.data) == 0  # empty placeholder

    def test_tactic_heatmap_renders(self):
        from dashboard.components.charts import tactic_heatmap_chart
        fig = tactic_heatmap_chart({
            "reconnaissance": {"detection_rate": 0.4, "sessions_seen": 10},
            "execution":      {"detection_rate": 0.8, "sessions_seen": 12},
        })
        assert len(fig.data) == 1
        # Heatmap z is 1xN
        assert len(fig.data[0].z[0]) == 2

    def test_activity_calendar_renders(self):
        from dashboard.components.charts import activity_calendar_chart
        fig = activity_calendar_chart([
            {"date": "2026-04-29", "mode": "soc", "count": 2},
            {"date": "2026-04-30", "mode": "pentester", "count": 1},
        ])
        assert len(fig.data) == 2  # one bar series per mode

    def test_coverage_donut_low(self):
        from dashboard.components.charts import coverage_donut
        fig = coverage_donut(15.0, detected=2, total=12)
        assert len(fig.data) == 1
        # The annotation should contain the percentage
        assert "15" in fig.layout.annotations[0].text

    def test_coverage_donut_high(self):
        from dashboard.components.charts import coverage_donut
        fig = coverage_donut(85.0, detected=10, total=12)
        # High coverage uses good color (green)
        # Just check it doesn't crash
        assert fig is not None

    def test_score_sparkline(self):
        from dashboard.components.charts import score_sparkline
        fig = score_sparkline([60, 65, 72, 78, 80], current=82)
        # Two traces: line + current marker
        assert len(fig.data) == 2

    def test_score_sparkline_no_current(self):
        from dashboard.components.charts import score_sparkline
        fig = score_sparkline([60, 65, 72])
        # Just the line, no marker
        assert len(fig.data) == 1

    def test_empty_chart(self):
        from dashboard.components.charts import empty_chart
        fig = empty_chart("Custom message")
        assert len(fig.data) == 0
        assert fig.layout.annotations[0].text == "Custom message"


class TestProgressLayout:
    def test_progress_layout_renders(self):
        from dashboard.layouts.progress import layout
        lo = layout()
        assert lo is not None
