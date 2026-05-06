"""
run_dashboard.py
─────────────────
Run the ASTRA dashboard standalone.

Usage:
    python run_dashboard.py

Environment variables:
    ASTRA_API_BASE       (default: http://localhost:8000)
    ASTRA_WS_BASE        (default: ws://localhost:8000)
    ASTRA_DASHBOARD_PORT (default: 8050)
    ASTRA_DASHBOARD_DEBUG (default: false)

Requires the API server to be running on :8000 (python run.py --seed).
"""

from dashboard.app import main


if __name__ == "__main__":
    main()
