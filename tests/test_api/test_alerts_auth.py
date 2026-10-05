"""
tests/test_api/test_alerts_auth.py
───────────────────────────────────
Guards for the alerts router, which shipped with no authentication at all:
anyone could list alerts across every user, read any alert, and rewrite any
user's triage decisions — and triage feeds is_true_positive, which drives
detection rate, MITRE coverage and leaderboard position.

Two kinds of assertion here, because they fail for different reasons:

  1. Structural — every route in a session-scoped router declares
     get_current_user somewhere in its dependency graph. This is the one that
     would have caught the original bug on the commit that introduced it, and
     it keeps working in local-dev mode where the auth dependency resolves to
     the demo user instead of raising 401.

  2. Behavioural — one user cannot reach another user's alerts, and gets 404
     rather than 403 so the id's existence is never confirmed.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import select

from db.models import Alert


def _dependency_calls(route):
    """Flatten a route's dependency graph into the set of callables it uses."""
    seen = set()

    def walk(dep):
        for sub in dep.dependencies:
            if sub.call is not None:
                seen.add(sub.call)
            walk(sub)

    walk(route.dependant)
    return seen


# Routes that are deliberately public. Anything NOT listed here must resolve a
# user, so a newly added router cannot quietly ship unauthenticated — which is
# exactly how the alerts router shipped.
#
#   /health, /ready              liveness and readiness probes
#   /scenarios*                  static scenario catalog, no user data
#   /mitre/technique, /matrix    public ATT&CK reference data
#   /reports/templates/{mode}    static report structure
#   /logs/stream/{session_id}    WebSocket: authenticates from the ?token query
#                                param inside the handler, because a browser
#                                cannot set headers on a WS handshake
INTENTIONALLY_PUBLIC = {
    "/health",
    "/ready",
    "/scenarios",
    "/scenarios/{scenario_id}",
    "/mitre/technique/{technique_id}",
    "/mitre/matrix",
    "/reports/templates/{mode}",
    "/logs/stream/{session_id}",
}


def test_no_route_is_unintentionally_public():
    """Enumerate the WHOLE app, not a hand-maintained list of routers.

    The earlier version named six modules explicitly, so a seventh router could
    be added with no auth and this test would still pass.
    """
    from api.app import create_app
    from api.firebase_auth import get_current_user, get_optional_user

    app = create_app()
    unprotected = []

    for route in app.routes:
        if not hasattr(route, "dependant"):
            continue
        path = getattr(route, "path", "")
        if path in INTENTIONALLY_PUBLIC or path.startswith(("/docs", "/redoc", "/openapi")):
            continue
        if not ({get_current_user, get_optional_user} & _dependency_calls(route)):
            methods = ",".join(sorted(getattr(route, "methods", []) or ["WS"]))
            unprotected.append(f"{methods} {path}")

    assert not unprotected, (
        "routes reachable with no auth dependency (add to INTENTIONALLY_PUBLIC "
        f"only if that is deliberate): {unprotected}"
    )


def test_the_public_allowlist_is_not_stale():
    """Every allowlisted path must still exist, so the list cannot rot."""
    from api.app import create_app

    paths = {getattr(r, "path", "") for r in create_app().routes}
    missing = sorted(INTENTIONALLY_PUBLIC - paths)
    assert not missing, f"allowlisted paths no longer exist: {missing}"


@pytest_asyncio.fixture
async def alice_alert(sqlite_db, two_users):
    """An alert belonging to alice's session."""
    _, alice_session = two_users["alice"]
    alert = Alert(
        id=str(uuid.uuid4()),
        session_id=alice_session.id,
        detection_type="sigma",
        title="Brute Force Success",
        description="multiple failed logons then a success",
        severity="critical",
        technique_id="T1110",
    )
    async with sqlite_db() as s:
        s.add(alert)
        await s.commit()
    return alert


@pytest.mark.asyncio
async def test_owner_can_read_their_alert(make_client, two_users, alice_alert):
    alice, _ = two_users["alice"]
    resp = await make_client(alice).get(f"/alerts/{alice_alert.id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == alice_alert.id


@pytest.mark.asyncio
async def test_other_user_cannot_read_alert(make_client, two_users, alice_alert):
    """404, not 403 — a non-owner must not learn the id exists."""
    bob, _ = two_users["bob"]
    resp = await make_client(bob).get(f"/alerts/{alice_alert.id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_other_user_cannot_triage_alert(make_client, sqlite_db, two_users, alice_alert):
    """The tampering path: triage drives scoring, so it must be owner-only."""
    bob, _ = two_users["bob"]
    resp = await make_client(bob).patch(
        f"/alerts/{alice_alert.id}/triage",
        json={"triage_status": "false_positive", "is_true_positive": False},
    )
    assert resp.status_code == 404

    async with sqlite_db() as s:
        row = (
            await s.execute(select(Alert).where(Alert.id == alice_alert.id))
        ).scalar_one()
    assert row.triage_status == "new", "a non-owner mutated the alert"
    assert row.is_true_positive is None


@pytest.mark.asyncio
async def test_listing_is_scoped_to_caller(make_client, two_users, alice_alert):
    """The unfiltered list previously spanned every user's sessions."""
    bob, _ = two_users["bob"]
    resp = await make_client(bob).get("/alerts")
    assert resp.status_code == 200
    ids = [a["id"] for a in resp.json()]
    assert alice_alert.id not in ids, "alice's alert leaked into bob's listing"

    alice, _ = two_users["alice"]
    resp = await make_client(alice).get("/alerts")
    assert alice_alert.id in [a["id"] for a in resp.json()]


@pytest.mark.asyncio
async def test_stats_requires_ownership(make_client, two_users):
    bob, _ = two_users["bob"]
    _, alice_session = two_users["alice"]
    resp = await make_client(bob).get(f"/alerts/stats/{alice_session.id}")
    assert resp.status_code == 404
