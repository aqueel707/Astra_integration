"""
tests/test_api/test_attacks_run.py
───────────────────────────────────
Regression guard for the /attacks/run launch path.

Why this file exists
────────────────────
`run_scenario_stream` shipped for a long time with `driver` never assigned:
the endpoint built an orchestrator, then `_drive()` awaited `driver.run(...)`.
The resulting NameError was swallowed by the task's own `except Exception`,
logged as "driver crashed", and the endpoint still returned 202 — so SOC mode
looked healthy from the outside while persisting nothing at all.

The suite had 367 passing tests and none of them touched the API layer, which
is exactly why that survived. The assertion that catches it is not "did we get
a 202" (we always did) but "did the run actually persist anything".

Isolation
─────────
The SessionDriver opens its OWN database sessions through db.engine.get_session,
so overriding the FastAPI dependency is not enough to redirect it. We swap
db.engine's module-level engine and session factory for an in-memory SQLite
pair instead, which redirects the endpoint and the background driver together.

We also build that engine directly rather than via db.engine.get_engine(),
because get_engine() hardcodes asyncpg-only connect_args (statement_cache_size)
that SQLite rejects with a TypeError.
"""

from __future__ import annotations

import os

# Must be set before the api package is imported: api.rate_limit builds its
# limiter at module import time and will reach for a real Redis otherwise, and
# firebase_auth decides its auth mode from the environment.
os.environ["REDIS_ENABLED"] = "false"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["FIREBASE_ENABLED"] = "false"

import asyncio
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import select
from sqlalchemy.pool import StaticPool

import db.engine as db_engine
from db.models import AttackEvent, Base, Session as SessionModel, User


SCENARIO = "ransomware"


@pytest_asyncio.fixture
async def sqlite_db(monkeypatch):
    """Point db.engine at an in-memory SQLite database for the whole process."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        # One shared connection, so the endpoint and the background driver see
        # the same in-memory database rather than two empty ones.
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    monkeypatch.setattr(db_engine, "_engine", engine)
    monkeypatch.setattr(db_engine, "_session_factory", factory)

    yield factory

    await engine.dispose()


@pytest_asyncio.fixture
async def seeded(sqlite_db):
    """A user and a session row owned by them."""
    user = User(id=str(uuid.uuid4()), username="tester", display_name="Tester")
    session = SessionModel(
        id=str(uuid.uuid4()),
        user_id=user.id,
        scenario_id=SCENARIO,
        role="blue_team",
        difficulty="beginner",
        status="created",
    )
    async with sqlite_db() as s:
        s.add_all([user, session])
        await s.commit()
    return user, session


@pytest_asyncio.fixture
async def client(seeded):
    """An ASGI client with auth overridden to the seeded user.

    Lifespan is deliberately not run: it would call init_db() against the real
    DATABASE_URL from .env.
    """
    from api.app import create_app
    from api.firebase_auth import get_current_user

    user, _ = seeded
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_run_persists_attack_events(seeded, sqlite_db, client):
    """The launch path must actually execute the scenario, not just return 202.

    This is the assertion that would have failed for the entire lifetime of the
    `driver` NameError.
    """
    from core.session_driver import get_task

    _, session = seeded

    resp = await client.post(
        f"/attacks/run/{SCENARIO}",
        params={"session_id": session.id, "step_delay_ms": 0, "difficulty": "beginner"},
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["session_id"] == session.id

    # The driver must be registered before the task is handed off, or
    # /attacks/abort can never find it.
    task = get_task(session.id)
    assert task is not None, "no background task registered for the session"

    await asyncio.wait_for(task, timeout=120)

    async with sqlite_db() as s:
        events = (
            await s.execute(select(AttackEvent).where(AttackEvent.session_id == session.id))
        ).scalars().all()
        row = (
            await s.execute(select(SessionModel).where(SessionModel.id == session.id))
        ).scalar_one()

    assert events, "run completed but persisted zero attack events"
    assert all(e.technique_id for e in events), "attack events missing technique ids"
    assert row.status == "completed", f"session left in status {row.status!r}"


@pytest.mark.asyncio
async def test_second_launch_is_rejected(seeded, client):
    """A session already running must not get a second driver.

    Two drivers on one session_id would both write attack events and race each
    other's score write.
    """
    from core.session_driver import drop_driver, get_task

    _, session = seeded

    first = await client.post(
        f"/attacks/run/{SCENARIO}",
        params={"session_id": session.id, "step_delay_ms": 0},
    )
    assert first.status_code == 202

    second = await client.post(
        f"/attacks/run/{SCENARIO}",
        params={"session_id": session.id, "step_delay_ms": 0},
    )
    assert second.status_code == 409, f"expected 409, got {second.status_code}"

    task = get_task(session.id)
    if task is not None:
        task.cancel()
        with pytest.raises((asyncio.CancelledError, Exception)):
            await task
    drop_driver(session.id)


@pytest.mark.asyncio
async def test_run_rejects_other_users_session(sqlite_db, client):
    """Ownership is enforced before anything is launched."""
    from core.session_driver import get_driver

    other = str(uuid.uuid4())
    resp = await client.post(
        f"/attacks/run/{SCENARIO}",
        params={"session_id": other, "step_delay_ms": 0},
    )
    assert resp.status_code == 404
    assert get_driver(other) is None, "a driver was registered for a foreign session"
