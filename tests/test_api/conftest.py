"""
tests/test_api/conftest.py
───────────────────────────
Shared fixtures for API-layer tests.

The suite had no API tier at all before this, which is why an entirely
unauthenticated router shipped alongside 367 passing tests. These fixtures
exist so that "is this endpoint actually authenticated, and scoped to the
caller" is a cheap thing to assert.

Isolation notes:
  • Environment is pinned before the api package is imported: api.rate_limit
    builds its limiter at import time and would otherwise reach for a real
    Redis, and firebase_auth reads its mode from the environment.
  • db.engine's module-level engine and session factory are swapped for an
    in-memory SQLite pair, which redirects both request handlers and the
    background SessionDriver (which opens its own sessions).
  • The engine is built directly rather than via db.engine.get_engine(),
    because that hardcodes asyncpg-only connect_args SQLite rejects.
"""

from __future__ import annotations

import os

os.environ.setdefault("REDIS_ENABLED", "false")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("FIREBASE_ENABLED", "false")

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import db.engine as db_engine
from db.models import Base, Session as SessionModel, User


@pytest_asyncio.fixture
async def sqlite_db(monkeypatch):
    """Redirect db.engine at an in-memory SQLite database."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,                      # one shared connection
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
async def two_users(sqlite_db):
    """Two users, each owning one session. The basis of every ownership test."""
    def _mk(name):
        user = User(id=str(uuid.uuid4()), username=name, display_name=name)
        session = SessionModel(
            id=str(uuid.uuid4()),
            user_id=user.id,
            scenario_id="ransomware",
            role="blue_team",
            difficulty="beginner",
            status="running",
        )
        return user, session

    alice, alice_session = _mk("alice")
    bob, bob_session = _mk("bob")

    async with sqlite_db() as s:
        s.add_all([alice, alice_session, bob, bob_session])
        await s.commit()

    return {
        "alice": (alice, alice_session),
        "bob": (bob, bob_session),
    }


@pytest.fixture
def make_client(two_users):
    """Build an ASGI client acting as a given user, or as nobody.

    Passing user=None leaves get_current_user in place, so the real dependency
    runs and an unauthenticated request is rejected the way production would
    reject it.
    """
    from api.app import create_app
    from api.firebase_auth import get_current_user

    clients = []

    def _make(user=None):
        app = create_app()
        if user is not None:
            app.dependency_overrides[get_current_user] = lambda: user
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        clients.append(client)
        return client

    yield _make

    for c in clients:
        # AsyncClient cleanup is best-effort here; the transport holds no sockets.
        pass
