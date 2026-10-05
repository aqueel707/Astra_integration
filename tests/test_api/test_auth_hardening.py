"""
tests/test_api/test_auth_hardening.py
──────────────────────────────────────
Guards for two auth defects:

  S2  The rate limiter derived its bucket key from an UNVERIFIED JWT, so a
      caller could mint a fresh bucket per request and never be throttled.

  S4  email_verified was never checked, so a password account could be created
      for someone else's address — which also permanently squatted the UNIQUE
      email column against the real owner, whose first sign-in then raised
      IntegrityError as an unexplained 500.
"""

from __future__ import annotations

import base64
import json
import uuid

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select

from db.models import User


# ══════════════════════════════════════════════════════════════════════════
# S2 — limiter bucket key
# ══════════════════════════════════════════════════════════════════════════

def _unsigned_jwt(sub: str) -> str:
    """A syntactically valid, completely unsigned JWT — what an attacker sends."""
    payload = base64.urlsafe_b64encode(json.dumps({"sub": sub}).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


class _FakeRequest:
    def __init__(self, ip: str, token: str | None = None):
        self.headers = {"authorization": f"Bearer {token}"} if token else {}
        self.client = type("C", (), {"host": ip})()
        self.scope = {"client": (ip, 1234)}


@pytest.mark.parametrize("sub", ["forged-a", "forged-b", "forged-c"])
def test_forged_tokens_cannot_choose_their_bucket(sub):
    """Every request from one IP shares a bucket regardless of the token."""
    from api.rate_limit import _client_key

    anonymous = _client_key(_FakeRequest("203.0.113.9"))
    forged = _client_key(_FakeRequest("203.0.113.9", _unsigned_jwt(sub)))

    assert forged == anonymous, "a token changed the bucket key"
    assert forged == "ip:203.0.113.9"


def test_distinct_ips_still_get_distinct_buckets():
    from api.rate_limit import _client_key

    assert _client_key(_FakeRequest("198.51.100.1")) != _client_key(_FakeRequest("198.51.100.2"))


# ══════════════════════════════════════════════════════════════════════════
# S4 — email verification
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "claims,allowed",
    [
        ({"firebase": {"sign_in_provider": "password"}, "email_verified": True}, True),
        ({"firebase": {"sign_in_provider": "password"}, "email_verified": False}, False),
        ({"firebase": {"sign_in_provider": "password"}}, False),
        # Federated providers prove the address themselves and often omit the claim.
        ({"firebase": {"sign_in_provider": "google.com"}}, True),
        ({"firebase": {"sign_in_provider": "apple.com"}, "email_verified": False}, True),
    ],
)
def test_email_verification_gate(claims, allowed):
    from api.firebase_auth import _assert_email_verified

    if allowed:
        _assert_email_verified(claims)          # must not raise
    else:
        with pytest.raises(HTTPException) as exc:
            _assert_email_verified(claims)
        assert exc.value.status_code == 403


def test_verification_gate_can_be_disabled(monkeypatch):
    """The escape hatch exists for an unverified legacy population."""
    import api.firebase_auth as fa

    monkeypatch.setattr(fa, "_REQUIRE_VERIFIED_EMAIL", False)
    fa._assert_email_verified({"firebase": {"sign_in_provider": "password"}})


# ══════════════════════════════════════════════════════════════════════════
# S4 — unique-column collisions must not become 500s
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_email_already_registered_returns_409(sqlite_db):
    from api.firebase_auth import _get_or_create_user_from_firebase

    async with sqlite_db() as s:
        s.add(User(id=str(uuid.uuid4()), username="original",
                   firebase_uid="uid-original", email="victim@gmail.com"))
        await s.commit()

    async with sqlite_db() as s:
        with pytest.raises(HTTPException) as exc:
            await _get_or_create_user_from_firebase(
                s, firebase_uid="uid-impostor", email="victim@gmail.com", display_name=None
            )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_username_collision_gets_a_suffix(sqlite_db):
    """alice@gmail.com and alice@proton.me both derive the username 'alice'."""
    from api.firebase_auth import _get_or_create_user_from_firebase

    async with sqlite_db() as s:
        first = await _get_or_create_user_from_firebase(
            s, firebase_uid="uid-1", email="alice@gmail.com", display_name=None
        )
        await s.commit()
        assert first.username == "alice"

    async with sqlite_db() as s:
        second = await _get_or_create_user_from_firebase(
            s, firebase_uid="uid-2", email="alice@proton.me", display_name=None
        )
        await s.commit()

    assert second.username != first.username
    assert second.username.startswith("alice")

    async with sqlite_db() as s:
        names = (await s.execute(select(User.username))).scalars().all()
    assert len(names) == len(set(names)), "usernames are not unique"


@pytest.mark.asyncio
async def test_returning_user_email_sync_never_collides(sqlite_db):
    """Syncing a returning user's email must not violate the unique column."""
    from api.firebase_auth import _get_or_create_user_from_firebase

    async with sqlite_db() as s:
        s.add_all([
            User(id=str(uuid.uuid4()), username="one", firebase_uid="uid-1", email="one@gmail.com"),
            User(id=str(uuid.uuid4()), username="two", firebase_uid="uid-2", email="two@gmail.com"),
        ])
        await s.commit()

    # uid-2 comes back claiming uid-1's address.
    async with sqlite_db() as s:
        user = await _get_or_create_user_from_firebase(
            s, firebase_uid="uid-2", email="one@gmail.com", display_name=None
        )
        await s.commit()
        assert user.email == "two@gmail.com", "email was overwritten into a collision"


# ══════════════════════════════════════════════════════════════════════════
# S4 — the gate must actually be WIRED into get_current_user
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_get_current_user_enforces_verification(sqlite_db, monkeypatch):
    """Guards the call site, not just the helper.

    The parametrised tests above exercise _assert_email_verified directly, so
    they would still pass if someone deleted the call from get_current_user.
    This one fails in that case.
    """
    import api.firebase_auth as fa
    from fastapi.security import HTTPAuthorizationCredentials

    monkeypatch.setattr(fa, "_init_firebase", lambda: True)

    async def _fake_verify(token: str) -> dict:
        return {
            "uid": "uid-unverified",
            "email": "someone@gmail.com",
            "email_verified": False,
            "firebase": {"sign_in_provider": "password"},
        }

    monkeypatch.setattr(fa, "_verify_firebase_token", _fake_verify)

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token")

    async with sqlite_db() as s:
        with pytest.raises(HTTPException) as exc:
            await fa.get_current_user(credentials=creds, db=s)

    assert exc.value.status_code == 403

    # ...and no user row was created for the unverified address.
    async with sqlite_db() as s:
        rows = (await s.execute(select(User).where(User.email == "someone@gmail.com"))).scalars().all()
    assert not rows, "an unverified signup still created a user row"


@pytest.mark.asyncio
async def test_get_current_user_admits_verified_user(sqlite_db, monkeypatch):
    """The happy path still works — the gate is not simply refusing everyone."""
    import api.firebase_auth as fa
    from fastapi.security import HTTPAuthorizationCredentials

    monkeypatch.setattr(fa, "_init_firebase", lambda: True)

    async def _fake_verify(token: str) -> dict:
        return {
            "uid": "uid-good",
            "email": "good@gmail.com",
            "email_verified": True,
            "firebase": {"sign_in_provider": "password"},
        }

    monkeypatch.setattr(fa, "_verify_firebase_token", _fake_verify)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token")

    async with sqlite_db() as s:
        user = await fa.get_current_user(credentials=creds, db=s)
        await s.commit()

    assert user.email == "good@gmail.com"
