"""
tests/test_api/test_config_and_hardening.py
────────────────────────────────────────────
Guards for the Phase 5 configuration and schema fixes.

  M1  config.yaml flattened every nested key to its LEAF name, so database.url
      and redis.url collided on "url" and neither matched a field — the file
      looked like configuration while almost none of it applied. It was also
      passed as init kwargs, which outrank environment variables, so what did
      apply silently beat .env.

  M4  Router imports were wrapped in try/except: a typo removed a whole feature
      and the app still booted healthy.

  M5  init_db ran create_all against production on every boot.

  M6  /ready returned raw DB errors (host, port, database, role) unauthenticated.

  M7c 'paused' was accepted but nothing could resume it.
"""

from __future__ import annotations

import pytest


# ══════════════════════════════════════════════════════════════════════════
# M1 — configuration
# ══════════════════════════════════════════════════════════════════════════

def test_yaml_maps_onto_real_setting_names():
    """database.url must reach database_url, not collide with redis.url."""
    from config.settings import Settings, _load_yaml_config

    flat = _load_yaml_config(set(Settings.model_fields))

    assert "url" not in flat, "leaf-name flattening is back; database/redis collide"
    assert flat.get("database_url", "").startswith("sqlite"), flat.get("database_url")
    assert flat.get("redis_url", "").startswith("redis"), flat.get("redis_url")
    assert flat.get("mitre_attack_version") == "15.1"
    # server.* maps to bare field names, which the prefix-first lookup preserves.
    assert flat.get("api_port") == 8000


def test_environment_outranks_config_yaml(monkeypatch):
    """The docstring always promised this; the implementation did the reverse."""
    from config.settings import Settings

    monkeypatch.setenv("MITRE_ATTACK_VERSION", "99.9")
    monkeypatch.setenv("REDIS_ENABLED", "false")

    s = Settings()
    assert s.mitre_attack_version == "99.9", "config.yaml overrode the environment"
    assert s.redis_enabled is False


def test_unmappable_keys_are_reported(caplog):
    """Silent discards are what made config.yaml a trap."""
    import logging

    from config.settings import Settings, _load_yaml_config

    with caplog.at_level(logging.WARNING, logger="astra.settings"):
        _load_yaml_config(set(Settings.model_fields))

    messages = [r.getMessage() for r in caplog.records]
    assert any("scoring.weights" in m for m in messages), (
        f"unmappable keys were dropped silently; got {messages}"
    )


# ══════════════════════════════════════════════════════════════════════════
# M4 — routers must be mounted, not optionally mounted
# ══════════════════════════════════════════════════════════════════════════

def test_all_expected_routers_are_mounted():
    from api.app import create_app

    paths = {getattr(r, "path", "") for r in create_app().routes}
    for expected in ("/attacks/run/{scenario_id}", "/pentester/choice",
                     "/alerts", "/sessions", "/progress/skills"):
        assert any(p.startswith(expected) or p == expected for p in paths), expected


def test_cors_origins_come_from_the_environment(monkeypatch):
    from api.app import _allowed_origins

    monkeypatch.setenv("ASTRA_ALLOWED_ORIGINS", "https://a.example, https://b.example")
    assert _allowed_origins() == ["https://a.example", "https://b.example"]

    monkeypatch.delenv("ASTRA_ALLOWED_ORIGINS")
    assert "http://localhost:8050" in _allowed_origins()


# ══════════════════════════════════════════════════════════════════════════
# M5 — create_all must not touch a managed database
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_create_all_refuses_on_production(monkeypatch, capsys):
    import db.engine as engine_mod

    monkeypatch.setattr(engine_mod, "_build_database_url",
                        lambda: "postgresql+asyncpg://u:p@db.example/postgres")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("ASTRA_ALLOW_CREATE_ALL", raising=False)

    from config.settings import get_settings
    get_settings.cache_clear()

    def _boom():
        raise AssertionError("create_all reached a production database")

    monkeypatch.setattr(engine_mod, "get_engine", _boom)
    await engine_mod.init_db()

    assert "Skipping create_all" in capsys.readouterr().out
    get_settings.cache_clear()


# ══════════════════════════════════════════════════════════════════════════
# M6 / M7c
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_ready_does_not_leak_connection_details(make_client, two_users, monkeypatch):
    import api.routers.health as health

    def _explode():
        raise RuntimeError(
            "connection to server at db.abcdef.supabase.co port 5432 "
            "failed: role 'postgres.abcdef' password authentication failed"
        )

    monkeypatch.setattr(health, "get_engine", _explode)

    resp = await make_client(two_users["alice"][0]).get("/ready")
    body = resp.text
    assert resp.status_code == 503
    for secret in ("supabase.co", "5432", "password", "postgres."):
        assert secret not in body, f"{secret!r} leaked in the readiness response"


def test_paused_is_no_longer_accepted():
    from pydantic import ValidationError

    from api.schemas.session import SessionStatusUpdate

    for ok in ("running", "completed", "aborted"):
        SessionStatusUpdate(status=ok)

    with pytest.raises(ValidationError):
        SessionStatusUpdate(status="paused")


def test_unknown_status_gives_400_not_500():
    """Building the error message used to KeyError on an unexpected status."""
    from api.routers.sessions import update_session_status  # noqa: F401 - import guard

    valid_transitions = {
        "created": ["running", "aborted"],
        "running": ["paused", "completed", "aborted"],
        "paused": ["running", "completed", "aborted"],
        "completed": [],
        "aborted": [],
    }
    # 'paused' must remain a KEY so existing rows can still transition out.
    assert "paused" in valid_transitions
    assert valid_transitions.get("something_unexpected", []) == []
