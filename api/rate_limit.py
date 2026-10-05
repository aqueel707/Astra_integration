"""
api/rate_limit.py
──────────────────
Redis-backed rate limiting via SlowAPI, applied globally as middleware.

Why Redis (not in-memory):
  The API runs on Render's free tier, which spins down on inactivity and can
  run more than one instance. An in-memory limiter would reset on every
  spin-down and wouldn't be shared across instances. Backing it with the same
  Upstash Redis the streaming layer already uses makes limits durable.

Why middleware (not per-route decorators):
  SlowAPIMiddleware enforces `default_limits` on EVERY route automatically,
  so we don't have to add `request: Request` to every handler signature or
  decorate each endpoint. One global cap, wired in one place.

Key strategy:
  Client IP, always.

  This previously preferred a uid read from the UNVERIFIED token payload, on the
  reasoning that "forging a uid only changes which throttle bucket you land in,
  never whether you're allowed through." That reasoning was wrong: the bucket IS
  the limit. Anyone could mint a syntactically valid unsigned JWT with a random
  `sub` per request, land in a fresh bucket every time, and never be throttled —
  and because a bearer token was present, the IP fallback never engaged either.

  Per-account limiting (the original goal, for users behind a shared campus NAT)
  requires a VERIFIED identity, which this middleware cannot have: it runs before
  route dependencies resolve, so no token has been checked yet. Adding it means a
  limit applied downstream of get_current_user, keyed on the verified uid — worth
  doing, but it belongs with whatever auth provider the project settles on rather
  than being built against Firebase specifics now.

Resilience:
  Redis is pinged synchronously at startup. If it's unreachable, we log a
  CRITICAL and fall back to an in-memory limiter so the limiter can never take
  the whole API down — it degrades instead of failing closed on the DB hop.

Tuning:
  RATE_LIMIT_DEFAULT env var overrides the default limit (e.g. "60/minute")
  without a code change.

Wire-in (api/app.py, inside create_app after the app exists):
    from api.rate_limit import init_rate_limiter
    init_rate_limiter(app)
"""

from __future__ import annotations

import logging
import os

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.requests import Request
from starlette.responses import JSONResponse

from config.settings import get_settings

logger = logging.getLogger("astra.rate_limit")

# Resolved once at import; also used in the attach log line.
DEFAULT_LIMIT = os.getenv("RATE_LIMIT_DEFAULT", "120/minute")


def _client_key(request: Request) -> str:
    """Bucket key: client IP, always.

    Deliberately ignores the Authorization header. Deriving the key from an
    unverified token let a caller choose their own bucket, which is not a
    throttle at all — see the module docstring.
    """
    return f"ip:{get_remote_address(request)}"


def _build_limiter() -> Limiter:
    settings = get_settings()
    redis_url = getattr(settings, "redis_url", None)

    common = dict(
        key_func=_client_key,
        default_limits=[DEFAULT_LIMIT],
        headers_enabled=True,  # emit X-RateLimit-* response headers
    )

    if redis_url and not redis_url.startswith("redis://localhost"):
        try:
            # Synchronous reachability check (sync fn, called at import time).
            import redis
            redis.Redis.from_url(redis_url, socket_connect_timeout=2).ping()
            logger.info(f"[rate_limit] Redis reachable at {redis_url.split('@')[-1]}")
            return Limiter(storage_uri=redis_url, **common)
        except Exception as e:
            # Degrade, don't die: a flaky limiter store must not 503 the API.
            logger.critical(
                f"[rate_limit] Redis unreachable ({e}); falling back to in-memory limiter."
            )
    else:
        logger.warning("[rate_limit] no production Redis URL; in-memory limiter (dev only)")

    return Limiter(**common)


# Singleton — import this in routers for per-route @limiter.limit overrides.
limiter = _build_limiter()


async def _rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"},
    )


def init_rate_limiter(app) -> None:
    """Attach the limiter, the 429 handler, and the global middleware.
    Call inside create_app() after the app object exists."""
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    logger.info(f"[rate_limit] global limiter attached (default {DEFAULT_LIMIT} per uid/IP)")


# ── Optional per-route tighter limits (handler must take `request: Request`) ──
#   from api.rate_limit import limiter
#   @router.post("/sessions")
#   @limiter.limit("10/minute")
#   async def create_session(request: Request, ...): ...