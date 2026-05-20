"""
api/firebase_auth.py
─────────────────────
Firebase Auth integration for FastAPI.

How it works:
  1. The Dash frontend (or any client) signs the user in via Firebase Auth.
  2. Firebase returns an ID token (a JWT signed by Firebase's private key).
  3. Every API call includes that token:
       Authorization: Bearer <firebase_id_token>
  4. This module verifies the token against Firebase's public keys.
  5. On success, it upserts the user into our `users` table and returns
     the User ORM object as a FastAPI dependency.

Setup:
  Set these environment variables on Koyeb (or in .env locally):
    FIREBASE_PROJECT_ID=your-project-id   (e.g. "astra-cyber-abc12")

  The firebase-admin SDK automatically fetches Firebase's public keys
  from Google — no private key needed for server-side token verification.
  (Private key would only be needed for creating custom tokens, which we
  don't do.)

Local development without Firebase:
  If FIREBASE_PROJECT_ID is not set, get_current_user falls back to the
  demo user so local development still works without Firebase configured.
  Set FIREBASE_ENABLED=false in your local .env to force this.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.deps import get_db
from db.models import User

logger = logging.getLogger("astra.firebase_auth")

# ---------------------------------------------------------------------------
# Firebase Admin SDK initialisation (lazy, once)
# ---------------------------------------------------------------------------
_firebase_initialised = False

def _get_firebase_credentials():
    """Resolve a Firebase credential.

    Prefers FIREBASE_SERVICE_ACCOUNT_B64 env var (production — Render),
    falls back to secrets/firebase-admin.json (local dev). Raises if
    neither is available so misconfiguration fails loudly instead of
    silently demoting to dev fallback."""
    import base64
    import json
    import os as _os
    from firebase_admin import credentials as _creds

    b64 = _os.environ.get("FIREBASE_SERVICE_ACCOUNT_B64")
    if b64:
        cert_dict = json.loads(base64.b64decode(b64))
        return _creds.Certificate(cert_dict)
    if _os.path.exists("secrets/firebase-admin.json"):
        return _creds.Certificate("secrets/firebase-admin.json")
    raise RuntimeError(
        "Firebase credentials not found. Set FIREBASE_SERVICE_ACCOUNT_B64 "
        "(production) or place secrets/firebase-admin.json (local dev)."
    )




def _init_firebase() -> bool:
    """
    Initialise the Firebase Admin SDK if FIREBASE_PROJECT_ID is set.
    Returns True if Firebase is active, False if running in dev-fallback mode.
    """
    global _firebase_initialised

    if _firebase_initialised:
        return True

    project_id = os.environ.get("FIREBASE_PROJECT_ID")
    enabled = os.environ.get("FIREBASE_ENABLED", "true").lower() != "false"

    if not project_id or not enabled:
        logger.warning(
            "[firebase] FIREBASE_PROJECT_ID not set or FIREBASE_ENABLED=false — "
            "running in dev fallback mode (all requests treated as demo user)"
        )
        return False

    try:
        import firebase_admin
        from firebase_admin import credentials

        if not firebase_admin._apps:
            firebase_admin.initialize_app(credential=_get_firebase_credentials(), 
                
                options={"projectId": project_id},
            )
        _firebase_initialised = True
        logger.info(f"[firebase] Initialised for project {project_id}")
        return True
    except Exception as e:
        logger.exception(f"[firebase] Init failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)


async def _verify_firebase_token(token: str) -> dict:
    """
    Verify a Firebase ID token and return the decoded claims.
    Raises HTTPException 401 on failure.
    """
    try:
        from firebase_admin import auth as firebase_auth
        decoded = firebase_auth.verify_id_token(token, check_revoked=False)
        return decoded
    except Exception as e:
        logger.warning(f"[firebase] Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Firebase token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# User upsert — maps Firebase UID → our users table
# ---------------------------------------------------------------------------

async def _get_or_create_user_from_firebase(
    db: AsyncSession,
    firebase_uid: str,
    email: Optional[str],
    display_name: Optional[str],
) -> User:
    """
    Look up a user by firebase_uid. If not found, create them.
    Also syncs email and display_name on each login.
    """
    import uuid

    # Try by firebase_uid
    result = await db.execute(
        select(User).where(User.firebase_uid == firebase_uid)
    )
    user = result.scalar_one_or_none()

    if user is None:
        # New user — create them
        username = _derive_username(email, firebase_uid)
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            firebase_uid=firebase_uid,
            email=email,
            display_name=display_name or username,
        )
        db.add(user)
        await db.flush()
        logger.info(f"[firebase] Created new user {user.id} for uid {firebase_uid}")
    else:
        # Returning user — sync latest email/display_name from Firebase
        if email and user.email != email:
            user.email = email
        if display_name and user.display_name != display_name:
            user.display_name = display_name

    return user


def _derive_username(email: Optional[str], firebase_uid: str) -> str:
    """Derive a username from email or fall back to a short UID prefix."""
    if email:
        # Use everything before the @ symbol, strip non-alphanumeric except _
        local = email.split("@")[0]
        clean = "".join(c for c in local if c.isalnum() or c == "_")
        if clean:
            return clean[:64]
    # Fallback: first 12 chars of UID (always unique)
    return f"user_{firebase_uid[:12]}"


# ---------------------------------------------------------------------------
# FastAPI dependency — use in any endpoint that needs the current user
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency that returns the authenticated User.

    Usage in a router:
        @router.post("/sessions")
        async def create_session(
            body: SessionCreate,
            user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            ...

    In development mode (no FIREBASE_PROJECT_ID set), always returns
    the demo user so local development works without Firebase config.
    """
    firebase_active = _init_firebase()

    # ── Development fallback ────────────────────────────────────────────
    if not firebase_active:
        result = await db.execute(
            select(User).where(User.username == "demo")
        )
        demo = result.scalar_one_or_none()
        if demo is None:
            import uuid
            demo = User(
                id=str(uuid.uuid4()),
                username="demo",
                display_name="Demo User",
                firebase_uid=None,
                email=None,
            )
            db.add(demo)
            await db.flush()
        return demo

    # ── Production: require Bearer token ───────────────────────────────
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    decoded = await _verify_firebase_token(credentials.credentials)

    uid   = decoded.get("uid")
    email = decoded.get("email")
    name  = decoded.get("name") or decoded.get("display_name")

    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing uid claim.",
        )

    user = await _get_or_create_user_from_firebase(db, uid, email, name)
    return user


# ---------------------------------------------------------------------------
# Optional current user (returns None if unauthenticated, for public routes)
# ---------------------------------------------------------------------------

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    Like get_current_user but returns None instead of raising 401.
    Use for endpoints that work both authenticated and anonymous.
    """
    try:
        return await get_current_user(credentials=credentials, db=db)
    except HTTPException:
        return None
