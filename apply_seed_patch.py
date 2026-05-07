#!/usr/bin/env python3
"""
apply_seed_patch.py — Aligns seed_demo_progress.py with the real db/models.py.

Problems being fixed:
  1. User has no `email` or `role` columns — only username + display_name
  2. Session uses `ended_at` (not `completed_at`)
  3. Session uses `config` (not `session_metadata`)
  4. Session has a `role` column (red_team/blue_team/full_spectrum) — map modes to it
  5. Progress router queries also need updating (session_metadata → config)

Mode mapping (dashboard ↔ DB):
  soc       → blue_team
  pentester → red_team
  purple    → full_spectrum

Run from repo root:
    cd ~/Desktop/astra/Astra
    python apply_seed_patch.py
"""

from __future__ import annotations

from pathlib import Path
import sys


if not Path("scripts/seed_demo_progress.py").exists():
    print("ERROR: run from repo root (~/Desktop/astra/Astra)")
    sys.exit(1)


changes = []


# ════════════════════════════════════════════════════════════════════════════
# FIX 1 — seed_demo_progress.py
# ════════════════════════════════════════════════════════════════════════════
seed = Path("scripts/seed_demo_progress.py")
text = seed.read_text()

# 1a. Fix User constructor: remove email/role, keep only valid fields
old_user = """                user = User(
                    id=str(uuid.uuid4()),
                    username=profile["username"],
                    email=f"{profile['username']}@demo.astra",
                    role="trainee",
                )"""
new_user = """                user = User(
                    id=str(uuid.uuid4()),
                    username=profile["username"],
                    display_name=profile["username"].title(),
                )"""
if old_user in text:
    text = text.replace(old_user, new_user)
    changes.append("seed: User() constructor (removed email/role, added display_name)")

# 1b. Fix Session constructor: completed_at → ended_at, session_metadata → config, add role
old_session = """                session_obj = SessionModel(
                    id=sess_dict["id"],
                    user_id=profile["_user_id"],
                    scenario_id=sess_dict["scenario_id"],
                    difficulty=sess_dict["difficulty"],
                    status=sess_dict["status"],
                    session_metadata=sess_dict["session_metadata"],
                    started_at=sess_dict["started_at"],
                    completed_at=sess_dict["completed_at"],
                )"""
new_session = """                # Map dashboard mode to DB role
                _mode_to_role = {"soc": "blue_team", "pentester": "red_team", "purple": "full_spectrum"}
                _mode = sess_dict["session_metadata"].get("mode", "soc")
                session_obj = SessionModel(
                    id=sess_dict["id"],
                    user_id=profile["_user_id"],
                    scenario_id=sess_dict["scenario_id"],
                    role=_mode_to_role.get(_mode, "blue_team"),
                    difficulty=sess_dict["difficulty"],
                    status=sess_dict["status"],
                    config=sess_dict["session_metadata"],  # store mode + demo flag in config
                    started_at=sess_dict["started_at"],
                    ended_at=sess_dict["completed_at"],
                )"""
if old_session in text:
    text = text.replace(old_session, new_session)
    changes.append("seed: Session() constructor (ended_at, config, added role mapping)")

# 1c. Fix the reset block too — looks for session_metadata
old_reset = """            demo_sessions = await db.execute(
                select(SessionModel).where(SessionModel.session_metadata.contains({"demo": True}))
            )"""
new_reset = """            demo_sessions = await db.execute(
                select(SessionModel).where(SessionModel.config.contains({"demo": True}))
            )"""
if old_reset in text:
    text = text.replace(old_reset, new_reset)
    changes.append("seed: reset query (session_metadata → config)")

seed.write_text(text)


# ════════════════════════════════════════════════════════════════════════════
# FIX 2 — api/routers/progress.py
# It also reads session_metadata; should read config instead.
# Also: it queries User.username — that's fine — but assumes role="trainee"-style
# filtering doesn't exist, so list_users should work as-is.
# ════════════════════════════════════════════════════════════════════════════
progress = Path("api/routers/progress.py")
if progress.exists():
    ptext = progress.read_text()
    p_changes = 0

    # Replace `session_metadata` lookups with `config`
    if "session.session_metadata" in ptext or "SessionModel.session_metadata" in ptext:
        ptext = ptext.replace("session.session_metadata", "session.config")
        ptext = ptext.replace("SessionModel.session_metadata", "SessionModel.config")
        p_changes += 1

    # The two metadata-or-fallback lines:
    old1 = "        meta = getattr(session, \"session_metadata\", None) or getattr(session, \"metadata_json\", None)"
    new1 = "        meta = getattr(session, \"config\", None)"
    if old1 in ptext:
        ptext = ptext.replace(old1, new1)
        p_changes += 1

    old2 = "        meta = getattr(session, \"session_metadata\", None) or {}"
    new2 = "        meta = getattr(session, \"config\", None) or {}"
    if old2 in ptext:
        ptext = ptext.replace(old2, new2)
        p_changes += 1

    if p_changes:
        progress.write_text(ptext)
        changes.append(f"api/routers/progress.py: {p_changes} session_metadata→config edits")


# ════════════════════════════════════════════════════════════════════════════
# Report
# ════════════════════════════════════════════════════════════════════════════
print("Patches applied:")
for c in changes:
    print(f"  • {c}")

if not changes:
    print("  (no changes — files already match real schema)")

print()
print("Verify with:")
print("    python scripts/seed_demo_progress.py")
print("    # then:")
print("    python -m pytest tests/test_dashboard/ -q")
