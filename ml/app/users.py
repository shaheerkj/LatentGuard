"""User store + role matrix backing RBAC.

Multi-role authentication on top of the existing JWT machinery. The
JWT payload's `role` claim now comes from the user record (Mongo
`users` collection), not a hard-coded "admin" string. A FastAPI
dependency `require_role(*roles)` wraps `require_auth` and 403s
when the caller's role is not in the allowed set.

Roles:

    admin                full control + user management
    security-operator    approve / reject / expire rules; cannot retrain
                         models or change consensus
    ml-engineer          retrain models + tune consensus; cannot approve
                         rules
    auditor              read-only everywhere

Bootstrap: if the users collection is empty (fresh deployment), we
seed the first admin from the BOOTSTRAP_ADMIN_USER /
BOOTSTRAP_ADMIN_PASSWORD_HASH env vars. The pre-RBAC env names
ADMIN_USER / ADMIN_PASSWORD_HASH are accepted as fallbacks so
existing compose files keep working.

A reserved "ml-service" identity exists implicitly: tokens minted
with sub="ml-service" by `auth.issue_token` carry role=admin so the
ML side can call the proxy's /__reload without a user record. The
proxy verifier accepts any of (admin, security-operator) for reload.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

import bcrypt
from pymongo import ASCENDING
from pymongo.errors import PyMongoError

from .db import get_db

logger = logging.getLogger("latentguard.ml.users")


class Role:
    ADMIN = "admin"
    SECURITY_OPERATOR = "security-operator"
    ML_ENGINEER = "ml-engineer"
    AUDITOR = "auditor"

    ALL = (ADMIN, SECURITY_OPERATOR, ML_ENGINEER, AUDITOR)

    # Convenience role sets for the endpoint matrix. Used as
    # require_role(*Role.RULE_OPERATORS) at route declaration.
    RULE_OPERATORS = (ADMIN, SECURITY_OPERATOR)
    MODEL_OPERATORS = (ADMIN, ML_ENGINEER)
    READ_ANY = ALL


def is_valid_role(role: str) -> bool:
    return role in Role.ALL


@dataclass(frozen=True)
class UserRecord:
    username: str
    role: str
    active: bool
    created_at: datetime | None
    last_login: datetime | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "role": self.role,
            "active": self.active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


# ---------------------------------------------------------------------------
# Collection helpers
# ---------------------------------------------------------------------------


def _collection():
    return get_db()["users"]


_INDEXES_READY = False


def _maybe_init() -> None:
    global _INDEXES_READY
    if _INDEXES_READY:
        return
    try:
        col = _collection()
        col.create_index([("username", ASCENDING)], unique=True)
        _INDEXES_READY = True
    except PyMongoError as exc:
        logger.warning("users: index init failed: %s", exc)


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception as exc:
        logger.warning("bcrypt verify error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def _bootstrap_env() -> tuple[str, str | None]:
    """Return (username, password_hash_or_None). Accepts both BOOTSTRAP_*
    (preferred, RBAC-aware naming) and ADMIN_* (pre-RBAC, backwards-compat).
    """
    user = (
        os.environ.get("BOOTSTRAP_ADMIN_USER")
        or os.environ.get("ADMIN_USER")
        or "admin"
    ).strip() or "admin"
    pwd_hash = (
        os.environ.get("BOOTSTRAP_ADMIN_PASSWORD_HASH")
        or os.environ.get("ADMIN_PASSWORD_HASH")
        or ""
    ).strip() or None
    return user, pwd_hash


def ensure_bootstrap_admin() -> dict[str, Any] | None:
    """If the users collection is empty, seed the first admin from env.

    Idempotent -- subsequent calls do nothing once any user exists.
    Returns the bootstrapped doc, or None if the collection was already
    populated.
    """
    _maybe_init()
    try:
        col = _collection()
        if col.estimated_document_count() > 0:
            return None
        user, pwd_hash = _bootstrap_env()
        if not pwd_hash:
            # Fall back to the same DEFAULT_ADMIN_HASH used in auth.py so
            # a fresh container still has a working login. The demo
            # password is documented in the deployment notes.
            from .auth import DEFAULT_ADMIN_HASH
            pwd_hash = DEFAULT_ADMIN_HASH
            logger.warning(
                "users: bootstrapping admin with default hash -- override "
                "BOOTSTRAP_ADMIN_PASSWORD_HASH before exposing this stack"
            )
        doc = {
            "username": user,
            "password_hash": pwd_hash,
            "role": Role.ADMIN,
            "active": True,
            "created_at": datetime.now(timezone.utc),
            "created_by": "bootstrap",
            "last_login": None,
            "updated_at": datetime.now(timezone.utc),
        }
        col.insert_one(doc)
        logger.info("users: bootstrapped admin=%s", user)
        return doc
    except PyMongoError as exc:
        logger.warning("users: bootstrap failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def get_user(username: str) -> dict[str, Any] | None:
    _maybe_init()
    try:
        return _collection().find_one({"username": username})
    except PyMongoError as exc:
        logger.warning("users.get: %s", exc)
        return None


def list_users() -> list[dict[str, Any]]:
    _maybe_init()
    try:
        return list(_collection().find({}, {"password_hash": 0}).sort("username", ASCENDING))
    except PyMongoError as exc:
        logger.warning("users.list: %s", exc)
        return []


def create_user(
    *,
    username: str,
    password: str,
    role: str,
    created_by: str,
) -> dict[str, Any]:
    _maybe_init()
    if not is_valid_role(role):
        raise ValueError(f"unknown role {role!r}")
    if not username or len(username) > 64:
        raise ValueError("username must be 1..64 chars")
    if len(password) < 8:
        raise ValueError("password must be at least 8 chars")
    col = _collection()
    if col.find_one({"username": username}):
        raise ValueError(f"user {username!r} already exists")
    doc = {
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "active": True,
        "created_at": datetime.now(timezone.utc),
        "created_by": created_by,
        "last_login": None,
        "updated_at": datetime.now(timezone.utc),
    }
    col.insert_one(doc)
    return doc


def update_user(
    username: str,
    *,
    role: str | None = None,
    active: bool | None = None,
    password: str | None = None,
    actor: str = "unknown",
) -> dict[str, Any]:
    _maybe_init()
    col = _collection()
    current = col.find_one({"username": username})
    if not current:
        raise KeyError(f"user {username!r} not found")
    sets: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if role is not None:
        if not is_valid_role(role):
            raise ValueError(f"unknown role {role!r}")
        sets["role"] = role
    if active is not None:
        sets["active"] = bool(active)
    if password is not None:
        if len(password) < 8:
            raise ValueError("password must be at least 8 chars")
        sets["password_hash"] = hash_password(password)
    sets["updated_by"] = actor
    col.update_one({"username": username}, {"$set": sets})
    return col.find_one({"username": username})


def delete_user(username: str) -> bool:
    """Hard-delete. Prefer update_user(active=False) to preserve audit trail."""
    _maybe_init()
    res = _collection().delete_one({"username": username})
    return res.deleted_count > 0


def record_login(username: str) -> None:
    _maybe_init()
    try:
        _collection().update_one(
            {"username": username},
            {"$set": {"last_login": datetime.now(timezone.utc)}},
        )
    except PyMongoError as exc:
        logger.warning("users.record_login: %s", exc)


# ---------------------------------------------------------------------------
# Lookup for the login flow
# ---------------------------------------------------------------------------


def authenticate(username: str, password: str) -> tuple[bool, dict[str, Any] | None]:
    """Returns (ok, user_doc_without_hash).

    Constant-ish-time: always run bcrypt even on missing/inactive users
    so wall-clock comparison cannot enumerate accounts. We do this by
    falling back to a "throwaway" hash that always fails compare.
    """
    _maybe_init()
    user = get_user(username)
    if user is None or not user.get("active", True):
        # Burn a bcrypt op so missing-user response time matches the
        # wrong-password path.
        _ = verify_password(password, "$2b$12$" + "x" * 53)
        return False, None
    if not verify_password(password, user.get("password_hash", "")):
        return False, None
    safe = {k: v for k, v in user.items() if k != "password_hash"}
    return True, safe
