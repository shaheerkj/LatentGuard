"""Auth: HS256 JWT + bcrypt password verify for the operator dashboard.

Single-admin model for the FYP demo. The SDS describes full RBAC
(admin / auditor / ml-engineer) — that's deferred. Today there is one
user, configured via env, that gets a JWT after a successful password
check. Every /api/* request other than /api/auth/login is gated by
`require_auth` (FastAPI dependency) on the ML side; the Go proxy
verifies the same JWT (same HS256 shared secret) for its operator
endpoints under /__*.

Env vars (set in infra/docker-compose.yml):
  ADMIN_USER             default 'admin'
  ADMIN_PASSWORD_HASH    bcrypt hash. If unset, a default 'admin' hash
                         is used so the demo works out of the box --
                         intentionally insecure, the dashboard warns.
  JWT_SECRET             HS256 signing key. If unset, an ephemeral
                         random secret is generated at boot (means
                         every restart invalidates tokens; fine for
                         dev, document this).
  JWT_TTL_HOURS          token lifetime in hours, default 12.

The default password is 'admin' -- hash precomputed below. Override
ADMIN_PASSWORD_HASH in production-style deployments.
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from dataclasses import dataclass

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("latentguard.ml.auth")

# bcrypt of the project owner's demo password (20-char random alnum), cost 12.
# Real credential lives outside the repo; this hash is the only thing checked
# in. Override ADMIN_PASSWORD_HASH in any deployment that matters.
DEFAULT_ADMIN_HASH = "$2b$12$nb3EVaoj8KMD2s2OtwCrN.6gL91P7lfE3EzUu45FXgtcrTm75cnRe"

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "latentguard"


@dataclass(frozen=True)
class AuthConfig:
    admin_user: str
    admin_hash: str
    secret: str
    ttl_seconds: int
    using_default_password: bool
    using_ephemeral_secret: bool


def _load_config() -> AuthConfig:
    user = os.environ.get("ADMIN_USER", "shaheerkj").strip() or "shaheerkj"
    pwd_hash = os.environ.get("ADMIN_PASSWORD_HASH", "").strip()
    using_default = False
    if not pwd_hash:
        pwd_hash = DEFAULT_ADMIN_HASH
        using_default = True

    secret = os.environ.get("JWT_SECRET", "").strip()
    using_ephemeral = False
    if not secret:
        # 32 random bytes -> hex. Tokens won't survive a service restart;
        # acceptable for dev, surface a clear warning on boot.
        secret = secrets.token_hex(32)
        using_ephemeral = True

    ttl_hours = int(os.environ.get("JWT_TTL_HOURS", "12") or "12")
    return AuthConfig(
        admin_user=user,
        admin_hash=pwd_hash,
        secret=secret,
        ttl_seconds=ttl_hours * 3600,
        using_default_password=using_default,
        using_ephemeral_secret=using_ephemeral,
    )


_CONFIG: AuthConfig | None = None


def get_config() -> AuthConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = _load_config()
        if _CONFIG.using_default_password:
            logger.warning(
                "auth: ADMIN_PASSWORD_HASH unset -- using built-in 'admin' "
                "password. OVERRIDE in any non-dev deployment."
            )
        if _CONFIG.using_ephemeral_secret:
            logger.warning(
                "auth: JWT_SECRET unset -- generated ephemeral secret at "
                "boot. Tokens invalidate on restart. Set JWT_SECRET for stability."
            )
    return _CONFIG


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception as exc:
        logger.warning("bcrypt verify error: %s", exc)
        return False


def issue_token(username: str) -> tuple[str, int]:
    """Returns (jwt, expires_at_unix). Caller decides what to expose."""
    cfg = get_config()
    now = int(time.time())
    exp = now + cfg.ttl_seconds
    payload = {
        "sub": username,
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": exp,
        "role": "admin",
    }
    token = jwt.encode(payload, cfg.secret, algorithm=JWT_ALGORITHM)
    return token, exp


def decode_token(token: str) -> dict:
    cfg = get_config()
    return jwt.decode(
        token,
        cfg.secret,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        options={"require": ["sub", "exp", "iat"]},
    )


# FastAPI dependency: require a valid bearer token. Used on every protected
# endpoint. Returns the decoded payload so handlers can read claims.
_bearer = HTTPBearer(auto_error=False)


def require_auth(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(creds.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token expired",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token: {exc}",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    request.state.user = payload.get("sub")
    return payload
