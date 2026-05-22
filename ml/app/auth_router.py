"""POST /api/auth/login + GET /api/auth/me + GET /api/auth/config-status.

Login is the ONLY /api/* endpoint that doesn't require a bearer token --
otherwise you couldn't authenticate. Everything else under /api/* is
protected by require_auth applied at router-include time in main.py.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from .auth import (
    get_config,
    issue_token,
    require_auth,
    verify_password,
)

logger = logging.getLogger("latentguard.ml.auth_router")

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    token: str
    expires_at: int
    user: str
    role: str = "admin"
    warnings: list[str] = []


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    cfg = get_config()
    # Constant-ish-time: always run bcrypt even on wrong username to avoid
    # a trivial user-enumeration timing oracle.
    pwd_ok = verify_password(payload.password, cfg.admin_hash)
    if payload.username != cfg.admin_user or not pwd_ok:
        logger.info("auth: failed login for user=%r", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    token, exp = issue_token(payload.username)
    warnings: list[str] = []
    if cfg.using_default_password:
        warnings.append("using default admin password -- set ADMIN_PASSWORD_HASH")
    if cfg.using_ephemeral_secret:
        warnings.append("JWT secret is ephemeral -- tokens invalidate on restart")
    logger.info("auth: issued token for user=%s", payload.username)
    return LoginResponse(
        token=token, expires_at=exp, user=payload.username, warnings=warnings,
    )


@router.get("/me")
def me(user_payload: dict = Depends(require_auth)) -> dict:
    """Echo the decoded JWT claims. Used by the dashboard on page load to
    confirm a stored token is still valid (and refresh user/role state)."""
    return {
        "user": user_payload.get("sub"),
        "role": user_payload.get("role", "admin"),
        "exp": user_payload.get("exp"),
        "iat": user_payload.get("iat"),
    }


@router.get("/config-status")
def config_status() -> dict:
    """Public (no token required): exposes whether the deployment is using
    the default password or an ephemeral JWT secret. The login page reads
    this to render a banner. We don't reveal the actual hash or secret."""
    cfg = get_config()
    return {
        "using_default_password": cfg.using_default_password,
        "using_ephemeral_secret": cfg.using_ephemeral_secret,
    }
