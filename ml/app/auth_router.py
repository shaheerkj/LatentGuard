"""Auth + user-management endpoints.

Public:
    POST /api/auth/login              -> JWT
    GET  /api/auth/config-status      -> deployment-warning flags

Authenticated (any role):
    GET  /api/auth/me                 -> claims for the current token
    POST /api/auth/me/password        -> change own password

Admin only:
    GET    /api/auth/users            -> list users
    POST   /api/auth/users            -> create user
    PUT    /api/auth/users/{username} -> update role / active / password
    DELETE /api/auth/users/{username} -> delete user

Everything except /login and /config-status requires a valid bearer
token; user-management routes additionally require role=admin.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .auth import (
    get_config,
    issue_token,
    require_auth,
    require_role,
)
from .users import (
    Role,
    authenticate,
    create_user,
    delete_user,
    ensure_bootstrap_admin,
    get_user,
    is_valid_role,
    list_users,
    record_login,
    update_user,
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
    role: str
    warnings: list[str] = []


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    cfg = get_config()
    # Seed the first admin if the users collection is empty. Idempotent.
    ensure_bootstrap_admin()

    ok, user = authenticate(payload.username, payload.password)
    if not ok or user is None:
        logger.info("auth: failed login for user=%r", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )

    role = user.get("role", Role.ADMIN)
    token, exp = issue_token(payload.username, role=role)
    record_login(payload.username)

    warnings: list[str] = []
    if cfg.using_ephemeral_secret:
        warnings.append("JWT secret is ephemeral -- tokens invalidate on restart")

    logger.info("auth: issued token for user=%s role=%s", payload.username, role)
    return LoginResponse(
        token=token, expires_at=exp, user=payload.username, role=role, warnings=warnings,
    )


@router.get("/me")
def me(user_payload: dict = Depends(require_auth)) -> dict:
    """Echo the decoded JWT claims + live user record.

    The live record is read fresh so a freshly-promoted role takes effect
    on the dashboard's next /me call (next page load), without waiting
    for the token TTL.
    """
    sub = user_payload.get("sub", "")
    live = get_user(sub) or {}
    return {
        "user": sub,
        "role": live.get("role", user_payload.get("role", Role.ADMIN)),
        "active": live.get("active", True),
        "exp": user_payload.get("exp"),
        "iat": user_payload.get("iat"),
    }


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


@router.post("/me/password")
def change_own_password(
    payload: PasswordChange, request: Request, user_payload: dict = Depends(require_auth)
) -> dict:
    sub = user_payload.get("sub", "")
    ok, _user = authenticate(sub, payload.current_password)
    if not ok:
        raise HTTPException(status_code=403, detail="current password incorrect")
    try:
        update_user(sub, password=payload.new_password, actor=sub)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True}


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


# ---------------------------------------------------------------------------
# User management -- admin-only
# ---------------------------------------------------------------------------


def _serialize_user(doc: dict) -> dict:
    return {
        "username": doc.get("username"),
        "role": doc.get("role"),
        "active": doc.get("active", True),
        "created_at": doc["created_at"].isoformat() if doc.get("created_at") else None,
        "updated_at": doc["updated_at"].isoformat() if doc.get("updated_at") else None,
        "last_login": doc["last_login"].isoformat() if doc.get("last_login") else None,
        "created_by": doc.get("created_by"),
    }


@router.get(
    "/users",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
def users_list() -> dict:
    rows = [_serialize_user(u) for u in list_users()]
    return {"rows": rows, "total": len(rows), "roles": list(Role.ALL)}


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: str


@router.post(
    "/users",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
def users_create(
    payload: CreateUserRequest, request: Request
) -> dict:
    actor = getattr(request.state, "user", "unknown")
    if not is_valid_role(payload.role):
        raise HTTPException(status_code=400, detail=f"unknown role {payload.role!r}")
    try:
        doc = create_user(
            username=payload.username,
            password=payload.password,
            role=payload.role,
            created_by=actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _serialize_user(doc)


class UpdateUserRequest(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)


@router.put(
    "/users/{username}",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
def users_update(
    username: str, payload: UpdateUserRequest, request: Request
) -> dict:
    actor = getattr(request.state, "user", "unknown")
    # Defensive: prevent demoting the only admin into a non-admin role,
    # otherwise the deployment can lock itself out.
    if payload.role is not None and payload.role != Role.ADMIN:
        current = get_user(username)
        if current and current.get("role") == Role.ADMIN:
            other_admins = [
                u for u in list_users()
                if u.get("role") == Role.ADMIN
                and u.get("username") != username
                and u.get("active", True)
            ]
            if not other_admins:
                raise HTTPException(
                    status_code=409,
                    detail="cannot demote the only active admin",
                )
    if payload.active is False:
        # Same guard for deactivation.
        current = get_user(username)
        if current and current.get("role") == Role.ADMIN:
            other_admins = [
                u for u in list_users()
                if u.get("role") == Role.ADMIN
                and u.get("username") != username
                and u.get("active", True)
            ]
            if not other_admins:
                raise HTTPException(
                    status_code=409,
                    detail="cannot deactivate the only active admin",
                )
    try:
        doc = update_user(
            username,
            role=payload.role,
            active=payload.active,
            password=payload.password,
            actor=actor,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _serialize_user(doc)


@router.delete(
    "/users/{username}",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
def users_delete(username: str, request: Request) -> dict:
    actor = getattr(request.state, "user", "unknown")
    if username == actor:
        raise HTTPException(status_code=409, detail="cannot delete your own account")
    current = get_user(username)
    if current and current.get("role") == Role.ADMIN:
        other_admins = [
            u for u in list_users()
            if u.get("role") == Role.ADMIN
            and u.get("username") != username
            and u.get("active", True)
        ]
        if not other_admins:
            raise HTTPException(
                status_code=409,
                detail="cannot delete the only active admin",
            )
    if not delete_user(username):
        raise HTTPException(status_code=404, detail=f"user {username!r} not found")
    return {"deleted": username}
