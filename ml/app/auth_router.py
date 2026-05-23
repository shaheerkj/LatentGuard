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
    brute_force_alerts,
    create_user,
    delete_user,
    disable_mfa,
    enable_mfa,
    ensure_bootstrap_admin,
    generate_mfa_secret,
    get_user,
    is_locked,
    is_valid_role,
    list_users,
    record_failure,
    record_ip_attempt,
    record_login,
    reset_failures,
    update_user,
    verify_mfa,
    IP_ALERT_THRESHOLD,
    LOCKOUT_MINUTES,
    MAX_FAILED_BEFORE_LOCKOUT,
)

logger = logging.getLogger("latentguard.ml.auth_router")

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    # Optional TOTP code when MFA is enrolled. The dashboard first hits
    # /login without it; on 412 (MFA required) it re-prompts for the
    # 6-digit code and retries.
    mfa_code: str | None = Field(default=None, max_length=10)


class LoginResponse(BaseModel):
    token: str
    expires_at: int
    user: str
    role: str
    mfa_enabled: bool = False
    warnings: list[str] = []


def _client_ip(request: Request) -> str:
    # Honour X-Forwarded-For when set (we live behind the proxy in
    # production); otherwise fall back to the immediate peer.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return (request.client.host if request.client else "") or "unknown"


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request) -> LoginResponse:
    cfg = get_config()
    # Seed the first admin if the users collection is empty. Idempotent.
    ensure_bootstrap_admin()

    ip = _client_ip(request)
    user_doc = get_user(payload.username)

    # SEC-4: lockout. Check BEFORE bcrypt so a locked account can't be
    # turned into a free oracle by repeated guesses.
    if user_doc and is_locked(user_doc):
        record_ip_attempt(ip, ok=False, username=payload.username)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"account locked after {MAX_FAILED_BEFORE_LOCKOUT} failed attempts; try again in <={LOCKOUT_MINUTES} min",
        )

    ok, user = authenticate(payload.username, payload.password)
    if not ok or user is None:
        record_failure(payload.username) if user_doc else None
        fail_count = record_ip_attempt(ip, ok=False, username=payload.username)
        # SEC-10: brute-force alert on the IP. Logged loud + audit so the
        # ops dashboard can pick it up. The alert itself is non-blocking
        # (the per-account lockout still does the actual stopping).
        if fail_count > IP_ALERT_THRESHOLD:
            logger.warning(
                "auth: brute-force suspected ip=%s fails_in_window=%d username=%r",
                ip, fail_count, payload.username,
            )
        logger.info("auth: failed login user=%r ip=%s", payload.username, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )

    # MFA gate (SEC-1). If enrolled and no code provided, return 412 so
    # the dashboard can prompt for the code without losing the password
    # round-trip. Wrong code on MFA-enabled accounts also counts toward
    # the failure counter.
    if user.get("mfa_enabled"):
        if not payload.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail="mfa_required",
            )
        if not verify_mfa(user, payload.mfa_code):
            record_failure(payload.username)
            record_ip_attempt(ip, ok=False, username=payload.username)
            logger.info("auth: bad MFA code user=%s ip=%s", payload.username, ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid mfa code",
            )

    role = user.get("role", Role.ADMIN)
    token, exp = issue_token(payload.username, role=role)
    record_login(payload.username)
    reset_failures(payload.username)
    record_ip_attempt(ip, ok=True, username=payload.username)

    warnings: list[str] = []
    if cfg.using_ephemeral_secret:
        warnings.append("JWT secret is ephemeral -- tokens invalidate on restart")

    logger.info("auth: issued token user=%s role=%s ip=%s mfa=%s",
                payload.username, role, ip, bool(user.get("mfa_enabled")))
    return LoginResponse(
        token=token, expires_at=exp, user=payload.username, role=role,
        mfa_enabled=bool(user.get("mfa_enabled")), warnings=warnings,
    )


# ---------------------------------------------------------------------------
# MFA enrollment for the current user (any role)
# ---------------------------------------------------------------------------


@router.post("/me/mfa/begin")
def me_mfa_begin(request: Request, user_payload: dict = Depends(require_auth)) -> dict:
    """Generate a pending TOTP secret. Returns the otpauth:// URI for QR
    rendering AND the raw secret so the operator can type it into the
    authenticator app manually if QR isn't available.
    """
    sub = user_payload.get("sub", "")
    secret, uri = generate_mfa_secret(sub)
    return {"secret": secret, "otpauth_uri": uri}


class MfaConfirm(BaseModel):
    code: str = Field(min_length=6, max_length=10)


@router.post("/me/mfa/confirm")
def me_mfa_confirm(payload: MfaConfirm, user_payload: dict = Depends(require_auth)) -> dict:
    sub = user_payload.get("sub", "")
    try:
        ok = enable_mfa(sub, payload.code)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not ok:
        raise HTTPException(status_code=400, detail="invalid code (clock skew? regenerate)")
    return {"ok": True, "mfa_enabled": True}


@router.post("/me/mfa/disable")
def me_mfa_disable(
    payload: dict, user_payload: dict = Depends(require_auth)
) -> dict:
    """Disable MFA after re-confirming the current password (defence in
    depth against a stolen session that wants to lower account security).
    """
    sub = user_payload.get("sub", "")
    pw = (payload or {}).get("password") or ""
    if not pw:
        raise HTTPException(status_code=400, detail="password required")
    ok, _ = authenticate(sub, pw)
    if not ok:
        raise HTTPException(status_code=403, detail="password incorrect")
    disable_mfa(sub)
    return {"ok": True, "mfa_enabled": False}


# ---------------------------------------------------------------------------
# Brute-force alert read (any authenticated role -- it's operational state)
# ---------------------------------------------------------------------------


@router.get("/alerts/brute-force")
def alerts_brute_force(_: dict = Depends(require_auth)) -> dict:
    return {"alerts": brute_force_alerts(), "threshold": IP_ALERT_THRESHOLD}


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
        "mfa_enabled": bool(live.get("mfa_enabled", False)),
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
    locked_until = doc.get("locked_until")
    if locked_until and hasattr(locked_until, "isoformat"):
        locked_until = locked_until.isoformat()
    return {
        "username": doc.get("username"),
        "role": doc.get("role"),
        "active": doc.get("active", True),
        "mfa_enabled": bool(doc.get("mfa_enabled", False)),
        "failed_login_count": int(doc.get("failed_login_count", 0)),
        "locked_until": locked_until,
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
