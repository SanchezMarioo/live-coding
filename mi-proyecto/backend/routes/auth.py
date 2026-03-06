import sqlite3
import secrets
import time
import json
import hashlib
import base64
import hmac
import struct
import io
from urllib.parse import quote

import qrcode
from collections import defaultdict, deque
from threading import Lock
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Blueprint, jsonify, request, session
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from werkzeug.security import check_password_hash, generate_password_hash

from flask import current_app

from db import get_db, utc_now_iso
from profile_utils import build_display_name, level_from_contributions
from validators import (
    ValidationError,
    enforce_allowed_fields,
    require_json_object,
    require_json_content_type,
    sanitize_text,
    validate_auth_intent,
    validate_email,
    validate_google_credential,
    validate_google_subject,
    validate_login_identifier,
    validate_password,
    validate_person_name,
    validate_totp_code,
    validate_username,
)

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

_auth_failures = defaultdict(deque)
_auth_lockouts = {}
_auth_state_lock = Lock()
_PENDING_2FA_TTL_SECONDS = 300
_TOTP_PERIOD_SECONDS = 30
_TOTP_DIGITS = 6


def _ensure_csrf_token() -> str:
    token = str(session.get("csrf_token", ""))
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _rotate_csrf_token() -> str:
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def _user_agent_fingerprint() -> str:
    user_agent = request.headers.get("User-Agent", "")[:512]
    return hashlib.sha256(user_agent.encode("utf-8", "ignore")).hexdigest()


def _set_authenticated_session(user_id: int) -> str:
    session.clear()
    session["user_id"] = int(user_id)
    csrf_token = _rotate_csrf_token()
    session["ua_fingerprint"] = _user_agent_fingerprint()
    session.permanent = True
    return csrf_token


def _generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _normalize_base32_secret(secret: str) -> bytes:
    sanitized = "".join(ch for ch in secret.upper() if ch.isalnum())
    padded = sanitized + ("=" * ((8 - len(sanitized) % 8) % 8))
    return base64.b32decode(padded, casefold=True)


def _totp_code(secret: str, for_timestamp: int) -> str:
    key = _normalize_base32_secret(secret)
    counter = int(for_timestamp // _TOTP_PERIOD_SECONDS)
    message = struct.pack(">Q", counter)
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    code_int = binary % (10 ** _TOTP_DIGITS)
    return str(code_int).zfill(_TOTP_DIGITS)


def _verify_totp(secret: str, code: str, *, skew_steps: int = 1) -> bool:
    now = int(time.time())
    for step in range(-skew_steps, skew_steps + 1):
        expected = _totp_code(secret, now + (step * _TOTP_PERIOD_SECONDS))
        if hmac.compare_digest(expected, code):
            return True
    return False


def _totp_qr_data_url(otpauth_url: str) -> str:
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=2)
    qr.add_data(otpauth_url)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _client_ip() -> str:
    return (request.remote_addr or "unknown").strip()


def _is_locked(auth_key: str, window_seconds: int, lock_seconds: int, max_attempts: int) -> bool:
    now = time.monotonic()
    with _auth_state_lock:
        lock_until = _auth_lockouts.get(auth_key)
        if lock_until and lock_until > now:
            return True
        if lock_until and lock_until <= now:
            _auth_lockouts.pop(auth_key, None)

        queue = _auth_failures[auth_key]
        while queue and (now - queue[0]) > window_seconds:
            queue.popleft()
        if len(queue) >= max_attempts:
            _auth_lockouts[auth_key] = now + lock_seconds
            return True
    return False


def _record_failure(auth_key: str, window_seconds: int) -> None:
    now = time.monotonic()
    with _auth_state_lock:
        queue = _auth_failures[auth_key]
        while queue and (now - queue[0]) > window_seconds:
            queue.popleft()
        queue.append(now)


def _clear_failures(auth_key: str) -> None:
    with _auth_state_lock:
        _auth_failures.pop(auth_key, None)
        _auth_lockouts.pop(auth_key, None)


def _public_user(row):
    contributions = int(row["contributions"]) if "contributions" in row.keys() else 0
    level = level_from_contributions(contributions)
    two_factor_enabled = bool(row["two_factor_enabled"]) if "two_factor_enabled" in row.keys() else False
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "firstName": row["first_name"],
        "lastName": row["last_name"],
        "avatarUrl": row["avatar_url"],
        "coverUrl": row["cover_url"],
        "displayName": build_display_name(row["first_name"], row["last_name"], row["username"]),
        "authProvider": row["auth_provider"],
        "twoFactorEnabled": two_factor_enabled,
        "contributions": contributions,
        "level": level,
        "createdAt": row["created_at"],
        "lastLoginAt": row["last_login_at"],
    }


def _fetch_user_with_stats(db, user_id: int):
    return db.execute(
        """
        SELECT
            u.id,
            u.username,
            u.email,
            u.first_name,
            u.last_name,
            u.avatar_url,
            u.cover_url,
            u.auth_provider,
            u.two_factor_enabled,
            u.created_at,
            u.last_login_at,
            COALESCE(stats.msg_count, 0) AS contributions
        FROM users u
        LEFT JOIN (
            SELECT user_id, COUNT(*) AS msg_count
            FROM messages
            GROUP BY user_id
        ) stats ON stats.user_id = u.id
        WHERE u.id = ?
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()


def _fetch_user_for_auth(db, user_id: int):
    return db.execute(
        """
        SELECT id, username, email, auth_provider, two_factor_secret, two_factor_enabled
        FROM users
        WHERE id = ?
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()


def _build_unique_username(db, base_value: str) -> str:
    base = "".join(ch for ch in base_value.lower() if ch.isalnum() or ch in "_-")
    if not base:
        base = "usergoogle"
    base = base[:20]

    candidate = base
    counter = 1
    while True:
        row = db.execute(
            "SELECT id FROM users WHERE lower(username) = lower(?) LIMIT 1",
            (candidate,),
        ).fetchone()
        if row is None:
            return candidate

        suffix = str(counter)
        trimmed = base[: max(3, 20 - len(suffix))]
        candidate = f"{trimmed}{suffix}"
        counter += 1


def _fetch_google_userinfo(access_token: str) -> dict:
    req = Request(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        method="GET",
    )
    try:
        with urlopen(req, timeout=5) as response:
            payload = response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise ValidationError("Invalid Google token") from exc

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValidationError("Invalid Google token") from exc

    if not isinstance(data, dict):
        raise ValidationError("Invalid Google token")

    return data


def _resolve_google_identity(credential: str, google_client_id: str) -> dict:
    if credential.count(".") == 2:
        try:
            return id_token.verify_oauth2_token(
                credential,
                google_requests.Request(),
                google_client_id,
            )
        except Exception as exc:
            raise ValidationError("Invalid Google token") from exc

    return _fetch_google_userinfo(credential)


@bp.post("/register")
def register():
    require_json_content_type(request.content_type)
    payload = require_json_object(request.get_json(silent=True) or {})
    enforce_allowed_fields(
        payload,
        {"email", "username", "firstName", "lastName", "password"},
        {"email", "username", "firstName", "lastName", "password"},
    )

    email = validate_email(payload.get("email"))
    username = validate_username(payload.get("username"))
    first_name = validate_person_name(payload.get("firstName"), "First name")
    last_name = validate_person_name(payload.get("lastName"), "Last name")
    password = validate_password(payload.get("password"))

    now = utc_now_iso()
    password_hash = generate_password_hash(password)

    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO users (username, email, first_name, last_name, password_hash, auth_provider, created_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (username, email, first_name, last_name, password_hash, "local", now, now),
        )
        db.commit()
    except sqlite3.IntegrityError as exc:
        message = str(exc).lower()
        if "users.username" in message:
            raise ValidationError("Username is already in use") from exc
        if "users.email" in message:
            raise ValidationError("Email is already registered") from exc
        raise ValidationError("User already exists") from exc

    row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()

    csrf_token = _set_authenticated_session(int(row["id"]))

    user = _fetch_user_with_stats(db, row["id"])
    return jsonify({"user": _public_user(user), "csrfToken": csrf_token}), 201


@bp.post("/login")
def login():
    require_json_content_type(request.content_type)
    payload = require_json_object(request.get_json(silent=True) or {})
    enforce_allowed_fields(payload, {"username", "password"}, {"username", "password"})

    identifier = payload.get("username")
    password = payload.get("password")

    candidate = validate_login_identifier(identifier)
    password = sanitize_text(password, 128)
    if len(password) < 1:
        raise ValidationError("Password is required")

    auth_key = f"login:{_client_ip()}:{candidate}"
    if _is_locked(auth_key, 300, 900, 8):
        return jsonify({"error": {"code": "auth_locked", "message": "Too many failed attempts, try later"}}), 429

    db = get_db()
    row = db.execute(
        """
        SELECT id, username, email, first_name, last_name, password_hash, auth_provider, two_factor_enabled, created_at, last_login_at
        FROM users
        WHERE lower(username) = ? OR lower(email) = ?
        LIMIT 1
        """,
        (candidate, candidate),
    ).fetchone()

    if row is not None and row["auth_provider"] == "google":
        _record_failure(auth_key, 300)
        return (
            jsonify(
                {
                    "error": {
                        "code": "google_auth_required",
                        "message": "This account uses Google sign-in",
                    }
                }
            ),
            401,
        )

    if row is None or not check_password_hash(row["password_hash"], password):
        _record_failure(auth_key, 300)
        return jsonify({"error": {"code": "invalid_credentials", "message": "Invalid credentials"}}), 401

    _clear_failures(auth_key)

    now = utc_now_iso()
    db.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now, row["id"]))
    db.commit()

    refreshed = _fetch_user_with_stats(db, row["id"])

    if bool(row["two_factor_enabled"]) and row["auth_provider"] == "local":
        session.clear()
        session["pending_2fa_user_id"] = int(row["id"])
        session["pending_2fa_until"] = int(time.time()) + _PENDING_2FA_TTL_SECONDS
        session["pending_2fa_ua"] = _user_agent_fingerprint()
        return jsonify({"twoFactorRequired": True}), 202

    csrf_token = _set_authenticated_session(int(row["id"]))

    return jsonify({"user": _public_user(refreshed), "csrfToken": csrf_token})


@bp.post("/google")
def google_auth():
    require_json_content_type(request.content_type)
    payload = require_json_object(request.get_json(silent=True) or {})
    enforce_allowed_fields(payload, {"credential", "intent"}, {"credential"})

    credential = validate_google_credential(payload.get("credential"))
    intent = validate_auth_intent(payload.get("intent", "login"))

    auth_key = f"google:{_client_ip()}"
    if _is_locked(auth_key, 300, 900, 10):
        return jsonify({"error": {"code": "auth_locked", "message": "Too many failed attempts, try later"}}), 429

    google_client_id = current_app.config.get("GOOGLE_CLIENT_ID", "")
    if not google_client_id:
        return (
            jsonify(
                {
                    "error": {
                        "code": "google_not_configured",
                        "message": "Google auth is not configured",
                    }
                }
            ),
            503,
        )

    try:
        token_info = _resolve_google_identity(credential, google_client_id)
    except ValidationError as exc:
        _record_failure(auth_key, 300)
        raise exc

    if not token_info.get("email_verified"):
        _record_failure(auth_key, 300)
        return jsonify({"error": {"code": "invalid_google_email", "message": "Google email is not verified"}}), 401

    email = validate_email(token_info.get("email"))
    google_sub = validate_google_subject(token_info.get("sub"))
    name = token_info.get("name") or email.split("@")[0]
    first_name = validate_person_name(token_info.get("given_name") or name.split(" ")[0], "First name")
    family_name = token_info.get("family_name") or " ".join(name.split(" ")[1:])
    last_name = validate_person_name(family_name, "Last name", required=False)

    db = get_db()
    existing = db.execute(
        "SELECT id, username, email, first_name, last_name, auth_provider, google_sub, created_at, last_login_at FROM users WHERE lower(email) = ? LIMIT 1",
        (email.lower(),),
    ).fetchone()

    if intent == "register" and existing is not None:
        _record_failure(auth_key, 300)
        return jsonify({"error": {"code": "email_taken", "message": "Email is already registered"}}), 409

    if intent == "login" and existing is None:
        _record_failure(auth_key, 300)
        return jsonify({"error": {"code": "not_found", "message": "Google account is not registered"}}), 404

    if existing is not None and existing["auth_provider"] != "google":
        _record_failure(auth_key, 300)
        return jsonify({"error": {"code": "provider_mismatch", "message": "Account is not a Google account"}}), 409

    if existing is not None and existing["google_sub"] and existing["google_sub"] != google_sub:
        _record_failure(auth_key, 300)
        return jsonify({"error": {"code": "google_subject_mismatch", "message": "Google account subject mismatch"}}), 401

    now = utc_now_iso()
    if existing is None:
        username = _build_unique_username(db, name)
        unusable_password = generate_password_hash(secrets.token_urlsafe(48))
        cursor = db.execute(
            """
            INSERT INTO users (username, email, first_name, last_name, password_hash, auth_provider, google_sub, created_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (username, email, first_name, last_name, unusable_password, "google", google_sub, now, now),
        )
        user_id = cursor.lastrowid
    else:
        user_id = existing["id"]
        db.execute(
            "UPDATE users SET auth_provider = 'google', google_sub = ?, first_name = ?, last_name = ?, last_login_at = ? WHERE id = ?",
            (google_sub, first_name, last_name, now, user_id),
        )

    db.commit()

    if user_id is None:
        raise ValidationError("Invalid user id")

    user = _fetch_user_with_stats(db, int(user_id))

    csrf_token = _set_authenticated_session(int(user_id))
    _clear_failures(auth_key)

    return jsonify({"user": _public_user(user), "csrfToken": csrf_token})


@bp.post("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@bp.post("/2fa/setup")
def setup_two_factor():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401

    db = get_db()
    row = _fetch_user_for_auth(db, int(user_id))
    if row is None:
        session.clear()
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401

    if row["auth_provider"] != "local":
        return jsonify({"error": {"code": "forbidden", "message": "Two-factor setup is only available for local accounts"}}), 403

    secret = row["two_factor_secret"] or _generate_totp_secret()
    if not row["two_factor_secret"]:
        db.execute("UPDATE users SET two_factor_secret = ? WHERE id = ?", (secret, int(user_id)))
        db.commit()

    issuer = "Retro Forum"
    label = quote(f"{issuer}:{row['username']}")
    params = f"secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    otpauth_url = f"otpauth://totp/{label}?{params}"
    qr_data_url = _totp_qr_data_url(otpauth_url)

    return jsonify(
        {
            "twoFactor": {
                "enabled": bool(row["two_factor_enabled"]),
                "secret": secret,
                "otpauthUrl": otpauth_url,
                "qrDataUrl": qr_data_url,
            }
        }
    )


@bp.post("/2fa/enable")
def enable_two_factor():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401

    require_json_content_type(request.content_type)
    payload = require_json_object(request.get_json(silent=True) or {})
    enforce_allowed_fields(payload, {"code"}, {"code"})
    code = validate_totp_code(payload.get("code"))

    db = get_db()
    row = _fetch_user_for_auth(db, int(user_id))
    if row is None:
        session.clear()
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401
    if row["auth_provider"] != "local":
        return jsonify({"error": {"code": "forbidden", "message": "Two-factor setup is only available for local accounts"}}), 403

    secret = row["two_factor_secret"] or _generate_totp_secret()
    if not _verify_totp(secret, code):
        return jsonify({"error": {"code": "invalid_2fa_code", "message": "Invalid two-factor code"}}), 401

    db.execute("UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?", (secret, int(user_id)))
    db.commit()

    return jsonify({"twoFactor": {"enabled": True}})


@bp.post("/2fa/disable")
def disable_two_factor():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401

    require_json_content_type(request.content_type)
    payload = require_json_object(request.get_json(silent=True) or {})
    enforce_allowed_fields(payload, {"code"}, {"code"})
    code = validate_totp_code(payload.get("code"))

    db = get_db()
    row = _fetch_user_for_auth(db, int(user_id))
    if row is None:
        session.clear()
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401

    secret = row["two_factor_secret"]
    if not row["two_factor_enabled"] or not secret:
        return jsonify({"twoFactor": {"enabled": False}})

    if not _verify_totp(secret, code):
        return jsonify({"error": {"code": "invalid_2fa_code", "message": "Invalid two-factor code"}}), 401

    db.execute("UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?", (int(user_id),))
    db.commit()

    return jsonify({"twoFactor": {"enabled": False}})


@bp.post("/2fa/verify-login")
def verify_two_factor_login():
    require_json_content_type(request.content_type)
    payload = require_json_object(request.get_json(silent=True) or {})
    enforce_allowed_fields(payload, {"code"}, {"code"})
    code = validate_totp_code(payload.get("code"))

    pending_user_id = session.get("pending_2fa_user_id")
    pending_until = int(session.get("pending_2fa_until", 0))
    pending_ua = str(session.get("pending_2fa_ua", ""))
    if not pending_user_id or int(time.time()) > pending_until:
        session.clear()
        return jsonify({"error": {"code": "unauthorized", "message": "2FA login challenge expired"}}), 401

    if pending_ua and not hmac.compare_digest(pending_ua, _user_agent_fingerprint()):
        session.clear()
        return jsonify({"error": {"code": "unauthorized", "message": "2FA login challenge invalid"}}), 401

    db = get_db()
    row = _fetch_user_for_auth(db, int(pending_user_id))
    if row is None or not row["two_factor_enabled"] or not row["two_factor_secret"]:
        session.clear()
        return jsonify({"error": {"code": "unauthorized", "message": "2FA login challenge invalid"}}), 401

    if not _verify_totp(str(row["two_factor_secret"]), code):
        return jsonify({"error": {"code": "invalid_2fa_code", "message": "Invalid two-factor code"}}), 401

    csrf_token = _set_authenticated_session(int(pending_user_id))
    user = _fetch_user_with_stats(db, int(pending_user_id))
    return jsonify({"user": _public_user(user), "csrfToken": csrf_token})


@bp.get("/me")
def me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401

    db = get_db()
    row = _fetch_user_with_stats(db, user_id)

    if row is None:
        session.clear()
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401

    csrf_token = _ensure_csrf_token()
    if not session.get("ua_fingerprint"):
        session["ua_fingerprint"] = _user_agent_fingerprint()
    return jsonify({"user": _public_user(row), "csrfToken": csrf_token})
