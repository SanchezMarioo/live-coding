from http import HTTPStatus
from collections import defaultdict, deque
from threading import Lock
import time
import secrets
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

import db
from config import Config
from routes import auth, messages, profile
from validators import ValidationError


_rate_limit_store = defaultdict(deque)
_rate_limit_lock = Lock()


def _check_rate_limit(key: str, window_seconds: int, max_attempts: int) -> bool:
    now = time.monotonic()
    with _rate_limit_lock:
        queue = _rate_limit_store[key]
        while queue and (now - queue[0]) > window_seconds:
            queue.popleft()
        if len(queue) >= max_attempts:
            return False
        queue.append(now)
        return True


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    weak_secrets = {"change-this-in-production", "dev-change-me", "secret", "password"}
    current_secret = str(app.config.get("SECRET_KEY", ""))
    if len(current_secret) < 32 or current_secret in weak_secrets:
        # Fallback to an ephemeral strong key to avoid running with known weak secrets.
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        app.logger.warning("Weak SECRET_KEY detected; using ephemeral runtime key.")

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_REFRESH_EACH_REQUEST"] = False

    CORS(
        app,
        supports_credentials=True,
        origins=app.config["CORS_ORIGINS"],
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    db.init_app(app)

    with app.app_context():
        db.init_db()

    app.register_blueprint(auth.bp)
    app.register_blueprint(messages.bp)
    app.register_blueprint(profile.bp)

    @app.before_request
    def enforce_rate_limits():
        if not request.path.startswith("/api/"):
            return None

        client_ip = (request.remote_addr or "unknown").strip()
        method = request.method.upper()
        path = request.path

        if method in {"POST", "PUT", "DELETE", "PATCH"} and path.startswith("/api/"):
            origin = request.headers.get("Origin", "").strip()
            referer = request.headers.get("Referer", "").strip()
            allowed_origins = set(app.config["CORS_ORIGINS"])

            referer_origin = ""
            if referer:
                parsed = urlparse(referer)
                if parsed.scheme and parsed.netloc:
                    referer_origin = f"{parsed.scheme}://{parsed.netloc}"

            # For cookie-authenticated state-changing requests, require same trusted origin.
            if origin:
                if origin not in allowed_origins:
                    return jsonify({"error": {"code": "csrf_blocked", "message": "Origin not allowed"}}), 403
            elif referer_origin:
                if referer_origin not in allowed_origins:
                    return jsonify({"error": {"code": "csrf_blocked", "message": "Referer not allowed"}}), 403
            else:
                return jsonify({"error": {"code": "csrf_blocked", "message": "Missing origin headers"}}), 403

        auth_paths = {"/api/auth/login", "/api/auth/register", "/api/auth/google"}
        write_paths = {"/api/messages"}

        if method == "POST" and path in auth_paths:
            allowed = _check_rate_limit(
                f"auth:{client_ip}:{path}",
                app.config["AUTH_RATE_LIMIT_WINDOW_SECONDS"],
                app.config["AUTH_RATE_LIMIT_MAX_ATTEMPTS"],
            )
            if not allowed:
                return jsonify({"error": {"code": "rate_limited", "message": "Too many auth attempts"}}), 429

        if (method == "POST" and path in write_paths) or (method in {"PUT", "DELETE"} and path.startswith("/api/messages/")):
            allowed = _check_rate_limit(
                f"write:{client_ip}:{path.split('/')[2]}",
                app.config["WRITE_RATE_LIMIT_WINDOW_SECONDS"],
                app.config["WRITE_RATE_LIMIT_MAX_ATTEMPTS"],
            )
            if not allowed:
                return jsonify({"error": {"code": "rate_limited", "message": "Too many write attempts"}}), 429

        return None

    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cross-Origin-Resource-Policy"] = "same-site"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        if request.path.startswith("/api/auth/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.errorhandler(ValidationError)
    def handle_validation_error(error: ValidationError):
        return jsonify({"error": {"code": "validation_error", "message": str(error)}}), 400

    @app.errorhandler(PermissionError)
    def handle_permission_error(_error: PermissionError):
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        message = error.description if isinstance(error.description, str) else "Request failed"
        status = error.code if isinstance(error.code, int) else HTTPStatus.BAD_REQUEST
        return jsonify({"error": {"code": error.name.lower().replace(" ", "_"), "message": message}}), status

    @app.errorhandler(Exception)
    def handle_unexpected_error(_error: Exception):
        return (
            jsonify({"error": {"code": "internal_error", "message": "Internal server error"}}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)
