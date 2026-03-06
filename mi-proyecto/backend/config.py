import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production")
    DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join("data", "app.db"))
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "484532142714-gas9d18cc01shpk4j2lvsaleut3t00i9.apps.googleusercontent.com")

    # Cookie-based auth settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "forum_session")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.getenv("SESSION_HOURS", "12")))

    # Disable verbose errors in API responses
    PROPAGATE_EXCEPTIONS = False
    TRAP_HTTP_EXCEPTIONS = False
    TRAP_BAD_REQUEST_ERRORS = False

    # Request hardening
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 1024 * 1024))  # 1MB
    JSON_SORT_KEYS = False

    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:8080").split(",")
        if origin.strip()
    ]

    TRUSTED_HOSTS = {
        host.strip().lower()
        for host in os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1,api").split(",")
        if host.strip()
    }

    AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("AUTH_RATE_LIMIT_WINDOW_SECONDS", "60"))
    AUTH_RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("AUTH_RATE_LIMIT_MAX_ATTEMPTS", "10"))
    WRITE_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("WRITE_RATE_LIMIT_WINDOW_SECONDS", "30"))
    WRITE_RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("WRITE_RATE_LIMIT_MAX_ATTEMPTS", "30"))
