import re
import base64
import binascii
from urllib.parse import urlparse, unquote
from typing import Any

ALLOWED_CATEGORIES = {"general", "anuncios", "preguntas", "ideas", "offtopic"}

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
_HAS_LETTER_RE = re.compile(r"[A-Za-z]")
_HAS_DIGIT_RE = re.compile(r"\d")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_PERSON_NAME_RE = re.compile(r"^[A-Za-zÀ-ÿ' -]{1,50}$")
_DATA_IMAGE_RE = re.compile(r"^data:(image\/(png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$", re.IGNORECASE)
_DANGEROUS_URL_EXT_RE = re.compile(
    r"\.(php\d?|phtml|phar|cgi|pl|asp|aspx|jsp|js|html?|svg)$",
    re.IGNORECASE,
)
_DANGEROUS_URL_TOKEN_RE = re.compile(
    r"\.(php\d?|phtml|phar|cgi|pl|asp|aspx|jsp|js|html?|svg)(?:$|[/?#&=])",
    re.IGNORECASE,
)
_ALLOWED_URL_IMAGE_EXT_RE = re.compile(r"\.(png|jpe?g|webp|gif)$", re.IGNORECASE)
_MAX_PROFILE_MEDIA_BYTES = 3 * 1024 * 1024
_EMBEDDED_SCRIPT_PATTERNS = (
    b"<?php",
    b"<script",
    b"<%",
    b"#!/usr/bin/php",
)


class ValidationError(ValueError):
    pass


def require_json_object(payload: Any) -> dict:
    if not isinstance(payload, dict):
        raise ValidationError("JSON body must be an object")
    return payload


def require_json_content_type(content_type: Any) -> None:
    if not isinstance(content_type, str):
        raise ValidationError("Content-Type must be application/json")
    if content_type.split(";")[0].strip().lower() != "application/json":
        raise ValidationError("Content-Type must be application/json")


def enforce_allowed_fields(payload: dict, allowed_fields: set[str], required_fields: set[str] | None = None) -> None:
    unknown = set(payload.keys()) - allowed_fields
    if unknown:
        raise ValidationError("Unexpected fields in request body")

    if required_fields:
        missing = [field for field in required_fields if field not in payload]
        if missing:
            raise ValidationError("Missing required fields")


def sanitize_text(value: Any, max_len: int) -> str:
    if not isinstance(value, str):
        raise ValidationError("Invalid field type")

    trimmed = value.replace("\x00", "").strip()
    normalized = " ".join(trimmed.split())
    if _CONTROL_CHAR_RE.search(normalized):
        raise ValidationError("Invalid control characters in input")
    if len(normalized) > max_len:
        raise ValidationError(f"Field exceeds max length {max_len}")

    return normalized


def validate_email(email: Any) -> str:
    value = sanitize_text(email, 254).lower()
    if not _EMAIL_RE.match(value):
        raise ValidationError("Invalid email format")
    return value


def validate_username(username: Any) -> str:
    value = sanitize_text(username, 20)
    if not _USERNAME_RE.match(value):
        raise ValidationError("Username must be 3-20 chars using letters, numbers, _ or -")
    return value


def validate_password(password: Any) -> str:
    value = sanitize_text(password, 128)
    if len(value) < 6:
        raise ValidationError("Password must be at least 6 characters")
    if not _HAS_LETTER_RE.search(value) or not _HAS_DIGIT_RE.search(value):
        raise ValidationError("Password must include at least one letter and one number")
    return value


def validate_person_name(name: Any, field_label: str = "Name", required: bool = True) -> str:
    value = sanitize_text(name, 50)
    if not value:
        if required:
            raise ValidationError(f"{field_label} is required")
        return ""
    if not _PERSON_NAME_RE.match(value):
        raise ValidationError(f"{field_label} contains invalid characters")
    return value


def validate_login_identifier(identifier: Any) -> str:
    value = sanitize_text(identifier, 254).lower()
    if len(value) < 3:
        raise ValidationError("Username or email is required")
    return value


def validate_google_credential(credential: Any) -> str:
    value = sanitize_text(credential, 4096)
    if len(value) < 20 or " " in value:
        raise ValidationError("Invalid Google token")
    return value


def validate_auth_intent(intent: Any) -> str:
    value = sanitize_text(intent, 20).lower()
    if value not in {"login", "register"}:
        raise ValidationError("Invalid auth intent")
    return value


def validate_google_subject(subject: Any) -> str:
    value = sanitize_text(subject, 255)
    if len(value) < 6:
        raise ValidationError("Invalid Google account subject")
    return value


def validate_totp_code(code: Any) -> str:
    value = sanitize_text(code, 16)
    if not re.fullmatch(r"\d{6}", value):
        raise ValidationError("Invalid two-factor code")
    return value


def validate_category(category: Any) -> str:
    value = sanitize_text(category, 20).lower()
    if value not in ALLOWED_CATEGORIES:
        raise ValidationError("Invalid category")
    return value


def validate_message_text(text: Any) -> str:
    value = sanitize_text(text, 500)
    if len(value) < 3:
        raise ValidationError("Message must be between 3 and 500 characters")
    if "<" in value or ">" in value:
        raise ValidationError("HTML tags are not allowed in messages")
    return value


def validate_profile_media_url(value: Any, field_label: str) -> str:
    if value is None:
        return ""

    text = sanitize_text(value, 1_000_000)
    if not text:
        return ""

    lower = text.lower()
    if lower.startswith("http://") or lower.startswith("https://"):
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValidationError(f"{field_label} must be a valid image URL")

        path = unquote(parsed.path or "")
        query = unquote(parsed.query or "")
        fragment = unquote(parsed.fragment or "")

        if (
            _DANGEROUS_URL_EXT_RE.search(path)
            or _DANGEROUS_URL_TOKEN_RE.search(query)
            or _DANGEROUS_URL_TOKEN_RE.search(fragment)
        ):
            raise ValidationError(f"{field_label} has an unsupported file extension")

        # If URL includes an extension, it must look like an image extension.
        if "." in path.rsplit("/", 1)[-1] and not _ALLOWED_URL_IMAGE_EXT_RE.search(path):
            raise ValidationError(f"{field_label} must point to a valid image extension")

        return text

    match = _DATA_IMAGE_RE.match(text)
    if match:
        mime = match.group(1).lower()
        payload = match.group(3)

        try:
            raw = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValidationError(f"{field_label} contains invalid base64 data") from exc

        if len(raw) == 0 or len(raw) > _MAX_PROFILE_MEDIA_BYTES:
            raise ValidationError(f"{field_label} exceeds max size of 3MB")

        raw_lower = raw.lower()
        if any(pattern in raw_lower for pattern in _EMBEDDED_SCRIPT_PATTERNS):
            raise ValidationError(f"{field_label} contains embedded script content")

        # Validate magic bytes so non-image payloads cannot masquerade as images.
        if mime == "image/png" and not raw.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValidationError(f"{field_label} is not a valid PNG image")
        if mime == "image/jpeg" and not raw.startswith(b"\xff\xd8\xff"):
            raise ValidationError(f"{field_label} is not a valid JPEG image")
        if mime == "image/webp" and not (raw.startswith(b"RIFF") and raw[8:12] == b"WEBP"):
            raise ValidationError(f"{field_label} is not a valid WEBP image")

        return text

    raise ValidationError(f"{field_label} must be a valid image URL or data URL")


def validate_social_action(value: Any) -> str:
    action = sanitize_text(value, 12).lower()
    if action not in {"add", "remove"}:
        raise ValidationError("Action must be add or remove")
    return action


def parse_positive_int(value: Any, field: str, min_value: int = 0, max_value: int = 100) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field} must be an integer") from exc

    if parsed < min_value or parsed > max_value:
        raise ValidationError(f"{field} must be between {min_value} and {max_value}")

    return parsed
