from flask import Blueprint, jsonify, request, session

from db import get_db
from profile_utils import build_display_name, level_from_contributions
from validators import (
    enforce_allowed_fields,
    parse_positive_int,
    require_json_content_type,
    require_json_object,
    validate_profile_media_url,
    validate_person_name,
    validate_username,
)

bp = Blueprint("profile", __name__, url_prefix="/api/profile")


def _require_auth() -> int:
    user_id = session.get("user_id")
    if not user_id:
        raise PermissionError("Authentication required")
    return int(user_id)


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
            u.created_at,
            u.last_login_at,
            COALESCE(stats.msg_count, 0) AS contributions,
            (SELECT COUNT(*) FROM user_friendships f WHERE f.user_id = u.id) AS friends_count,
            (SELECT COUNT(*) FROM user_follows f WHERE f.followee_user_id = u.id) AS followers_count,
            (SELECT COUNT(*) FROM user_follows f WHERE f.follower_user_id = u.id) AS following_count
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


def _fetch_user_by_username(db, username: str):
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
            u.created_at,
            u.last_login_at,
            COALESCE(stats.msg_count, 0) AS contributions,
            (SELECT COUNT(*) FROM user_friendships f WHERE f.user_id = u.id) AS friends_count,
            (SELECT COUNT(*) FROM user_follows f WHERE f.followee_user_id = u.id) AS followers_count,
            (SELECT COUNT(*) FROM user_follows f WHERE f.follower_user_id = u.id) AS following_count
        FROM users u
        LEFT JOIN (
            SELECT user_id, COUNT(*) AS msg_count
            FROM messages
            GROUP BY user_id
        ) stats ON stats.user_id = u.id
        WHERE lower(u.username) = lower(?)
        LIMIT 1
        """,
        (username,),
    ).fetchone()


def _is_friend(db, viewer_id: int | None, target_id: int) -> bool:
    if not viewer_id:
        return False
    row = db.execute(
        "SELECT 1 FROM user_friendships WHERE user_id = ? AND friend_user_id = ? LIMIT 1",
        (viewer_id, target_id),
    ).fetchone()
    return row is not None


def _is_following(db, viewer_id: int | None, target_id: int) -> bool:
    if not viewer_id:
        return False
    row = db.execute(
        "SELECT 1 FROM user_follows WHERE follower_user_id = ? AND followee_user_id = ? LIMIT 1",
        (viewer_id, target_id),
    ).fetchone()
    return row is not None


def _public_messages_for_user(db, user_id: int, limit: int, offset: int):
    rows = db.execute(
        """
        SELECT
            m.id,
            m.user_id,
            m.parent_id,
            m.category,
            m.text,
            m.created_at,
            m.updated_at,
            u.username,
            u.first_name,
            u.last_name,
            u.avatar_url,
            COALESCE(stats.msg_count, 0) AS contributions
        FROM messages m
        INNER JOIN users u ON u.id = m.user_id
        LEFT JOIN (
            SELECT user_id, COUNT(*) AS msg_count
            FROM messages
            GROUP BY user_id
        ) stats ON stats.user_id = u.id
        WHERE m.user_id = ?
        ORDER BY datetime(m.created_at) DESC, m.id DESC
        LIMIT ? OFFSET ?
        """,
        (user_id, limit, offset),
    ).fetchall()

    data = []
    for row in rows:
        contributions = int(row["contributions"])
        data.append(
            {
                "id": row["id"],
                "userId": row["user_id"],
                "username": row["username"],
                "authorDisplayName": build_display_name(row["first_name"], row["last_name"], row["username"]),
                "avatarUrl": row["avatar_url"],
                "authorContributions": contributions,
                "authorLevel": level_from_contributions(contributions),
                "parentId": row["parent_id"],
                "category": row["category"],
                "text": row["text"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }
        )
    return data


def _profile_payload(row, *, include_email: bool, viewer_id: int | None, db):
    contributions = int(row["contributions"])
    level = level_from_contributions(contributions)
    user_id = int(row["id"])
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"] if include_email else None,
        "firstName": row["first_name"],
        "lastName": row["last_name"],
        "avatarUrl": row["avatar_url"],
        "coverUrl": row["cover_url"],
        "displayName": build_display_name(row["first_name"], row["last_name"], row["username"]),
        "authProvider": row["auth_provider"],
        "contributions": contributions,
        "social": {
            "friends": int(row["friends_count"]),
            "followers": int(row["followers_count"]),
            "following": int(row["following_count"]),
            "viewerIsFriend": _is_friend(db, viewer_id, user_id),
            "viewerFollows": _is_following(db, viewer_id, user_id),
        },
        "level": level,
        "createdAt": row["created_at"],
        "lastLoginAt": row["last_login_at"],
    }


@bp.get("/me")
def get_profile_me():
    user_id = _require_auth()
    db = get_db()

    row = _fetch_user_with_stats(db, user_id)
    if row is None:
        session.clear()
        return jsonify({"error": {"code": "unauthorized", "message": "Authentication required"}}), 401

    return jsonify({"profile": _profile_payload(row, include_email=True, viewer_id=user_id, db=db)})


@bp.patch("/me")
def update_profile_me():
    user_id = _require_auth()
    require_json_content_type(request.content_type)
    payload = require_json_object(request.get_json(silent=True) or {})
    enforce_allowed_fields(payload, {"firstName", "lastName", "avatarUrl", "coverUrl"}, {"firstName", "lastName"})

    first_name = validate_person_name(payload.get("firstName"), "First name")
    last_name = validate_person_name(payload.get("lastName"), "Last name")
    avatar_url = validate_profile_media_url(payload.get("avatarUrl", ""), "Avatar URL")
    cover_url = validate_profile_media_url(payload.get("coverUrl", ""), "Cover URL")

    db = get_db()
    db.execute(
        "UPDATE users SET first_name = ?, last_name = ?, avatar_url = ?, cover_url = ? WHERE id = ?",
        (first_name, last_name, avatar_url, cover_url, user_id),
    )
    db.commit()

    row = _fetch_user_with_stats(db, user_id)
    return jsonify({"profile": _profile_payload(row, include_email=True, viewer_id=user_id, db=db)})


@bp.get("/<username>")
def get_public_profile(username: str):
    safe_username = validate_username(username)
    viewer_id = session.get("user_id")
    viewer_id_int = int(viewer_id) if viewer_id else None

    limit = parse_positive_int(request.args.get("limit", 50), "limit", 1, 100)
    offset = parse_positive_int(request.args.get("offset", 0), "offset", 0, 10_000)

    db = get_db()
    row = _fetch_user_by_username(db, safe_username)
    if row is None:
        return jsonify({"error": {"code": "not_found", "message": "Profile not found"}}), 404

    profile = _profile_payload(row, include_email=viewer_id_int == int(row["id"]), viewer_id=viewer_id_int, db=db)
    messages = _public_messages_for_user(db, int(row["id"]), limit, offset)

    return jsonify({"profile": profile, "messages": messages, "limit": limit, "offset": offset})


def _require_target_user(db, username: str, viewer_id: int):
    safe_username = validate_username(username)
    row = _fetch_user_by_username(db, safe_username)
    if row is None:
        return None
    if int(row["id"]) == viewer_id:
        raise ValueError("self")
    return row


@bp.post("/<username>/friend")
def add_friend(username: str):
    viewer_id = _require_auth()
    db = get_db()
    try:
        target = _require_target_user(db, username, viewer_id)
    except ValueError:
        return jsonify({"error": {"code": "validation_error", "message": "Cannot friend yourself"}}), 400
    if target is None:
        return jsonify({"error": {"code": "not_found", "message": "Profile not found"}}), 404

    db.execute(
        "INSERT OR IGNORE INTO user_friendships (user_id, friend_user_id, created_at) VALUES (?, ?, datetime('now'))",
        (viewer_id, int(target["id"])),
    )
    db.execute(
        "INSERT OR IGNORE INTO user_friendships (user_id, friend_user_id, created_at) VALUES (?, ?, datetime('now'))",
        (int(target["id"]), viewer_id),
    )
    db.commit()

    refreshed = _fetch_user_by_username(db, target["username"])
    return jsonify({"profile": _profile_payload(refreshed, include_email=False, viewer_id=viewer_id, db=db)})


@bp.delete("/<username>/friend")
def remove_friend(username: str):
    viewer_id = _require_auth()
    db = get_db()
    try:
        target = _require_target_user(db, username, viewer_id)
    except ValueError:
        return jsonify({"error": {"code": "validation_error", "message": "Cannot unfriend yourself"}}), 400
    if target is None:
        return jsonify({"error": {"code": "not_found", "message": "Profile not found"}}), 404

    db.execute(
        "DELETE FROM user_friendships WHERE user_id = ? AND friend_user_id = ?",
        (viewer_id, int(target["id"])),
    )
    db.execute(
        "DELETE FROM user_friendships WHERE user_id = ? AND friend_user_id = ?",
        (int(target["id"]), viewer_id),
    )
    db.commit()

    refreshed = _fetch_user_by_username(db, target["username"])
    return jsonify({"profile": _profile_payload(refreshed, include_email=False, viewer_id=viewer_id, db=db)})


@bp.post("/<username>/follow")
def follow_user(username: str):
    viewer_id = _require_auth()
    db = get_db()
    try:
        target = _require_target_user(db, username, viewer_id)
    except ValueError:
        return jsonify({"error": {"code": "validation_error", "message": "Cannot follow yourself"}}), 400
    if target is None:
        return jsonify({"error": {"code": "not_found", "message": "Profile not found"}}), 404

    db.execute(
        "INSERT OR IGNORE INTO user_follows (follower_user_id, followee_user_id, created_at) VALUES (?, ?, datetime('now'))",
        (viewer_id, int(target["id"])),
    )
    db.commit()

    refreshed = _fetch_user_by_username(db, target["username"])
    return jsonify({"profile": _profile_payload(refreshed, include_email=False, viewer_id=viewer_id, db=db)})


@bp.delete("/<username>/follow")
def unfollow_user(username: str):
    viewer_id = _require_auth()
    db = get_db()
    try:
        target = _require_target_user(db, username, viewer_id)
    except ValueError:
        return jsonify({"error": {"code": "validation_error", "message": "Cannot unfollow yourself"}}), 400
    if target is None:
        return jsonify({"error": {"code": "not_found", "message": "Profile not found"}}), 404

    db.execute(
        "DELETE FROM user_follows WHERE follower_user_id = ? AND followee_user_id = ?",
        (viewer_id, int(target["id"])),
    )
    db.commit()

    refreshed = _fetch_user_by_username(db, target["username"])
    return jsonify({"profile": _profile_payload(refreshed, include_email=False, viewer_id=viewer_id, db=db)})
