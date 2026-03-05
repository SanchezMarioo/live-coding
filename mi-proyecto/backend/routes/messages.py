from flask import Blueprint, jsonify, request, session

from db import get_db, utc_now_iso
from profile_utils import build_display_name, level_from_contributions
from validators import (
    ValidationError,
    enforce_allowed_fields,
    parse_positive_int,
    require_json_object,
    require_json_content_type,
    validate_category,
    validate_message_text,
)

bp = Blueprint("messages", __name__, url_prefix="/api/messages")


def _message_payload(row):
    contributions = int(row["author_contributions"]) if "author_contributions" in row.keys() else 0
    author_level = level_from_contributions(contributions)
    return {
        "id": row["id"],
        "userId": row["user_id"],
        "username": row["username"],
        "avatarUrl": row["avatar_url"],
        "authorDisplayName": build_display_name(row["first_name"], row["last_name"], row["username"]),
        "authorLevel": author_level,
        "authorContributions": contributions,
        "parentId": row["parent_id"],
        "category": row["category"],
        "text": row["text"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def _require_auth() -> int:
    user_id = session.get("user_id")
    if not user_id:
        raise PermissionError("Authentication required")
    return int(user_id)


@bp.get("")
def list_messages():
    category = request.args.get("category", "all")
    if category != "all":
        category = validate_category(category)

    limit = parse_positive_int(request.args.get("limit", 50), "limit", 1, 100)
    offset = parse_positive_int(request.args.get("offset", 0), "offset", 0, 10_000)

    db = get_db()

    where_sql = ""
    params = []
    if category != "all":
        where_sql = "WHERE m.category = ?"
        params.append(category)

    count_row = db.execute(
        f"""
        SELECT COUNT(*) AS total
        FROM messages m
        {where_sql}
        """,
        params,
    ).fetchone()

    rows = db.execute(
        f"""
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
            COALESCE(stats.msg_count, 0) AS author_contributions
        FROM messages m
        INNER JOIN users u ON u.id = m.user_id
        LEFT JOIN (
            SELECT user_id, COUNT(*) AS msg_count
            FROM messages
            GROUP BY user_id
        ) stats ON stats.user_id = u.id
        {where_sql}
        ORDER BY datetime(m.created_at) DESC, m.id DESC
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()

    messages = [_message_payload(row) for row in rows]

    return jsonify({
        "messages": messages,
        "total": count_row["total"],
        "limit": limit,
        "offset": offset,
    })


@bp.post("")
def create_message():
    user_id = _require_auth()
    require_json_content_type(request.content_type)
    payload = require_json_object(request.get_json(silent=True) or {})
    enforce_allowed_fields(payload, {"text", "category", "parentId"}, {"text"})

    text = validate_message_text(payload.get("text"))
    category = validate_category(payload.get("category", "general"))

    parent_id = payload.get("parentId")
    parent_value = None
    if parent_id is not None:
        parent_value = parse_positive_int(parent_id, "parentId", 1, 2_147_483_647)

    db = get_db()
    if parent_value is not None:
        parent = db.execute(
            "SELECT id FROM messages WHERE id = ?",
            (parent_value,),
        ).fetchone()
        if parent is None:
            return jsonify({"error": {"code": "not_found", "message": "Parent message not found"}}), 404

    now = utc_now_iso()
    cursor = db.execute(
        """
        INSERT INTO messages (user_id, parent_id, category, text, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, parent_value, category, text, now, now),
    )
    db.commit()

    message_id = cursor.lastrowid
    row = db.execute(
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
            COALESCE(stats.msg_count, 0) AS author_contributions
        FROM messages m
        INNER JOIN users u ON u.id = m.user_id
        LEFT JOIN (
            SELECT user_id, COUNT(*) AS msg_count
            FROM messages
            GROUP BY user_id
        ) stats ON stats.user_id = u.id
        WHERE m.id = ?
        """,
        (message_id,),
    ).fetchone()

    return jsonify({"message": _message_payload(row)}), 201


@bp.put("/<int:message_id>")
def update_message(message_id: int):
    user_id = _require_auth()
    require_json_content_type(request.content_type)
    payload = require_json_object(request.get_json(silent=True) or {})
    enforce_allowed_fields(payload, {"text"}, {"text"})

    text = validate_message_text(payload.get("text"))
    now = utc_now_iso()

    db = get_db()
    row = db.execute(
        "SELECT id, user_id FROM messages WHERE id = ?",
        (message_id,),
    ).fetchone()

    if row is None:
        return jsonify({"error": {"code": "not_found", "message": "Message not found"}}), 404

    if int(row["user_id"]) != user_id:
        return jsonify({"error": {"code": "forbidden", "message": "Not allowed to edit this message"}}), 403

    db.execute(
        "UPDATE messages SET text = ?, updated_at = ? WHERE id = ?",
        (text, now, message_id),
    )
    db.commit()

    refreshed = db.execute(
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
            COALESCE(stats.msg_count, 0) AS author_contributions
        FROM messages m
        INNER JOIN users u ON u.id = m.user_id
        LEFT JOIN (
            SELECT user_id, COUNT(*) AS msg_count
            FROM messages
            GROUP BY user_id
        ) stats ON stats.user_id = u.id
        WHERE m.id = ?
        """,
        (message_id,),
    ).fetchone()

    return jsonify({"message": _message_payload(refreshed)})


@bp.delete("/<int:message_id>")
def delete_message(message_id: int):
    user_id = _require_auth()
    db = get_db()

    row = db.execute(
        "SELECT id, user_id FROM messages WHERE id = ?",
        (message_id,),
    ).fetchone()

    if row is None:
        return jsonify({"error": {"code": "not_found", "message": "Message not found"}}), 404

    if int(row["user_id"]) != user_id:
        return jsonify({"error": {"code": "forbidden", "message": "Not allowed to delete this message"}}), 403

    db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    db.commit()

    return jsonify({"message": "Message deleted"})
