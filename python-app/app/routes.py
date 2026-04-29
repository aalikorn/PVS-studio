from flask import Blueprint, current_app, request, jsonify
from .db import get_db
from .models import User, Document
from .auth import create_token, require_auth
from sqlalchemy.orm import selectinload
from sqlalchemy import select

bp = Blueprint("api", __name__)

@bp.route("/", methods=["GET"])
def index():
    return jsonify({
        "project": "IDOR + Weak JWT demo",
        "mode": current_app.config.get("MODE", "unknown"),
        "endpoints": ["/health", "/login", "/users/<id>/docs"]
    })

@bp.route("/health", methods=["GET"])
def health():
    """
    Lightweight health-check endpoint.

    - Always returns JSON.
    - Checks basic application configuration.
    - Tries a very small DB query to verify connectivity.
      If DB check fails, status becomes "degraded" and HTTP 503 is returned.
    """
    status = "ok"
    db_status = "ok"

    try:
        db = get_db()
        # Very cheap query: just check we can talk to the database
        db.execute(select(1))
    except Exception as exc:
        status = "degraded"
        db_status = "error"
        current_app.logger.exception("Health-check DB probe failed: %%s", exc)

    payload = {
        "status": status,
        "mode": current_app.config.get("MODE", "unknown"),
        "db": db_status,
    }

    http_status = 200 if status == "ok" else 503
    current_app.logger.info("Health-check result: %%s", payload)
    return jsonify(payload), http_status
@bp.route("/login", methods=["POST"])
def login():
    """
    Simple login: provide username -> get JWT.
    NOTE: in the vulnerable demo we don't require password (intentional).
    """
    data = request.get_json() or {}
    username = data.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400

    db = get_db()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        return jsonify({"error": "user not found"}), 404

    token = create_token(user.id, user.username, user.role)
    return jsonify({"access_token": token})

@bp.route("/users/<int:user_id>/docs", methods=["GET"])
@require_auth
def get_user_docs(user_id):
    """
    IDOR demonstration:
    - in VULN mode: does NOT check that request.jwt_payload['user_id'] == user_id
    - in FIXED mode: enforces that the requester either is the owner or has role=admin
    """
    db = get_db()
    q = db.query(User).options(selectinload(User.docs)).filter(User.id == user_id)
    user = q.first()
    if not user:
        return jsonify({"error": "user not found"}), 404

    payload = request.jwt_payload

    if current_app.config["MODE"] == "VULN":
        # intentionally missing authorization check (IDOR)
        return jsonify({
            "requested_user_id": user.id,
            "username": user.username,
            "docs": [d.filename for d in user.docs],
            "token_payload": payload
        })

    # FIXED: enforce that token user_id == requested user_id OR role==admin
    if payload.get("user_id") != user.id and payload.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403

    return jsonify({
        "requested_user_id": user.id,
        "username": user.username,
        "docs": [d.filename for d in user.docs],
    })

def register_routes(app):
    app.register_blueprint(bp, url_prefix="")
