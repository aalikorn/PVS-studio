import jwt
from flask import current_app
from functools import wraps
from flask import request, jsonify

def create_token(user_id: int, username: str, role: str):
    cfg = current_app.config
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
    }
    if cfg["MODE"] == "VULN":
        # weak secret in vulns mode
        token = jwt.encode(payload, cfg["WEAK_SECRET"], algorithm="HS256")
    else:
        token = jwt.encode(payload, cfg["STRONG_SECRET"], algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def decode_token(raw_token: str):
    cfg = current_app.config
    if not raw_token:
        return None
    parts = raw_token.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1]

    if cfg["MODE"] == "VULN":
        # INTENTIONALLY vulnerable: skip signature verification
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        except Exception:
            return None
    else:
        # FIXED: strictly verify signature + algorithms
        try:
            payload = jwt.decode(token, cfg["STRONG_SECRET"], algorithms=cfg["JWT_ALGORITHMS"])
            return payload
        except Exception:
            return None

def require_auth(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        raw = request.headers.get("Authorization", "")
        payload = decode_token(raw)
        if not payload:
            return jsonify({"error": "unauthorized"}), 401
        # attach payload to request context
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return wrapped
