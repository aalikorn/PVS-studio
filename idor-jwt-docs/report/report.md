# **[F25] Group Project Report - Team 13.**

## Network and Cyber Security

### Application Security: Exploitation and Fix of IDOR and Weak JWT in a Microservice API

---

**Description:** This project demonstrates two practical API-layer vulnerabilities — IDOR and Weak JWT verification — in a containerized microservice. We provide PoCs (curl + Burp Suite + Python scripts), show scalable exploitation (Burp Intruder), implement fixes (strict authorization checks + strict JWT verification), and verify them. The environment is Docker Compose-based and CI includes Bandit and Trivy scans.

## I. Goal and tasks

### Goal

The goal of this project is to **demonstrate and analyze common application-layer security vulnerabilities** in a controlled environment, focusing on:

- **Insecure Direct Object Reference (IDOR)**
- **Weak JSON Web Token (JWT) implementation**

The project aims to:

- Design a vulnerable REST API
- Exploit the vulnerabilities using industry-standard tools
- Demonstrate how these vulnerabilities scale
- Propose and implement secure fixes

---

### Team Responsibilities

| Team member      | Responsibility                                              |
| ---------------- | ----------------------------------------------------------- |
| Daria Nikolaeva  | Backend Engineer (Flask API & PoC scripts)                  |
| Aleksei Fominykh | Infrastructure & DevOps (Docker, Compose, logs)             |
| Sofia Kulagina   | CI, Security scans, DB seeding automation                   |
| Diana Yakupova   | Documentation, threat model (CWE mapping), attack checklist |

---

## II. Execution plan and methodology

### Methodology

The project was executed using a **hands-on, attack-driven methodology** commonly applied in application security testing.

1. A REST API using JWT-based authentication was designed and implemented.
2. The application was deployed in a **Docker Compose** environment to ensure reproducibility.
3. Two intentional vulnerabilities were introduced:

   - Missing authorization checks leading to **IDOR**
   - Weak JWT secret and insufficient token verification

4. The vulnerabilities were exploited using:

   - `curl` for baseline request validation
   - **Burp Suite Repeater** for controlled request modification
   - **Burp Suite Intruder** to demonstrate scalable exploitation
   - Custom **Python PoC scripts** for reproducible attacks

5. Secure fixes were implemented for both vulnerabilities.
6. The fixes were verified by re-running the same attack scenarios and confirming access denial.

---

### Architecture Overview

The application follows a simple microservice-style architecture:

- **Flask API** (Python)

  - Authentication via JWT
  - Protected endpoint: `/users/<id>/docs`

- **PostgreSQL** database

  - Stores users and associated documents

- **Docker Compose**

  - Isolates services and ensures reproducible deployment

- **CI/CD pipeline (GitHub Actions)**

  - Static security analysis (Bandit)
  - Container vulnerability scanning (Trivy)

The security mode of the application is controlled via environment variable in `docker-compose.yml`:

```bash
MODE=VULN | FIXED
```

This enables demonstration of both vulnerable and secured states using the same codebase.

---

### Proof-of-Concept Tooling

To ensure reproducibility and automation, the following scripts were used:

- `exploit_idor.py` — automates IDOR exploitation
- `forge_jwt.py` — demonstrates JWT forgery using

---

## III. Development of solution and Proof of Concept

### Summary

We implemented a minimal Flask API (Postgres backend) with two intentionally vulnerable modes (MODE=VULN and MODE=FIXED). The vulnerable mode omits authorization checks (IDOR) and uses weak JWT verification. PoC artifacts include Python attack scripts (app/poc/\*), Burp Suite captures (Repeater / Intruder), curl outputs and container logs stored under demo/logs/.

### Vulnerability 1: Insecure Direct Object Reference (IDOR)

#### CWE Mapping

- **CWE-639**: Authorization bypass through user-controlled key
- **Estimated CVSS v3.1 Base Score**: 7.5 (High) — network vector, low privileges required, high confidentiality impact.

### Attack Surface

Endpoint:

```
GET /users/<user_id>/docs
```

Authorization:

```
Authorization: Bearer <JWT>
```

---

### Exploitation Scenario

### Step 1: Start service

1. Start environment and seed DB:

   ```bash
   bash start.sh
   ```

2. Check health:

   ```bash
   curl http://127.0.0.1:5001/health
   # Expected JSON: {"db":"ok","mode":"VULN","status":"ok"}
   ```

3. Obtain Bob’s token (save output to file):

   ```bash
   curl -s -X POST http://127.0.0.1:5001/login \
   -H "Content-Type: application/json" \
   -d '{"username":"bob"}' | jq . > demo/logs/login_bob.json
   ```

   `demo/logs/login_bob.json` contains `access_token`.

4. Legitimate request (Bob get his docs)

   ```bash
   curl -H "Authorization: Bearer <BOB_TOKEN>" \
   http://127.0.0.1:5001/users/2/docs -v
   ```

5. IDOR exploitation (reuse Bob token but request another user)
   ```bash
   curl -H "Authorization: Bearer <BOB_TOKEN>" \
   http://127.0.0.1:5001/users/1/docs -v
   ```
   Expected in mode `VULN`: `200 OK` + JSON with Bob’s docs and token payload.

### Step 2: Burp Suite steps

### Burp Repeater

**Steps**

1. Proxy → Intercept → **Intercept is ON**.

2. In terminal use curl with proxy:

   ```bash
   curl -x http://127.0.0.1:8080
   -X POST http://127.0.0.1:5001/login
   -H "Content-Type: application/json"
   -d '{"username":"bob"}'
   ```

   Burp will show the POST /login in Proxy → Intercept.
   ![[Снимок экрана 2025-12-14 в 03.06.22.png]]

3. Right-click the captured request → **Forward**.
   Burp will show this request in **HTTP history**.
   ![[Снимок экрана 2025-12-14 в 03.06.39.png]]

4. In Repeater panel: run the captured POST /login to get token (Send). Copy token from response (or save the response).
   ![[Снимок экрана 2025-12-14 в 03.07.51.png]]

5. Create a new GET request in Repeater:

   - Method: **GET**
   - URL: `/users/2/docs`
   - Headers: `Authorization: Bearer <BOB_TOKEN>`
   - Click **Send** → verify response (200).
     ![[Pasted image 20251214081929.png]]

6. Modify the URL to `/users/1/docs` (do not change Authorization header) → **Send**.

- If `MODE=VULN` you will get `200 OK` with Alice’s docs.
  ![[Pasted image 20251214082052.png]]

---

### Burp Intruder

**Steps**

1. From Repeater request `/users/1/docs` → right-click → **Send to Intruder**.

2. Intruder → **Positions**: highlight the numeric `1` in the path `/users/1/docs` → click **Add §**.

3. Intruder → **Payloads**: Type = **Numbers**, From = `1`, To = `5`.
   ![[Pasted image 20251214082422.png]]

4. Click **Start attack**.

5. Burp will show the multiple `200 OK` responses disclosing different users’ documents.
   ![[Pasted image 20251214082507.png]]

---

### Vulnerability 2: Weak JWT implementation

**CWE:** CWE-347 — Improper Verification of Cryptographic Signature

**Issue:** The vulnerable mode accepts tokens without strict verification (supports `alg=none` or skips signature verification), and uses a weak hardcoded secret in VULN mode.

**Why this matters:** An attacker can craft a forged token (change `user_id` or `role`) and present it to the API, obtaining unauthorized access even if endpoints have checks.

**PoC: forging and using unsigned token**

1. Manual forge (example technique):

- JWT format: `base64url(header).base64url(payload).signature`

- Unsigned token with `alg: none`: `header.payload.` (note trailing dot)

- Example header: `{"alg":"none","typ":"JWT"}`

- Example payload: `{"user_id":1,"username":"alice","role":"user"}`

- Build token (see `app/poc/forge_jwt.py` which does this for you).

### Step 1: using of script

Using `forge_jwt.py`:

```bash
API_URL=http://127.0.0.1:5001 python3 app/poc/forge_jwt.py \
> demo/logs/forge_jwt_vuln.txt
```

`demo/logs/forge_jwt_vuln.txt` will contain the forged token and the response to `/users/1/docs`.

### Step 2: Burp Suite steps

1. In Repeater use a captured `GET /users/1/docs` request. Replace `Authorization: Bearer <TOKEN>` with the forged token produced above. Click **Send**.
2. Expected in VULN: `200 OK` and Alice’s docs.
   ![[Pasted image 20251214083253.png]]

**Artifacts**

- `demo/logs/forge_jwt_vuln.txt`

---

### Remediation and verification

**Fix summary**

1. **IDOR fix:** enforce that the token’s `user_id` == requested `user_id` OR `role == 'admin'`.

2. **JWT fix:** enforce signature verification with a strong secret and restrict accepted algorithms.

**Exact diffs**

_routes.py_ (IDOR)

```diff

@@

- if current_app.config["MODE"] == "VULN":

- # intentionally missing authorization check (IDOR)

- return jsonify({

- "requested_user_id": user.id,

- "username": user.username,

- "docs": [d.filename for d in user.docs],

- "token_payload": payload

- })

-

- # FIXED: enforce that token user_id == requested user_id OR role==admin

- if payload.get("user_id") != user.id and payload.get("role") != "admin":

- return jsonify({"error": "forbidden"}), 403

+ # FIXED: enforce that token user_id == requested user_id OR role==admin

+ if payload.get("user_id") != user.id and payload.get("role") != "admin":

+ return jsonify({"error": "forbidden"}), 403

+

+ return jsonify({

+ "requested_user_id": user.id,

+ "username": user.username,

+ "docs": [d.filename for d in user.docs],

+ })

```

_auth.py_ (JWT verification)

```diff

@@

- if cfg["MODE"] == "VULN":

- # INTENTIONALLY vulnerable: skip signature verification

- try:

- payload = jwt.decode(token, options={"verify_signature": False})

- return payload

- except Exception:

- return None

- else:

- # FIXED: strictly verify signature + algorithms

- try:

- payload = jwt.decode(token, cfg["STRONG_SECRET"], algorithms=cfg["JWT_ALGORITHMS"])

- return payload

- except Exception:

- return None

+ # FIXED: strictly verify signature + algorithms using a strong secret

+ try:

+ payload = jwt.decode(token, cfg["STRONG_SECRET"], algorithms=cfg["JWT_ALGORITHMS"])

+ return payload

+ except Exception:

+ return None

```

**How to switch to FIXED mode and verify**

1. Edit `docker-compose.yml` to set `MODE: FIXED` under the flask_app service environment block. Example:

```yaml
services:

flask_app:

---
environment:

MODE: FIXED
```

2. Rebuild containers:

```bash

docker compose up -d --build

```

3. Re-run the same PoCs:

```bash

# IDOR test

curl -H "Authorization: Bearer <BOB_TOKEN>" http://127.0.0.1:5001/users/1/docs -v

# Expected: 403 Forbidden (or 401 if JWT invalid)

# Forged JWT test (use forged token)

curl -H "Authorization: Bearer <FORGED_TOKEN>" http://127.0.0.1:5001/users/1/docs -v

# Expected: 401 Unauthorized or 403 Forbidden (signature invalid)

```

**Artifacts after fix**
![[Pasted image 20251214083823.png]]

![[Pasted image 20251214083839.png]]

---

### CI/CD and security scans (evidence to include)

- Bandit and Trivy runs are included in `.github/workflows/ci.yml`.

  Here is CI pipeline where all logs:
  https://github.com/versceana/idor-jwt/actions/runs/20198109330/job/57985022517

  `demo/logs/bandit-report.json` contain info about Bandit.

- Screenshot of successful pipeline run.
  ![[Снимок экрана 2025-12-14 в 08.44.19.png]]

---

### PoC artifacts list (files to attach in `demo/`)

- `demo/logs/login_bob.json` — login output (token)

- `demo/logs/exploit_idor_vuln.txt` — exploit script stdout (vuln)

- `demo/logs/forge_jwt_vuln.txt` — forged jwt script stdout (vuln)
- CI outputs: `demo/logs/bandit-report.json`

- Screenshots in `demo/report/`

---

## VI. Difficulties Faced and Skills Acquired

### Difficulties

- JWT signing and validation pitfalls
- Burp Suite Intruder configuration
- Distinguishing authentication vs authorization flaws

---

### Skills Acquired

- Practical exploitation of IDOR
- JWT attack and defense understanding
- Secure API design principles
- Professional vulnerability reporting

---

## VII. Conclusion and Judgment

This project demonstrates how **small authorization mistakes lead to critical security breaches**.
IDOR vulnerabilities scale easily and become severe when combined with weak authentication mechanisms like improperly implemented JWT.

By exploiting and then fixing these issues, we gained hands-on experience in **real-world Application Security**, bridging theory and practice.

---

## Demo Video

Google Drive link:
https://drive.google.com/file/d/1F324XIiejUrXomEl5d_HoJtWi7kagIMM/view?usp=sharing
