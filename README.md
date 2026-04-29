# IDOR & JWT Weaknesses: a case study in static analysis with PVS-Studio
Tap to [demo video](https://drive.google.com/file/d/1aJOuvXBbHfUTXMJLkhe3hOOmdTLJWChf/view?usp=sharing).

**What’s inside:** A tiny microservice that shows two common API security flaws (IDOR and unsigned JWTs) in `VULN` mode, and how to fix them in `FIXED` mode. Also includes a full SAST pipeline with PVS‑Studio + custom rules.

The application supports two runtime modes:

- **`MODE=VULN`**: intentionally vulnerable behavior for reproduction and triage
- **`MODE=FIXED`**: hardened behavior for verification

---

## Get it running

### Run with Docker Compose

Vulnerable:

```bash
MODE=VULN docker compose -f docker-compose-java.yml up -d --build
curl -s http://localhost:5001/health
```

Fixed:

```bash
docker compose -f docker-compose-java.yml down
MODE=FIXED docker compose -f docker-compose-java.yml up -d --build
curl -s http://localhost:5001/health
```

You should see `{"mode":"VULN" ...}` or `{"mode":"FIXED" ...}` in the response.

### One-command helper

```bash
./start.sh
```

---

## API endpoints

- `GET /` — API info
- `GET /health` — health check + DB probe
- `POST /login` — returns JWT for a username
- `GET /users/{id}/docs` — protected documents endpoint (**IDOR target**)

---

## Reproducing the vulnerabilities (VULN vs FIXED)

### 1) IDOR

Login as Alice:

```bash
TOKEN=$(curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

Try to read Bob’s docs with Alice’s token:

```bash
curl -i http://localhost:5001/users/2/docs \
  -H "Authorization: Bearer $TOKEN"
```

Expected:

- **VULN**: `200 OK`
- **FIXED**: `403 Forbidden`

### 2) Unsigned JWT (alg=none)

```bash
UNSIGNED_TOKEN="eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InVzZXIifQ."
curl -i http://localhost:5001/users/1/docs \
  -H "Authorization: Bearer $UNSIGNED_TOKEN"
```

Expected:

- **VULN**: `200 OK`
- **FIXED**: `401 Unauthorized`

---

## CI/SAST

GitHub Actions workflow is in `.github/workflows/ci.yml` and produces:

- **PVS‑Studio Java analysis** (SARIF + HTML + raw log as artifacts)
- **Trivy** filesystem scan (SARIF)
- **Repo custom security rules** (SARIF uploaded to Code Scanning + saved as artifact)

---

## Custom rules (project-specific SAST)

Why: business-logic vulnerabilities like IDOR/JWT patterns are often not detected by generic analyzers without project context.

- Rules metadata: `custom-rules/rules/rules.json`
- Rule test fixtures: `custom-rules/fixtures/`
- Rule checks: `custom-rules/tests/scan_rules.py`
- Project scan → SARIF: `custom-rules/scan_project_sarif.py`

Run locally:

```bash
python3 custom-rules/scan_project_sarif.py
```

---

## Triage and report materials

The main “what we did + evidence” lives in `docs/`:

- `docs/pvs-report.md` — report (IMRaD)
- `docs/findings-table.csv` — triaged findings registry (CWE + status)

---

## Requirements

- Docker + Docker Compose
- Java 17 (for local build/dev)
- Maven (optional for local build: `cd java-app && mvn test`)

---

## References

- OWASP IDOR testing guide: `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References`
- RFC 7518 (JWA): `https://www.rfc-editor.org/rfc/rfc7518`
- RFC 8725 (JWT best practices): `https://www.rfc-editor.org/rfc/rfc8725`
- PVS‑Studio docs: `https://pvs-studio.com/en/docs/`
