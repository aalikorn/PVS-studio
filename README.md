# Exploitation and Fix of IDOR and Weak JWT in a Microservice API

## Overview

This project demonstrates two critical API-layer vulnerabilities:
- **IDOR** (Insecure Direct Object Reference) on `GET /users/<id>/docs`
- **Weak JWT** acceptance (e.g., accepting `alg=none` or skipping signature verification)

The repository contains **two implementations**:
1. **Python/Flask** (original) - in `app/` directory
2. **Java/Spring Boot** (new) - in `java-app/` directory

Both implementations support:
- Vulnerable mode (MODE=VULN) and fixed mode (MODE=FIXED)
- PoC scripts for exploitation
- Docker Compose for reproducible environment
- Comprehensive testing
- CI pipeline configuration

## Team & Responsibilities

- **Aleksei Fominykh** — Custom PVS-Studio rules, infra, docker-compose, logging
- **Sofia Kulagina** — CI (GitHub Actions), security scan config, seed automation
- **Daria Nikolaeva** — Java rewrite, Flask app, PoC scripts, testing, documentation
- **Diana Yakupova** — Burp testing, threat model, report, demo orchestration

## Quick Start

### Java Implementation (Recommended for PVS-Studio)

**Vulnerable Mode**:
```bash
MODE=VULN docker-compose -f docker-compose-java.yml up --build
```

**Fixed Mode**:
```bash
MODE=FIXED docker-compose -f docker-compose-java.yml up --build
```

Access the service at <http://localhost:5001>

### Python Implementation (Original)

```bash
MODE=VULN docker-compose up --build
# or
MODE=FIXED docker-compose up --build
```

Access the service at <http://localhost:5001>

## Project Structure

```
.
├── app/                          # Python/Flask implementation
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── routes.py            # API endpoints
│   │   ├── auth.py              # JWT handling
│   │   ├── models.py            # Database models
│   │   └── config.py
│   ├── poc/                     # Python PoC scripts
│   └── seed_db.py
│
├── java-app/                     # Java/Spring Boot implementation
│   ├── src/main/java/com/security/demo/
│   │   ├── controller/          # REST controllers
│   │   ├── security/            # JWT utilities
│   │   ├── model/               # JPA entities
│   │   ├── repository/          # Data access
│   │   └── config/              # Configuration
│   ├── src/test/                # Unit tests
│   ├── poc/                     # Bash PoC scripts
│   └── pom.xml
│
├── custom-rules/                 # PVS-Studio custom rules
│   ├── rules/
│   │   └── rules.json
│   ├── fixtures/
│   │   ├── vulnerable/          # Test cases for rules
│   │   └── fixed/
│   └── tests/
│
├── docs/
│   └── methods.md               # Methodology documentation
│
├── demo/                        # Demo artifacts
│   ├── logs/
│   └── report/
│
├── docker-compose.yml           # Python deployment
├── docker-compose-java.yml      # Java deployment
└── README.md
```

## API Endpoints

Both implementations expose identical endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information |
| `/health` | GET | Health check with DB status |
| `/login` | POST | Authenticate user, get JWT |
| `/users/{id}/docs` | GET | Get user documents (requires auth) |

## Demonstrating Vulnerabilities

### 1. IDOR Vulnerability

**Exploit in VULN mode**:
```bash
# Login as Alice
TOKEN=$(curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}' | jq -r '.access_token')

# Access Bob's documents (user_id=2) using Alice's token
curl http://localhost:5001/users/2/docs \
  -H "Authorization: Bearer $TOKEN"
```

**Result**:
- **VULN mode**: ✓ Success - Alice can see Bob's documents (IDOR vulnerability)
- **FIXED mode**: ✗ 403 Forbidden - Access denied

### 2. Weak JWT

**Exploit in VULN mode**:
```bash
# Create unsigned token (alg=none)
UNSIGNED_TOKEN="eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InVzZXIifQ."

# Use forged token
curl http://localhost:5001/users/1/docs \
  -H "Authorization: Bearer $UNSIGNED_TOKEN"
```

**Result**:
- **VULN mode**: ✓ Success - Unsigned token accepted
- **FIXED mode**: ✗ 401 Unauthorized - Token rejected

### Automated PoC Scripts

**Java implementation**:
```bash
cd java-app
./poc/exploit_idor.sh
./poc/forge_jwt.sh
```

**Python implementation**:
```bash
cd app
python poc/exploit_idor.py
python poc/forge_jwt.py
```

## Test Users

Both implementations seed identical test data:

| Username | ID | Role | Documents |
|----------|----|----|-----------|
| alice | 1 | user | 2 |
| bob | 2 | user | 3 |
| charlie | 3 | user | 1 |
| admin | 4 | admin | 0 |
| victim | 5 | user | 2 |

## Testing

### Java Tests
```bash
cd java-app
mvn test
```

Tests verify:
- IDOR vulnerability exists in VULN mode
- IDOR is fixed in FIXED mode
- Weak JWT accepted in VULN mode
- JWT validation works in FIXED mode
- Authorization logic for admin and regular users

### Python Tests
```bash
cd app
pytest
```

## Security Issues

### Vulnerabilities (VULN Mode)

1. **IDOR**: Missing authorization check - any authenticated user can access any user's documents
2. **Weak JWT Secret**: Short, predictable secret ("weak_secret_123")
3. **No Signature Verification**: Accepts unsigned JWT tokens (alg=none)
4. **Information Disclosure**: Exposes token payload in API responses

### Fixes (FIXED Mode)

1. **Authorization Check**: Validates user ownership or admin role
2. **Strong Secret**: 32+ character secret from environment
3. **Signature Verification**: Strictly validates JWT signatures
4. **Minimal Response**: Removes sensitive information from responses

## PVS-Studio Integration

The Java implementation includes custom PVS-Studio rules for detecting:

1. **IDOR patterns**: Methods accessing resources without authorization checks
2. **Weak JWT usage**: Unsigned token parsing, weak secrets

See [`custom-rules/README.md`](custom-rules/README.md) for details.

### Running PVS-Studio Analysis

```bash
# Analyze Java code
cd java-app
pvs-studio-analyzer analyze -o pvs-studio.log
plog-converter -t sarif -o report.sarif pvs-studio.log
```

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/`) includes:
- Build and test
- PVS-Studio static analysis
- SARIF report generation
- Artifact upload

## Documentation

- [`docs/methods.md`](docs/methods.md) - Detailed methodology for rewrite and vulnerability reproduction
- [`java-app/README.md`](java-app/README.md) - Java implementation guide
- [`custom-rules/README.md`](custom-rules/README.md) - PVS-Studio custom rules

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MODE` | Application mode (VULN or FIXED) | VULN |
| `DATABASE_URL` | PostgreSQL connection string | (see docker-compose) |
| `WEAK_SECRET` | JWT secret for VULN mode | weak_secret_123 |
| `STRONG_SECRET` | JWT secret for FIXED mode | (auto-generated) |

## Requirements

- Docker & Docker Compose
- Java 17+ (for local Java development)
- Python 3.10+ (for local Python development)
- Maven 3.6+ (for Java builds)
- PostgreSQL 16 (provided via Docker)

## SAST Tools

[PVS-Studio](https://pvs-studio.com/en/pvs-studio/?utm_source=website&utm_medium=github&utm_campaign=open_source) - static analyzer for C, C++, C#, and Java code.

## License

This is a security demonstration project for educational purposes.

## References

- [OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [PVS-Studio Documentation](https://pvs-studio.com/en/docs/)
