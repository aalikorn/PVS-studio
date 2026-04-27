# IDOR and JWT Vulnerability Demo - Java Implementation

## Overview

This is a Java/Spring Boot rewrite of the IDOR and JWT vulnerability demonstration project. It maintains identical functionality to the original Python/Flask implementation while demonstrating the same security vulnerabilities.

## Features

- **Two Modes**: VULN (vulnerable) and FIXED (secure)
- **IDOR Vulnerability**: Insecure Direct Object Reference in document access
- **Weak JWT**: Accepts unsigned tokens and uses weak secrets in VULN mode
- **Automatic Seeding**: Pre-populated test users and documents
- **Comprehensive Tests**: Unit tests verifying vulnerabilities and fixes
- **Docker Support**: Containerized deployment with PostgreSQL

## Quick Start

### Prerequisites

- Java 17 or higher
- Maven 3.6+
- Docker and Docker Compose (for containerized deployment)

### Running with Docker (Recommended)

**Vulnerable Mode**:
```bash
MODE=VULN docker-compose -f docker-compose-java.yml up --build
```

**Fixed Mode**:
```bash
MODE=FIXED docker-compose -f docker-compose-java.yml up --build
```

The application will be available at `http://localhost:5001`

### Running Locally

1. **Start PostgreSQL**:
   ```bash
   docker run -d \
     -e POSTGRES_DB=mydb \
     -e POSTGRES_USER=myuser \
     -e POSTGRES_PASSWORD=mypassword \
     -p 5432:5432 \
     postgres:16-alpine
   ```

2. **Build and run**:
   ```bash
   cd java-app
   mvn clean package
   MODE=VULN java -jar target/idor-jwt-demo-1.0.0.jar
   ```

## API Endpoints

### GET /
Returns API information and available endpoints.

```bash
curl http://localhost:5001/
```

### GET /health
Health check endpoint with database connectivity test.

```bash
curl http://localhost:5001/health
```

### POST /login
Authenticate and receive JWT token.

```bash
curl -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

### GET /users/{id}/docs
Retrieve documents for a specific user (requires authentication).

```bash
curl http://localhost:5001/users/1/docs \
  -H "Authorization: Bearer <token>"
```

## Demonstrating Vulnerabilities

### IDOR Vulnerability (VULN Mode)

1. **Login as Alice**:
   ```bash
   TOKEN=$(curl -s -X POST http://localhost:5001/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice"}' | jq -r '.access_token')
   ```

2. **Access Bob's documents** (user_id=2):
   ```bash
   curl http://localhost:5001/users/2/docs \
     -H "Authorization: Bearer $TOKEN"
   ```

   **Result in VULN mode**: ✓ Success - Alice can see Bob's documents (IDOR vulnerability)
   
   **Result in FIXED mode**: ✗ 403 Forbidden - Access denied

### Weak JWT (VULN Mode)

1. **Create unsigned token**:
   ```bash
   # Token with alg=none (no signature)
   UNSIGNED_TOKEN="eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InVzZXIifQ."
   ```

2. **Use unsigned token**:
   ```bash
   curl http://localhost:5001/users/1/docs \
     -H "Authorization: Bearer $UNSIGNED_TOKEN"
   ```

   **Result in VULN mode**: ✓ Success - Unsigned token accepted
   
   **Result in FIXED mode**: ✗ 401 Unauthorized - Token rejected

## Test Users

The application seeds the following test users:

| Username | ID | Role | Documents |
|----------|----|----|-----------|
| alice | 1 | user | 2 |
| bob | 2 | user | 3 |
| charlie | 3 | user | 1 |
| admin | 4 | admin | 0 |
| victim | 5 | user | 2 |

## Running Tests

```bash
cd java-app
mvn test
```

Tests verify:
- IDOR vulnerability exists in VULN mode
- IDOR is fixed in FIXED mode
- Weak JWT accepted in VULN mode
- JWT validation works in FIXED mode
- Admin access control
- User self-access

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MODE` | Application mode (VULN or FIXED) | VULN |
| `DATABASE_URL` | PostgreSQL JDBC URL | jdbc:postgresql://localhost:5432/mydb |
| `DB_USER` | Database username | myuser |
| `DB_PASSWORD` | Database password | mypassword |
| `STRONG_SECRET` | JWT secret for FIXED mode | (auto-generated) |

### Application Properties

Configuration is in [`application.properties`](src/main/resources/application.properties).

## Project Structure

```
java-app/
├── src/
│   ├── main/
│   │   ├── java/com/security/demo/
│   │   │   ├── IdorJwtDemoApplication.java    # Main application
│   │   │   ├── DataSeeder.java                # Database seeding
│   │   │   ├── config/
│   │   │   │   ├── AppConfig.java             # Application configuration
│   │   │   │   └── WebConfig.java             # Web configuration
│   │   │   ├── controller/
│   │   │   │   └── ApiController.java         # REST endpoints
│   │   │   ├── dto/
│   │   │   │   ├── LoginRequest.java
│   │   │   │   ├── LoginResponse.java
│   │   │   │   ├── UserDocsResponse.java
│   │   │   │   └── ErrorResponse.java
│   │   │   ├── model/
│   │   │   │   ├── User.java                  # User entity
│   │   │   │   └── Document.java              # Document entity
│   │   │   ├── repository/
│   │   │   │   ├── UserRepository.java
│   │   │   │   └── DocumentRepository.java
│   │   │   └── security/
│   │   │       ├── JwtUtil.java               # JWT operations
│   │   │       └── JwtAuthenticationFilter.java
│   │   └── resources/
│   │       └── application.properties
│   └── test/
│       └── java/com/security/demo/
│           └── VulnerabilityTests.java        # Comprehensive tests
├── Dockerfile
└── pom.xml
```

## Security Issues Demonstrated

### Vulnerable Version (MODE=VULN)

1. **IDOR**: No authorization check - any authenticated user can access any user's documents
2. **Weak JWT Secret**: Uses "weak_secret_123" (easily brute-forced)
3. **No Signature Verification**: Accepts unsigned JWT tokens (alg=none)
4. **Information Disclosure**: Exposes token payload in responses

### Fixed Version (MODE=FIXED)

1. **Authorization Check**: Validates user ownership or admin role
2. **Strong Secret**: Uses 32+ character secret from environment
3. **Signature Verification**: Strictly validates JWT signatures
4. **Minimal Response**: Removes sensitive information from responses

## Integration with PVS-Studio

This implementation is designed to work with PVS-Studio custom rules for detecting:

1. **IDOR patterns**: Methods accessing resources without authorization
2. **Weak JWT usage**: Unsigned token parsing, weak secrets

See [`../custom-rules/`](../custom-rules/) for PVS-Studio rule definitions.

## License

This is a security demonstration project for educational purposes.

## Authors

- **Daria Nikolaeva** - Java implementation, testing, documentation
