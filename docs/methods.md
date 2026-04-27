# Methods: Project Rewrite and Vulnerability Reproduction

## Overview

This document describes the methodology used to rewrite the IDOR and JWT vulnerability demonstration project from Python (Flask) to Java (Spring Boot), ensuring reproducibility of security vulnerabilities in both vulnerable and fixed modes.

## 1. Technology Selection

### Original Implementation
- **Language**: Python 3.x
- **Framework**: Flask
- **Database**: PostgreSQL with SQLAlchemy ORM
- **JWT Library**: PyJWT
- **Deployment**: Docker Compose

### New Implementation
- **Language**: Java 17
- **Framework**: Spring Boot 3.2.0
- **Database**: PostgreSQL with Spring Data JPA (Hibernate)
- **JWT Library**: JJWT (io.jsonwebtoken) 0.12.3
- **Build Tool**: Maven
- **Deployment**: Docker Compose

### Rationale for Java Selection

1. **PVS-Studio Compatibility**: PVS-Studio has excellent support for Java static analysis
2. **Type Safety**: Java's strong typing helps demonstrate security issues more clearly
3. **Enterprise Relevance**: Spring Boot is widely used in production environments
4. **Custom Rule Development**: Java's AST is well-documented for creating custom PVS-Studio rules
5. **Testing Framework**: JUnit 5 provides robust testing capabilities

## 2. Architecture Mapping

### Component Translation

| Python Component | Java Component | Purpose |
|-----------------|----------------|---------|
| `app/main.py` | `IdorJwtDemoApplication.java` | Application entry point |
| `app/routes.py` | `ApiController.java` | REST API endpoints |
| `app/auth.py` | `JwtUtil.java` + `JwtAuthenticationFilter.java` | JWT handling |
| `app/models.py` | `User.java` + `Document.java` | Data models |
| `app/db.py` | Spring Data JPA repositories | Database access |
| `app/config.py` | `AppConfig.java` + `application.properties` | Configuration |
| `seed_db.py` | `DataSeeder.java` | Database seeding |

### Endpoint Mapping

All endpoints maintain identical behavior:

- `GET /` - API information
- `GET /health` - Health check with DB connectivity test
- `POST /login` - User authentication (returns JWT)
- `GET /users/{id}/docs` - Retrieve user documents (IDOR vulnerability point)

## 3. Vulnerability Implementation

### 3.1 IDOR (Insecure Direct Object Reference)

**Location**: [`ApiController.java:getUserDocs()`](../java-app/src/main/java/com/security/demo/controller/ApiController.java)

#### Vulnerable Mode (MODE=VULN)
```java
if (appConfig.isVulnerableMode()) {
    // VULNERABILITY: No authorization check
    // Any authenticated user can access any other user's documents
    logger.warn("VULN MODE: Returning documents without authorization check");
    
    // Returns documents without checking if token user_id matches requested user_id
    return ResponseEntity.ok(response);
}
```

**Exploitation**: An attacker with a valid JWT for user A can access user B's documents by simply changing the URL parameter.

#### Fixed Mode (MODE=FIXED)
```java
if (!userId.equals(tokenUserId) && !"admin".equals(tokenRole)) {
    logger.warn("FIXED MODE: Forbidden - user {} attempted to access user {}'s documents", 
        tokenUserId, userId);
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(new ErrorResponse("forbidden"));
}
```

**Fix**: Validates that the authenticated user is either the document owner or has admin role.

### 3.2 Weak JWT Implementation

**Location**: [`JwtUtil.java:decodeToken()`](../java-app/src/main/java/com/security/demo/security/JwtUtil.java)

#### Vulnerable Mode (MODE=VULN)

**Vulnerability 1: No Signature Verification**
```java
if (appConfig.isVulnerableMode()) {
    // VULNERABILITY: Skip signature verification
    logger.warn("VULN MODE: Decoding token without signature verification");
    
    return Jwts.parser()
            .unsecured()
            .build()
            .parseUnsecuredClaims(token)
            .getPayload();
}
```

**Vulnerability 2: Weak Secret Key**
```java
String secret = appConfig.isVulnerableMode() 
    ? appConfig.getWeakSecret()  // "weak_secret_123"
    : appConfig.getStrongSecret();
```

**Exploitation**: 
- Attacker can forge tokens with `alg=none` (no signature)
- Attacker can brute-force the weak secret and create valid tokens
- Attacker can modify token claims (user_id, role) without detection

#### Fixed Mode (MODE=FIXED)

**Fix 1: Strict Signature Validation**
```java
SecretKey key = Keys.hmacShaKeyFor(
    appConfig.getStrongSecret().getBytes(StandardCharsets.UTF_8)
);

return Jwts.parser()
        .verifyWith(key)
        .build()
        .parseSignedClaims(token)
        .getPayload();
```

**Fix 2: Strong Secret Key**
- Minimum 32 characters
- Configurable via environment variable
- Default: `this_is_a_very_strong_secret_key_with_at_least_32_characters`

## 4. Data Seeding

### Seed Data Structure

The application automatically seeds the database on startup with test data:

**Users**:
- `alice` (id=1, role=user) - 2 documents
- `bob` (id=2, role=user) - 3 documents
- `charlie` (id=3, role=user) - 1 document
- `admin` (id=4, role=admin) - 0 documents
- `victim` (id=5, role=user) - 2 documents

**Documents**:
- alice_passport.pdf
- alice_contract.pdf
- bob_id_card.pdf
- bob_bank_statement.pdf
- bob_medical_record.pdf
- charlie_diploma.pdf
- victim_secret_document.pdf
- victim_private_info.pdf

### Implementation

Seeding is handled by [`DataSeeder.java`](../java-app/src/main/java/com/security/demo/DataSeeder.java), which implements `CommandLineRunner` to execute on application startup.

## 5. Testing Strategy

### Unit Tests

Location: [`VulnerabilityTests.java`](../java-app/src/test/java/com/security/demo/VulnerabilityTests.java)

**Test Coverage**:

1. **testIdorVulnerabilityInVulnMode**: Verifies IDOR exists - Alice can access Bob's documents
2. **testIdorFixedInFixedMode**: Verifies IDOR is fixed - Alice cannot access Bob's documents
3. **testWeakJwtInVulnMode**: Verifies unsigned tokens are accepted
4. **testJwtValidationInFixedMode**: Verifies unsigned tokens are rejected
5. **testAdminAccessInFixedMode**: Verifies admin can access any user's documents
6. **testOwnDocumentAccessInFixedMode**: Verifies users can access their own documents
7. **testLoginEndpoint**: Verifies authentication works
8. **testHealthEndpoint**: Verifies health check works

### Running Tests

```bash
cd java-app
mvn test
```

## 6. Deployment and Reproducibility

### Environment Variables

| Variable | Purpose | VULN Mode | FIXED Mode |
|----------|---------|-----------|------------|
| `MODE` | Application mode | `VULN` | `FIXED` |
| `DATABASE_URL` | PostgreSQL connection | Same | Same |
| `STRONG_SECRET` | JWT signing key | Not used | Required (32+ chars) |

### Docker Compose

**Vulnerable Mode**:
```bash
MODE=VULN docker-compose -f docker-compose-java.yml up --build
```

**Fixed Mode**:
```bash
MODE=FIXED docker-compose -f docker-compose-java.yml up --build
```

### Verification Steps

1. **Start the application**:
   ```bash
   MODE=VULN docker-compose -f docker-compose-java.yml up --build
   ```

2. **Login as Alice**:
   ```bash
   curl -X POST http://localhost:5001/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice"}'
   ```
   Save the returned `access_token`.

3. **Exploit IDOR (VULN mode)**:
   ```bash
   curl http://localhost:5001/users/2/docs \
     -H "Authorization: Bearer <alice_token>"
   ```
   Result: Alice can see Bob's documents (user_id=2)

4. **Test Fix (FIXED mode)**:
   ```bash
   MODE=FIXED docker-compose -f docker-compose-java.yml up --build
   # Repeat steps 2-3
   ```
   Result: 403 Forbidden - Alice cannot access Bob's documents

## 7. Key Differences from Python Implementation

### Improvements

1. **Type Safety**: Java's type system catches errors at compile time
2. **Dependency Injection**: Spring's DI container manages component lifecycle
3. **Auto-configuration**: Spring Boot reduces boilerplate configuration
4. **Built-in Testing**: Spring Test provides comprehensive testing support
5. **Production-Ready**: Includes actuator endpoints, metrics, and health checks

### Maintained Features

1. **Same API Contract**: All endpoints have identical request/response formats
2. **Same Vulnerabilities**: IDOR and weak JWT behave identically
3. **Same Fixes**: Authorization logic is equivalent
4. **Same Data Model**: Users and documents have identical structure
5. **Same Deployment**: Docker Compose with PostgreSQL

## 8. Security Issues Identified and Fixed

### Issues in Vulnerable Version

1. **IDOR**: Missing authorization check in document access endpoint
2. **Weak JWT Secret**: Short, predictable secret key ("weak_secret_123")
3. **No Signature Verification**: Accepts unsigned JWT tokens (alg=none)
4. **Information Disclosure**: Exposes token payload in API responses
5. **No Rate Limiting**: Allows unlimited authentication attempts

### Fixes Implemented

1. **Authorization Check**: Validates user ownership or admin role
2. **Strong Secret**: 32+ character secret key from environment
3. **Signature Verification**: Strictly validates JWT signatures
4. **Minimal Response**: Removes token payload from responses
5. **Logging**: Adds security event logging for audit trails

## 9. PVS-Studio Integration Points

The Java implementation is designed to work with PVS-Studio custom rules:

### Rule 1: IDOR Detection
**Target**: Methods that access user resources without authorization checks
**Pattern**: 
- Method accepts user ID parameter
- Method has authentication but no authorization
- No comparison between token user_id and requested user_id

**Example Detection Point**:
```java
@GetMapping("/users/{userId}/docs")
public ResponseEntity<?> getUserDocs(@PathVariable Long userId, ...) {
    // Should check: tokenUserId.equals(userId) || role.equals("admin")
}
```

### Rule 2: Weak JWT Detection
**Target**: JWT parsing without signature verification
**Pattern**:
- Calls to `Jwts.parser().unsecured()`
- Calls to `parseUnsecuredClaims()`
- Short secret keys (< 32 characters)

**Example Detection Point**:
```java
Jwts.parser()
    .unsecured()  // PVS-Studio should flag this
    .build()
    .parseUnsecuredClaims(token)
```

## 10. Conclusion

The Java rewrite successfully maintains all functionality of the original Python implementation while:

- Preserving identical vulnerabilities in VULN mode
- Implementing proper fixes in FIXED mode
- Adding comprehensive unit tests
- Improving type safety and maintainability
- Enabling PVS-Studio static analysis integration

The project demonstrates that security vulnerabilities transcend programming languages and frameworks, and proper security practices must be applied regardless of technology stack.
