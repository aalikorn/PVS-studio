# Custom rules for IDOR and weak JWT

This directory contains two repository-local custom security checks that complement PVS-Studio for the Java version of this project.

Important limitation:

- PVS-Studio's public documentation describes a user annotation mechanism for C++, C#, and Java, but it does not expose a public SDK for writing brand-new diagnostics in the repository itself.
- The official PVS-Studio site instead documents:
  - JSON annotations that enrich existing analysis;
  - paid development of new custom diagnostics by the PVS-Studio team.

Because of that limitation, the rules here are implemented as a small repository-local companion checker. It is designed to be stored and versioned next to the project and to run alongside the regular PVS-Studio pipeline.

The repository's `java-app` keeps vulnerable and fixed behavior behind the runtime `MODE` switch, so a plain static scan of `src/main/java` would see both branches at once. For that reason, the custom rule tests use isolated vulnerable/fixed Java fixtures that represent the effective code in each mode.

What is included:

- `rules/rules.json` - metadata for two custom rules.
- `tests/scan_rules.py` - lightweight static checker for Java fixtures.
- `fixtures/vulnerable/` - code samples that must trigger the rules.
- `fixtures/fixed/` - code samples that must not trigger the rules.

Rules:

1. `PVS-CUSTOM-IDOR-001`
   Detects a controller method that takes a user identifier from a route parameter and uses it to fetch resources without an obvious authorization guard.

2. `PVS-CUSTOM-JWT-002`
   Detects weak JWT parsing/verification patterns:
   - `Jwts.parser().unsecured()` / `parseUnsecuredClaims(...)`;
   - `setSigningKey(...)` used without any `.require...` constraints;
   - too-short literal signing key passed into `setSigningKey(...)`;
   - too-short literal secret passed into `Keys.hmacShaKeyFor(...)`.

How to run:

```bash
python3 custom-rules/tests/scan_rules.py
```

Expected result:

- vulnerable fixtures: findings are reported;
- fixed fixtures: no findings.

Relevant official PVS-Studio documentation consulted on April 28, 2026:

- [User annotation mechanism in JSON format](https://pvs-studio.com/en/docs/manual/6810/)
- [Annotating Java entities in JSON format](https://pvs-studio.com/en/docs/manual/7180/)
- [Annotating C# entities in JSON format](https://pvs-studio.com/en/docs/manual/6808/)
- [Custom diagnostics are developed by PVS-Studio as a paid service](https://pvs-studio.com/en/custom/)

What was verified in this repository:

- the IDOR rule fires on `fixtures/vulnerable/IDORController.java` and stays silent on `fixtures/fixed/IDORController.java`;
- the JWT rule fires on vulnerable patterns matching the task:
  - unsecured parsing;
  - parser configuration without claim requirements;
  - short literal HMAC secrets;
- the JWT rule stays silent on the fixed fixture that uses `verifyWith(...)` and claim requirements.
