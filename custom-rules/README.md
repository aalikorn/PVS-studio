# Custom rules for IDOR and weak JWT

This directory contains two repository-local custom security checks that complement PVS-Studio for the future Java rewrite of this project.

Important limitation:

- PVS-Studio's public documentation describes a user annotation mechanism for C++, C#, and Java, but it does not expose a public SDK for writing brand-new diagnostics in the repository itself.
- The official PVS-Studio site instead documents:
  - JSON annotations that enrich existing analysis;
  - paid development of new custom diagnostics by the PVS-Studio team.

Because the repository currently contains only the original Python demo and does not yet contain the promised Java/C# rewrite, the rules here are implemented as a small companion checker with Java fixtures that model the same vulnerabilities.

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
   - `Jwts.parser()` used without any `.require...` constraints;
   - too-short literal signing key passed into `setSigningKey(...)`;
   - too-short literal secret passed into `Keys.hmacShaKeyFor(...)`.

How to run:

```bash
python3 custom-rules/tests/scan_rules.py
```

Expected result:

- vulnerable fixtures: findings are reported;
- fixed fixtures: no findings.

Relevant official PVS-Studio documentation consulted on April 27, 2026:

- [User annotation mechanism in JSON format](https://pvs-studio.com/en/docs/manual/6810/)
- [Annotating Java entities in JSON format](https://pvs-studio.com/en/docs/manual/7180/)
- [Annotating C# entities in JSON format](https://pvs-studio.com/en/docs/manual/6808/)
- [Custom diagnostics are developed by PVS-Studio as a paid service](https://pvs-studio.com/en/custom/)
