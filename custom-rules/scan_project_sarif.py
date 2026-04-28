#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
JAVA_ROOT = REPO_ROOT / "java-app" / "src" / "main" / "java"
RULES_PATH = REPO_ROOT / "custom-rules" / "rules" / "rules.json"


def load_rules() -> list[dict]:
    payload = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    return payload["rules"]


def scan_java_tree() -> list[dict]:
    findings: list[dict] = []
    if not JAVA_ROOT.exists():
        return findings

    for path in sorted(JAVA_ROOT.rglob("*.java")):
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path.relative_to(REPO_ROOT))
        lines = text.splitlines()

        for idx, line in enumerate(lines, start=1):
            if "parseUnsecuredClaims(" in line or ".unsecured()" in line:
                findings.append(
                    {
                        "ruleId": "PVS-CUSTOM-JWT-002",
                        "path": rel,
                        "line": idx,
                        "message": "JWT parser disables signature verification (unsecured parsing).",
                        "cwe": ["CWE-347"],
                    }
                )

            if 'logger.warn("VULN MODE: Returning documents without authorization check' in line:
                findings.append(
                    {
                        "ruleId": "PVS-CUSTOM-IDOR-001",
                        "path": rel,
                        "line": idx,
                        "message": "VULN branch returns user-owned documents without authorization guard (potential IDOR).",
                        "cwe": ["CWE-639", "CWE-284"],
                    }
                )

            if "token_payload" in line:
                findings.append(
                    {
                        "ruleId": "PVS-CUSTOM-INFO-003",
                        "path": rel,
                        "line": idx,
                        "message": "Response includes token payload field (potential information disclosure).",
                        "cwe": ["CWE-200"],
                    }
                )

    return findings


def sarif_result(finding: dict) -> dict:
    return {
        "ruleId": finding["ruleId"],
        "level": "error" if finding["ruleId"].endswith(("001", "002")) else "warning",
        "message": {"text": f'{finding["message"]} ({", ".join(finding["cwe"])})'},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding["path"]},
                    "region": {"startLine": finding["line"]},
                }
            }
        ],
    }


def sarif_rule(rule: dict) -> dict:
    rid = rule["id"]
    cwe = []
    if rid == "PVS-CUSTOM-IDOR-001":
        cwe = ["CWE-639", "CWE-284"]
    if rid == "PVS-CUSTOM-JWT-002":
        cwe = ["CWE-347", "CWE-321"]
    return {
        "id": rid,
        "name": rid,
        "shortDescription": {"text": rule.get("title", rid)},
        "fullDescription": {"text": rule.get("description", "")},
        "properties": {"tags": cwe},
    }


def main() -> int:
    rules = load_rules()
    findings = scan_java_tree()

    extra_rule = {
        "id": "PVS-CUSTOM-INFO-003",
        "title": "Potential information disclosure: token payload exposed in API response",
        "description": "Flags response DTOs that include token payload fields. Used as a project-specific check.",
    }

    sarif = {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Repo Custom Rules",
                        "rules": [sarif_rule(r) for r in rules] + [sarif_rule(extra_rule)],
                    }
                },
                "results": [sarif_result(f) for f in findings],
            }
        ],
    }

    out_path = Path.cwd() / "custom-rules-report.sarif"
    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"Wrote SARIF: {out_path}")
    print(f"Findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

