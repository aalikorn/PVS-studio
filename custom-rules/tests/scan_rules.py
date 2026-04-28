#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent
RULES_PATH = ROOT / "rules" / "rules.json"
FIXTURES_ROOT = ROOT / "fixtures"


def load_rules() -> dict[str, dict]:
    payload = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    return {rule["id"]: rule for rule in payload["rules"]}


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def line_number_for_match(text: str, match: re.Match[str], group: int = 0) -> int:
    return line_number_for_offset(text, match.start(group))


def display_path(path: Path) -> str:
    for base in (PROJECT_ROOT, ROOT):
        try:
            return str(path.relative_to(base))
        except ValueError:
            continue
    return str(path)


def detect_idor(path: Path, text: str, rule: dict) -> list[dict]:
    if "@PathVariable" not in text:
        return []

    route_param_match = re.search(r"@PathVariable\s+(?:\w+\s+)?(?:Long|long|Integer|int|String)\s+(\w+)", text)
    if not route_param_match:
        return []

    route_param = route_param_match.group(1)
    has_route = any(marker in text for marker in ("@GetMapping", "@PostMapping", "@RequestMapping"))
    uses_identifier_for_fetch = any(
        pattern in text
        for pattern in (
            f"findByUserId({route_param})",
            f"findById({route_param})",
            f"findByIdWithDocs({route_param})",
            f"getUserDocs({route_param})",
            f"loadUser({route_param})",
        )
    )
    has_guard = any(
        pattern in text
        for pattern in (
            "@PreAuthorize",
            f"Objects.equals(authenticatedUserId, {route_param})",
            f"Objects.equals(principalUserId, {route_param})",
            f"principal.getName()), {route_param}",
            f"== {route_param}",
            "hasRole(\"ADMIN\")",
            "hasAuthority(\"ADMIN\")",
            "isAdmin",
            "accessChecker.canAccessUser",
        )
    )

    if has_route and uses_identifier_for_fetch and not has_guard:
        target = text.index(route_param)
        return [
            {
                "ruleId": rule["id"],
                "title": rule["title"],
                "path": display_path(path),
                "line": line_number_for_offset(text, target),
            }
        ]

    vuln_mode_branch = re.search(
        r"if\s*\([^{;]*isVulnerableMode\(\)\)\s*\{(?P<body>.*?)\}\s*else\s*\{",
        text,
        flags=re.DOTALL,
    )
    if has_route and uses_identifier_for_fetch and vuln_mode_branch:
        branch_body = vuln_mode_branch.group("body")
        branch_has_guard = any(
            pattern in branch_body
            for pattern in (
                "@PreAuthorize",
                "Objects.equals(",
                "hasRole(\"ADMIN\")",
                "hasAuthority(\"ADMIN\")",
                "isAdmin",
                "accessChecker.canAccessUser",
                "forbidden",
            )
        )
        branch_uses_data = any(
            pattern in branch_body
            for pattern in (
                "user.getDocs()",
                "repository.findByUserId",
                "userRepository.findByIdWithDocs",
                "ResponseEntity.ok",
            )
        )
        if branch_uses_data and not branch_has_guard:
            return [
                {
                    "ruleId": rule["id"],
                    "title": rule["title"],
                    "path": display_path(path),
                    "line": line_number_for_match(text, vuln_mode_branch),
                    "details": "A vulnerable-mode branch returns user-owned data without an authorization guard.",
                }
            ]
    return []


def detect_short_literals(text: str, token: str) -> list[tuple[str, int]]:
    findings: list[tuple[str, int]] = []
    for match in re.finditer(token, text, flags=re.DOTALL):
        literal = match.group(1)
        if len(literal.encode("utf-8")) < 32:
            findings.append((literal, match.start(1)))
    return findings


def find_jwt_parser_chains(text: str) -> list[re.Match[str]]:
    pattern = r"Jwts\.(?:parser|parserBuilder)\(\).*?;"
    return list(re.finditer(pattern, text, flags=re.DOTALL))


def detect_weak_jwt(path: Path, text: str, rule: dict) -> list[dict]:
    findings: list[dict] = []

    for chain_match in find_jwt_parser_chains(text):
        chain = chain_match.group(0)
        has_require = any(
            marker in chain
            for marker in (".require(", ".requireIssuer(", ".requireAudience(", ".requireSubject(")
        )
        has_verify = ".verifyWith(" in chain
        has_legacy_signing_key = ".setSigningKey(" in chain
        uses_unsecured_parser = ".unsecured(" in chain or ".parseUnsecuredClaims(" in chain

        if uses_unsecured_parser:
            findings.append(
                {
                    "ruleId": rule["id"],
                    "title": rule["title"],
                    "path": display_path(path),
                    "line": line_number_for_match(text, chain_match),
                    "details": "JWT parser explicitly disables signature verification with unsecured parsing.",
                }
            )

        if has_legacy_signing_key and not has_require and not has_verify:
            offset = chain_match.start()
            findings.append(
                {
                    "ruleId": rule["id"],
                    "title": rule["title"],
                    "path": display_path(path),
                    "line": line_number_for_offset(text, offset),
                    "details": "JWT parser uses setSigningKey(...) without any require-constraints.",
                }
            )

    short_key_patterns = (
        r'setSigningKey\("([^"]+)"\)',
        r'hmacShaKeyFor\("([^"]+)"\.getBytes',
    )
    for pattern in short_key_patterns:
        for literal, offset in detect_short_literals(text, pattern):
            findings.append(
                {
                    "ruleId": rule["id"],
                    "title": rule["title"],
                    "path": display_path(path),
                    "line": line_number_for_offset(text, offset),
                    "details": f'Literal key "{literal}" is shorter than 32 bytes.',
                }
            )

    return findings


def scan_tree(root: Path, rules: dict[str, dict]) -> list[dict]:
    findings: list[dict] = []
    for path in sorted(root.rglob("*.java")):
        text = path.read_text(encoding="utf-8")
        findings.extend(detect_idor(path, text, rules["PVS-CUSTOM-IDOR-001"]))
        findings.extend(detect_weak_jwt(path, text, rules["PVS-CUSTOM-JWT-002"]))
    return findings


def print_findings(label: str, findings: list[dict]) -> None:
    print(label)
    if not findings:
        print("  no findings")
        return
    for finding in findings:
        details = finding.get("details")
        suffix = f" - {details}" if details else ""
        print(
            f"  {finding['ruleId']}:{finding['line']} {finding['path']} - {finding['title']}{suffix}"
        )


def main() -> int:
    rules = load_rules()
    vulnerable_findings = scan_tree(FIXTURES_ROOT / "vulnerable", rules)
    fixed_findings = scan_tree(FIXTURES_ROOT / "fixed", rules)

    print_findings("vulnerable fixtures", vulnerable_findings)
    print_findings("fixed fixtures", fixed_findings)

    vulnerable_rule_ids = {finding["ruleId"] for finding in vulnerable_findings}
    expected_ids = {"PVS-CUSTOM-IDOR-001", "PVS-CUSTOM-JWT-002"}

    if vulnerable_rule_ids != expected_ids:
        print(
            f"Unexpected vulnerable finding set: expected {sorted(expected_ids)}, got {sorted(vulnerable_rule_ids)}",
            file=sys.stderr,
        )
        return 1

    if fixed_findings:
        print("Fixed fixtures should not produce findings.", file=sys.stderr)
        return 1

    print("All custom rule checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
