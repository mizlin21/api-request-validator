"""
API Security Request Validator (Enhanced Version)

Features:
- Basic API contract validation (methods, endpoints, headers, body)
- OWASP-style security checks (SQLi, XSS, long input)
- Simple JSON "schema" validation (type + max length)
- Structured security report with severities
- OWASP + MITRE ATT&CK tags on findings
- CLI support: can read requests from a JSON file or use built-in samples

Usage:
    python api_request_validator.py
    python api_request_validator.py -f requests.json
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
import json
import argparse
from pathlib import Path


# ------------------------------------------------------------
# 1. BASIC API CONTRACT (endpoints and allowed methods)
# ------------------------------------------------------------

ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE"}

# API specification + simple schema rules
API_RULES: Dict[str, Dict[str, Any]] = {
    "/users": {
        "methods": {"GET", "POST"},
        "required_fields": {
            "POST": ["username", "email"]
        },
        # Simple "schema": type + max_length for each field
        "schema": {
            "POST": {
                "username": {"type": "string", "max_length": 30},
                "email": {"type": "string", "max_length": 100},
            }
        },
    },
    "/users/{id}": {
        "methods": {"GET", "PUT", "DELETE"},
        "required_fields": {
            "PUT": ["email"]
        },
        "schema": {
            "PUT": {
                "email": {"type": "string", "max_length": 100},
            }
        },
    },
}


# ------------------------------------------------------------
# 2. HELPER: Endpoint pattern matching (/users/42 → /users/{id})
# ------------------------------------------------------------

def match_endpoint(pattern: str, endpoint: str) -> bool:
    pattern_parts = pattern.strip("/").split("/")
    endpoint_parts = endpoint.strip("/").split("/")

    if len(pattern_parts) != len(endpoint_parts):
        return False

    for p, e in zip(pattern_parts, endpoint_parts):
        if p.startswith("{") and p.endswith("}"):
            # Treat {id}, {name}, etc. as variable placeholders
            continue
        if p != e:
            return False

    return True


def find_endpoint_rules(endpoint: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    for pattern, rules in API_RULES.items():
        if match_endpoint(pattern, endpoint):
            return pattern, rules
    return None, None


# ------------------------------------------------------------
# 3. Helper for creating structured security findings
# ------------------------------------------------------------

def make_issue(
    message: str,
    severity: str = "MEDIUM",
    owasp: Optional[str] = None,
    mitre: Optional[str] = None,
    check_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "message": message,
        "severity": severity,
        "owasp": owasp,
        "mitre": mitre,
        "check_id": check_id,
    }


# ------------------------------------------------------------
# 4. Basic validators (method, endpoint, headers, body)
# ------------------------------------------------------------

def validate_method(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    method = request.get("method", "").upper()

    if method not in ALLOWED_METHODS:
        issues.append(
            make_issue(
                message=f"Method '{method}' is not allowed. Use one of: {sorted(ALLOWED_METHODS)}",
                severity="HIGH",
                owasp="API9:2019 Improper Assets Management",
                mitre="T1190",  # Exploit public-facing application
                check_id="METHOD_NOT_ALLOWED",
            )
        )

    return issues


def validate_endpoint(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    endpoint = request.get("endpoint", "")

    if not endpoint.startswith("/"):
        issues.append(
            make_issue(
                message="Endpoint should start with '/'.",
                severity="LOW",
                check_id="ENDPOINT_FORMAT",
            )
        )
        return issues

    pattern, rules = find_endpoint_rules(endpoint)
    if rules is None:
        issues.append(
            make_issue(
                message=f"Endpoint '{endpoint}' is not defined in API_RULES.",
                severity="HIGH",
                owasp="API1:2019 Broken Object Level Authorization",
                mitre="T1190",
                check_id="UNKNOWN_ENDPOINT",
            )
        )
        return issues

    method = request.get("method", "").upper()
    if method not in rules["methods"]:
        issues.append(
            make_issue(
                message=(
                    f"Method '{method}' is not allowed for endpoint pattern '{pattern}'. "
                    f"Allowed methods: {sorted(rules['methods'])}"
                ),
                severity="MEDIUM",
                owasp="API4:2019 Lack of Resources & Rate Limiting",
                mitre="T1190",
                check_id="METHOD_NOT_ALLOWED_FOR_ENDPOINT",
            )
        )

    return issues


def validate_headers(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    headers = request.get("headers", {})

    if not isinstance(headers, dict):
        issues.append(
            make_issue(
                message="Headers must be a dictionary (key-value pairs).",
                severity="MEDIUM",
                check_id="HEADERS_TYPE",
            )
        )
        return issues

    auth = headers.get("Authorization")
    if not auth:
        issues.append(
            make_issue(
                message="Missing 'Authorization' header.",
                severity="HIGH",
                owasp="API2:2019 Broken User Authentication",
                mitre="T1078",  # Valid accounts
                check_id="MISSING_AUTH_HEADER",
            )
        )
    else:
        if not auth.startswith("Bearer "):
            issues.append(
                make_issue(
                    message="Authorization header should start with 'Bearer '.",
                    severity="MEDIUM",
                    owasp="API2:2019 Broken User Authentication",
                    check_id="AUTH_FORMAT",
                )
            )
        token = auth.split(" ", 1)[1] if " " in auth else ""
        if len(token) < 10:
            issues.append(
                make_issue(
                    message="Bearer token looks too short. Use a longer token string.",
                    severity="MEDIUM",
                    owasp="API2:2019 Broken User Authentication",
                    check_id="SHORT_TOKEN",
                )
            )

    method = request.get("method", "").upper()
    if method in {"POST", "PUT"}:
        content_type = headers.get("Content-Type")
        if content_type != "application/json":
            issues.append(
                make_issue(
                    message=(
                        "For POST/PUT requests, 'Content-Type' should be "
                        "'application/json'."
                    ),
                    severity="MEDIUM",
                    owasp="API8:2019 Injection",
                    check_id="CONTENT_TYPE_INVALID",
                )
            )

    return issues


def validate_body_required_fields(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    body = request.get("body", {})

    if body is None:
        body = {}

    if not isinstance(body, dict):
        issues.append(
            make_issue(
                message="Body must be a JSON-like dictionary.",
                severity="MEDIUM",
                owasp="API8:2019 Injection",
                check_id="BODY_NOT_DICT",
            )
        )
        return issues

    endpoint = request.get("endpoint", "")
    method = request.get("method", "").upper()

    pattern, rules = find_endpoint_rules(endpoint)
    if rules is None:
        # Endpoint already handled in validate_endpoint
        return issues

    required_fields_for_method = rules.get("required_fields", {}).get(method, [])
    for field in required_fields_for_method:
        if field not in body:
            issues.append(
                make_issue(
                    message=f"Missing required field '{field}' in request body for {method} {pattern}.",
                    severity="HIGH",
                    owasp="API3:2019 Excessive Data Exposure",
                    check_id="MISSING_REQUIRED_FIELD",
                )
            )

    return issues


# ------------------------------------------------------------
# 5. JSON "schema" validation (types + length)
# ------------------------------------------------------------

TYPE_MAP = {
    "string": str,
    "integer": int,
    "float": float,
    "boolean": bool,
}


def validate_body_schema(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    body = request.get("body", {}) or {}
    endpoint = request.get("endpoint", "")
    method = request.get("method", "").upper()

    pattern, rules = find_endpoint_rules(endpoint)
    if rules is None:
        return issues

    schema_for_method = rules.get("schema", {}).get(method)
    if not schema_for_method:
        return issues  # No schema defined, nothing to check

    for field_name, ruleset in schema_for_method.items():
        if field_name not in body:
            continue  # Missing fields are handled in required_fields check

        value = body[field_name]
        expected_type_name = ruleset.get("type")
        max_length = ruleset.get("max_length")

        if expected_type_name:
            expected_type = TYPE_MAP.get(expected_type_name)
            if expected_type and not isinstance(value, expected_type):
                issues.append(
                    make_issue(
                        message=(
                            f"Field '{field_name}' should be of type '{expected_type_name}', "
                            f"but got '{type(value).__name__}'."
                        ),
                        severity="MEDIUM",
                        owasp="API8:2019 Injection",
                        check_id="FIELD_WRONG_TYPE",
                    )
                )

        if max_length and isinstance(value, str) and len(value) > max_length:
            issues.append(
                make_issue(
                    message=(
                        f"Field '{field_name}' is too long (len={len(value)}). "
                        f"Maximum allowed is {max_length}."
                    ),
                    severity="LOW",
                    owasp="API4:2019 Lack of Resources & Rate Limiting",
                    check_id="FIELD_TOO_LONG",
                )
            )

    return issues


# ------------------------------------------------------------
# 6. OWASP-style security pattern checks (SQLi, XSS, etc.)
# ------------------------------------------------------------

def get_all_string_values(body: Dict[str, Any]) -> List[str]:
    """Collect all string values from a (possibly nested) body."""
    strings: List[str] = []

    def _collect(value: Any):
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                _collect(v)
        elif isinstance(value, list):
            for v in value:
                _collect(v)

    _collect(body)
    return strings


def validate_security_patterns(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    body = request.get("body", {}) or {}

    all_strings = get_all_string_values(body)

    # Very simple pattern checks (demo-level, not production)
    for text in all_strings:
        lowered = text.lower()

        # SQLi-like patterns
        if " or " in lowered and "1=1" in lowered:
            issues.append(
                make_issue(
                    message=f"Possible SQL injection pattern detected in value: {text!r}",
                    severity="HIGH",
                    owasp="API8:2019 Injection",
                    mitre="T1190",
                    check_id="SQLI_PATTERN",
                )
            )

        if "union select" in lowered:
            issues.append(
                make_issue(
                    message=f"Possible SQL injection 'UNION SELECT' pattern in value: {text!r}",
                    severity="HIGH",
                    owasp="API8:2019 Injection",
                    mitre="T1190",
                    check_id="SQLI_UNION",
                )
            )

        # XSS-like patterns
        if "<script" in lowered:
            issues.append(
                make_issue(
                    message=f"Possible XSS pattern detected in value: {text!r}",
                    severity="HIGH",
                    owasp="API3:2019 Excessive Data Exposure",
                    mitre="T1059",  # Command/script execution
                    check_id="XSS_SCRIPT_TAG",
                )
            )

        if "onerror=" in lowered or "onload=" in lowered:
            issues.append(
                make_issue(
                    message=f"Possible XSS event handler in value: {text!r}",
                    severity="MEDIUM",
                    owasp="API3:2019 Excessive Data Exposure",
                    check_id="XSS_EVENT_HANDLER",
                )
            )

        # Very long values (DoS / resource abuse hint)
        if len(text) > 500:
            issues.append(
                make_issue(
                    message="Very large input value detected (length > 500). Consider enforcing size limits.",
                    severity="MEDIUM",
                    owasp="API4:2019 Lack of Resources & Rate Limiting",
                    check_id="VERY_LONG_INPUT",
                )
            )

    return issues


# ------------------------------------------------------------
# 7. Main validation aggregator + report generator
# ------------------------------------------------------------

def validate_request(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    issues.extend(validate_method(request))
    issues.extend(validate_endpoint(request))
    issues.extend(validate_headers(request))
    issues.extend(validate_body_required_fields(request))
    issues.extend(validate_body_schema(request))
    issues.extend(validate_security_patterns(request))
    return issues


def summarize_severities(issues: List[Dict[str, Any]]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for issue in issues:
        sev = issue.get("severity", "UNKNOWN")
        summary[sev] = summary.get(sev, 0) + 1
    return summary


def generate_report(request: Dict[str, Any], issues: List[Dict[str, Any]]) -> Dict[str, Any]:
    method = request.get("method", "").upper()
    endpoint = request.get("endpoint", "")
    status = "VALID" if not issues else "INVALID"

    report = {
        "method": method,
        "endpoint": endpoint,
        "status": status,
        "issue_count": len(issues),
        "by_severity": summarize_severities(issues),
        "issues": issues,
    }
    return report


def print_report(report: Dict[str, Any], index: int) -> None:
    print("-" * 70)
    print(f"Request #{index}: {report['method']} {report['endpoint']}")
    print(f"Status: {report['status']}")
    print(f"Issues: {report['issue_count']}  |  By severity: {report['by_severity']}")

    if report["issues"]:
        print("Findings:")
        for issue in report["issues"]:
            sev = issue.get("severity", "UNKNOWN")
            msg = issue.get("message", "")
            owasp = issue.get("owasp")
            mitre = issue.get("mitre")
            check_id = issue.get("check_id")
            line = f" - [{sev}] {msg}"
            if check_id:
                line += f" (ID: {check_id})"
            if owasp:
                line += f" | OWASP: {owasp}"
            if mitre:
                line += f" | MITRE: {mitre}"
            print(line)


# ------------------------------------------------------------
# 8. Sample requests (fallback demo data)
# ------------------------------------------------------------

SAMPLE_REQUESTS = [
    {
        "name": "Valid GET /users",
        "method": "GET",
        "endpoint": "/users",
        "headers": {
            "Authorization": "Bearer 1234567890abcdef",
        },
        "body": None,
    },
    {
        "name": "Invalid method (PATCH not allowed)",
        "method": "PATCH",
        "endpoint": "/users",
        "headers": {
            "Authorization": "Bearer 1234567890abcdef",
        },
        "body": None,
    },
    {
        "name": "Missing Authorization header",
        "method": "GET",
        "endpoint": "/users",
        "headers": {},
        "body": None,
    },
    {
        "name": "POST /users missing email",
        "method": "POST",
        "endpoint": "/users",
        "headers": {
            "Authorization": "Bearer 1234567890abcdef",
            "Content-Type": "application/json",
        },
        "body": {
            "username": "linda",
        },
    },
    {
        "name": "Valid POST /users",
        "method": "POST",
        "endpoint": "/users",
        "headers": {
            "Authorization": "Bearer 1234567890abcdef",
            "Content-Type": "application/json",
        },
        "body": {
            "username": "linda",
            "email": "linda@example.com",
        },
    },
    {
        "name": "Valid PUT /users/42",
        "method": "PUT",
        "endpoint": "/users/42",
        "headers": {
            "Authorization": "Bearer 1234567890abcdef",
            "Content-Type": "application/json",
        },
        "body": {
            "email": "new_email@example.com",
        },
    },
    {
        "name": "SQLi attempt in username",
        "method": "POST",
        "endpoint": "/users",
        "headers": {
            "Authorization": "Bearer 1234567890abcdef",
            "Content-Type": "application/json",
        },
        "body": {
            "username": "admin' OR 1=1 --",
            "email": "attacker@example.com",
        },
    },
    {
        "name": "XSS attempt in email",
        "method": "POST",
        "endpoint": "/users",
        "headers": {
            "Authorization": "Bearer 1234567890abcdef",
            "Content-Type": "application/json",
        },
        "body": {
            "username": "linda",
            "email": "<script>alert('xss')</script>",
        },
    },
    {
        "name": "Unknown endpoint /unknown",
        "method": "GET",
        "endpoint": "/unknown",
        "headers": {
            "Authorization": "Bearer 1234567890abcdef",
        },
        "body": None,
    },
]


# ------------------------------------------------------------
# 9. CLI & main()
# ------------------------------------------------------------

def load_requests_from_file(path: Path) -> List[Dict[str, Any]]:
    """
    Load JSON from a file. It can be:
    - a single request object
    - a list of request objects
    """
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        return [data]
    elif isinstance(data, list):
        return data
    else:
        raise ValueError("JSON file must contain an object or a list of objects.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="API Security Request Validator (with OWASP & MITRE tagging)."
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Optional path to a JSON file containing one or more requests.",
    )
    args = parser.parse_args()

    print("=== API Security Request Validator ===")
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file not found: {path}")
            return
        print(f"Loading requests from: {path}")
        requests = load_requests_from_file(path)
    else:
        print("No file provided. Using built-in SAMPLE_REQUESTS demo.\n")
        requests = SAMPLE_REQUESTS

    for index, request in enumerate(requests, start=1):
        report = generate_report(request, validate_request(request))
        print_report(report, index)

    print("-" * 70)
    print("Done. You can also run with: python api_request_validator.py -f my_requests.json")


if __name__ == "__main__":
    main()
