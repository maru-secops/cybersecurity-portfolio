#!/usr/bin/env python3
"""
Pre-Commit OpSec & NDA Sanitization Guard for public cybersecurity repositories.

Checks staged Git blobs and local Git author configuration before every commit:
- Enforces GitHub noreply author email (*@users.noreply.github.com)
- Blocks sensitive file names (.env, keys, packet captures, drafts)
- Blocks binary files from being committed unintentionally
- Blocks public IPv4 addresses outside RFC 5737, RFC 1918, and loopback ranges
- Blocks common API tokens, private key headers, local OS paths, and non-safe emails
- Optionally loads extra private/NDA patterns from OPSEC_LOCAL_BLOCKLIST (local-only)
"""

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SAFE_EMAIL_DOMAINS = {
    "users.noreply.github.com",
    "example.com",
    "example.org",
    "example.net",
}

SAFE_IPV4_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),     # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # RFC 5737 TEST-NET-3
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 Private Lab
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 Private Lab
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 Private Lab
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("0.0.0.0/8"),        # Unspecified
]

FORBIDDEN_FILENAME_PATTERNS = [
    (re.compile(r"(^|/)\.env(\.|$)", re.I), "Environment / secrets file"),
    (re.compile(r"\.(pem|key|p12|pfx|pcap|pcapng|cap)$", re.I), "Sensitive key or packet capture"),
    (re.compile(r"(DRAFT|PRIVATE)", re.I), "Draft/private file name"),
    (re.compile(r"security_audit\.log$", re.I), "Internal audit log"),
]

FORBIDDEN_CONTENT_PATTERNS = [
    (re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+", re.I), "Local Windows user path"),
    (re.compile(r"(?:/Users/|/home/)[A-Za-z0-9._-]+/"), "Local Unix/macOS user path"),
    (re.compile(r"\b(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{10,}"), "GitHub token"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Google API key"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "API secret key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"-----BEGIN [A-Z ]*" + r"PRIVATE KEY-----"), "Private key block"),
]

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def run_git_text(args: list[str]) -> str:
    res = subprocess.run(
        ["git"] + args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return res.stdout if res.returncode == 0 else ""


def get_staged_blob(filepath: str) -> bytes:
    res = subprocess.run(
        ["git", "show", f":{filepath}"],
        capture_output=True,
    )
    return res.stdout if res.returncode == 0 else b""


def load_local_blocklist(violations: list[str]) -> list[tuple[re.Pattern, str]]:
    """Load optional private/NDA regex patterns from a local file outside the repo.

    Enforces OWASP 'Fail Securely': if OPSEC_LOCAL_BLOCKLIST is configured, a
    missing/unreadable file or invalid regex aborts the commit instead of
    silently continuing without local protections.
    """
    patterns: list[tuple[re.Pattern, str]] = []
    blocklist_path = os.environ.get("OPSEC_LOCAL_BLOCKLIST", "").strip()
    if not blocklist_path:
        return patterns

    path = Path(blocklist_path)
    if not path.is_file():
        violations.append(
            f"[FAIL-SECURELY] Configured OPSEC_LOCAL_BLOCKLIST not found: {path}"
        )
        return patterns

    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        violations.append(
            f"[FAIL-SECURELY] Unable to read OPSEC_LOCAL_BLOCKLIST ({path}): {exc}"
        )
        return patterns

    for lineno, raw_line in enumerate(raw_lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            patterns.append(
                (re.compile(line, re.IGNORECASE), "Local private/NDA blocklist match")
            )
        except re.error as exc:
            violations.append(
                f"[FAIL-SECURELY] Invalid regex in OPSEC_LOCAL_BLOCKLIST line {lineno}: {exc}"
            )
    return patterns


def check_author_email(violations: list[str]) -> None:
    email = run_git_text(["config", "user.email"]).strip()
    if not email:
        violations.append("[GIT CONFIG] user.email is not set.")
    elif not email.lower().endswith("@users.noreply.github.com"):
        violations.append(
            f"[GIT CONFIG] user.email '{email}' is not a GitHub noreply address "
            "(expected *@users.noreply.github.com)."
        )


def scan_staged_files(
    violations: list[str], local_patterns: list[tuple[re.Pattern, str]]
) -> int:
    raw = run_git_text(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
    files = [f.strip() for f in raw.splitlines() if f.strip()]
    all_patterns = FORBIDDEN_CONTENT_PATTERNS + local_patterns

    for filepath in files:
        for pat, desc in FORBIDDEN_FILENAME_PATTERNS:
            if pat.search(filepath):
                violations.append(f"[FILE] {filepath}: {desc}")

        blob = get_staged_blob(filepath)
        if not blob:
            continue

        if b"\x00" in blob:
            violations.append(f"[BINARY] {filepath}: Binary files are not allowed in this public repo.")
            continue

        try:
            content = blob.decode("utf-8")
        except UnicodeDecodeError:
            violations.append(f"[BINARY] {filepath}: Non-UTF-8 / binary file is not allowed.")
            continue

        for lineno, line in enumerate(content.splitlines(), start=1):
            for pat, desc in all_patterns:
                if pat.search(line):
                    violations.append(f"[CONTENT] {filepath}:{lineno} -> {desc}")

            for match in EMAIL_RE.finditer(line):
                domain = match.group(1).lower()
                if domain not in SAFE_EMAIL_DOMAINS:
                    violations.append(
                        f"[EMAIL] {filepath}:{lineno} -> Non-safe email '{match.group(0)}'"
                    )

            for match in IPV4_RE.finditer(line):
                ip_str = match.group(1)
                try:
                    ip_obj = ipaddress.IPv4Address(ip_str)
                except ValueError:
                    continue
                if not any(ip_obj in net for net in SAFE_IPV4_NETWORKS):
                    violations.append(
                        f"[IP] {filepath}:{lineno} -> Public IPv4 '{ip_str}' "
                        "(use RFC 5737: 192.0.2.x, 198.51.100.x, 203.0.113.x)"
                    )

    return len(files)


def main() -> int:
    violations: list[str] = []
    local_patterns = load_local_blocklist(violations)
    check_author_email(violations)
    file_count = scan_staged_files(violations, local_patterns)

    if violations:
        print("\n[OPSEC-BLOCKED] Commit aborted! Violations detected:\n", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        print("\nPlease sanitize the flagged items before committing again.\n", file=sys.stderr)
        return 1

    extra = f" (+{len(local_patterns)} local blocklist rules)" if local_patterns else ""
    print(f"[OPSEC-OK] Checked {file_count} staged file(s) & git author email{extra}. Clean!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
