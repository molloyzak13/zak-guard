"""
Core scanning logic for zak-guard.

scan_file(path, allowlist) -> list[Finding]
scan_diff(diff_text, allowlist) -> list[Finding]
scan_staged(allowlist) -> list[Finding]
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .rules import RULES, Rule, check_entropy, redact


# Extensions that are binary or not worth scanning for text secrets
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".a", ".o",
    ".pyc", ".pyo", ".class",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".lock",  # package lock files are too large and never contain real secrets
}

# Files that are themselves test fixtures, known-fake data, or deliberately contain patterns
SKIP_FILENAMES = {
    ".pre-commit-hooks.yaml",
}


@dataclass
class Finding:
    rule_name: str
    description: str
    file_path: str
    line_number: int
    redacted_match: str
    line_preview: str

    def format(self) -> str:
        preview = self.line_preview.strip()
        if len(preview) > 120:
            preview = preview[:117] + "..."
        return (
            f"  [{self.rule_name}] {self.file_path}:{self.line_number}\n"
            f"    {self.description}: {self.redacted_match}\n"
            f"    > {preview}"
        )


def _load_allowlist(allowlist_path: Optional[str]) -> set[str]:
    """Load allowlisted patterns from a file (one per line, # comments ignored)."""
    if not allowlist_path:
        return set()
    p = Path(allowlist_path)
    if not p.exists():
        return set()
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def _is_allowlisted(value: str, allowlist: set[str]) -> bool:
    """Check if value matches any allowlist entry (exact string or substring)."""
    for entry in allowlist:
        if entry in value:
            return True
    return False


def _scan_text(
    text: str,
    file_path: str,
    allowlist: set[str],
    line_offset: int = 0,
) -> list[Finding]:
    """Scan raw text content for secret patterns. Returns list of Finding objects."""
    findings: list[Finding] = []
    lines = text.splitlines()

    for lineno, line in enumerate(lines, start=1 + line_offset):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                # Use group(1) if capturing group exists, else group(0)
                try:
                    value = match.group(1)
                except IndexError:
                    value = match.group(0)

                if not value:
                    continue

                # Entropy gate
                if not check_entropy(value, rule.entropy_min):
                    continue

                # Allowlist check
                if _is_allowlisted(value, allowlist):
                    continue

                findings.append(
                    Finding(
                        rule_name=rule.name,
                        description=rule.description,
                        file_path=file_path,
                        line_number=lineno,
                        redacted_match=redact(value),
                        line_preview=line,
                    )
                )
                # One finding per rule per line is enough (avoid flooding on a single bad line)
                break

    return findings


def scan_file(path: str, allowlist_path: Optional[str] = None) -> list[Finding]:
    """Scan a single file on disk."""
    p = Path(path)
    if p.suffix.lower() in BINARY_EXTENSIONS:
        return []
    if p.name in SKIP_FILENAMES:
        return []
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []

    allowlist = _load_allowlist(allowlist_path)
    return _scan_text(text, str(path), allowlist)


def scan_directory(root: str, allowlist_path: Optional[str] = None) -> list[Finding]:
    """Recursively scan all non-binary files under root."""
    findings: list[Finding] = []
    root_path = Path(root)

    for p in sorted(root_path.rglob("*")):
        if not p.is_file():
            continue
        # Skip .git internals
        if ".git" in p.parts:
            continue
        findings.extend(scan_file(str(p), allowlist_path))

    return findings


def scan_staged(allowlist_path: Optional[str] = None) -> list[Finding]:
    """
    Scan only the staged changes (what `git diff --cached` shows).

    Parses unified diff output so we only flag lines that are being ADDED,
    not lines that already exist in the repo. Exit non-zero if the staged
    diff can't be fetched.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--unified=0"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git diff --cached failed: {e.stderr.strip()}") from e
    except FileNotFoundError:
        raise RuntimeError("git not found in PATH")

    return _scan_diff_text(result.stdout, allowlist_path)


def _scan_diff_text(diff_text: str, allowlist_path: Optional[str] = None) -> list[Finding]:
    """Parse a unified diff and scan only added lines (+) per file."""
    allowlist = _load_allowlist(allowlist_path)
    findings: list[Finding] = []

    current_file: Optional[str] = None
    current_line: int = 0
    DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
    DIFF_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for raw_line in diff_text.splitlines():
        m_file = DIFF_FILE_RE.match(raw_line)
        if m_file:
            current_file = m_file.group(1)
            current_line = 0
            continue

        m_hunk = DIFF_HUNK_RE.match(raw_line)
        if m_hunk:
            current_line = int(m_hunk.group(1)) - 1  # will be incremented on first +line
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_line += 1
            if current_file is None:
                continue
            # Skip binary files and known-safe filenames
            p = Path(current_file)
            if p.suffix.lower() in BINARY_EXTENSIONS:
                continue
            if p.name in SKIP_FILENAMES:
                continue
            added_line = raw_line[1:]  # strip the leading +
            line_findings = _scan_text(added_line, current_file, allowlist, line_offset=current_line - 1)
            findings.extend(line_findings)
        elif not raw_line.startswith("-"):
            # Context line (no + or -) — still advances the new-file line counter
            if current_line > 0:
                current_line += 1

    return findings
