"""
zak-guard CLI entry point.

Usage:
  zak-guard [--staged] [--allowlist FILE]          # scan staged changes (default)
  zak-guard --all [--allowlist FILE]               # scan entire repo from cwd
  zak-guard --all PATH [--allowlist FILE]          # scan a specific path
  zak-guard install                                # wire the git pre-commit hook
"""

import argparse
import os
import stat
import sys
from pathlib import Path

from .scanner import scan_staged, scan_directory, scan_file, Finding


EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


PRE_COMMIT_HOOK = """\
#!/usr/bin/env sh
# zak-guard pre-commit hook (installed by: zak-guard install)
# Scans staged changes for secrets before each commit.
exec zak-guard --staged
"""


def install_hook() -> int:
    """Write the pre-commit hook into .git/hooks/pre-commit."""
    git_dir = _find_git_dir()
    if git_dir is None:
        print("error: not inside a git repository", file=sys.stderr)
        return EXIT_ERROR

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        existing = hook_path.read_text()
        if "zak-guard" in existing:
            print(f"zak-guard hook already installed at {hook_path}")
            return EXIT_CLEAN
        # Back up existing hook
        backup = hook_path.with_suffix(".pre-zak-guard")
        hook_path.rename(backup)
        print(f"existing pre-commit hook backed up to {backup}")

    hook_path.write_text(PRE_COMMIT_HOOK)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print(f"installed zak-guard pre-commit hook at {hook_path}")
    return EXIT_CLEAN


def _find_git_dir() -> Path | None:
    """Walk up the directory tree looking for a .git directory."""
    p = Path.cwd()
    for candidate in [p, *p.parents]:
        git = candidate / ".git"
        if git.is_dir():
            return git
    return None


def _print_summary(findings: list[Finding], mode: str) -> None:
    if findings:
        print(f"\nzak-guard found {len(findings)} potential secret(s) ({mode}):\n")
        for f in findings:
            print(f.format())
        print(
            "\nIf these are false positives, add the matching string to an allowlist file\n"
            "and pass --allowlist <file> (or set ZAK_GUARD_ALLOWLIST in your environment).\n"
            "Never commit real secrets. Redact them from history with git-filter-repo."
        )
    else:
        print(f"zak-guard: no secrets found ({mode})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="zak-guard",
        description="Scan staged changes (or a path) for secrets before they hit your repo.",
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    # install subcommand
    subparsers.add_parser("install", help="Install zak-guard as the git pre-commit hook")

    # Main scan flags
    parser.add_argument(
        "--staged",
        action="store_true",
        default=False,
        help="Scan staged changes only (default mode for the pre-commit hook)",
    )
    parser.add_argument(
        "--all",
        dest="scan_all",
        metavar="PATH",
        nargs="?",
        const=".",
        default=None,
        help="Scan all files under PATH (default: current directory)",
    )
    parser.add_argument(
        "--allowlist",
        metavar="FILE",
        default=os.environ.get("ZAK_GUARD_ALLOWLIST"),
        help="Path to a file of known-safe strings to ignore (one per line)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="zak-guard 0.1.0",
    )

    args = parser.parse_args(argv)

    if args.subcommand == "install":
        return install_hook()

    allowlist = args.allowlist

    if args.scan_all is not None:
        # --all [PATH]
        target = args.scan_all
        path = Path(target)
        if path.is_file():
            findings = scan_file(target, allowlist)
            mode = f"file scan: {target}"
        elif path.is_dir():
            findings = scan_directory(target, allowlist)
            mode = f"directory scan: {target}"
        else:
            print(f"error: path does not exist: {target}", file=sys.stderr)
            return EXIT_ERROR
        _print_summary(findings, mode)
        return EXIT_FINDINGS if findings else EXIT_CLEAN

    # Default: staged scan (also what --staged explicitly requests)
    try:
        findings = scan_staged(allowlist)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR

    _print_summary(findings, "staged changes")
    return EXIT_FINDINGS if findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
