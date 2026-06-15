"""
Integration tests for zak-guard scanner: file scanning, directory scanning,
diff parsing, and allowlist suppression.

Fixture files in tests/fixtures/ contain obviously fake secrets (see comments
in each file). No real credentials appear anywhere in this repo.
"""

from pathlib import Path

from zak_guard.scanner import scan_file, scan_directory, _scan_diff_text


FIXTURES = Path(__file__).parent / "fixtures"


class TestScanFile:
    def test_detects_secrets_in_env_file(self):
        path = FIXTURES / "fake_secrets.env"
        findings = scan_file(str(path))
        # Should find multiple secrets
        assert len(findings) > 0
        names = {f.rule_name for f in findings}
        # At minimum we expect the AWS key and at least one more
        assert "aws-access-key-id" in names

    def test_detects_secrets_in_py_file(self):
        path = FIXTURES / "fake_secrets.py"
        findings = scan_file(str(path))
        assert len(findings) > 0
        names = {f.rule_name for f in findings}
        assert "github-pat-classic" in names or "aws-access-key-id" in names

    def test_clean_file_no_findings(self):
        path = FIXTURES / "clean_file.py"
        findings = scan_file(str(path))
        assert findings == [], f"unexpected findings on clean file: {findings}"

    def test_nonexistent_file_returns_empty(self):
        findings = scan_file("/tmp/definitely-does-not-exist-xyzzy-zak-guard")
        assert findings == []

    def test_finding_redacts_secret(self):
        path = FIXTURES / "fake_secrets.env"
        findings = scan_file(str(path))
        for f in findings:
            # The redacted match should never contain a long contiguous run from the fake key
            assert "EXAMPLEFAKEKEY" not in f.redacted_match
            assert "..." in f.redacted_match or f.redacted_match == "****"

    def test_finding_has_correct_fields(self):
        path = FIXTURES / "fake_secrets.env"
        findings = scan_file(str(path))
        assert len(findings) > 0
        f = findings[0]
        assert f.file_path == str(path)
        assert f.line_number >= 1
        assert f.rule_name
        assert f.description
        assert f.redacted_match
        assert f.line_preview

    def test_finding_format_output(self):
        path = FIXTURES / "fake_secrets.env"
        findings = scan_file(str(path))
        assert len(findings) > 0
        formatted = findings[0].format()
        assert "[" in formatted  # rule name in brackets
        assert ":" in formatted  # file:line


class TestAllowlist:
    def test_allowlist_suppresses_matching_finding(self):
        path = FIXTURES / "fake_secrets.env"
        allowlist = FIXTURES / "allowlist.txt"
        # The allowlist suppresses AKIAEXAMPLEFAKEKEY01 and the classic GitHub PAT
        findings = scan_file(str(path), str(allowlist))
        names = {f.rule_name for f in findings}
        assert "aws-access-key-id" not in names

    def test_empty_allowlist_path_still_works(self):
        path = FIXTURES / "fake_secrets.env"
        findings = scan_file(str(path), None)
        assert len(findings) > 0

    def test_nonexistent_allowlist_path_is_ignored(self):
        path = FIXTURES / "fake_secrets.env"
        findings = scan_file(str(path), "/tmp/no-such-allowlist-file-xyzzy")
        assert len(findings) > 0


class TestScanDirectory:
    def test_scans_fixtures_dir(self):
        findings = scan_directory(str(FIXTURES))
        assert len(findings) > 0

    def test_clean_subdirectory(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1 + 1\n")
        findings = scan_directory(str(tmp_path))
        assert findings == []

    def test_directory_with_secret_file(self, tmp_path):
        secret_file = tmp_path / "config.env"
        secret_file.write_text(
            "AWS_ACCESS_KEY_ID=AKIAEXAMPLEFAKEKEY02\n"
        )
        findings = scan_directory(str(tmp_path))
        assert len(findings) > 0
        assert any(f.rule_name == "aws-access-key-id" for f in findings)


class TestDiffScanner:
    def test_added_line_with_secret_flagged(self):
        diff = (
            "diff --git a/config.env b/config.env\n"
            "--- a/config.env\n"
            "+++ b/config.env\n"
            "@@ -0,0 +1,2 @@\n"
            "+AWS_ACCESS_KEY_ID=AKIAEXAMPLEFAKEKEY03\n"
            "+NORMAL=value\n"
        )
        findings = _scan_diff_text(diff)
        assert len(findings) > 0
        assert any(f.rule_name == "aws-access-key-id" for f in findings)

    def test_removed_line_not_flagged(self):
        diff = (
            "diff --git a/config.env b/config.env\n"
            "--- a/config.env\n"
            "+++ b/config.env\n"
            "@@ -1,2 +1,1 @@\n"
            "-AWS_ACCESS_KEY_ID=AKIAEXAMPLEFAKEKEY04\n"
            " NORMAL=value\n"
        )
        findings = _scan_diff_text(diff)
        # Removed lines should NOT be flagged (they're being deleted, not added)
        assert findings == []

    def test_context_line_not_flagged(self):
        diff = (
            "diff --git a/config.env b/config.env\n"
            "--- a/config.env\n"
            "+++ b/config.env\n"
            "@@ -1,2 +1,2 @@\n"
            " AWS_ACCESS_KEY_ID=AKIAEXAMPLEFAKEKEY05\n"
            "+ANOTHER=value\n"
        )
        findings = _scan_diff_text(diff)
        # Context line (leading space) must not be flagged
        assert all(f.file_path != "AKIAEXAMPLEFAKEKEY05" for f in findings)
        # The added ANOTHER=value line is clean, so no findings
        assert findings == []

    def test_multiple_files_in_diff(self):
        diff = (
            "diff --git a/a.env b/a.env\n"
            "--- a/a.env\n"
            "+++ b/a.env\n"
            "@@ -0,0 +1 @@\n"
            "+GITHUB_TOKEN=ghp_FakeTokenExampleABCDEFGHIJKLMNOP1234\n"
            "diff --git a/b.env b/b.env\n"
            "--- a/b.env\n"
            "+++ b/b.env\n"
            "@@ -0,0 +1 @@\n"
            "+AWS_ACCESS_KEY_ID=AKIAEXAMPLEFAKEKEY06\n"
        )
        findings = _scan_diff_text(diff)
        file_paths = {f.file_path for f in findings}
        assert "a.env" in file_paths
        assert "b.env" in file_paths

    def test_empty_diff_no_findings(self):
        findings = _scan_diff_text("")
        assert findings == []

    def test_allowlist_in_diff(self):
        diff = (
            "diff --git a/a.env b/a.env\n"
            "--- a/a.env\n"
            "+++ b/a.env\n"
            "@@ -0,0 +1 @@\n"
            "+AWS_ACCESS_KEY_ID=AKIAEXAMPLEFAKEKEY01\n"
        )
        allowlist = FIXTURES / "allowlist.txt"
        findings = _scan_diff_text(diff, str(allowlist))
        # AKIAEXAMPLEFAKEKEY01 is in the allowlist
        assert not any(f.rule_name == "aws-access-key-id" for f in findings)
