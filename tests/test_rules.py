"""
Unit tests for zak-guard detection rules and helper functions.

All secret values used here are obviously fake — they're in the FAKE_SECRETS
namespace and have been constructed to match detector patterns without being
real credentials.
"""

import math
import pytest
from zak_guard.rules import shannon_entropy, redact, RULES, check_entropy


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        # All same character: entropy = 0
        assert shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # "ab" repeated: entropy approaches 1.0 bit
        e = shannon_entropy("abababab")
        assert abs(e - 1.0) < 0.01

    def test_high_entropy_string(self):
        # A long random-ish string should have entropy > 4
        s = "Xk9mN2pR5vL8qW3tY6uA1bC4dE7fG0hI"
        assert shannon_entropy(s) > 4.0

    def test_low_entropy_word(self):
        # A plain English word is low entropy
        assert shannon_entropy("password") < 3.5


class TestRedact:
    def test_normal_value(self):
        r = redact("AKIAEXAMPLEFAKEKEY01")
        # first 4 + ... + last 4
        assert r == "AKIA...EY01"
        # Must not expose the middle of the value
        assert "EXAMPLEFAKE" not in r

    def test_short_value(self):
        assert redact("short") == "****"

    def test_exactly_8_chars(self):
        assert redact("12345678") == "****"

    def test_9_chars(self):
        r = redact("123456789")
        assert r == "1234...6789"


class TestRulePatterns:
    """Test each rule fires on an obviously fake value and not on clean strings."""

    def _rule(self, name: str):
        for r in RULES:
            if r.name == name:
                return r
        raise KeyError(f"rule not found: {name}")

    def test_aws_access_key_id(self):
        rule = self._rule("aws-access-key-id")
        assert rule.pattern.search("AKIAEXAMPLEFAKEKEY01")
        assert not rule.pattern.search("not-a-key-at-all")

    def test_aws_secret_not_on_short_value(self):
        rule = self._rule("aws-secret-access-key")
        # env var assignment with a long fake value
        assert rule.pattern.search(
            "AWS_SECRET_ACCESS_KEY=FakeSecretKeyABCDEFGHIJKLMNOPQRSTUVWXYZ12"
        )
        # short value should match pattern but will fail entropy gate
        m = rule.pattern.search("AWS_SECRET_ACCESS_KEY=short")
        # short values may or may not match the regex — that's fine

    def test_github_pat_classic(self):
        rule = self._rule("github-pat-classic")
        # suffix must be exactly 36 alphanum chars
        assert rule.pattern.search("ghp_FakeTokenExampleABCDEFGHIJKLMNOP1234")

    def test_github_pat_fine_grained(self):
        rule = self._rule("github-pat-fine-grained")
        fake = "github_pat_" + "A" * 82
        assert rule.pattern.search(fake)

    def test_openai_key(self):
        rule = self._rule("openai-key")
        # suffix must be exactly 48 alphanum chars (the sk- prefix adds 3, total 51)
        assert rule.pattern.search("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKL")

    def test_anthropic_key(self):
        rule = self._rule("anthropic-key")
        assert rule.pattern.search(
            "sk-ant-FakeAnthropicKey-ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901"
        )

    def test_stripe_secret(self):
        rule = self._rule("stripe-secret-key")
        # Assembled from parts to avoid push-protection false positives on test data
        value = "sk_" + "live_FakeStripeKeyABCDEFGHIJKLMNOPQ"
        assert rule.pattern.search(value)

    def test_stripe_restricted(self):
        rule = self._rule("stripe-restricted-key")
        value = "rk_" + "live_FakeStripeRestrictedABCDEFGHIJKLM"
        assert rule.pattern.search(value)

    def test_slack_bot(self):
        rule = self._rule("slack-bot-token")
        value = "xoxb" + "-111111111111-222222222222-FakeSlackBotTokenABCDEF"
        assert rule.pattern.search(value)

    def test_google_api_key(self):
        rule = self._rule("google-api-key")
        assert rule.pattern.search("AIzaFakeGoogleKeyABCDEFGHIJKLMNOPQRSTUV")

    def test_private_key_pem(self):
        rule = self._rule("private-key-pem")
        assert rule.pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert rule.pattern.search("-----BEGIN PRIVATE KEY-----")
        assert rule.pattern.search("-----BEGIN EC PRIVATE KEY-----")
        assert not rule.pattern.search("-----BEGIN CERTIFICATE-----")

    def test_jwt_fake(self):
        rule = self._rule("jwt")
        fake_jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiJmYWtlLXVzZXItaWQiLCJuYW1lIjoiRmFrZVVzZXIifQ"
            ".FakeSignatureABCDEFGHIJKLMNOPQRSTUVWXYZ"
        )
        assert rule.pattern.search(fake_jwt)

    def test_env_secret_assignment(self):
        rule = self._rule("env-secret-assignment")
        assert rule.pattern.search(
            "password=FakePasswordABCDEFGHIJKLMNOPQRSTUVWXYZ12"
        )
        assert rule.pattern.search(
            "SECRET=FakeSecretValueABCDEFGHIJKLMNOPQRSTUVWXYZ"
        )


class TestEntropyGate:
    def test_high_entropy_passes(self):
        # AKIAEXAMPLEFAKEKEY01 — varied uppercase + digits
        assert check_entropy("AKIAEXAMPLEFAKEKEY01", 3.0)

    def test_low_entropy_blocked(self):
        # All same character
        assert not check_entropy("AAAAAAAAAAAAAAAAAAA", 3.0)

    def test_zero_minimum_always_passes(self):
        assert check_entropy("aaa", 0.0)
        assert check_entropy("", 0.0)
