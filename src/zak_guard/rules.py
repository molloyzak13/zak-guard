"""
Secret detection rules for zak-guard.

Each rule is a dict with:
  name:        short identifier shown in output
  pattern:     compiled regex that matches the secret
  entropy_min: minimum Shannon entropy required (0 = disable entropy check)
  description: human-readable label

Patterns are ordered from most specific to least to reduce false positives.
"""

import math
import re
import string
from dataclasses import dataclass
from typing import Optional


@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    description: str
    entropy_min: float = 0.0


def shannon_entropy(s: str, alphabet: str = string.printable) -> float:
    """Shannon entropy of string s over the given alphabet."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


RULES: list[Rule] = [
    # AWS access key ID (AKIA... 20 chars, base36-ish)
    Rule(
        name="aws-access-key-id",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        description="AWS Access Key ID",
        entropy_min=3.0,
    ),
    # AWS secret access key (40-char base64 after common env var names)
    Rule(
        name="aws-secret-access-key",
        pattern=re.compile(
            r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?"
        ),
        description="AWS Secret Access Key",
        entropy_min=4.5,
    ),
    # GitHub fine-grained PAT
    Rule(
        name="github-pat-fine-grained",
        pattern=re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        description="GitHub Fine-Grained Personal Access Token",
        entropy_min=4.0,
    ),
    # GitHub classic PAT
    Rule(
        name="github-pat-classic",
        pattern=re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
        description="GitHub Classic Personal Access Token (ghp_)",
        entropy_min=4.0,
    ),
    # GitHub OAuth app token
    Rule(
        name="github-oauth-token",
        pattern=re.compile(r"\b(gho_[A-Za-z0-9]{36})\b"),
        description="GitHub OAuth Token (gho_)",
        entropy_min=4.0,
    ),
    # GitHub Actions runner token
    Rule(
        name="github-actions-token",
        pattern=re.compile(r"\b(ghs_[A-Za-z0-9]{36})\b"),
        description="GitHub Actions Token (ghs_)",
        entropy_min=4.0,
    ),
    # GitHub refresh token
    Rule(
        name="github-refresh-token",
        pattern=re.compile(r"\b(ghr_[A-Za-z0-9]{36})\b"),
        description="GitHub Refresh Token (ghr_)",
        entropy_min=4.0,
    ),
    # OpenAI key (sk-... legacy)
    Rule(
        name="openai-key",
        pattern=re.compile(r"\b(sk-[A-Za-z0-9]{48})\b"),
        description="OpenAI API Key",
        entropy_min=4.0,
    ),
    # OpenAI project key (sk-proj-...)
    Rule(
        name="openai-project-key",
        pattern=re.compile(r"\b(sk-proj-[A-Za-z0-9\-_]{40,})\b"),
        description="OpenAI Project API Key",
        entropy_min=4.0,
    ),
    # Anthropic key
    Rule(
        name="anthropic-key",
        pattern=re.compile(r"\b(sk-ant-[A-Za-z0-9\-_]{40,})\b"),
        description="Anthropic API Key",
        entropy_min=4.0,
    ),
    # DeepSeek key
    Rule(
        name="deepseek-key",
        pattern=re.compile(r"\b(sk-[A-Za-z0-9]{32,})\b"),
        description="DeepSeek/generic sk- API Key",
        entropy_min=4.5,
    ),
    # Stripe live secret key
    Rule(
        name="stripe-secret-key",
        pattern=re.compile(r"\b(sk_live_[A-Za-z0-9]{24,})\b"),
        description="Stripe Live Secret Key",
        entropy_min=4.0,
    ),
    # Stripe restricted key
    Rule(
        name="stripe-restricted-key",
        pattern=re.compile(r"\b(rk_live_[A-Za-z0-9]{24,})\b"),
        description="Stripe Live Restricted Key",
        entropy_min=4.0,
    ),
    # Slack bot token
    Rule(
        name="slack-bot-token",
        pattern=re.compile(r"\b(xoxb-[0-9A-Za-z\-]{20,})\b"),
        description="Slack Bot Token (xoxb-)",
        entropy_min=3.5,
    ),
    # Slack user token
    Rule(
        name="slack-user-token",
        pattern=re.compile(r"\b(xoxp-[0-9A-Za-z\-]{20,})\b"),
        description="Slack User Token (xoxp-)",
        entropy_min=3.5,
    ),
    # Slack workspace token
    Rule(
        name="slack-workspace-token",
        pattern=re.compile(r"\b(xoxa-[0-9A-Za-z\-]{20,})\b"),
        description="Slack Workspace Token (xoxa-)",
        entropy_min=3.5,
    ),
    # Google API key
    Rule(
        name="google-api-key",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        description="Google API Key",
        entropy_min=3.5,
    ),
    # PEM private key block
    Rule(
        name="private-key-pem",
        pattern=re.compile(
            r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)",
            re.IGNORECASE,
        ),
        description="PEM Private Key Block",
        entropy_min=0.0,
    ),
    # JWT (three base64url segments)
    Rule(
        name="jwt",
        pattern=re.compile(
            r"\b(ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"
        ),
        description="JSON Web Token (JWT)",
        entropy_min=4.0,
    ),
    # Generic .env-style KEY=long_value (high entropy on the value side)
    Rule(
        name="env-secret-assignment",
        pattern=re.compile(
            r"(?i)(?:password|secret|token|api[_\-]?key|private[_\-]?key|auth[_\-]?key)"
            r"\s*[=:]\s*['\"]?([A-Za-z0-9/+\-_.]{20,})['\"]?"
        ),
        description="Generic secret assignment (.env style)",
        entropy_min=4.0,
    ),
]


def redact(value: str) -> str:
    """Show first 4 and last 4 characters only. Never expose the full secret."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def check_entropy(value: str, minimum: float) -> bool:
    """Return True if entropy check passes (value is high-entropy or check is disabled)."""
    if minimum <= 0:
        return True
    return shannon_entropy(value) >= minimum
