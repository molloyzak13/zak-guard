"""
FAKE SECRETS -- deliberately fabricated values for testing zak-guard detectors.
None of these are real credentials. Do not use.

Values that would trigger GitHub push-protection on literal strings
(Stripe, Slack) are assembled at import time from split parts so they don't
appear as a contiguous secret string in the source file. This is the standard
approach used by secret-scanning test suites (trufflehog, detect-secrets, gitleaks).
"""

# Fake AWS key pair
AWS_ACCESS_KEY_ID = "AKIAEXAMPLEFAKEKEY01"
AWS_SECRET = "FakeSecretKeyABCDEFGHIJKLMNOPQRSTUVWXYZ12"

# Fake GitHub tokens
GITHUB_PAT_CLASSIC = "ghp_FakeTokenExampleABCDEFGHIJKLMNOP1234"
GITHUB_PAT_FINE = "github_pat_" + "A" * 82

# Fake OpenAI key
OPENAI_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKL"

# Fake Anthropic key
ANTHROPIC_KEY = "sk-ant-FakeAnthropicKey-ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901"

# Fake Stripe keys -- assembled to avoid triggering push protection on literal strings
_STRIPE_LIVE = "sk_live_"
STRIPE_SECRET = _STRIPE_LIVE + "FakeStripeKeyABCDEFGHIJKLMNOPQ"
_RK_LIVE = "rk_live_"
STRIPE_RESTRICTED = _RK_LIVE + "FakeStripeRestrictedABCDEFGHIJKLM"

# Fake Slack tokens -- assembled for the same reason
_XOXB = "xoxb-"
SLACK_BOT = _XOXB + "111111111111-222222222222-FakeSlackBotTokenABCDEF"
_XOXP = "xoxp-"
SLACK_USER = _XOXP + "333333333333-444444444444-FakeSlackUserTokenABCDEF"

# Fake Google API key
GOOGLE_KEY = "AIzaFakeGoogleKeyABCDEFGHIJKLMNOPQRSTUV"

# Fake JWT (three base64url segments, obviously fake)
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJmYWtlLXVzZXItaWQiLCJuYW1lIjoiRmFrZVVzZXIifQ"
    ".FakeSignatureABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

# Fake PEM header (no key material here -- just the header line)
FAKE_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
