"""
A clean file with no secrets — used to verify zak-guard produces no false positives
on ordinary code.
"""

import os


def greet(name: str) -> str:
    """Return a greeting string."""
    return f"Hello, {name}!"


def get_config() -> dict:
    """Read config from environment (the right way: don't hardcode secrets)."""
    return {
        "api_key": os.environ.get("API_KEY", ""),
        "debug": os.environ.get("DEBUG", "false").lower() == "true",
        "host": os.environ.get("HOST", "localhost"),
        "port": int(os.environ.get("PORT", "8080")),
    }


# Normal constants that look slightly secret-ish but are too short/low-entropy
SHORT_ID = "abc123"
FEATURE_FLAG = "feature-x-enabled"
VERSION = "1.0.0"
