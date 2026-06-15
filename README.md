# zak-guard

A pre-commit secret scanner. Catches AWS keys, GitHub PATs, Stripe tokens, private keys, and other credentials before they land in your repo.

Works standalone as a CLI tool and as a hook in the [pre-commit](https://pre-commit.com) framework.

---

## What it catches

| Rule | Examples |
|---|---|
| AWS access key ID | `AKIA...` (20-char, high entropy) |
| AWS secret access key | `AWS_SECRET_ACCESS_KEY=...` env var assignments |
| GitHub PATs (classic + fine-grained) | `ghp_...`, `github_pat_...` |
| GitHub OAuth / Actions / refresh tokens | `gho_`, `ghs_`, `ghr_` |
| OpenAI keys (legacy + project) | `sk-...`, `sk-proj-...` |
| Anthropic keys | `sk-ant-...` |
| DeepSeek / generic `sk-` keys | `sk-` prefix with high entropy |
| Stripe live keys | `sk_live_...`, `rk_live_...` |
| Slack tokens | `xoxb-`, `xoxp-`, `xoxa-` |
| Google API keys | `AIza...` |
| PEM private key blocks | `-----BEGIN ... PRIVATE KEY-----` |
| JWTs | Three base64url segments |
| Generic `.env` assignments | `PASSWORD=...`, `SECRET=...`, `TOKEN=...` with high entropy |

Every finding shows `file:line`, the rule name, and a redacted match (`AKIA...Y01`). The full value is never printed.

---

## Install

```sh
pip install zak-guard
# or
pipx install zak-guard
```

---

## Use as a CLI

Scan staged changes (what you're about to commit):

```sh
zak-guard --staged
```

Scan everything in the current directory:

```sh
zak-guard --all
```

Scan a specific path:

```sh
zak-guard --all ./src
```

Suppress known false positives with an allowlist:

```sh
zak-guard --staged --allowlist .zak-guard-allowlist
```

Wire it as a git pre-commit hook:

```sh
zak-guard install
```

---

## Use with the pre-commit framework

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/molloyzak13/zak-guard
    rev: v0.1.0
    hooks:
      - id: zak-guard
```

Then install:

```sh
pre-commit install
```

---

## Allowlist

Create a text file with one entry per line. Any detected value that contains an allowlist entry is suppressed. Lines starting with `#` are comments.

```
# .zak-guard-allowlist
AKIAEXAMPLE         # known-fake key in test fixtures
sk_live_test_       # Stripe test mode prefix used in integration tests
```

Pass it with `--allowlist <file>` or set the `ZAK_GUARD_ALLOWLIST` environment variable.

---

## How detectors work

Each rule combines a regex pattern with a Shannon entropy minimum. The entropy gate cuts false positives on placeholder values like `YOUR_API_KEY_HERE` or `xxxxxxxxxxxx` that match the pattern shape but are obviously not real credentials.

The staged scanner (`--staged`) parses `git diff --cached` and flags only added lines. It won't block you for secrets that were already in the repo before your change.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean, no findings |
| 1 | One or more secrets detected |
| 2 | Error (not inside a git repo, git not found, etc.) |

---

## Development

```sh
git clone https://github.com/molloyzak13/zak-guard
cd zak-guard
pip install -e ".[dev]"
pytest -v
```

---

## License

MIT
