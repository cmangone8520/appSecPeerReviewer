# appSec Peer Reviewer

A **production-grade GitHub App** that performs world-class application-security peer review on every pull request, posting findings as **inline PR comments**.

Built for Tier-1 financial institutions with a zero-tolerance security mandate.  Supports **any programming language** — Python, Java, C/C++, C#, Go, Rust, JavaScript/TypeScript, COBOL, PL/SQL, Terraform, Kubernetes YAML, Dockerfiles, and more.

For each `pull_request` event (`opened` / `synchronize` / `reopened` / `ready_for_review`) it:

1. Applies webhook guardrails first: payload-size limits and short-lived replay protection (`X-GitHub-Delivery`).
2. Verifies the webhook HMAC-SHA256 signature (fail-closed, constant-time comparison).
3. Authenticates as a GitHub App and mints a per-installation access token.
4. Fetches the unified diff for the PR.
5. Runs **three reviewers in parallel** via the pluggable reviewer registry:
   - **LLM review** — sends the diff to the configured LLM provider (OpenAI or Anthropic Claude, swappable with one env-var change) with an 18-category enterprise security prompt covering OWASP Top 10, PCI-DSS, SWIFT, financial-domain risks, LLM/bot security, supply-chain, legacy tech, and more.
   - **Secret scan** — high-confidence regex patterns (AWS, GitHub, OpenAI, Stripe, Slack, Google, private-key blocks) over `+` lines only.
   - **Dependency CVE** — parses newly-added pinned deps in `requirements*.txt` / `pyproject.toml` / `package.json` and queries [osv.dev](https://osv.dev) for known vulnerabilities.
6. Deduplicates findings on `(file, line, vuln_class)`, keeps the highest severity, and posts a single consolidated PR review (`GITHUB_REVIEW_EVENT`, default `COMMENT`) with one inline comment per finding.

Startup now fails fast when required secrets are missing (`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`, plus provider API key) so misconfiguration is caught before handling production webhooks.

LLM findings whose `line` is not a `+` line in the diff are dropped — GitHub rejects them anyway and this is cheap hallucination filtering.

---

## Table of contents

- [Architecture overview](#architecture-overview)
- [Technical specification](#technical-specification)
- [Prerequisites](#prerequisites)
- [Local setup — full walkthrough](#local-setup--full-walkthrough)
  - [Step 1 — Clone and install](#step-1--clone-and-install)
  - [Step 2 — Set up the smee.io tunnel](#step-2--set-up-the-smeeio-tunnel)
  - [Step 3 — Create the GitHub App](#step-3--create-the-github-app)
  - [Step 4 — Install the App on a repo](#step-4--install-the-app-on-a-repo)
  - [Step 5 — Configure `.env`](#step-5--configure-env)
  - [Step 5.1 — Where each token/secret comes from](#step-51--where-each-tokensecret-comes-from)
  - [Step 6 — Start the server](#step-6--start-the-server)
  - [Step 7 — Open a test PR](#step-7--open-a-test-pr)
- [Swapping LLM providers](#swapping-llm-providers)
- [Customising the security prompt](#customising-the-security-prompt)
- [Tests](#tests)
- [Configuration reference](#configuration-reference)
- [Adding a custom reviewer plugin](#adding-a-custom-reviewer-plugin)
- [Adding a new LLM provider](#adding-a-new-llm-provider)
- [Troubleshooting](#troubleshooting)
- [Deploy to Fly.io](#deploy-to-flyio)
- [Project layout](#project-layout)
- [Known limitations](#known-limitations)

---

## Architecture overview

```
GitHub Webhook
      │
      ▼
┌──────────────────────────────────────────────────────────────────┐
│ FastAPI (`app/main.py`)                                         │
│                                                                  │
│  `/webhook`                                                      │
│   1) Content-Length / body-size guard (`MAX_WEBHOOK_BYTES`)      │
│   2) Replay guard (`WEBHOOK_REPLAY_*`)                           │
│   3) HMAC verify (`X-Hub-Signature-256`)                         │
│   4) Event/action filtering                                       │
│   5) `BackgroundTasks` dispatch                                  │
│                                                                  │
│  `/health`                                                       │
└──────────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────────┐
│ Background review task (`app/review/tasks.py`)                  │
│  - ContextVar correlation (`delivery_id`)                        │
│  - GitHub installation token                                     │
│  - PR diff fetch                                                 │
│  - Max diff guard (`MAX_DIFF_BYTES`)                             │
│  - Run review pipeline                                           │
│  - Post consolidated review                                      │
└──────────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────────┐
│ Review pipeline (`app/review/pipeline.py`)                      │
│  ReviewerRegistry fan-out (async gather):                        │
│   - `SecretScanner` (regex over added lines)                     │
│   - `DependencyReviewer` (OSV.dev lookup)                        │
│   - `LLMReviewer` (provider-agnostic LLM analysis)               │
│  Deduplicate (`file`, `line`, `vulnerability_class`)             │
└──────────────────────────────────────────────────────────────────┘
      │
      ├────────► OpenAI / Anthropic
      └────────► OSV.dev
```

**Key design patterns:**

| Pattern | Where |
|---|---|
| **Reviewer Protocol** (`Reviewer`) | `app/review/base.py` — add reviewers with zero pipeline changes |
| **Plugin Registry** (`ReviewerRegistry`) | `app/review/registry.py` — register/replace reviewers at startup |
| **LLM Client Protocol** (`LLMClient`) | `app/llm/base.py` — swap providers with one env-var |
| **LLM Factory** | `app/llm/factory.py` — maps `LLM_PROVIDER` → concrete client |
| **ContextVar correlation** | `app/logging_utils.py` — every log line carries `delivery_id` |
| **Typed exception hierarchy** | `app/exceptions.py` — distinct types for config/auth/GitHub/review failures |
| **Lifespan DI** | `app/main.py` — pipeline injected into `app.state` at startup |
| **Validated Settings** | `app/config.py` — `field_validator` rejects bad config at boot |
| **Webhook hardening** | `app/main.py` — payload limits + replay dedupe before expensive work |

---

## Technical specification

### Runtime model

- **Framework:** FastAPI + Uvicorn, async I/O throughout.
- **Concurrency:** webhook returns quickly (`202`), heavy work executes in background task.
- **Core contracts:** `Reviewer` Protocol (`app/review/base.py`) and `LLMClient` Protocol (`app/llm/base.py`).
- **Failure semantics:** typed expected errors are warning-level; unexpected errors are exception-level with traceback.
- **Correlation:** every review lifecycle is tagged with `delivery_id` via `ContextVar`.

### Security and guardrails

- **Inbound webhook validation:** content-length parsing, max payload enforcement, replay suppression, HMAC verification.
- **Scope control:** only actionable PR events are processed; draft PRs and unrelated events are ignored.
- **Diff safety:** oversized diffs are skipped by policy (`MAX_DIFF_BYTES`) to avoid unbounded cost/latency.
- **LLM safety:** model output restricted to JSON object contract; hallucinated/non-added line findings are dropped.
- **Config safety:** startup fails fast when required credentials are missing.

### Reliability characteristics

- **External dependencies:** GitHub REST API, one LLM provider (OpenAI or Anthropic), OSV.dev.
- **Timeouts:** per-service HTTP timeout settings for GitHub auth/API, OpenAI, and OSV.
- **Idempotency:** short-lived in-memory delivery replay cache (single-process scope).
- **Determinism:** findings are deduped and severity-sorted before posting.

---

## Prerequisites

- **Python 3.11+**
- **Node.js 18+** (for `smee-client` only; no JS code in the project)
- **Git**
- An **LLM API key** — OpenAI (default) or Anthropic Claude
- A **GitHub account** with permission to create a GitHub App

```bash
# macOS
brew install python@3.11 node git

# Debian/Ubuntu
apt install python3.11-venv python3.11-dev nodejs git

# Verify
python3.11 --version   # 3.11.x
node --version         # v18.x+
```

---

## Local setup — full walkthrough

```
┌─ Terminal 1 (smee tunnel) ──────────────┐   ┌─ Terminal 2 (server) ──────────────────┐
│ npx smee-client \                        │   │ uv run uvicorn app.main:app \           │
│   --url https://smee.io/<channel> \      │ ─►│   --host 0.0.0.0 --port 8080 --reload  │
│   --target http://localhost:8080/webhook │   └────────────────────────────────────────┘
└──────────────────────────────────────────┘
```

### Step 1 — Clone and install

```bash
git clone https://github.com/<your-org>/appSecPeerReviewer.git
cd appSecPeerReviewer
```

Install with [uv](https://github.com/astral-sh/uv) (recommended — respects `uv.lock`):

```bash
pip install uv
uv sync
```

Or with a plain virtualenv:

```bash
python3.11 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Verify:

```bash
uv run pytest -q        # 13 passed
uv run ruff check app tests
```

### Step 2 — Set up the smee.io tunnel

1. Open **https://smee.io** → click **Start a new channel**.
2. Copy the channel URL (e.g. `https://smee.io/AbC123XyZ`). Keep this tab open.

### Step 3 — Create the GitHub App

Open **https://github.com/settings/apps/new** (or the org equivalent).

| Field | Value |
|---|---|
| **GitHub App name** | `appsec-peer-reviewer-<your-handle>` (globally unique) |
| **Homepage URL** | Any URL you control |
| **Webhook URL** | Your smee.io channel URL |
| **Webhook secret** | Generate: `openssl rand -hex 32` — **save this value** |

**Repository permissions:**

| Permission | Access |
|---|---|
| Pull requests | **Read & write** |
| Contents | **Read-only** |
| Metadata | Read-only (default) |

**Subscribe to events:** ✓ **Pull request**

Click **Create GitHub App**, then:

1. Note the **App ID** at the top of the settings page.
2. Scroll to **Private keys** → **Generate a private key** → save the `.pem` file.

### Step 4 — Install the App on a repo

App settings → **Install App** → choose your account → select the target repo(s).

### Step 5 — Configure `.env`

Create a `.env` in the repository root. Minimum required values:

```dotenv
# ── LLM provider (see "Swapping LLM providers" below) ──────────────────────
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o
OPENAI_HTTP_TIMEOUT=30
OPENAI_MAX_OUTPUT_TOKENS=4096

# ── GitHub App ───────────────────────────────────────────────────────────────
GITHUB_APP_ID=123456
GITHUB_WEBHOOK_SECRET=<the openssl rand -hex 32 value from Step 3>
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEow...
-----END RSA PRIVATE KEY-----"

# ── Optional ─────────────────────────────────────────────────────────────────
GITHUB_API_BASE=https://api.github.com
MAX_DIFF_BYTES=200000
MAX_WEBHOOK_BYTES=1048576
WEBHOOK_REPLAY_TTL_SECONDS=600
WEBHOOK_REPLAY_CACHE_SIZE=10000
GITHUB_REVIEW_EVENT=COMMENT
LOG_LEVEL=INFO
PROMPT_FILE=prompts/security_review.txt
```

> **Private key:** paste the full multiline PEM directly (as shown) — `pydantic-settings` handles multiline quoted values.  
> Or export it in your shell before starting: `export GITHUB_APP_PRIVATE_KEY="$(cat app.pem)"`

### Step 5.1 — Where each token/secret comes from

Use this as a credential checklist for local end-to-end setup:

| `.env` key | What it is | Where to get it |
|---|---|---|
| `GITHUB_APP_ID` | Numeric GitHub App identifier | GitHub App settings page (top section) |
| `GITHUB_WEBHOOK_SECRET` | Shared secret used to sign webhook payloads | Value you create while creating the GitHub App (`openssl rand -hex 32`) |
| `GITHUB_APP_PRIVATE_KEY` | App private key PEM used to sign GitHub App JWTs | GitHub App settings -> **Private keys** -> **Generate a private key** |
| `OPENAI_API_KEY` | OpenAI API credential | [OpenAI API keys](https://platform.openai.com/api-keys) |
| `ANTHROPIC_API_KEY` | Anthropic API credential | [Anthropic Console keys](https://console.anthropic.com/settings/keys) |

Important token behavior:

- `GITHUB_APP_PRIVATE_KEY` is **not** an installation token. It signs a short-lived App JWT.
- The app automatically exchanges that JWT for a GitHub **installation access token** at runtime (`get_installation_token()`).
- You usually do **not** manually create or paste a GitHub installation token into `.env`.

If you need to manually inspect an installation token for debugging:

1. In GitHub App settings, open **Install App** and ensure the app is installed on your target repo.
2. Copy the `installation_id` from an incoming webhook payload or by querying installations via GitHub API.
3. Mint an App JWT using your `GITHUB_APP_ID` + PEM.
4. Call:

```bash
curl -X POST \
  -H "Authorization: Bearer <APP_JWT>" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/app/installations/<INSTALLATION_ID>/access_tokens"
```

The response includes a short-lived `token` (typically around 1 hour). The service already does this automatically during each review job.

### Step 6 — Start the server

**Terminal 1 — smee forwarder:**
```bash
npx --yes smee-client \
  --url https://smee.io/<channel> \
  --target http://localhost:8080/webhook
```

**Terminal 2 — the app:**
```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

Check it's up:

```bash
curl -s http://localhost:8080/health
# {"status":"ok"}
```

Startup log shows active reviewers and LLM provider:

```
INFO [...] appSec Peer Reviewer started reviewers=['secret-scan', 'dependency-cve', 'llm']
INFO [...] LLMReviewer initialised provider=openai model=gpt-4o
INFO [...] loaded system prompt path=prompts/security_review.txt chars=9842
```

### Step 7 — Open a test PR

Push a branch on an installed repo and open a pull request. Within 10–60 seconds:

- **Terminal 1** prints `POST /webhook` lines.
- **Terminal 2** logs the full pipeline: `review started` → `diff fetched` → each reviewer → `review complete`.
- **PR page** shows a consolidated **appSec Peer Reviewer** review with inline comments.

**What each log step means:**

```
webhook received event=pull_request body_bytes=...
webhook scheduled review target=owner/repo#N action=opened
review started target=owner/repo#N head=abc12345
installation token acquired installation_id=... elapsed_ms=...
github get_pr_diff success target=owner/repo#N diff_bytes=...
secret scan complete findings=0
osv query complete deps=2 findings=0 elapsed_ms=...
llm review complete provider=openai accepted=3 dropped={...}
pipeline complete before_dedupe=3 after_dedupe=3 elapsed_ms=...
posting review findings=3 target=owner/repo#N
review complete findings=3 target=owner/repo#N total_elapsed_ms=...
```

---

## Swapping LLM providers

The LLM layer is fully abstracted behind the `LLMClient` Protocol.  To switch providers, **only change `.env`** — no code changes required.

### OpenAI (default)

```dotenv
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o
```

Supports any model that accepts `json_object` response format (e.g. `gpt-4o`, `gpt-4-turbo`, `gpt-4o-mini`).

### Anthropic Claude

First install the optional SDK:

```bash
uv add anthropic
# or: pip install anthropic
```

Then in `.env`:

```dotenv
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-opus-4-5
```

Restart the server — the startup log confirms the active provider:

```
INFO [...] LLMReviewer initialised provider=anthropic model=claude-opus-4-5
```

---

## Customising the security prompt

The security review prompt lives in **`prompts/security_review.txt`** — edit it freely in any text editor without touching any code.

**Restart the server** to pick up changes (the prompt is loaded once at startup).

The file currently covers **18 mandatory vulnerability categories**:

1. Injection (SQL, NoSQL, command, EL, template, XSS, GraphQL)
2. Broken Access Control
3. Cryptographic Failures
4. Hardcoded Secrets & Credential Exposure (**always CRITICAL**)
5. Authentication & Session Management
6. Insecure Deserialization
7. SSRF
8. Security Misconfiguration (Docker, Kubernetes, Terraform/IaC)
9. Sensitive Data Exposure & Privacy (PII, PAN, PHI)
10. Vulnerable & Outdated Components
11. Insufficient Logging & Alerting
12. Path Traversal & File System Abuse
13. XXE
14. Race Conditions & Concurrency Security
15. **Financial-Domain Risks** (float/double on money, PCI-DSS, SWIFT/ISO 20022, double-spend, idempotency)
16. LLM / AI / Bot Security (Prompt Injection, Excessive Agency)
17. Supply Chain & Build Pipeline Security
18. Legacy Technology Risks (COBOL, C/C++, PHP, PL/SQL, Bash)

The **zero-tolerance policy** always flags as CRITICAL: hardcoded credentials, MD5/SHA-1/DES/ECB crypto, injection vectors, float on monetary amounts, PAN/CVV/SSN storage, and unsafe deserialization.

To point the service at a different prompt file:

```dotenv
PROMPT_FILE=/path/to/my_custom_prompt.txt
```

---

## Tests

```bash
uv run pytest -q
uv run ruff check app tests
```

| Test file | What it covers |
|---|---|
| `tests/test_diff_parser.py` | Unified-diff parsing builds correct per-file added-line sets; `is_added_line` rejects context lines and unknown files |
| `tests/test_secrets.py` | High-confidence regex flags real-shape AWS/GitHub tokens on `+` lines; no false-positives on near-misses |
| `tests/test_webhook_sig.py` | HMAC-SHA256 accepts valid signatures; rejects tampered body, wrong secret, missing/malformed header, empty secret |
| `tests/test_pipeline_dedupe.py` | Findings on same `(file, line, vuln_class)` collapse to highest severity; summary body counts correctly |
| `tests/test_deps.py` | Extracts `name==version` from `requirements*.txt`, `pyproject.toml`; ignores range specifiers |

OpenAI/Anthropic, GitHub API, and OSV.dev are not called by the unit suite — those are exercised end-to-end by opening a real PR (Step 7).

---

## Configuration reference

| Env var | Required? | Default | Purpose |
|---|---|---|---|
| `LLM_PROVIDER` | no | `openai` | Active LLM provider. Values: `openai`, `anthropic`. |
| `OPENAI_API_KEY` | if openai | — | OpenAI auth key. |
| `OPENAI_MODEL` | no | `gpt-4o` | Any `json_object`-capable model. |
| `OPENAI_HTTP_TIMEOUT` | no | `30.0` | Timeout (seconds) per OpenAI request. |
| `OPENAI_MAX_OUTPUT_TOKENS` | no | `4096` | Upper bound on OpenAI completion size. |
| `ANTHROPIC_API_KEY` | if anthropic | — | Anthropic auth key. |
| `ANTHROPIC_MODEL` | no | `claude-opus-4-5` | Any Anthropic Messages-compatible model. |
| `GITHUB_APP_ID` | **yes** | — | Numeric GitHub App ID. |
| `GITHUB_APP_PRIVATE_KEY` | **yes** | — | RSA PEM contents (multiline OK). Used to mint App JWTs. |
| `GITHUB_WEBHOOK_SECRET` | **yes** | — | Must exactly match the secret set on the GitHub App. |
| `GITHUB_API_BASE` | no | `https://api.github.com` | Override for GitHub Enterprise Server. |
| `GITHUB_API_VERSION` | no | `2022-11-28` | API version header for GitHub REST requests. |
| `GITHUB_USER_AGENT` | no | `appsec-peer-reviewer/1.0` | User-Agent header for GitHub requests. |
| `GITHUB_HTTP_TIMEOUT` | no | `30.0` | Timeout for diff fetch/review post calls. |
| `GITHUB_AUTH_HTTP_TIMEOUT` | no | `15.0` | Timeout for installation token requests. |
| `GITHUB_JWT_EXPIRY_SECONDS` | no | `540` | GitHub App JWT lifetime. |
| `GITHUB_JWT_CLOCK_SKEW_SECONDS` | no | `60` | Backdating offset for JWT `iat`. |
| `GITHUB_JWT_ALGORITHM` | no | `RS256` | JWT signing algorithm. |
| `GITHUB_TOKEN_EXPIRY_BUFFER_SECONDS` | no | `3300` | Buffer used when tracking token freshness. |
| `GITHUB_REVIEW_EVENT` | no | `COMMENT` | PR review event (`COMMENT`, `APPROVE`, `REQUEST_CHANGES`). |
| `MAX_DIFF_BYTES` | no | `200000` | Diffs larger than this are skipped. |
| `MAX_WEBHOOK_BYTES` | no | `1048576` | Hard cap for incoming webhook payload bytes. |
| `WEBHOOK_REPLAY_TTL_SECONDS` | no | `600` | Delivery-id replay suppression window. |
| `WEBHOOK_REPLAY_CACHE_SIZE` | no | `10000` | Max replay IDs retained in memory. |
| `PROMPT_FILE` | no | `prompts/security_review.txt` | Path to the LLM system-prompt file. |
| `LOG_LEVEL` | no | `INFO` | Standard Python log level (`DEBUG`/`INFO`/`WARNING`/`ERROR`). |
| `OSV_API_URL` | no | `https://api.osv.dev/v1/query` | OSV single-package query endpoint. |
| `OSV_BATCH_API_URL` | no | `https://api.osv.dev/v1/querybatch` | OSV batch endpoint (reserved). |
| `OSV_HTTP_TIMEOUT` | no | `15.0` | Timeout for OSV API calls. |

---

## Adding a custom reviewer plugin

The reviewer system is fully pluggable via the `Reviewer` Protocol.

**1. Create `app/review/reviewers/my_reviewer.py`:**

```python
from ...models import Finding
from ..base import ReviewContext

class MyReviewer:
    name = "my-reviewer"

    async def review(self, ctx: ReviewContext) -> list[Finding]:
        # ctx.diff_text   — raw unified diff
        # ctx.parsed      — list[FileDiff] with added_lines per file
        # ctx.settings    — all app config
        # ctx.delivery_id — correlation ID for logging
        return []
```

**2. Register it in `app/review/registry.py` `build_default_registry()`:**

```python
from .reviewers.my_reviewer import MyReviewer
registry.register(MyReviewer())
```

**3. Restart.** No other files change.

---

## Adding a new LLM provider

**1. Create `app/llm/my_provider_client.py`:**

```python
from .base import LLMResponse

class MyProviderClient:
    provider = "myprovider"

    def __init__(self, api_key: str, model: str) -> None: ...

    @property
    def model(self) -> str: ...

    async def complete(self, system_prompt: str, user_message: str) -> LLMResponse: ...
```

**2. Add to the registry in `app/llm/factory.py`:**

```python
from .my_provider_client import MyProviderClient

_REGISTRY = {
    ...
    "myprovider": lambda s: MyProviderClient(api_key=s.my_api_key, model=s.my_model),
}
```

**3. Add the config fields to `app/config.py` and set `LLM_PROVIDER=myprovider` in `.env`.**

---

## Troubleshooting

**`401 Unauthorized` on `/webhook`**  
Your `GITHUB_WEBHOOK_SECRET` in `.env` doesn't match the App's webhook secret.  Regenerate the secret in GitHub App settings, update `.env`, and restart.

**Webhook arrives but no review is posted**  
Check the log for `webhook ignored: action=...` — only `opened`, `synchronize`, `reopened`, and `ready_for_review` trigger a review. Draft PRs are also ignored.

**`PyJWT` / `RS256` errors**  
The PEM didn't load correctly. Verify:
```bash
uv run python -c "from app.config import get_settings; s=get_settings(); print(s.github_app_private_key[:30])"
```
Output should start with `-----BEGIN RSA PRIVATE KEY-----`.

**OpenAI 401**  `OPENAI_API_KEY` is wrong or expired. Rotate it and update `.env`.

**OpenAI 429 / model not found**  
Rate limit or wrong model name. Try `OPENAI_MODEL=gpt-4o-mini` or check your tier.

**Anthropic `ImportError`**  
Run `uv add anthropic` (or `pip install anthropic`).

**OSV returns no vulnerabilities for a known-vulnerable dep**  
Only `name==version` pinned entries are checked. Range specifiers (`>=`, `^`), lockfiles (`poetry.lock`, `package-lock.json`), and transitive deps are out of scope.

**`LLM_PROVIDER` unknown error**  
Set `LLM_PROVIDER` to an exact match from the registered providers: `openai` or `anthropic`.

---

## Deploy to Fly.io

```bash
brew install flyctl
fly auth login
fly launch --copy-config --no-deploy

fly secrets set \
  LLM_PROVIDER=openai \
  OPENAI_API_KEY=... \
  OPENAI_MODEL=gpt-4o \
  GITHUB_APP_ID=... \
  GITHUB_APP_PRIVATE_KEY="$(cat ~/.config/appsec-peer-reviewer/app.pem)" \
  GITHUB_WEBHOOK_SECRET=...

fly deploy
```

Update the GitHub App's **Webhook URL** from your smee channel to `https://<app>.fly.dev/webhook`.

To use Claude on Fly.io:
```bash
fly secrets set LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-...
fly deploy
```

---

## Project layout

```
app/
  main.py               FastAPI: /health + /webhook, lifespan DI, background task
  config.py             pydantic-settings with field validators
  exceptions.py         Typed exception hierarchy (Config/Webhook/GitHub/Review)
  logging_utils.py      ContextVar correlation ID, configure_logging()
  models.py             Finding / ReviewResult Pydantic schemas
  webhook.py            HMAC-SHA256 signature verification (fail-closed)
  diff/
    models.py           FileDiff dataclass
    parser.py           parse_diff(), is_added_line()
  github/
    auth.py             App JWT (RS256) + per-installation access tokens
    client.py           get_pr_diff(), post_review() (Reviews API)
  llm/
    base.py             LLMClient Protocol + LLMResponse dataclass
    openai_client.py    OpenAI chat-completions implementation
    anthropic_client.py Anthropic Messages implementation
    factory.py          build_llm_client(settings) — maps LLM_PROVIDER → client
  review/
    base.py             Reviewer Protocol + ReviewContext dataclass
    registry.py         ReviewerRegistry + build_default_registry()
    pipeline.py         ReviewPipeline (fan-out, gather, dedupe) + summary_body()
    reviewers/
      llm.py            LLMReviewer — provider-agnostic, loads prompt file
      secrets.py        SecretScanner — 10 high-confidence regex patterns
      deps.py           DependencyReviewer — OSV.dev CVE lookup
prompts/
  security_review.txt   Editable 18-category financial-grade security prompt
tests/                  13 unit tests (diff, secrets, webhook sig, dedupe, deps)
Dockerfile              Multi-stage production image
fly.toml                Fly.io deployment config
```

### Backward-compatibility shims

The old module paths still work during migration:

```python
from app.diff_parser import parse_diff       # → app.diff.parser
from app.github_auth import get_installation_token  # → app.github.auth
from app.github_client import get_pr_diff    # → app.github.client
from app.review.secrets import scan          # → app.review.reviewers.secrets
from app.review.deps import extract_added_deps  # → app.review.reviewers.deps
```

---

## Known limitations

- **LLM line numbers** are validated against the diff but the model can still produce false positives — treat findings as "review prompts", not blocking gates.
- **Dep CVE check** only covers newly-added pinned versions (`name==version`). Lockfiles, range specifiers, and transitive deps are out of scope.
- **Diffs over `MAX_DIFF_BYTES`** (default 200 KB) are skipped to avoid context-window blowup.
- **Replay cache scope is process-local** — current replay protection is in-memory and not shared across multiple app instances.
- **Review event defaults to `COMMENT`** — set `GITHUB_REVIEW_EVENT=REQUEST_CHANGES` (or `APPROVE`) to change behavior.
- **No result caching** — every PR open/sync triggers a full pipeline run including an LLM API call.
- **No per-installation rate limiting** — busy repos will generate proportional LLM API costs.
