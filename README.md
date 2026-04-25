# appSec Peer Reviewer

A GitHub App that runs an LLM-driven application-security review on every pull request and posts findings as **inline PR comments**.

For each `pull_request` event (`opened` / `synchronize` / `reopened` / `ready_for_review`) it:

1. Verifies the webhook signature (HMAC-SHA256 with your webhook secret).
2. Authenticates as a GitHub App and mints a per-installation access token.
3. Fetches the unified diff for the PR.
4. Runs three reviewers in parallel:
   - **LLM review** — sends the diff to OpenAI (default `gpt-5`, configurable) with a security-focused system prompt covering OWASP Top 10, authn/authz mistakes, unsafe crypto, deserialization, SSRF, prompt injection, etc.
   - **Secret scan** — high-confidence regex patterns (AWS, GitHub, OpenAI, Stripe, Slack, Google, private-key blocks) over added lines only.
   - **Dependency CVE** — parses added pinned deps in `requirements.txt` / `pyproject.toml` / `package.json` and queries [osv.dev](https://osv.dev) for known vulns.
5. Dedupes findings on `(file, line, vuln_class)`, keeps the highest severity, and posts them as one consolidated PR review (event `COMMENT`).

LLM findings whose `line` isn't actually a `+` line in the diff are dropped — GitHub would reject them anyway, and it's a cheap way to filter hallucinated locations.

---

## Table of contents

- [Prerequisites (macOS)](#prerequisites-macos)
- [Run on macOS — full walkthrough](#run-on-macos--full-walkthrough)
  - [Step 1 — Clone and install](#step-1--clone-and-install)
  - [Step 2 — Set up the smee.io tunnel](#step-2--set-up-the-smeeio-tunnel)
  - [Step 3 — Create the GitHub App](#step-3--create-the-github-app)
  - [Step 4 — Install the App on a repo](#step-4--install-the-app-on-a-repo)
  - [Step 5 — Configure `.env`](#step-5--configure-env)
  - [Step 6 — Start everything (two terminals)](#step-6--start-everything-two-terminals)
  - [Step 7 — Open a test PR](#step-7--open-a-test-pr)
- [Run on Linux (notes)](#run-on-linux-notes)
- [Tests](#tests)
- [Configuration reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)
- [Optional: deploy to Fly.io](#optional-deploy-to-flyio)
- [Layout](#layout)
- [Limitations (MVP)](#limitations-mvp)

---

## Prerequisites (macOS)

You need:

- **macOS 13+** (Apple Silicon or Intel — both work; everything below is universal).
- **Homebrew** — https://brew.sh.
- **Python 3.11 or newer** (the system Python that ships with macOS is fine for scripting but not for installs; use Homebrew's).
- **Node.js 18+** (only used to run `smee-client` via `npx`; you don't need any JS code).
- **Git**.
- An **OpenAI API key** with access to your chosen model (default `gpt-5`).
- A **GitHub account** with permission to create a GitHub App (any account works; for org-owned repos you create the App under the org).

Install everything via Homebrew if you don't already have it:

```bash
brew install python@3.11 node git
```

Verify versions:

```bash
python3.11 --version    # Python 3.11.x
node --version          # v18.x or higher
git --version
```

> **Note on `python` vs `python3`:** macOS doesn't ship a `python` command anymore; always use `python3` (or the explicit `python3.11`). The instructions below use `python3.11` to avoid ambiguity if you have multiple Pythons installed via pyenv/asdf.

---

## Run on macOS — full walkthrough

You'll end up with two terminal tabs running side-by-side:

```
┌─ Terminal tab 1 (smee tunnel) ──────────┐   ┌─ Terminal tab 2 (the agent) ──────────┐
│ npx smee-client \                       │   │ source .venv/bin/activate             │
│   --url https://smee.io/<channel> \     │ ─►│ uvicorn app.main:app \                │
│   --target http://localhost:8080/webhook│   │   --host 0.0.0.0 --port 8080 --reload │
└─────────────────────────────────────────┘   └───────────────────────────────────────┘
                ▲                                              │
                │ HTTPS webhook delivery                       │ inline review
   GitHub ─────┘                                               ▼
                                                           Your PR
```

### Step 1 — Clone and install

```bash
mkdir -p ~/code && cd ~/code
git clone https://github.com/cmangone8520/appSecPeerReviewer.git
cd appSecPeerReviewer
git checkout devin/1777095141-scaffold-mvp     # default branch with the MVP scaffold
```

Create and activate a Python virtualenv, then install dependencies (production + dev):

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

Sanity-check that everything compiles and tests pass:

```bash
pytest -q          # expect: 12 passed
ruff check app tests
```

> **macOS firewall popup:** the first time you run `uvicorn` (a few steps below), macOS may prompt "Do you want the application 'python3.11' to accept incoming network connections?" — click **Allow**. If you click Deny by accident, you can fix it later in **System Settings → Network → Firewall**.

### Step 2 — Set up the smee.io tunnel

GitHub can't deliver webhooks directly to `localhost`, so we route them through [smee.io](https://smee.io), a free relay GitHub built specifically for local-app development.

1. Open https://smee.io in your browser.
2. Click **Start a new channel**.
3. Copy the channel URL — it looks like `https://smee.io/AbC123XyZ` and is permanent until you discard it. **Keep this tab open**, you'll paste this URL into the GitHub App below.

You don't need to install smee globally; we'll run it via `npx` in step 6.

### Step 3 — Create the GitHub App

Open https://github.com/settings/apps/new (or `https://github.com/organizations/<org>/settings/apps/new` for an org-owned App).

Fill in:

| Field | Value |
|---|---|
| **GitHub App name** | `appsec-peer-reviewer-<your-handle>` (must be globally unique) |
| **Homepage URL** | `https://github.com/cmangone8520/appSecPeerReviewer` (or any URL you control) |
| **Webhook URL** | The smee.io channel URL from Step 2 (`https://smee.io/AbC...`) |
| **Webhook secret** | A random string. Generate one with: `openssl rand -hex 32` and **save it** — you'll paste the same value into `.env` later. |
| **Webhook → Active** | ✓ checked |

**Repository permissions:**

| Permission | Access |
|---|---|
| Pull requests | **Read & write** (post reviews and inline comments) |
| Contents | **Read-only** (fetch the diff) |
| Metadata | Read-only (default — leave as is) |

**Subscribe to events:** check **Pull request**.

**Where can this GitHub App be installed?** — your call; `Only on this account` is fine for personal use.

Click **Create GitHub App**.

After creation:

1. **App ID**: at the top of the App's settings page. Copy this number.
2. **Generate a private key**: scroll to "Private keys" → **Generate a private key**. A `.pem` file downloads. **Don't lose it** — GitHub never shows it again, you'd have to generate a new one. Move it to a stable path:

   ```bash
   mkdir -p ~/.config/appsec-peer-reviewer
   mv ~/Downloads/<your-app>.*.private-key.pem ~/.config/appsec-peer-reviewer/app.pem
   chmod 600 ~/.config/appsec-peer-reviewer/app.pem
   ```

### Step 4 — Install the App on a repo

In the App settings → **Install App** (left sidebar) → choose your account → pick the repo(s) you want reviewed. You can install on a single repo or "All repositories" (you can change later).

Once installed, GitHub will start sending events for those repos to your smee.io URL — but smee just buffers them until you start the forwarder in Step 6.

### Step 5 — Configure `.env`

```bash
cp .env.example .env
```

Edit `.env`:

```dotenv
# OpenAI
OPENAI_API_KEY=sk-...your-key-here...
OPENAI_MODEL=gpt-5

# GitHub App
GITHUB_APP_ID=123456                                    # from Step 3
GITHUB_APP_PRIVATE_KEY_PATH=/Users/<you>/.config/appsec-peer-reviewer/app.pem   # see below
GITHUB_WEBHOOK_SECRET=<the openssl rand -hex 32 value from Step 3>
```

**About the private key:** `GITHUB_APP_PRIVATE_KEY` accepts the **PEM contents** directly. There are two ways to provide it:

**Option A (recommended on macOS): point at the file in `.env`** — easier, no quoting/newline issues:

```dotenv
GITHUB_APP_PRIVATE_KEY="$(cat /Users/<you>/.config/appsec-peer-reviewer/app.pem)"
```

…but `.env` files don't expand `$(…)` themselves. Instead either:

- export the var in your shell before launching uvicorn:

  ```bash
  export GITHUB_APP_PRIVATE_KEY="$(cat ~/.config/appsec-peer-reviewer/app.pem)"
  ```

- or use a `direnv` / `dotenv-cli` shim that does support command substitution.

**Option B: paste the PEM contents directly into `.env`** — works but you must preserve newlines. The simplest reliable form is to wrap it in quotes and keep the literal newlines:

```dotenv
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA....
....
-----END RSA PRIVATE KEY-----"
```

Pydantic-Settings reads multi-line quoted env vars correctly. Avoid pasting it on a single line with `\n` escapes unless you actually use a `.env` loader that interprets them.

### Step 6 — Start everything (two terminals)

**Terminal 1 — start the smee forwarder.** Replace `<channel>` with the smee URL from Step 2.

```bash
npx --yes smee-client \
  --url https://smee.io/<channel> \
  --target http://localhost:8080/webhook
```

You should see:

```
Forwarding https://smee.io/<channel> to http://localhost:8080/webhook
Connected https://smee.io/<channel>
```

Leave this running.

**Terminal 2 — start the agent.**

```bash
cd ~/code/appSecPeerReviewer
source .venv/bin/activate
# If you used Option A in Step 5:
export GITHUB_APP_PRIVATE_KEY="$(cat ~/.config/appsec-peer-reviewer/app.pem)"
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

Verify the health endpoint from a third terminal (or a browser tab):

```bash
curl -s http://localhost:8080/health
# {"status":"ok"}
```

> **Background note for macOS users:** if you want the agent to keep running after you close the terminal, the simplest path is `nohup uvicorn ... &` or a `tmux` session. There's a `launchd` plist example in the [Troubleshooting](#troubleshooting) section if you want it managed by macOS itself.

### Step 7 — Open a test PR

On a repo where you installed the App, push a branch with at least one changed file and open a pull request. Within ~10–60 seconds (latency is dominated by the OpenAI call) you should see:

- **Terminal 1 (smee)** print `POST /webhook` lines.
- **Terminal 2 (agent)** log `reviewing <owner>/<repo>#<N> @ <sha>` and then `posted N findings on <owner>/<repo>#<N>`.
- **PR page**: a single review titled **"appSec Peer Reviewer"** with inline comments at the flagged lines. Each comment shows severity, vulnerability class, source (`llm` / `secret-scan` / `dependency-cve`), explanation, and suggested fix.

There's a pre-built test PR with intentional issues (hardcoded GitHub PAT, AWS access key, SQL injection, eval-RCE, open redirect, vulnerable pinned deps) at: **https://github.com/cmangone8520/appSecPeerReviewer/pull/1**. Once your local agent is running, that PR is the easiest way to confirm all three reviewers fire.

---

## Run on Linux (notes)

The instructions above work unchanged. The only differences worth calling out:

- Use your distro's package manager instead of Homebrew (`apt install python3.11-venv nodejs git` on Debian/Ubuntu, `dnf install python3.11 nodejs git` on Fedora).
- No firewall popup; if you have `ufw` or similar, ensure it's not blocking inbound 8080 if you're testing from another machine.

---

## Tests

```bash
source .venv/bin/activate
pytest -q          # 12 unit tests cover diff parsing, secret scan, signature verification, dedupe, dep extraction
ruff check app tests
```

What the suite covers:

| File | Asserts |
|---|---|
| `tests/test_diff_parser.py` | unified-diff parsing builds correct per-file added-line sets; `is_added_line` rejects context lines and unknown files |
| `tests/test_secrets.py` | high-confidence regex flags real-shape AWS/GitHub tokens on `+` lines; doesn't false-positive on near-misses |
| `tests/test_webhook_sig.py` | HMAC-SHA256 verification accepts valid signatures, rejects tampered bodies, wrong secrets, missing/malformed headers, and empty secret config |
| `tests/test_pipeline_dedupe.py` | findings on same `(file, line, vuln_class)` collapse to highest severity; summary body counts findings correctly |
| `tests/test_deps.py` | extracts pinned `name==version` deps from added `requirements.txt` and `pyproject.toml` lines; ignores range specifiers |

The OpenAI call, the GitHub API, and OSV.dev are not hit by the suite — those are integration concerns covered by a real PR opening (Step 7).

---

## Configuration reference

| Env var | Required? | Default | Purpose |
|---|---|---|---|
| `OPENAI_API_KEY` | yes | — | OpenAI auth. If unset, LLM review is skipped (secret-scan + dep-CVE still run). |
| `OPENAI_MODEL` | no | `gpt-5` | Any chat-completions-capable model name. |
| `GITHUB_APP_ID` | yes | — | The numeric App ID. |
| `GITHUB_APP_PRIVATE_KEY` | yes | — | PEM contents (multiline OK). Used to mint App JWTs. |
| `GITHUB_WEBHOOK_SECRET` | yes | — | Must exactly match the secret you set on the App. |
| `GITHUB_API_BASE` | no | `https://api.github.com` | Override for GitHub Enterprise Server. |
| `MAX_DIFF_BYTES` | no | `200000` | Diffs larger than this are skipped (avoids OpenAI context blowup). |
| `LOG_LEVEL` | no | `INFO` | Standard Python log levels. |

---

## Troubleshooting

**Health endpoint works but PRs aren't reviewed.**
- Check Terminal 1 (smee). If it shows nothing on PR open, the GitHub App's **Webhook URL** is wrong, or the App isn't installed on the repo. In the App settings → **Advanced** → **Recent Deliveries** shows every webhook GitHub tried to send and any errors.
- Check Terminal 2 (agent). If you see `401 Unauthorized` on `/webhook`, your `GITHUB_WEBHOOK_SECRET` doesn't match what the App is sending.
- If smee shows POSTs but the agent doesn't log anything, smee is forwarding but uvicorn isn't running on `:8080` — re-check Terminal 2.

**`Bad signature` 401 from `/webhook`.**
- Your `.env` `GITHUB_WEBHOOK_SECRET` doesn't match the App's webhook secret. Re-paste the value from Step 3 into the App settings (you can rotate it any time) and into `.env`, then restart uvicorn.

**`PyJWT` / `RS256` errors when the agent tries to authenticate.**
- The PEM didn't load correctly. Sanity-check:
  ```bash
  python3 -c 'import os; print(repr(os.environ["GITHUB_APP_PRIVATE_KEY"][:60]))'
  ```
  You should see something starting with `'-----BEGIN'`. If it's a single line with literal `\n`, your loader didn't expand the escapes — switch to Option A (point at the `.pem` file via `export $(cat …)`).

**OpenAI 401 / 429.**
- 401: bad `OPENAI_API_KEY`.
- 429: model rate limit. Try a smaller model (`OPENAI_MODEL=gpt-4o-mini`) or wait it out. The agent logs the error and silently skips LLM review for that PR — secret-scan and dep-CVE still post.

**OSV "no vulns" on a dep you know is vulnerable.**
- The dep parser only looks at `name==version` (PyPI) and `"name": "version"` (npm) on `+` lines. Range specifiers (`>=`, `^`, `~`), lockfiles (`package-lock.json`, `poetry.lock`), and transitive deps are out of scope for the MVP.

**LLM keeps commenting on lines that don't exist.**
- The pipeline runs every LLM finding through `is_added_line(parsed_diff, file, line)` and drops misses. If the model still produces a wrong-line comment occasionally, increase signal by switching to a stronger model via `OPENAI_MODEL`.

**Want it to run continuously on macOS without a terminal open.**
- Easiest: `tmux new -s appsec` and run uvicorn inside, then detach with `Ctrl-b d`.
- More permanent: write a `launchd` plist at `~/Library/LaunchAgents/com.user.appsecpeerreviewer.plist` that runs `uvicorn`, then `launchctl load -w ~/Library/LaunchAgents/com.user.appsecpeerreviewer.plist`. Don't forget the smee forwarder needs the same treatment.

**Resetting the smee channel.**
- Just visit the channel page in the browser; clicking "Force Reconnect" or generating a new channel works. Channels don't expire.

---

## Optional: deploy to Fly.io

Once you're happy with how the agent behaves locally, you can move it off your laptop. The repo already includes `Dockerfile` and `fly.toml`.

```bash
brew install flyctl
fly auth login
fly launch --copy-config --no-deploy

fly secrets set \
  OPENAI_API_KEY=... \
  OPENAI_MODEL=gpt-5 \
  GITHUB_APP_ID=... \
  GITHUB_APP_PRIVATE_KEY="$(cat ~/.config/appsec-peer-reviewer/app.pem)" \
  GITHUB_WEBHOOK_SECRET=...

fly deploy
```

Then change the GitHub App's **Webhook URL** from your smee channel to `https://<your-fly-app>.fly.dev/webhook`. You can stop the smee forwarder.

---

## Layout

```
app/
  main.py             FastAPI: /health and /webhook (HMAC verified, schedules background review)
  webhook.py          HMAC-SHA256 signature verification (constant-time compare, fail-closed)
  config.py           pydantic-settings, env-var driven
  models.py           Finding / ReviewResult schemas (severity, vuln class, source)
  github_auth.py      App JWT (RS256) + per-installation access tokens
  github_client.py    PR diff fetch, review/comment posting (Reviews API)
  diff_parser.py      Parses unified diffs to per-file added-line sets
  review/
    llm.py            OpenAI call + JSON validation + line-validity filter
    secrets.py        High-confidence secret regexes (vendor-published shapes)
    deps.py           OSV.dev CVE lookup on pinned dep additions
    pipeline.py       Orchestrates fan-out, dedupes, builds summary body
tests/                12 unit tests
Dockerfile, fly.toml  Optional Fly.io deploy
```

---

## Limitations (MVP)

- LLM line numbers are validated against the diff, but the model can still produce false positives — treat findings as "review prompts," not blocking gates.
- Dep CVE check only looks at **newly added pinned versions** in `requirements.txt` / `pyproject.toml` / `package.json`. Range specifiers, lockfiles, and transitive deps are out of scope here.
- Diffs over `MAX_DIFF_BYTES` (default 200 KB) are skipped to avoid blowing up the OpenAI context window.
- Review event is `COMMENT`, not `REQUEST_CHANGES` — the bot doesn't block merge. Switch in `app/main.py` if you want it to.
- No per-installation rate limiting yet; if someone installs the App on a busy repo, every PR open/sync will hit OpenAI.
