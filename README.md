# appSec Peer Reviewer

A GitHub App that runs an LLM-driven application-security review on every pull request and posts findings as **inline PR comments**.

For each `pull_request` event (`opened` / `synchronize` / `reopened` / `ready_for_review`) it:

1. Verifies the webhook signature (HMAC-SHA256).
2. Authenticates as a GitHub App and mints a per-installation token.
3. Fetches the unified diff for the PR.
4. Runs three reviewers in parallel:
   - **LLM review** — sends the diff to OpenAI (default `gpt-5`, configurable) with a security-focused system prompt covering OWASP Top 10, authn/authz mistakes, unsafe crypto, deserialization, SSRF, prompt injection, etc.
   - **Secret scan** — high-confidence regex patterns (AWS, GitHub, OpenAI, Stripe, Slack, Google, private-key blocks) over added lines only.
   - **Dependency CVE** — parses added pinned deps in `requirements.txt` / `pyproject.toml` / `package.json` and queries [osv.dev](https://osv.dev) for known vulns.
5. Dedupes findings on `(file, line, vuln_class)` keeping the highest severity, and posts them as one consolidated PR review (event `COMMENT`).

LLM findings whose `line` isn't actually a `+` line in the diff are dropped — GitHub would reject them anyway, and it cheaply filters hallucinated locations.

---

## Run on localhost

GitHub can't deliver webhooks directly to `localhost`, so we use **smee.io** (GitHub's official local-dev tunnel) to forward events.

### 1. Install + configure

```bash
git clone https://github.com/cmangone8520/appSecPeerReviewer.git
cd appSecPeerReviewer
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

Fill in `.env`:

```
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-5

GITHUB_APP_ID=<numeric app id>
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=<random string you also paste into the App settings>
```

### 2. Create the GitHub App

1. https://github.com/settings/apps → **New GitHub App**.
2. Webhook URL: a smee.io channel — go to https://smee.io and click **Start a new channel**, then paste that URL.
3. Webhook secret: same value as `GITHUB_WEBHOOK_SECRET` in `.env`.
4. **Permissions**:
   - Repository → **Pull requests**: Read & write (needed to post reviews).
   - Repository → **Contents**: Read-only (needed to fetch the diff).
   - Repository → **Metadata**: Read-only (default).
5. **Subscribe to events**: `Pull request`.
6. Create the app, generate a **private key** (downloads a `.pem`), paste its contents into `GITHUB_APP_PRIVATE_KEY`. Note the numeric **App ID** at the top of the settings page.
7. **Install** the App on the repo(s) you want reviewed.

### 3. Start the smee forwarder

```bash
npx smee-client --url https://smee.io/<your-channel> --target http://localhost:8080/webhook
```

Leave that running in one terminal.

### 4. Start the agent

```bash
. .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

`GET http://localhost:8080/health` should return `{"status":"ok"}`.

### 5. Open a PR on the repo where the App is installed

A review titled **"appSec Peer Reviewer"** should appear within ~10–60 seconds (latency is dominated by the OpenAI call). Each finding is an inline comment with severity, vulnerability class, and a suggested fix.

---

## Test it

```bash
. .venv/bin/activate
pytest -q          # 12 unit tests cover diff parsing, secret scan, signature verify, dedupe, dep extraction
ruff check app tests
```

---

## Deploy to Fly.io (optional, when you're ready to leave it running)

```bash
fly launch --copy-config --no-deploy
fly secrets set \
  OPENAI_API_KEY=... \
  GITHUB_APP_ID=... \
  GITHUB_APP_PRIVATE_KEY="$(cat path/to/key.pem)" \
  GITHUB_WEBHOOK_SECRET=...
fly deploy
```

Then change the GitHub App's webhook URL from your smee channel to `https://<your-fly-app>.fly.dev/webhook`.

---

## Layout

```
app/
  main.py             FastAPI: /health and /webhook
  webhook.py          HMAC-SHA256 signature verification
  config.py           pydantic-settings, env-var driven
  models.py           Finding / ReviewResult schemas
  github_auth.py      App JWT + installation access tokens
  github_client.py    PR diff fetch, review/comment posting
  diff_parser.py      Parses unified diffs to per-file added-line sets
  review/
    llm.py            OpenAI call + JSON validation + line-validity filter
    secrets.py        High-confidence secret regexes (vendor-published shapes)
    deps.py           OSV.dev CVE lookup on pinned dep additions
    pipeline.py       Orchestrates fan-out, dedupes, builds summary body
tests/                12 unit tests
Dockerfile, fly.toml  Optional Fly.io deploy
```

## Limitations (MVP)

- LLM line numbers are validated against the diff but the model can still produce false positives — treat findings as "review prompts," not blocking gates.
- Dep CVE check only looks at **newly added pinned versions** in `requirements.txt` / `pyproject.toml` / `package.json`. Range specifiers, lockfiles, and transitive deps are out of scope here.
- Diffs over `MAX_DIFF_BYTES` (default 200 KB) are skipped to avoid blowing up the OpenAI context window.
- Review event is `COMMENT`, not `REQUEST_CHANGES` — the bot doesn't block merge. Switch in `app/main.py` if you want it to.
