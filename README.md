# Codex Proxy

OpenAI-compatible proxy for Codex sessions with a built-in admin panel, automatic token refresh, streaming support, and deploy-ready Docker packaging.

This project lets you sign in with your Codex/OpenAI account, persist the session locally, and expose a `base_url` that can be used by tools expecting an OpenAI-style API.

## Highlights

- OpenAI-compatible endpoints:
  - `GET /v1/models`
  - `POST /v1/chat/completions`
  - `POST /v1/responses`
- Admin panel with protected access
- Automatic OAuth login and token refresh
- Manual login fallback by pasting the final callback URL
- QR code login page for opening the auth flow on another device
- Dynamic model discovery with static fallback and manual refresh from the panel
- Optional API key protection for clients using the proxy
- Ready for local use, Docker, and Coolify deployments

## Project Structure

```text
.
├── codex_proxy.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

## Requirements

- Python 3.11+
- A Codex/OpenAI account able to complete the OAuth flow

## Local Development

Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start the server:

```bash
PANEL_ACCESS_TOKEN=change-me-panel-token \
PROXY_API_KEY=change-me-api-key \
python codex_proxy.py
```

Open the admin panel:

```text
http://localhost:1455/
```

OpenAI-compatible base URL:

```text
http://localhost:1455/v1
```

## Authentication Modes

### 1. Direct callback mode

Use the regular login button in the admin panel. The server opens an OAuth flow and receives the callback directly at:

```text
/auth/callback
```

This is the simplest option when your configured callback URL is accepted by the upstream flow.

### 2. Manual callback import mode

Use `Colar URL de retorno` in the admin panel when the upstream flow requires a different callback URL, such as a localhost callback.

Flow:

1. Open the manual login page.
2. Start the auth flow from the generated link or QR code.
3. Complete login.
4. Copy the final callback URL shown by the browser.
5. Paste it into the panel.
6. The server extracts `code` and `state`, exchanges them for tokens, and saves the session.

Default manual callback URL:

```text
http://localhost:1455/auth/callback
```

You can override it with `CODEX_MANUAL_REDIRECT_URI`.

## Environment Variables

Core configuration:

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `1455` | HTTP port |
| `PUBLIC_BASE_URL` | `http://localhost:${PORT}` | Public URL used by the UI |
| `CODEX_REDIRECT_URI` | `${PUBLIC_BASE_URL}/auth/callback` | Direct callback URL |
| `CODEX_MANUAL_REDIRECT_URI` | `http://localhost:1455/auth/callback` | Manual callback URL for paste-based login |
| `CODEX_CLIENT_VERSION` | `26.318.11754` | Client version used when probing upstream model endpoints |
| `SESSION_FILE` | `./codex_session.json` | Persisted session path |

Access control:

| Variable | Default | Description |
|---|---|---|
| `PANEL_ACCESS_TOKEN` | generated at boot | Admin panel access token |
| `PROXY_API_KEY` | empty | Optional Bearer token required by `/v1/*` |
| `PANEL_SESSION_TTL_SECONDS` | `43200` | Admin panel session lifetime |
| `PANEL_RATE_LIMIT_MAX_ATTEMPTS` | `6` | Failed panel logins before temporary block |
| `PANEL_RATE_LIMIT_WINDOW_SECONDS` | `900` | Rate limit window |
| `AUTH_REQUEST_TTL_SECONDS` | `900` | OAuth request lifetime |

Proxy behavior:

| Variable | Default | Description |
|---|---|---|
| `OPENAI_DEFAULT_MODEL` | first configured alias | Default public model |
| `OPENAI_COMPAT_MODELS` | built-in alias list | Static fallback merged into `/v1/models` |
| `MODELS_CACHE_TTL_SECONDS` | `3600` | How long dynamic model discovery stays fresh |
| `MODELS_RETRY_COOLDOWN_SECONDS` | `120` | Minimum delay before retrying a failed model refresh |
| `TRUST_PROXY_HEADERS` | `false` | Use `X-Forwarded-For` / `X-Real-IP` |
| `PANEL_SECURE_COOKIE` | auto | Force secure cookies |

See `.env.example` for a practical starting point.

## API Usage

Example with the official Python SDK:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:1455/v1",
    api_key="change-me-api-key",
)

resp = client.chat.completions.create(
    model="gpt-5.1-codex",
    messages=[
        {"role": "user", "content": "Say hello in Portuguese."}
    ],
)

print(resp.choices[0].message.content)
```

Example with `curl`:

```bash
curl http://localhost:1455/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer change-me-api-key" \
  -d '{
    "model": "gpt-5.1-codex",
    "messages": [
      {"role": "user", "content": "Diga oi."}
    ]
  }'
```

## Docker

Build the image:

```bash
docker build -t codex-proxy .
```

Run the container:

```bash
docker run --rm -p 8000:8000 \
  -e PUBLIC_BASE_URL=http://localhost:8000 \
  -e CODEX_REDIRECT_URI=http://localhost:8000/auth/callback \
  -e CODEX_MANUAL_REDIRECT_URI=http://localhost:1455/auth/callback \
  -e PANEL_ACCESS_TOKEN=change-me-panel-token \
  -e PROXY_API_KEY=change-me-api-key \
  -e SESSION_FILE=/app/data/codex_session.json \
  -v $(pwd)/data:/app/data \
  codex-proxy
```

## Docker Compose

1. Copy the example environment file:

```bash
cp .env.example .env
```

2. Edit the values.

3. Start the service:

```bash
docker compose up -d --build
```

By default, the compose file stores session data in `./data`.

If you change `SESSION_FILE` or mount a custom volume, make sure the container can write to that path.

## Coolify

This repository is ready to deploy on Coolify using the included `Dockerfile` or `docker-compose.yml`.

Recommended setup:

1. Create a new application from this repository.
2. Choose `Dockerfile` or `Docker Compose` deployment.
3. Set a persistent volume for `/app/data`.
4. Configure these variables at minimum:
   - `PUBLIC_BASE_URL=https://your-domain.example`
   - `CODEX_REDIRECT_URI=https://your-domain.example/auth/callback`
   - `CODEX_MANUAL_REDIRECT_URI=http://localhost:1455/auth/callback`
   - `SESSION_FILE=/app/data/codex_session.json`
   - `PANEL_ACCESS_TOKEN=<strong-random-value>`
   - `PROXY_API_KEY=<strong-random-value>`
   - `TRUST_PROXY_HEADERS=true`
   - `PANEL_SECURE_COOKIE=true`
5. Redeploy the application.

If the direct callback flow is not accepted by the upstream auth flow, use the manual login mode from the panel and paste the final callback URL there.

If manual login fails while saving the session, the most common cause is a volume permission issue on `/app/data`. Confirm that the mounted persistent storage is writable by the container.

## Notes

- `/v1/models` prefers dynamic discovery from upstream endpoints and falls back to the local compatibility list when discovery is unavailable.
- The upstream authentication and response formats may change over time.
- The session file contains live credentials. Keep it outside version control and use restricted permissions.
- In container deployments, `SESSION_FILE` must point to a writable path. The default Docker image expects `/app/data` to be writable when persistence is enabled.

## Development Notes

Useful commands:

```bash
python -m py_compile codex_proxy.py
python -m uvicorn codex_proxy:app --host 127.0.0.1 --port 1455
```

## Contributing

Issues and pull requests are welcome.

When proposing changes, include:

- a short description of the use case
- any environment assumptions
- notes about direct callback vs manual callback behavior when relevant
