import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlparse

from curl_cffi import requests
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse


APP_HOST = os.getenv("HOST", "0.0.0.0")
APP_PORT = int(os.getenv("PORT", "1455"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", f"http://localhost:{APP_PORT}")
CLIENT_ID = os.getenv("CODEX_CLIENT_ID", "app_EMoamEEZ73f0CkXaXp7hrann")
REDIRECT_URI = os.getenv("CODEX_REDIRECT_URI", f"{PUBLIC_BASE_URL}/auth/callback")
MANUAL_REDIRECT_URI = os.getenv(
    "CODEX_MANUAL_REDIRECT_URI", "http://localhost:1455/auth/callback"
)
AUTH_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
AUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
UPSTREAM_API_BASE_URL = os.getenv(
    "CODEX_API_BASE_URL", "https://chatgpt.com/backend-api"
).rstrip("/")
UPSTREAM_URL = os.getenv(
    "CODEX_UPSTREAM_URL", f"{UPSTREAM_API_BASE_URL}/codex/responses"
)
UPSTREAM_MODEL = os.getenv("CODEX_UPSTREAM_MODEL", "gpt-5.1-codex")
CODEX_CLIENT_VERSION = os.getenv("CODEX_CLIENT_VERSION", "26.318.11754")
UPSTREAM_IMPERSONATE = os.getenv("CODEX_IMPERSONATE", "chrome120")
UPSTREAM_TIMEOUT = float(os.getenv("CODEX_TIMEOUT", "120"))
MODELS_CACHE_TTL_SECONDS = int(os.getenv("MODELS_CACHE_TTL_SECONDS", "3600"))
MODELS_RETRY_COOLDOWN_SECONDS = int(
    os.getenv("MODELS_RETRY_COOLDOWN_SECONDS", "120")
)
PROXY_API_KEY = os.getenv("PROXY_API_KEY", "").strip()
SESSION_FILE = Path(os.getenv("SESSION_FILE", "./codex_session.json")).resolve()
PANEL_ACCESS_TOKEN = os.getenv("PANEL_ACCESS_TOKEN", "").strip() or secrets.token_urlsafe(24)
PANEL_TOKEN_WAS_GENERATED = not bool(os.getenv("PANEL_ACCESS_TOKEN", "").strip())
PANEL_SESSION_COOKIE_NAME = os.getenv(
    "PANEL_SESSION_COOKIE_NAME", "codex_panel_session"
).strip()
AUTH_CONTEXT_SECRET = (
    os.getenv("AUTH_CONTEXT_SECRET", "").strip() or PANEL_ACCESS_TOKEN
).encode("utf-8")
PANEL_SESSION_TTL_SECONDS = int(os.getenv("PANEL_SESSION_TTL_SECONDS", "43200"))
PANEL_RATE_LIMIT_MAX_ATTEMPTS = int(
    os.getenv("PANEL_RATE_LIMIT_MAX_ATTEMPTS", "6")
)
PANEL_RATE_LIMIT_WINDOW_SECONDS = int(
    os.getenv("PANEL_RATE_LIMIT_WINDOW_SECONDS", "900")
)
AUTH_REQUEST_TTL_SECONDS = int(os.getenv("AUTH_REQUEST_TTL_SECONDS", "900"))
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
PANEL_SECURE_COOKIE = os.getenv("PANEL_SECURE_COOKIE", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
} or PUBLIC_BASE_URL.startswith("https://")
MODEL_ALIASES = [
    model.strip()
    for model in os.getenv(
        "OPENAI_COMPAT_MODELS",
        "gpt-5.1-codex,gpt-5,gpt-4.1,gpt-4o,gpt-4,gpt-3.5-turbo",
    ).split(",")
    if model.strip()
]
DEFAULT_PUBLIC_MODEL = os.getenv(
    "OPENAI_DEFAULT_MODEL", MODEL_ALIASES[0] if MODEL_ALIASES else UPSTREAM_MODEL
)
BROWSER_USER_AGENT = os.getenv(
    "CODEX_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
)

if DEFAULT_PUBLIC_MODEL not in MODEL_ALIASES:
    MODEL_ALIASES.insert(0, DEFAULT_PUBLIC_MODEL)
if UPSTREAM_MODEL not in MODEL_ALIASES:
    MODEL_ALIASES.insert(0, UPSTREAM_MODEL)


app = FastAPI(title="Codex OpenAI Compatibility Proxy")

session_lock = Lock()
pending_auth_lock = Lock()
pending_auth: dict[str, dict[str, Any]] = {}
panel_session_lock = Lock()
panel_rate_limit_lock = Lock()
panel_sessions: dict[str, dict[str, Any]] = {}
panel_login_attempts: dict[str, list[float]] = {}
models_lock = Lock()
models_state: dict[str, Any] = {
    "dynamic_models": [],
    "last_refresh_at": None,
    "last_attempt_at": None,
    "last_error": None,
    "last_source": None,
}


def now_ts() -> int:
    return int(time.time())


def escape_html(value: Any) -> str:
    return html.escape(str(value))


def client_ip(request: Request) -> str:
    if TRUST_PROXY_HEADERS:
        forwarded_for = request.headers.get("x-forwarded-for", "").strip()
        if forwarded_for:
            return forwarded_for.split(",")[0].strip() or "unknown"

        real_ip = request.headers.get("x-real-ip", "").strip()
        if real_ip:
            return real_ip

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


def sanitize_next_path(raw_next: str | None) -> str:
    if not raw_next:
        return "/"
    if not raw_next.startswith("/"):
        return "/"
    if raw_next.startswith("//"):
        return "/"
    return raw_next


def cleanup_panel_sessions() -> None:
    now = now_ts()
    expired_ids = [
        session_id
        for session_id, session_data in panel_sessions.items()
        if session_data.get("expires_at", 0) <= now
    ]
    for session_id in expired_ids:
        panel_sessions.pop(session_id, None)


def create_panel_session(client_address: str) -> str:
    session_id = secrets.token_urlsafe(32)
    with panel_session_lock:
        cleanup_panel_sessions()
        panel_sessions[session_id] = {
            "client_ip": client_address,
            "created_at": now_ts(),
            "expires_at": now_ts() + PANEL_SESSION_TTL_SECONDS,
        }
    return session_id


def delete_panel_session(session_id: str | None) -> None:
    if not session_id:
        return
    with panel_session_lock:
        panel_sessions.pop(session_id, None)


def get_valid_panel_session(request: Request) -> tuple[str | None, dict[str, Any] | None]:
    session_id = request.cookies.get(PANEL_SESSION_COOKIE_NAME)
    if not session_id:
        return None, None

    with panel_session_lock:
        cleanup_panel_sessions()
        session_data = panel_sessions.get(session_id)
        if not session_data:
            return None, None

        session_data["expires_at"] = now_ts() + PANEL_SESSION_TTL_SECONDS
        return session_id, dict(session_data)


def panel_redirect_to_login(request: Request) -> RedirectResponse:
    next_path = sanitize_next_path(request.url.path)
    response = RedirectResponse(
        url=f"/panel/login?next={quote(next_path)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.delete_cookie(PANEL_SESSION_COOKIE_NAME, path="/")
    return response


def require_panel_session_json(request: Request) -> tuple[str, dict[str, Any]]:
    session_id, session_data = get_valid_panel_session(request)
    if not session_id or not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Painel requer autenticacao administrativa.",
        )
    return session_id, session_data


def get_rate_limit_retry_after(client_address: str) -> int:
    now = time.time()
    with panel_rate_limit_lock:
        attempts = panel_login_attempts.get(client_address, [])
        attempts = [
            attempt_ts
            for attempt_ts in attempts
            if now - attempt_ts < PANEL_RATE_LIMIT_WINDOW_SECONDS
        ]
        if attempts:
            panel_login_attempts[client_address] = attempts
        else:
            panel_login_attempts.pop(client_address, None)

        if len(attempts) < PANEL_RATE_LIMIT_MAX_ATTEMPTS:
            return 0

        oldest_attempt = attempts[0]
        retry_after = int(PANEL_RATE_LIMIT_WINDOW_SECONDS - (now - oldest_attempt)) + 1
        return max(retry_after, 1)


def record_failed_panel_login(client_address: str) -> None:
    now = time.time()
    with panel_rate_limit_lock:
        attempts = panel_login_attempts.get(client_address, [])
        attempts = [
            attempt_ts
            for attempt_ts in attempts
            if now - attempt_ts < PANEL_RATE_LIMIT_WINDOW_SECONDS
        ]
        attempts.append(now)
        panel_login_attempts[client_address] = attempts


def clear_failed_panel_logins(client_address: str) -> None:
    with panel_rate_limit_lock:
        panel_login_attempts.pop(client_address, None)


def ensure_session_dir() -> None:
    try:
        SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Nao foi possivel preparar o diretorio da sessao em {SESSION_FILE.parent}. "
                f"Verifique as permissoes do volume ou do caminho configurado. ({exc})"
            ),
        ) from exc


def load_session() -> dict[str, Any] | None:
    with session_lock:
        if not SESSION_FILE.exists():
            return None

        try:
            raw = SESSION_FILE.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Nao foi possivel ler a sessao salva: {exc}",
            ) from exc

    return data or None


def save_session(session_data: dict[str, Any]) -> None:
    ensure_session_dir()
    temp_file = SESSION_FILE.with_suffix(f"{SESSION_FILE.suffix}.tmp")

    with session_lock:
        try:
            temp_file.write_text(
                json.dumps(session_data, indent=2, ensure_ascii=True),
                encoding="utf-8",
            )
            os.replace(temp_file, SESSION_FILE)
        except OSError as exc:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except OSError:
                pass
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    f"Nao foi possivel salvar a sessao em {SESSION_FILE}. "
                    f"Verifique as permissoes do volume ou do caminho configurado. ({exc})"
                ),
            ) from exc
        try:
            os.chmod(SESSION_FILE, 0o600)
        except OSError:
            pass


def clear_session() -> None:
    with session_lock:
        try:
            if SESSION_FILE.exists():
                SESSION_FILE.unlink()
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    f"Nao foi possivel remover a sessao em {SESSION_FILE}. "
                    f"Verifique as permissoes do volume ou do caminho configurado. ({exc})"
                ),
            ) from exc


def decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        payload_b64 = token.split(".")[1]
    except IndexError as exc:
        raise ValueError("token JWT invalido") from exc

    padding = len(payload_b64) % 4
    if padding:
        payload_b64 += "=" * (4 - padding)

    try:
        payload_text = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
        return json.loads(payload_text)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("nao foi possivel decodificar o JWT") from exc


def build_session_from_token_response(
    token_data: dict[str, Any], refresh_fallback: str | None = None
) -> dict[str, Any]:
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token") or refresh_fallback
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="OAuth retornou uma resposta sem access_token.",
        )

    payload = decode_jwt_payload(access_token)
    auth_data = payload.get("https://api.openai.com/auth", {})
    profile_data = payload.get("https://api.openai.com/profile", {})

    expires_at = payload.get("exp")
    expires_in = token_data.get("expires_in")
    if expires_in is not None:
        try:
            expires_at = now_ts() + int(expires_in)
        except (TypeError, ValueError):
            pass

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": auth_data.get("chatgpt_account_id"),
        "email": profile_data.get("email"),
        "plan_type": auth_data.get("chatgpt_plan_type"),
        "expires_at": expires_at,
        "updated_at": now_ts(),
    }


def browser_headers(accept: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Accept": accept,
        "User-Agent": BROWSER_USER_AGENT,
    }


def is_session_expiring(session_data: dict[str, Any], skew_seconds: int = 60) -> bool:
    expires_at = session_data.get("expires_at")
    if not isinstance(expires_at, int):
        return False
    return expires_at <= now_ts() + skew_seconds


def ensure_session(force_refresh: bool = False) -> dict[str, Any]:
    session_data = load_session()
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sessao ausente. Faça login em /auth/login.",
        )

    if not force_refresh and not is_session_expiring(session_data):
        return session_data

    refresh_token = session_data.get("refresh_token")
    if not refresh_token:
        if session_data.get("access_token") and not is_session_expiring(session_data, 0):
            return session_data
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sessao expirada e sem refresh token. Faça login novamente.",
        )

    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "refresh_token": refresh_token,
    }

    try:
        response = requests.post(
            AUTH_TOKEN_URL,
            json=payload,
            headers=browser_headers("application/json"),
            impersonate=UPSTREAM_IMPERSONATE,
            timeout=UPSTREAM_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Falha ao renovar a sessao: {exc}",
        ) from exc

    if response.status_code != 200:
        detail = response.text[:600]
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Refresh token rejeitado pelo upstream: {detail}",
        )

    updated_session = build_session_from_token_response(
        response.json(), refresh_fallback=refresh_token
    )
    save_session(updated_session)
    return updated_session


def require_proxy_api_key(request: Request) -> None:
    if not PROXY_API_KEY:
        return

    expected = f"Bearer {PROXY_API_KEY}"
    if request.headers.get("Authorization") != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization invalido para o proxy.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def build_login_redirect_url(
    code_challenge: str,
    state: str,
    redirect_uri: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email offline_access",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": "pi",
    }
    return f"{AUTH_AUTHORIZE_URL}?{urlencode(params)}"


def code_challenge_from_verifier(code_verifier: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("utf-8")).digest()
    ).decode("utf-8").rstrip("=")


def create_auth_request(redirect_uri: str, mode: str) -> dict[str, Any]:
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
    state = secrets.token_hex(16)

    auth_request = {
        "state": state,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "mode": mode,
        "created_at": now_ts(),
    }

    cleanup_expired_auth_requests()
    with pending_auth_lock:
        pending_auth[state] = auth_request

    return auth_request


def get_auth_request_by_state(state: str) -> dict[str, Any] | None:
    with pending_auth_lock:
        auth_request = pending_auth.get(state)
        if not auth_request:
            return None
        return dict(auth_request)


def current_auth_request(mode: str | None = None) -> dict[str, Any] | None:
    cleanup_expired_auth_requests()
    with pending_auth_lock:
        candidates = [
            auth_request
            for auth_request in pending_auth.values()
            if mode is None or auth_request.get("mode") == mode
        ]
        if not candidates:
            return None
        latest = max(candidates, key=lambda item: int(item.get("created_at", 0)))
        return dict(latest)


def clear_auth_request(state: str | None = None) -> None:
    with pending_auth_lock:
        if state is None:
            pending_auth.clear()
            return
        pending_auth.pop(state, None)


def auth_request_is_expired(auth_request: dict[str, Any]) -> bool:
    created_at = auth_request.get("created_at")
    if not isinstance(created_at, int):
        return True
    return created_at + AUTH_REQUEST_TTL_SECONDS < now_ts()


def cleanup_expired_auth_requests() -> None:
    with pending_auth_lock:
        expired_states = [
            state
            for state, auth_request in pending_auth.items()
            if auth_request_is_expired(auth_request)
        ]
        for state in expired_states:
            pending_auth.pop(state, None)


def build_auth_url_from_request(auth_request: dict[str, Any]) -> str:
    return build_login_redirect_url(
        code_challenge=code_challenge_from_verifier(auth_request["code_verifier"]),
        state=auth_request["state"],
        redirect_uri=auth_request["redirect_uri"],
    )


def encode_auth_context(auth_request: dict[str, Any]) -> str:
    payload = {
        "state": auth_request.get("state"),
        "code_verifier": auth_request.get("code_verifier"),
        "redirect_uri": auth_request.get("redirect_uri"),
        "mode": auth_request.get("mode"),
        "created_at": auth_request.get("created_at"),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
    signature = hmac.new(
        AUTH_CONTEXT_SECRET,
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_b64}.{signature}"


def decode_auth_context(auth_context_token: str | None) -> dict[str, Any] | None:
    if not auth_context_token:
        return None

    try:
        payload_b64, signature = auth_context_token.split(".", 1)
    except ValueError:
        return None

    expected_signature = hmac.new(
        AUTH_CONTEXT_SECRET,
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not secrets.compare_digest(signature, expected_signature):
        return None

    padding = len(payload_b64) % 4
    if padding:
        payload_b64 += "=" * (4 - padding)

    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None

    if not isinstance(payload, dict):
        return None
    return payload


def resolve_manual_auth_request(
    returned_state: str,
    auth_context_token: str | None,
) -> dict[str, Any]:
    cleanup_expired_auth_requests()
    auth_request = get_auth_request_by_state(returned_state)
    if auth_request:
        if auth_request_is_expired(auth_request):
            clear_auth_request(returned_state)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="O link de login expirou. Gere um novo QR code em /auth/manual.",
            )
        return auth_request

    auth_context = decode_auth_context(auth_context_token)
    if not auth_context or auth_context.get("state") != returned_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Nenhum login pendente foi encontrado para esse retorno. "
                "Se o servidor reiniciou ou o fluxo expirou, gere um novo link em /auth/manual."
            ),
        )

    if auth_request_is_expired(auth_context):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O link de login expirou. Gere um novo QR code em /auth/manual.",
        )

    return auth_context


def validate_auth_request(
    expected_mode: str,
    returned_state: str,
) -> dict[str, Any]:
    cleanup_expired_auth_requests()
    auth_request = get_auth_request_by_state(returned_state)
    if not auth_request:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Nenhum login pendente foi encontrado para esse retorno. "
                "Se o servidor reiniciou ou o fluxo expirou, gere um novo link em /auth/manual."
            ),
        )

    if auth_request.get("mode") != expected_mode:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O modo de login pendente nao corresponde a esta acao.",
        )

    if auth_request_is_expired(auth_request):
        clear_auth_request(returned_state)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O link de login expirou. Gere um novo QR code em /auth/login.",
        )

    if returned_state != auth_request.get("state"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State invalido ou login expirado. Refaça /auth/login.",
        )

    return auth_request


def exchange_auth_code(auth_code: str, auth_request: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "client_id": CLIENT_ID,
        "code_verifier": auth_request["code_verifier"],
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": auth_request["redirect_uri"],
    }

    try:
        response = requests.post(
            AUTH_TOKEN_URL,
            json=payload,
            headers=browser_headers("application/json"),
            impersonate=UPSTREAM_IMPERSONATE,
            timeout=UPSTREAM_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Falha ao trocar o code por token: {exc}",
        ) from exc

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"OAuth recusou a troca do code: {response.text[:600]}",
        )

    session_data = build_session_from_token_response(response.json())
    save_session(session_data)
    clear_auth_request(auth_request.get("state"))
    reset_models_state()
    return session_data


def render_auth_success_page() -> str:
    return f"""
<!doctype html>
<html lang=\"pt-BR\">
  <head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>Login concluido</title>
    <script src=\"https://cdn.tailwindcss.com\"></script>
  </head>
  <body class=\"min-h-screen overflow-x-hidden bg-zinc-950 text-zinc-100\">
    <div class=\"pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.12),_transparent_24%),radial-gradient(circle_at_bottom_right,_rgba(168,85,247,0.12),_transparent_22%),linear-gradient(to_bottom,_rgba(9,9,11,0.96),_rgba(9,9,11,1))]\"></div>
    <main class=\"relative z-10 mx-auto flex min-h-screen max-w-3xl items-center px-5 py-8 sm:px-6\">
      <section class=\"w-full rounded-[24px] border border-white/10 bg-white/[0.04] p-6 shadow-xl shadow-cyan-950/10 backdrop-blur sm:p-7\">
        <div class=\"inline-flex items-center rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.24em] text-emerald-200\">Tudo certo</div>
        <h1 class=\"mt-4 text-3xl font-semibold text-white\">Login concluido</h1>
        <p class=\"mt-4 text-sm leading-7 text-zinc-300\">A conexao foi salva neste servidor. Se voce iniciou o processo em outro dispositivo, pode fechar esta tela e voltar ao painel principal.</p>
        <div class=\"mt-6 space-y-3 rounded-2xl border border-white/10 bg-black/20 p-4 text-sm text-zinc-300\">
          <p>Sessao salva em <code class=\"rounded bg-white/5 px-2 py-1 text-zinc-100\">{SESSION_FILE}</code></p>
          <p>URL de integracao <code class=\"rounded bg-white/5 px-2 py-1 text-zinc-100\">{PUBLIC_BASE_URL}/v1</code></p>
        </div>
        <div class=\"mt-6 flex flex-wrap gap-2.5\">
          <a href=\"/\" class=\"inline-flex items-center rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-cyan-300\">Voltar ao painel</a>
        </div>
      </section>
    </main>
  </body>
</html>
"""


def extract_code_and_state_from_returned_url(returned_url: str) -> tuple[str, str]:
    parsed = urlparse(returned_url.strip())
    params = parse_qs(parsed.query)
    auth_code = params.get("code", [""])[0].strip()
    auth_state = params.get("state", [""])[0].strip()
    if not auth_code or not auth_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nao foi possivel localizar code/state na URL informada.",
        )
    return auth_code, auth_state


def dedupe_model_ids(model_ids: list[str]) -> list[str]:
    unique_ids: list[str] = []
    seen: set[str] = set()
    for model_id in model_ids:
        normalized = model_id.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique_ids.append(normalized)
    return unique_ids


def static_model_ids() -> list[str]:
    return dedupe_model_ids(MODEL_ALIASES)


def get_models_state_snapshot() -> dict[str, Any]:
    with models_lock:
        return {
            "dynamic_models": list(models_state.get("dynamic_models", [])),
            "last_refresh_at": models_state.get("last_refresh_at"),
            "last_attempt_at": models_state.get("last_attempt_at"),
            "last_error": models_state.get("last_error"),
            "last_source": models_state.get("last_source"),
        }


def set_models_state(**updates: Any) -> dict[str, Any]:
    with models_lock:
        models_state.update(updates)
        return {
            "dynamic_models": list(models_state.get("dynamic_models", [])),
            "last_refresh_at": models_state.get("last_refresh_at"),
            "last_attempt_at": models_state.get("last_attempt_at"),
            "last_error": models_state.get("last_error"),
            "last_source": models_state.get("last_source"),
        }


def reset_models_state() -> dict[str, Any]:
    return set_models_state(
        dynamic_models=[],
        last_refresh_at=None,
        last_attempt_at=None,
        last_error=None,
        last_source=None,
    )


def model_discovery_endpoints() -> list[str]:
    return [
        f"{UPSTREAM_API_BASE_URL}/codex/models?client_version={CODEX_CLIENT_VERSION}",
        f"{UPSTREAM_API_BASE_URL}/models",
        f"{UPSTREAM_API_BASE_URL}/sentinel/chat-requirements",
    ]


def flatten_model_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: Any = None

    chat_models = payload.get("chat_models")
    if isinstance(chat_models, dict) and isinstance(chat_models.get("models"), list):
        candidates = chat_models.get("models")
    elif isinstance(payload.get("models"), list):
        candidates = payload.get("models")
    elif isinstance(payload.get("data"), list):
        candidates = payload.get("data")
    elif isinstance(payload.get("categories"), list):
        candidates = payload.get("categories")

    if not isinstance(candidates, list):
        return []

    flattened: list[dict[str, Any]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue

        nested_models = item.get("models")
        if isinstance(nested_models, list):
            for nested_item in nested_models:
                if isinstance(nested_item, dict):
                    flattened.append(nested_item)
            continue

        flattened.append(item)

    return flattened


def normalize_dynamic_model_ids(model_entries: list[dict[str, Any]]) -> list[str]:
    discovered_ids: list[str] = []

    for entry in model_entries:
        model_id = entry.get("slug") or entry.get("id") or entry.get("name")
        if isinstance(model_id, str) and model_id.strip():
            discovered_ids.append(model_id.strip())

    return dedupe_model_ids(discovered_ids)


def model_cache_is_stale(snapshot: dict[str, Any]) -> bool:
    last_refresh_at = snapshot.get("last_refresh_at")
    if not isinstance(last_refresh_at, int):
        return True
    return last_refresh_at + MODELS_CACHE_TTL_SECONDS < now_ts()


def build_public_model_ids(dynamic_models: list[str] | None = None) -> list[str]:
    merged = list(dynamic_models or []) + static_model_ids()
    return dedupe_model_ids(merged)


def build_public_model_entries(dynamic_models: list[str] | None = None) -> list[dict[str, Any]]:
    return [
        {
            "id": model_id,
            "object": "model",
            "created": now_ts(),
            "owned_by": "openai",
        }
        for model_id in build_public_model_ids(dynamic_models)
    ]


def resolve_requested_upstream_model(requested_model: Any) -> str:
    if not isinstance(requested_model, str) or not requested_model.strip():
        return UPSTREAM_MODEL

    normalized_model = requested_model.strip()
    dynamic_models = set(get_models_state_snapshot().get("dynamic_models", []))
    if normalized_model in dynamic_models or normalized_model == UPSTREAM_MODEL:
        return normalized_model

    return UPSTREAM_MODEL


def build_models_dashboard_state() -> dict[str, Any]:
    snapshot = get_models_state_snapshot()
    effective_models = build_public_model_ids(snapshot.get("dynamic_models", []))
    return {
        "models": effective_models,
        "count": len(effective_models),
        "dynamic_count": len(snapshot.get("dynamic_models", [])),
        "using_dynamic": bool(snapshot.get("dynamic_models")),
        "last_refresh_at": snapshot.get("last_refresh_at"),
        "last_attempt_at": snapshot.get("last_attempt_at"),
        "last_error": snapshot.get("last_error"),
        "last_source": snapshot.get("last_source"),
    }


def fetch_dynamic_models_from_upstream(force_session_refresh: bool = False) -> tuple[list[str], str]:
    last_error = "nenhum endpoint retornou modelos"

    for attempt in range(2):
        session_data = ensure_session(force_refresh=force_session_refresh or attempt > 0)
        should_retry_after_refresh = False

        for endpoint_url in model_discovery_endpoints():
            try:
                response = requests.get(
                    endpoint_url,
                    headers=build_model_discovery_headers(session_data),
                    impersonate=UPSTREAM_IMPERSONATE,
                    timeout=UPSTREAM_TIMEOUT,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = f"{endpoint_url}: {exc}"
                continue

            if response.status_code in {401, 403} and attempt == 0:
                should_retry_after_refresh = True
                last_error = f"{endpoint_url}: autenticacao rejeitada"
                break

            if response.status_code != 200:
                last_error = f"{endpoint_url}: HTTP {response.status_code}"
                continue

            try:
                payload = response.json()
            except Exception as exc:  # noqa: BLE001
                last_error = f"{endpoint_url}: JSON invalido ({exc})"
                continue

            if not isinstance(payload, dict):
                last_error = f"{endpoint_url}: resposta fora do formato esperado"
                continue

            discovered_models = normalize_dynamic_model_ids(flatten_model_entries(payload))
            if discovered_models:
                source_path = endpoint_url.replace(f"{UPSTREAM_API_BASE_URL}/", "")
                return discovered_models, source_path

            last_error = f"{endpoint_url}: resposta sem modelos utilizaveis"

        if should_retry_after_refresh:
            continue
        break

    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Nao foi possivel atualizar os modelos dinamicamente: {last_error}",
    )


def refresh_dynamic_models(raise_on_error: bool = False) -> dict[str, Any]:
    set_models_state(last_attempt_at=now_ts())

    try:
        discovered_models, source = fetch_dynamic_models_from_upstream()
    except HTTPException as exc:
        snapshot = set_models_state(last_error=str(exc.detail))
        if raise_on_error:
            raise
        return snapshot

    return set_models_state(
        dynamic_models=discovered_models,
        last_refresh_at=now_ts(),
        last_error=None,
        last_source=source,
    )


def ensure_models_catalog(force_refresh: bool = False) -> dict[str, Any]:
    snapshot = get_models_state_snapshot()

    if force_refresh:
        return refresh_dynamic_models(raise_on_error=False)

    if snapshot.get("dynamic_models") and not model_cache_is_stale(snapshot):
        return snapshot

    last_attempt_at = snapshot.get("last_attempt_at")
    if isinstance(last_attempt_at, int):
        if last_attempt_at + MODELS_RETRY_COOLDOWN_SECONDS > now_ts():
            return snapshot

    return refresh_dynamic_models(raise_on_error=False)


def normalize_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not isinstance(item, dict):
                continue

            item_type = item.get("type")
            if item_type in {"text", "input_text", "output_text"}:
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif item_type == "image_url":
                image_url = item.get("image_url")
                if isinstance(image_url, dict):
                    image_url = image_url.get("url")
                if isinstance(image_url, str) and image_url:
                    parts.append(f"[image: {image_url}]")
            elif item_type in {"audio", "input_audio"}:
                parts.append("[audio omitted]")

        return "\n".join(part for part in parts if part)

    if isinstance(content, dict):
        text = content.get("text")
        if isinstance(text, str):
            return text

    return str(content)


def build_chat_payload(openai_body: dict[str, Any]) -> tuple[dict[str, Any], str]:
    messages = openai_body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="messages precisa ser uma lista nao vazia.",
        )

    requested_n = openai_body.get("n")
    if requested_n not in (None, 1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O proxy ainda nao suporta n > 1.",
        )

    instructions: list[str] = []
    input_items: list[dict[str, Any]] = []

    for raw_message in messages:
        if not isinstance(raw_message, dict):
            continue

        role = raw_message.get("role", "user")
        content = normalize_content(raw_message.get("content"))

        if role == "system":
            if content:
                instructions.append(content)
            continue

        item: dict[str, Any] = {
            "role": role,
            "content": content,
        }
        if raw_message.get("name"):
            item["name"] = raw_message["name"]

        input_items.append(item)

    if not input_items and not instructions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A requisicao nao gerou nenhuma entrada utilizavel.",
        )

    payload: dict[str, Any] = {
        "model": resolve_requested_upstream_model(openai_body.get("model")),
        "store": False,
        "stream": True,
        "input": input_items,
        "text": {"verbosity": "medium"},
        "include": ["reasoning.encrypted_content"],
        "tool_choice": openai_body.get("tool_choice", "auto"),
        "parallel_tool_calls": openai_body.get("parallel_tool_calls", True),
    }

    if instructions:
        payload["instructions"] = "\n\n".join(instructions)

    max_output_tokens = openai_body.get("max_completion_tokens")
    if max_output_tokens is None:
        max_output_tokens = openai_body.get("max_tokens")
    if max_output_tokens is not None:
        payload["max_output_tokens"] = max_output_tokens

    tools = openai_body.get("tools")
    if isinstance(tools, list):
        payload["tools"] = tools

    response_model = openai_body.get("model") or DEFAULT_PUBLIC_MODEL
    return payload, response_model


def normalize_responses_input(raw_input: Any) -> list[dict[str, Any]]:
    if raw_input is None:
        return []

    if isinstance(raw_input, str):
        return [{"role": "user", "content": raw_input}]

    if isinstance(raw_input, dict):
        return [
            {
                "role": raw_input.get("role", "user"),
                "content": normalize_content(
                    raw_input.get("content", raw_input.get("text"))
                ),
            }
        ]

    if not isinstance(raw_input, list):
        return [{"role": "user", "content": str(raw_input)}]

    normalized: list[dict[str, Any]] = []
    for item in raw_input:
        if isinstance(item, str):
            normalized.append({"role": "user", "content": item})
            continue

        if not isinstance(item, dict):
            continue

        role = item.get("role", "user")
        if item.get("type") == "message":
            role = item.get("role", role)

        normalized.append(
            {
                "role": role,
                "content": normalize_content(item.get("content", item.get("text"))),
            }
        )

    return normalized


def build_responses_payload(openai_body: dict[str, Any]) -> tuple[dict[str, Any], str]:
    payload: dict[str, Any] = {
        "model": resolve_requested_upstream_model(openai_body.get("model")),
        "store": bool(openai_body.get("store", False)),
        "stream": True,
        "input": normalize_responses_input(openai_body.get("input")),
        "text": openai_body.get("text")
        if isinstance(openai_body.get("text"), dict)
        else {"verbosity": "medium"},
        "include": ["reasoning.encrypted_content"],
        "tool_choice": openai_body.get("tool_choice", "auto"),
        "parallel_tool_calls": openai_body.get("parallel_tool_calls", True),
    }

    if openai_body.get("instructions"):
        payload["instructions"] = openai_body["instructions"]

    max_output_tokens = openai_body.get("max_output_tokens")
    if max_output_tokens is not None:
        payload["max_output_tokens"] = max_output_tokens

    tools = openai_body.get("tools")
    if isinstance(tools, list):
        payload["tools"] = tools

    response_model = openai_body.get("model") or DEFAULT_PUBLIC_MODEL
    return payload, response_model


def upstream_headers(session_data: dict[str, Any]) -> dict[str, str]:
    account_id = session_data.get("account_id")
    if not account_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sessao sem chatgpt-account-id. Faça login novamente.",
        )

    return {
        "Authorization": f"Bearer {session_data['access_token']}",
        "chatgpt-account-id": account_id,
        "originator": "pi",
        "User-Agent": "pi (Windows 10.0; Win64; x64)",
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        "OpenAI-Beta": "responses=experimental",
    }


def build_model_discovery_headers(session_data: dict[str, Any]) -> dict[str, str]:
    headers = upstream_headers(session_data).copy()
    headers["Accept"] = "application/json"
    headers.pop("Content-Type", None)
    return headers


def post_upstream(payload: dict[str, Any]):
    last_response = None

    for attempt in range(2):
        session_data = ensure_session(force_refresh=attempt > 0)

        try:
            response = requests.post(
                UPSTREAM_URL,
                json=payload,
                headers=upstream_headers(session_data),
                impersonate=UPSTREAM_IMPERSONATE,
                stream=True,
                timeout=UPSTREAM_TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Falha ao conectar no upstream Codex: {exc}",
            ) from exc

        if response.status_code == 200:
            return response

        last_response = response
        if response.status_code in {401, 403} and attempt == 0:
            continue
        break

    detail = "sem resposta"
    if last_response is not None:
        try:
            detail = last_response.content.decode("utf-8", errors="replace")[:800]
        except Exception:  # noqa: BLE001
            detail = str(last_response)[:800]

    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Upstream Codex respondeu com erro: {detail}",
    )


def iter_sse_events(upstream_response):
    for line_bytes in upstream_response.iter_lines():
        if not line_bytes:
            continue

        line = line_bytes.decode("utf-8", errors="replace")
        if not line.startswith("data: "):
            continue

        data_str = line[6:].strip()
        if not data_str:
            continue
        if data_str == "[DONE]":
            yield "[DONE]"
            break

        try:
            yield json.loads(data_str)
        except json.JSONDecodeError:
            continue


def close_upstream_response(upstream_response) -> None:
    try:
        upstream_response.close()
    except Exception:  # noqa: BLE001
        pass


def map_chat_usage(upstream_usage: dict[str, Any] | None) -> dict[str, int]:
    if not isinstance(upstream_usage, dict):
        return {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }

    prompt_tokens = upstream_usage.get("input_tokens")
    if prompt_tokens is None:
        prompt_tokens = upstream_usage.get("prompt_tokens", 0)

    completion_tokens = upstream_usage.get("output_tokens")
    if completion_tokens is None:
        completion_tokens = upstream_usage.get("completion_tokens", 0)

    total_tokens = upstream_usage.get("total_tokens")
    if total_tokens is None:
        total_tokens = prompt_tokens + completion_tokens

    return {
        "prompt_tokens": int(prompt_tokens),
        "completion_tokens": int(completion_tokens),
        "total_tokens": int(total_tokens),
    }


def collect_text_response(upstream_response) -> tuple[str, dict[str, Any] | None]:
    full_text: list[str] = []
    upstream_usage: dict[str, Any] | None = None

    try:
        for event in iter_sse_events(upstream_response):
            if event == "[DONE]":
                break
            if not isinstance(event, dict):
                continue

            event_type = event.get("type")
            if event_type == "error":
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=json.dumps(event, ensure_ascii=True)[:800],
                )

            if event_type == "response.output_text.delta":
                delta = event.get("delta")
                if isinstance(delta, str):
                    full_text.append(delta)

            if event_type == "response.completed":
                response_obj = event.get("response")
                if isinstance(response_obj, dict):
                    usage = response_obj.get("usage")
                    if isinstance(usage, dict):
                        upstream_usage = usage
    finally:
        close_upstream_response(upstream_response)

    return "".join(full_text), upstream_usage


def sse_line(payload: Any) -> str:
    if payload == "[DONE]":
        return "data: [DONE]\n\n"
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def build_chat_completion_response(
    model: str, content: str, upstream_usage: dict[str, Any] | None
) -> dict[str, Any]:
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": now_ts(),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": map_chat_usage(upstream_usage),
    }


def build_responses_output_text(content: str, response_id: str, message_id: str) -> dict[str, Any]:
    return {
        "id": response_id,
        "object": "response",
        "created_at": now_ts(),
        "status": "completed",
        "error": None,
        "incomplete_details": None,
        "output": [
            {
                "id": message_id,
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": content,
                        "annotations": [],
                    }
                ],
            }
        ],
    }


def build_responses_response(
    model: str,
    content: str,
    upstream_usage: dict[str, Any] | None,
    instructions: str | None,
    tools: list[Any] | None,
    response_id: str | None = None,
    message_id: str | None = None,
) -> dict[str, Any]:
    response_id = response_id or f"resp_{uuid.uuid4().hex[:24]}"
    message_id = message_id or f"msg_{uuid.uuid4().hex[:24]}"
    data = build_responses_output_text(content, response_id, message_id)
    data["model"] = model
    data["instructions"] = instructions
    data["parallel_tool_calls"] = True
    data["tools"] = tools or []
    data["tool_choice"] = "auto"
    data["usage"] = {
        "input_tokens": map_chat_usage(upstream_usage)["prompt_tokens"],
        "output_tokens": map_chat_usage(upstream_usage)["completion_tokens"],
        "total_tokens": map_chat_usage(upstream_usage)["total_tokens"],
    }
    return data


def chat_stream_generator(upstream_response, response_model: str):
    stream_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    created = now_ts()

    yield sse_line(
        {
            "id": stream_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": response_model,
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant", "content": ""},
                    "finish_reason": None,
                }
            ],
        }
    )

    try:
        for event in iter_sse_events(upstream_response):
            if event == "[DONE]":
                break
            if not isinstance(event, dict):
                continue

            event_type = event.get("type")
            if event_type == "error":
                yield sse_line({"error": event})
                yield sse_line("[DONE]")
                return

            if event_type != "response.output_text.delta":
                continue

            delta = event.get("delta")
            if not isinstance(delta, str) or not delta:
                continue

            yield sse_line(
                {
                    "id": stream_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": response_model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": delta},
                            "finish_reason": None,
                        }
                    ],
                }
            )

        yield sse_line(
            {
                "id": stream_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": response_model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": "stop",
                    }
                ],
            }
        )
        yield sse_line("[DONE]")
    finally:
        close_upstream_response(upstream_response)


def responses_stream_generator(
    upstream_response,
    response_model: str,
    instructions: str | None,
    tools: list[Any] | None,
):
    response_id = f"resp_{uuid.uuid4().hex[:24]}"
    message_id = f"msg_{uuid.uuid4().hex[:24]}"
    full_text: list[str] = []
    upstream_usage: dict[str, Any] | None = None

    yield sse_line(
        {
            "type": "response.created",
            "response": {
                "id": response_id,
                "object": "response",
                "created_at": now_ts(),
                "status": "in_progress",
                "model": response_model,
                "output": [],
            },
        }
    )

    try:
        for event in iter_sse_events(upstream_response):
            if event == "[DONE]":
                break
            if not isinstance(event, dict):
                continue

            event_type = event.get("type")
            if event_type == "error":
                yield sse_line(event)
                yield sse_line("[DONE]")
                return

            if event_type == "response.completed":
                response_obj = event.get("response")
                if isinstance(response_obj, dict):
                    usage = response_obj.get("usage")
                    if isinstance(usage, dict):
                        upstream_usage = usage
                continue

            if event_type != "response.output_text.delta":
                continue

            delta = event.get("delta")
            if not isinstance(delta, str) or not delta:
                continue

            full_text.append(delta)
            yield sse_line(
                {
                    "type": "response.output_text.delta",
                    "response_id": response_id,
                    "item_id": message_id,
                    "output_index": 0,
                    "content_index": 0,
                    "delta": delta,
                }
            )

        text = "".join(full_text)
        yield sse_line(
            {
                "type": "response.output_text.done",
                "response_id": response_id,
                "item_id": message_id,
                "output_index": 0,
                "content_index": 0,
                "text": text,
            }
        )
        yield sse_line(
            {
                "type": "response.completed",
                "response": build_responses_response(
                    model=response_model,
                    content=text,
                    upstream_usage=upstream_usage,
                    instructions=instructions,
                    tools=tools,
                    response_id=response_id,
                    message_id=message_id,
                ),
            }
        )
        yield sse_line("[DONE]")
    finally:
        close_upstream_response(upstream_response)


def render_panel_login_page(
    next_path: str,
    error_message: str | None = None,
    retry_after: int = 0,
) -> str:
    error_block = ""
    if error_message:
        error_block = f"""
        <div class=\"rounded-2xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100\">
          {escape_html(error_message)}
        </div>
        """

    retry_block = ""
    if retry_after > 0:
        retry_block = f"""
        <p class=\"text-xs text-amber-200/80\">Muitas tentativas falhas. Aguarde cerca de {retry_after}s antes de tentar novamente.</p>
        """

    token_hint = (
        "A chave de acesso deste painel foi gerada automaticamente neste inicio. Use o valor exibido no log do servidor."
        if PANEL_TOKEN_WAS_GENERATED
        else "Use a chave administrativa configurada para este servidor."
    )

    return f"""
<!doctype html>
<html lang=\"pt-BR\">
  <head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>Painel Bloqueado</title>
    <script src=\"https://cdn.tailwindcss.com\"></script>
  </head>
  <body class=\"min-h-screen overflow-x-hidden bg-zinc-950 text-zinc-100\">
    <div class=\"pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.12),_transparent_26%),radial-gradient(circle_at_bottom_right,_rgba(168,85,247,0.12),_transparent_22%),linear-gradient(to_bottom,_rgba(9,9,11,0.92),_rgba(9,9,11,1))]\"></div>
    <main class=\"relative z-10 mx-auto flex min-h-screen max-w-5xl items-center px-5 py-8 sm:px-6\">
      <div class=\"grid w-full gap-5 lg:grid-cols-[1.15fr_0.85fr]\">
        <section class=\"rounded-[24px] border border-white/10 bg-white/[0.04] p-6 shadow-xl shadow-cyan-950/10 backdrop-blur sm:p-7\">
          <div class=\"mb-8 inline-flex items-center rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.24em] text-cyan-200\">
            Area Administrativa
          </div>
          <h1 class=\"max-w-xl text-3xl font-semibold leading-tight text-white sm:text-[2rem]\">Acesso restrito para gerenciar sua conta e sua URL de integracao.</h1>
          <p class=\"mt-4 max-w-2xl text-sm leading-7 text-zinc-300 sm:text-[15px]\">
            Aqui voce acompanha o estado da conexao, entra na conta quando precisar e encontra a URL para usar o servico nos seus clientes. O acesso fica protegido por uma chave administrativa e por bloqueio de tentativas excessivas.
          </p>
          <div class=\"mt-7 grid gap-3 sm:grid-cols-3\">
            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
              <p class=\"text-[11px] uppercase tracking-[0.22em] text-zinc-500\">Painel</p>
              <p class=\"mt-2 text-base font-medium text-white\">Acesso protegido</p>
              <p class=\"mt-2 text-sm text-zinc-400\">A entrada no painel usa uma chave exclusiva e mantem a sessao separada do uso normal do servico.</p>
            </div>
            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
              <p class=\"text-[11px] uppercase tracking-[0.22em] text-zinc-500\">Defesa</p>
              <p class=\"mt-2 text-base font-medium text-white\">Protecao de acesso</p>
              <p class=\"mt-2 text-sm text-zinc-400\">Apos {PANEL_RATE_LIMIT_MAX_ATTEMPTS} tentativas em {PANEL_RATE_LIMIT_WINDOW_SECONDS}s, novas entradas ficam temporariamente bloqueadas.</p>
            </div>
            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
              <p class=\"text-[11px] uppercase tracking-[0.22em] text-zinc-500\">URL de uso</p>
              <p class=\"mt-2 text-base font-medium text-white\">{escape_html(PUBLIC_BASE_URL)}/v1</p>
              <p class=\"mt-2 text-sm text-zinc-400\">Use este endereco como base para conectar apps, ferramentas e clientes compativeis.</p>
            </div>
          </div>
        </section>

        <section class=\"rounded-[24px] border border-white/10 bg-zinc-900/70 p-6 shadow-xl shadow-black/30 backdrop-blur sm:p-7\">
          <div class=\"mb-6\">
            <p class=\"text-[11px] font-medium uppercase tracking-[0.28em] text-zinc-500\">Acesso administrativo</p>
            <h2 class=\"mt-2 text-xl font-semibold text-white\">Destravar painel</h2>
            <p class=\"mt-3 text-sm leading-6 text-zinc-400\">{escape_html(token_hint)}</p>
          </div>
          <form method=\"post\" action=\"/panel/login?next={quote(next_path)}\" class=\"space-y-4\">
            {error_block}
            <label class=\"block\">
              <span class=\"mb-2 block text-sm font-medium text-zinc-300\">Chave de acesso</span>
              <input
                type=\"password\"
                name=\"access_token\"
                autocomplete=\"current-password\"
                spellcheck=\"false\"
                required
                class=\"w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/20\"
                placeholder=\"Digite a chave do painel\"
              >
            </label>
            <button
              type=\"submit\"
              class=\"inline-flex w-full items-center justify-center rounded-xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-cyan-300\"
            >
              Entrar no painel
            </button>
            {retry_block}
          </form>
          <div class=\"mt-6 rounded-2xl border border-white/10 bg-black/20 p-4 text-sm text-zinc-400\">
            <p class=\"font-medium text-zinc-200\">Resumo de acesso</p>
            <p class=\"mt-2\">Nome da sessao: <code class=\"rounded bg-white/5 px-2 py-1 text-zinc-200\">{escape_html(PANEL_SESSION_COOKIE_NAME)}</code></p>
            <p class=\"mt-2\">Duracao da sessao: <code class=\"rounded bg-white/5 px-2 py-1 text-zinc-200\">{PANEL_SESSION_TTL_SECONDS}s</code></p>
            <p class=\"mt-2\">Modo seguro: <code class=\"rounded bg-white/5 px-2 py-1 text-zinc-200\">{'ativo' if PANEL_SECURE_COOKIE else 'desativado'}</code></p>
          </div>
        </section>
      </div>
    </main>
  </body>
</html>
"""


def render_dashboard_page(
    request: Request,
    panel_session_data: dict[str, Any],
    session_data: dict[str, Any] | None,
) -> str:
    logged_in = bool(session_data and session_data.get("access_token"))
    expires_at = session_data.get("expires_at") if session_data else None
    expires_text = (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expires_at))
        if isinstance(expires_at, int)
        else "desconhecido"
    )
    panel_expires_at = panel_session_data.get("expires_at")
    panel_expires_text = (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(panel_expires_at))
        if isinstance(panel_expires_at, int)
        else "desconhecido"
    )
    auth_mode = (
        "Clientes precisam enviar a chave definida para este servidor."
        if PROXY_API_KEY
        else "Nenhuma chave fixa foi definida para os clientes no momento."
    )
    dashboard_models = build_models_dashboard_state()
    models_updated_at = dashboard_models.get("last_refresh_at")
    models_updated_text = (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(models_updated_at))
        if isinstance(models_updated_at, int)
        else "ainda nao atualizado"
    )
    current_public_model = (
        dashboard_models["models"][0]
        if dashboard_models.get("models")
        else DEFAULT_PUBLIC_MODEL
    )
    models_notice = request.query_params.get("models_notice")
    models_notice_kind = request.query_params.get("models_notice_kind", "success")
    if models_notice_kind == "error":
        notice_classes = "border-rose-500/30 bg-rose-500/10 text-rose-100"
    else:
        notice_classes = "border-emerald-400/20 bg-emerald-400/10 text-emerald-100"
    models_notice_block = ""
    if models_notice:
        models_notice_block = f"""
        <div class=\"mx-5 mt-5 rounded-2xl border px-4 py-3 text-sm {notice_classes} sm:mx-6\">{escape_html(models_notice)}</div>
        """
    models_error_block = ""
    if dashboard_models.get("last_error"):
        models_error_block = f"""
        <p class=\"mt-3 rounded-xl border border-amber-400/20 bg-amber-400/10 px-3 py-2 text-xs leading-5 text-amber-100\">{escape_html(str(dashboard_models['last_error']))}</p>
        """
    login_state = "Conectado" if logged_in else "Nao conectado"
    login_tone_class = "text-emerald-300" if logged_in else "text-amber-300"
    proxy_example = f"{PUBLIC_BASE_URL}/v1"
    sdk_example = f'''from openai import OpenAI

client = OpenAI(
    base_url="{PUBLIC_BASE_URL}/v1",
    api_key="{PROXY_API_KEY or 'sua-chave-do-proxy'}",
)

resp = client.chat.completions.create(
    model="{current_public_model}",
    messages=[{{"role": "user", "content": "Diga oi"}}],
)

print(resp.choices[0].message.content)
'''

    return f"""
<!doctype html>
<html lang=\"pt-BR\">
  <head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>Codex Proxy Admin</title>
    <script src=\"https://cdn.tailwindcss.com\"></script>
  </head>
  <body class=\"min-h-screen overflow-x-hidden bg-zinc-950 text-zinc-100\">
    <div class=\"pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.12),_transparent_28%),radial-gradient(circle_at_bottom_right,_rgba(168,85,247,0.12),_transparent_24%),linear-gradient(to_bottom,_rgba(9,9,11,0.96),_rgba(9,9,11,1))]\"></div>
    <main class=\"relative z-10 mx-auto max-w-6xl px-5 py-6 sm:px-6 lg:px-8\">
      <section class=\"overflow-hidden rounded-[26px] border border-white/10 bg-white/[0.04] shadow-xl shadow-cyan-950/10 backdrop-blur\">
        <div class=\"border-b border-white/10 px-5 py-5 sm:px-6 lg:flex lg:items-start lg:justify-between\">
          <div>
            <div class=\"inline-flex items-center rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.24em] text-cyan-200\">Painel Principal</div>
            <h1 class=\"mt-3 text-2xl font-semibold text-white sm:text-[2rem]\">Centro de controle do Codex Proxy</h1>
            <p class=\"mt-3 max-w-3xl text-sm leading-6 text-zinc-300\">Veja o estado da sua conta, acompanhe a validade da sessao e copie a URL de integracao para usar seus clientes com rapidez.</p>
          </div>
          <div class=\"mt-5 flex flex-wrap gap-2.5 lg:mt-0\">
            <a href=\"/auth/login\" class=\"inline-flex items-center rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-cyan-300\">Conectar conta Codex</a>
            <a href=\"/auth/manual\" class=\"inline-flex items-center rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-white/10\">Colar URL de retorno</a>
            <form method=\"post\" action=\"/admin/refresh-models\">
              <button type=\"submit\" class=\"inline-flex items-center rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-white/10\">Atualizar modelos</button>
            </form>
            <a href=\"/auth/logout\" class=\"inline-flex items-center rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-white/10\">Remover conexao atual</a>
            <a href=\"/panel/logout\" class=\"inline-flex items-center rounded-xl border border-rose-400/20 bg-rose-400/10 px-4 py-2.5 text-sm font-semibold text-rose-100 transition hover:bg-rose-400/20\">Sair do painel</a>
          </div>
        </div>
        {models_notice_block}

        <div class=\"grid gap-3 border-b border-white/10 px-5 py-5 sm:grid-cols-2 xl:grid-cols-4 sm:px-6\">
          <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
            <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">Conta Codex</p>
            <p class=\"mt-3 text-xl font-semibold text-white\">{escape_html(login_state)}</p>
            <p class=\"mt-2 text-sm {login_tone_class}\">{escape_html(session_data.get('email', 'Sem conta autenticada') if session_data else 'Sem conta autenticada')}</p>
          </div>
          <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
            <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">Plano</p>
            <p class=\"mt-3 text-xl font-semibold text-white\">{escape_html(session_data.get('plan_type', 'desconhecido') if session_data else 'desconhecido')}</p>
            <p class=\"mt-2 text-sm text-zinc-400\">Expira em {escape_html(expires_text)}</p>
          </div>
          <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
            <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">Painel</p>
            <p class=\"mt-3 text-xl font-semibold text-white\">Acesso liberado</p>
            <p class=\"mt-2 text-sm text-zinc-400\">Valido ate {escape_html(panel_expires_text)}</p>
          </div>
          <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
            <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">Origem</p>
            <p class=\"mt-3 text-xl font-semibold text-white\">{escape_html(client_ip(request))}</p>
            <p class=\"mt-2 text-sm text-zinc-400\">Origem usada neste acesso</p>
          </div>
        </div>

        <div class=\"grid gap-3 px-5 py-5 lg:grid-cols-[1.15fr_0.85fr] sm:px-6\">
          <section class=\"space-y-3\">
            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-5\">
              <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">Endereco principal</p>
              <div class=\"mt-3 flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between\">
                <code class=\"overflow-x-auto rounded-xl bg-zinc-950 px-4 py-3 text-sm text-cyan-200\">{escape_html(proxy_example)}</code>
                <span class=\"inline-flex items-center rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-medium text-white\">{dashboard_models['count']} modelos</span>
              </div>
              <div class=\"mt-4 grid gap-3 sm:grid-cols-2\">
                <div class=\"rounded-2xl border border-white/10 bg-white/5 p-4\">
                  <p class=\"text-[11px] uppercase tracking-[0.2em] text-zinc-500\">Recursos</p>
                  <p class=\"mt-2 text-sm leading-6 text-zinc-300\">Disponibiliza conversa, respostas e listagem de modelos com renovacao automatica da conexao.</p>
                </div>
                <div class=\"rounded-2xl border border-white/10 bg-white/5 p-4\">
                  <p class=\"text-[11px] uppercase tracking-[0.2em] text-zinc-500\">Acesso dos clientes</p>
                  <p class=\"mt-2 text-sm leading-6 text-zinc-300\">{escape_html(auth_mode)}</p>
                </div>
              </div>
            </div>

            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-5\">
              <div class=\"flex items-center justify-between gap-4\">
                <div>
                  <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">Catalogo de modelos</p>
                  <h2 class=\"mt-2 text-lg font-semibold text-white\">Descoberta dinamica</h2>
                </div>
                <span class=\"rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-medium uppercase tracking-[0.22em] text-cyan-200\">{dashboard_models['dynamic_count']} dinamicos</span>
              </div>
              <div class=\"mt-4 grid gap-3 sm:grid-cols-2\">
                <div class=\"rounded-2xl border border-white/10 bg-white/5 p-4\">
                  <p class=\"text-[11px] uppercase tracking-[0.2em] text-zinc-500\">Origem atual</p>
                  <p class=\"mt-2 text-sm leading-6 text-zinc-300\">{escape_html(dashboard_models.get('last_source') or 'fallback local')}</p>
                </div>
                <div class=\"rounded-2xl border border-white/10 bg-white/5 p-4\">
                  <p class=\"text-[11px] uppercase tracking-[0.2em] text-zinc-500\">Ultima atualizacao</p>
                  <p class=\"mt-2 text-sm leading-6 text-zinc-300\">{escape_html(models_updated_text)}</p>
                </div>
              </div>
              {models_error_block}
              <div class=\"mt-4 flex flex-wrap gap-2\">
                {''.join(f'<code class="rounded bg-white/5 px-2 py-1 text-xs text-zinc-200">{escape_html(model_id)}</code>' for model_id in dashboard_models['models'][:10])}
              </div>
              <p class=\"mt-3 text-xs leading-5 text-zinc-500\">A lista da API em <code>/v1/models</code> usa descoberta dinamica quando disponivel e cai para o fallback local quando necessario.</p>
            </div>

            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-5\">
              <div class=\"flex items-center justify-between gap-4\">
                <div>
                  <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">Uso rapido</p>
                  <h2 class=\"mt-2 text-lg font-semibold text-white\">Exemplo de uso</h2>
                </div>
                <span class=\"rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-medium uppercase tracking-[0.22em] text-emerald-200\">Pronto para copiar</span>
              </div>
              <pre class=\"mt-4 overflow-x-auto rounded-xl border border-white/10 bg-zinc-950 p-4 text-sm leading-6 text-zinc-200\">{escape_html(sdk_example)}</pre>
            </div>
          </section>

          <aside class=\"space-y-3\">
            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-5\">
              <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">Conexao atual</p>
              <dl class=\"mt-4 space-y-4 text-sm\">
                <div>
                  <dt class=\"text-zinc-500\">URL de retorno</dt>
                  <dd class=\"mt-1 break-all rounded-xl bg-white/5 px-3 py-2 text-zinc-200\">{escape_html(REDIRECT_URI)}</dd>
                </div>
                <div>
                  <dt class=\"text-zinc-500\">Identificador da conta</dt>
                  <dd class=\"mt-1 break-all rounded-xl bg-white/5 px-3 py-2 text-zinc-200\">{escape_html(session_data.get('account_id', 'desconhecido') if session_data else 'desconhecido')}</dd>
                </div>
                <div>
                  <dt class=\"text-zinc-500\">Arquivo local</dt>
                  <dd class=\"mt-1 break-all rounded-xl bg-white/5 px-3 py-2 text-zinc-200\">{escape_html(SESSION_FILE)}</dd>
                </div>
              </dl>
            </div>

            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-5\">
              <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">Acesso ao painel</p>
              <dl class=\"mt-4 space-y-4 text-sm\">
                <div>
                  <dt class=\"text-zinc-500\">Chave administrativa</dt>
                  <dd class=\"mt-1 rounded-xl bg-white/5 px-3 py-2 text-zinc-200\">{escape_html('gerada ao iniciar' if PANEL_TOKEN_WAS_GENERATED else 'definida manualmente')}</dd>
                </div>
                <div>
                  <dt class=\"text-zinc-500\">Sessao do painel</dt>
                  <dd class=\"mt-1 rounded-xl bg-white/5 px-3 py-2 text-zinc-200\">{escape_html(PANEL_SESSION_COOKIE_NAME)} | modo seguro: {escape_html('ativo' if PANEL_SECURE_COOKIE else 'desativado')}</dd>
                </div>
                <div>
                  <dt class=\"text-zinc-500\">Protecao contra tentativas</dt>
                  <dd class=\"mt-1 rounded-xl bg-white/5 px-3 py-2 text-zinc-200\">{PANEL_RATE_LIMIT_MAX_ATTEMPTS} tentativas / {PANEL_RATE_LIMIT_WINDOW_SECONDS}s por origem</dd>
                </div>
              </dl>
            </div>
          </aside>
        </div>
      </section>
    </main>
  </body>
</html>
"""


def render_auth_connect_page(auth_url: str) -> str:
    auth_url_json = json.dumps(auth_url)

    return f"""
<!doctype html>
<html lang=\"pt-BR\">
  <head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>Entrar com Codex</title>
    <script src=\"https://cdn.tailwindcss.com\"></script>
    <script src=\"https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js\"></script>
  </head>
  <body class=\"min-h-screen overflow-x-hidden bg-zinc-950 text-zinc-100\">
    <div class=\"pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.12),_transparent_24%),radial-gradient(circle_at_bottom_right,_rgba(168,85,247,0.12),_transparent_22%),linear-gradient(to_bottom,_rgba(9,9,11,0.96),_rgba(9,9,11,1))]\"></div>
    <main class=\"relative z-10 mx-auto flex min-h-screen max-w-5xl items-center px-5 py-8 sm:px-6\">
      <div class=\"grid w-full gap-4 lg:grid-cols-[1.05fr_0.95fr]\">
        <section class=\"rounded-[24px] border border-white/10 bg-white/[0.04] p-6 shadow-xl shadow-cyan-950/10 backdrop-blur sm:p-7\">
          <div class=\"inline-flex items-center rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.24em] text-cyan-200\">Entrar com Codex</div>
          <h1 class=\"mt-4 max-w-xl text-3xl font-semibold leading-tight text-white sm:text-[2rem]\">Escolha como abrir o login.</h1>
          <p class=\"mt-4 max-w-2xl text-sm leading-7 text-zinc-300\">Voce pode continuar neste navegador ou escanear o QR code com o celular. Assim o login pode ser concluido mesmo quando a conta estiver ativa em outro dispositivo.</p>

          <div class=\"mt-7 grid gap-3 sm:grid-cols-3\">
            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
              <p class=\"text-[11px] uppercase tracking-[0.22em] text-zinc-500\">Passo 1</p>
              <p class=\"mt-2 text-base font-medium text-white\">Abra o login</p>
              <p class=\"mt-2 text-sm text-zinc-400\">Use o botao abaixo no computador ou o QR code no celular.</p>
            </div>
            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
              <p class=\"text-[11px] uppercase tracking-[0.22em] text-zinc-500\">Passo 2</p>
              <p class=\"mt-2 text-base font-medium text-white\">Conclua o acesso</p>
              <p class=\"mt-2 text-sm text-zinc-400\">Ao terminar, a conexao sera salva automaticamente neste servidor.</p>
            </div>
            <div class=\"rounded-2xl border border-white/10 bg-black/20 p-4\">
              <p class=\"text-[11px] uppercase tracking-[0.22em] text-zinc-500\">Passo 3</p>
              <p class=\"mt-2 text-base font-medium text-white\">Volte ao painel</p>
              <p class=\"mt-2 text-sm text-zinc-400\">Esta tela acompanha o status e retorna ao painel assim que tudo estiver pronto.</p>
            </div>
          </div>

          <div class=\"mt-7 flex flex-wrap gap-2.5\">
            <a href=\"{escape_html(auth_url)}\" class=\"inline-flex items-center rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-cyan-300\">Continuar neste navegador</a>
            <button id=\"copy-auth-link\" type=\"button\" class=\"inline-flex items-center rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-white/10\">Copiar link</button>
            <a href=\"/auth/manual\" class=\"inline-flex items-center rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-white/10\">Usar URL de retorno</a>
            <a href=\"/\" class=\"inline-flex items-center rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-white/10\">Voltar ao painel</a>
          </div>

          <div id=\"auth-ready-banner\" class=\"mt-5 hidden rounded-2xl border border-emerald-400/20 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-100\">
            Login concluido. Voltando para o painel.
          </div>

          <div class=\"mt-5 rounded-2xl border border-white/10 bg-black/20 p-4 text-sm text-zinc-400\">
            <p class=\"font-medium text-zinc-200\">Link de entrada</p>
            <code class=\"mt-3 block break-all rounded-xl bg-zinc-950 px-3 py-3 text-xs text-cyan-200\">{escape_html(auth_url)}</code>
          </div>
        </section>

        <section class=\"rounded-[24px] border border-white/10 bg-zinc-900/70 p-6 shadow-xl shadow-black/30 backdrop-blur sm:p-7\">
          <div class=\"flex items-center justify-between gap-4\">
            <div>
              <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">QR code</p>
              <h2 class=\"mt-2 text-xl font-semibold text-white\">Abrir no celular</h2>
            </div>
            <span class=\"rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.22em] text-zinc-300\">Opcional</span>
          </div>

          <div class=\"mt-5 flex justify-center rounded-[24px] border border-white/10 bg-black/20 p-5\">
            <div class=\"rounded-[20px] bg-zinc-950 p-4 shadow-inner shadow-black/30\">
              <div id=\"codex-login-qr\" class=\"flex min-h-[188px] min-w-[188px] items-center justify-center\"></div>
            </div>
          </div>

          <p class=\"mt-4 text-sm leading-6 text-zinc-400\">Se a sua conta estiver ativa no celular, basta escanear e concluir por la. Esta pagina detecta quando o acesso for salvo.</p>
        </section>
      </div>
    </main>

    <script>
      const authUrl = {auth_url_json};
      new QRCode(document.getElementById("codex-login-qr"), {{
        text: authUrl,
        width: 188,
        height: 188,
        colorDark: "#e4e4e7",
        colorLight: "#09090b",
        correctLevel: QRCode.CorrectLevel.M,
      }});

      const copyButton = document.getElementById("copy-auth-link");
      copyButton?.addEventListener("click", async () => {{
        try {{
          await navigator.clipboard.writeText(authUrl);
          copyButton.textContent = "Link copiado";
          setTimeout(() => {{ copyButton.textContent = "Copiar link"; }}, 1600);
        }} catch (_error) {{
          copyButton.textContent = "Nao foi possivel copiar";
          setTimeout(() => {{ copyButton.textContent = "Copiar link"; }}, 1800);
        }}
      }});

      const readyBanner = document.getElementById("auth-ready-banner");
      const pollStatus = async () => {{
        try {{
          const response = await fetch("/auth/status", {{ credentials: "same-origin" }});
          if (!response.ok) return;
          const data = await response.json();
          if (data.logged_in) {{
            readyBanner?.classList.remove("hidden");
            setTimeout(() => {{ window.location.href = "/"; }}, 1200);
          }}
        }} catch (_error) {{
        }}
      }};

      setInterval(pollStatus, 3000);
      pollStatus();
    </script>
  </body>
</html>
"""


def render_manual_auth_page(
    auth_url: str,
    manual_redirect_uri: str,
    auth_context_token: str,
    error_message: str | None = None,
) -> str:
    auth_url_json = json.dumps(auth_url)
    error_block = ""
    if error_message:
        error_block = f"""
        <div class=\"rounded-2xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100\">
          {escape_html(error_message)}
        </div>
        """

    return f"""
<!doctype html>
<html lang=\"pt-BR\">
  <head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>Login manual</title>
    <script src=\"https://cdn.tailwindcss.com\"></script>
    <script src=\"https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js\"></script>
  </head>
  <body class=\"min-h-screen overflow-x-hidden bg-zinc-950 text-zinc-100\">
    <div class=\"pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.12),_transparent_24%),radial-gradient(circle_at_bottom_right,_rgba(168,85,247,0.12),_transparent_22%),linear-gradient(to_bottom,_rgba(9,9,11,0.96),_rgba(9,9,11,1))]\"></div>
    <main class=\"relative z-10 mx-auto max-w-6xl px-5 py-8 sm:px-6\">
      <div class=\"grid gap-4 lg:grid-cols-[1.05fr_0.95fr]\">
        <section class=\"rounded-[24px] border border-white/10 bg-white/[0.04] p-6 shadow-xl shadow-cyan-950/10 backdrop-blur sm:p-7\">
          <div class=\"inline-flex items-center rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.24em] text-cyan-200\">Login manual</div>
          <h1 class=\"mt-4 text-3xl font-semibold text-white sm:text-[2rem]\">Cole a URL final se o retorno nao vier para este servidor.</h1>
          <p class=\"mt-4 text-sm leading-7 text-zinc-300\">Este modo serve para ambientes publicados onde o login pode exigir outro endereco de retorno. Voce conclui o acesso, copia a URL final exibida pelo navegador e cola aqui para salvar a conexao.</p>

          <div class=\"mt-6 rounded-2xl border border-white/10 bg-black/20 p-4 text-sm text-zinc-300\">
            <p class=\"font-medium text-zinc-100\">URL de retorno usada neste modo</p>
            <code class=\"mt-3 block break-all rounded-xl bg-zinc-950 px-3 py-3 text-xs text-cyan-200\">{escape_html(manual_redirect_uri)}</code>
          </div>

          <div class=\"mt-6 flex flex-wrap gap-2.5\">
            <a href=\"{escape_html(auth_url)}\" class=\"inline-flex items-center rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-cyan-300\">Abrir login</a>
            <button id=\"copy-manual-auth-link\" type=\"button\" class=\"inline-flex items-center rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-white/10\">Copiar link</button>
            <a href=\"/auth/login\" class=\"inline-flex items-center rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-white/10\">Voltar ao modo direto</a>
          </div>

          <form method=\"post\" action=\"/auth/manual\" class=\"mt-6 space-y-4\">
            <input type=\"hidden\" name=\"auth_context\" value=\"{escape_html(auth_context_token)}\">
            {error_block}
            <label class=\"block\">
              <span class=\"mb-2 block text-sm font-medium text-zinc-300\">Cole a URL final de retorno</span>
              <textarea
                name=\"returned_url\"
                rows=\"5\"
                spellcheck=\"false\"
                required
                placeholder=\"Cole aqui a URL completa que comeca com {escape_html(manual_redirect_uri)}\"
                class=\"w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/20\"
              ></textarea>
            </label>
            <button type=\"submit\" class=\"inline-flex items-center rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-cyan-300\">Extrair e salvar conexao</button>
          </form>
        </section>

        <section class=\"rounded-[24px] border border-white/10 bg-zinc-900/70 p-6 shadow-xl shadow-black/30 backdrop-blur sm:p-7\">
          <div class=\"flex items-center justify-between gap-4\">
            <div>
              <p class=\"text-[11px] uppercase tracking-[0.24em] text-zinc-500\">QR code</p>
              <h2 class=\"mt-2 text-xl font-semibold text-white\">Abrir em outro dispositivo</h2>
            </div>
            <span class=\"rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.22em] text-zinc-300\">Alternativo</span>
          </div>

          <div class=\"mt-5 flex justify-center rounded-[24px] border border-white/10 bg-black/20 p-5\">
            <div class=\"rounded-[20px] bg-zinc-950 p-4 shadow-inner shadow-black/30\">
              <div id=\"manual-codex-login-qr\" class=\"flex min-h-[188px] min-w-[188px] items-center justify-center\"></div>
            </div>
          </div>

          <div class=\"mt-5 space-y-3 rounded-2xl border border-white/10 bg-black/20 p-4 text-sm text-zinc-400\">
            <p>1. Abra o login pelo botao ou QR code.</p>
            <p>2. Conclua a autenticacao.</p>
            <p>3. Copie a URL final que o navegador tentou abrir.</p>
            <p>4. Cole essa URL no campo ao lado para salvar a sessao.</p>
          </div>
        </section>
      </div>
    </main>

    <script>
      const authUrl = {auth_url_json};
      new QRCode(document.getElementById("manual-codex-login-qr"), {{
        text: authUrl,
        width: 188,
        height: 188,
        colorDark: "#e4e4e7",
        colorLight: "#09090b",
        correctLevel: QRCode.CorrectLevel.M,
      }});

      const copyButton = document.getElementById("copy-manual-auth-link");
      copyButton?.addEventListener("click", async () => {{
        try {{
          await navigator.clipboard.writeText(authUrl);
          copyButton.textContent = "Link copiado";
          setTimeout(() => {{ copyButton.textContent = "Copiar link"; }}, 1600);
        }} catch (_error) {{
          copyButton.textContent = "Nao foi possivel copiar";
          setTimeout(() => {{ copyButton.textContent = "Copiar link"; }}, 1800);
        }}
      }});
    </script>
  </body>
</html>
"""


@app.get("/panel/login", response_class=HTMLResponse)
async def panel_login_page(request: Request, next: str | None = None):
    session_id, _panel_session = get_valid_panel_session(request)
    if session_id:
        return RedirectResponse(
            url=sanitize_next_path(next),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    retry_after = get_rate_limit_retry_after(client_ip(request))
    error_message = request.query_params.get("error")
    return HTMLResponse(
        render_panel_login_page(
            next_path=sanitize_next_path(next),
            error_message=error_message,
            retry_after=retry_after,
        ),
        status_code=status.HTTP_200_OK,
    )


@app.post("/panel/login")
async def panel_login_submit(request: Request, next: str | None = None):
    next_path = sanitize_next_path(next)
    request_ip = client_ip(request)
    retry_after = get_rate_limit_retry_after(request_ip)
    if retry_after > 0:
        return HTMLResponse(
            render_panel_login_page(
                next_path=next_path,
                error_message="Acesso temporariamente bloqueado por excesso de tentativas.",
                retry_after=retry_after,
            ),
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
        )

    raw_body = (await request.body()).decode("utf-8", errors="ignore")
    form_data = parse_qs(raw_body)
    submitted_token = form_data.get("access_token", [""])[0].strip()

    if not submitted_token or not secrets.compare_digest(submitted_token, PANEL_ACCESS_TOKEN):
        record_failed_panel_login(request_ip)
        retry_after = get_rate_limit_retry_after(request_ip)
        response = HTMLResponse(
            render_panel_login_page(
                next_path=next_path,
                error_message="Token administrativo invalido.",
                retry_after=retry_after,
            ),
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
        if retry_after > 0:
            response.headers["Retry-After"] = str(retry_after)
        return response

    clear_failed_panel_logins(request_ip)
    panel_session_id = create_panel_session(request_ip)
    response = RedirectResponse(url=next_path, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        PANEL_SESSION_COOKIE_NAME,
        panel_session_id,
        httponly=True,
        samesite="lax",
        secure=PANEL_SECURE_COOKIE,
        max_age=PANEL_SESSION_TTL_SECONDS,
        path="/",
    )
    return response


@app.get("/panel/logout")
async def panel_logout(request: Request):
    session_id, _panel_session = get_valid_panel_session(request)
    delete_panel_session(session_id)
    response = RedirectResponse(url="/panel/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(PANEL_SESSION_COOKIE_NAME, path="/")
    return response


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    _panel_session_id, panel_session_data = get_valid_panel_session(request)
    if not panel_session_data:
        return panel_redirect_to_login(request)

    session_data = load_session()
    return HTMLResponse(render_dashboard_page(request, panel_session_data, session_data))


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/auth/status")
async def auth_status(request: Request) -> dict[str, Any]:
    require_panel_session_json(request)
    session_data = load_session()
    return {
        "logged_in": bool(session_data and session_data.get("access_token")),
        "account_id": session_data.get("account_id") if session_data else None,
        "email": session_data.get("email") if session_data else None,
        "plan_type": session_data.get("plan_type") if session_data else None,
        "expires_at": session_data.get("expires_at") if session_data else None,
        "session_file": str(SESSION_FILE),
        "base_url": f"{PUBLIC_BASE_URL}/v1",
    }


@app.get("/auth/login", response_class=HTMLResponse)
async def auth_login(request: Request):
    panel_session_id, _panel_session = get_valid_panel_session(request)
    if not panel_session_id:
        return panel_redirect_to_login(request)

    auth_request = create_auth_request(redirect_uri=REDIRECT_URI, mode="callback")
    auth_url = build_auth_url_from_request(auth_request)
    return HTMLResponse(render_auth_connect_page(auth_url))


@app.get("/auth/manual", response_class=HTMLResponse)
async def auth_manual_page(request: Request):
    panel_session_id, _panel_session = get_valid_panel_session(request)
    if not panel_session_id:
        return panel_redirect_to_login(request)

    auth_request = create_auth_request(redirect_uri=MANUAL_REDIRECT_URI, mode="manual")
    auth_url = build_auth_url_from_request(auth_request)
    auth_context_token = encode_auth_context(auth_request)
    return HTMLResponse(
        render_manual_auth_page(
            auth_url,
            MANUAL_REDIRECT_URI,
            auth_context_token=auth_context_token,
        )
    )


@app.post("/auth/manual", response_class=HTMLResponse)
async def auth_manual_submit(request: Request):
    require_panel_session_json(request)
    raw_body = (await request.body()).decode("utf-8", errors="ignore")
    form_data = parse_qs(raw_body)
    returned_url = form_data.get("returned_url", [""])[0].strip()
    auth_context_token = form_data.get("auth_context", [""])[0].strip()

    auth_request = decode_auth_context(auth_context_token) or current_auth_request("manual")
    if not auth_request or auth_request.get("mode") != "manual":
        auth_request = create_auth_request(redirect_uri=MANUAL_REDIRECT_URI, mode="manual")

    auth_url = build_auth_url_from_request(auth_request)
    auth_context_token = encode_auth_context(auth_request)

    try:
        auth_code, auth_state = extract_code_and_state_from_returned_url(returned_url)
        validated_auth_request = resolve_manual_auth_request(auth_state, auth_context_token)
        exchange_auth_code(auth_code, validated_auth_request)
    except HTTPException as exc:
        return HTMLResponse(
            render_manual_auth_page(
                auth_url=auth_url,
                manual_redirect_uri=MANUAL_REDIRECT_URI,
                auth_context_token=auth_context_token,
                error_message=str(exc.detail),
            ),
            status_code=exc.status_code,
        )

    return HTMLResponse(render_auth_success_page())


@app.get("/auth/callback", response_class=HTMLResponse)
async def auth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
) -> str:
    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Callback sem code/state.",
        )

    validated_auth_request = validate_auth_request(
        expected_mode="callback",
        returned_state=state,
    )
    exchange_auth_code(code, validated_auth_request)
    return render_auth_success_page()


@app.get("/auth/logout", response_class=HTMLResponse)
async def auth_logout(request: Request) -> str:
    require_panel_session_json(request)
    clear_session()
    reset_models_state()
    with pending_auth_lock:
        pending_auth.clear()

    return """
<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="utf-8">
    <title>Logout</title>
  </head>
  <body>
    <h1>Sessao removida</h1>
    <p><a href="/">Voltar para o painel</a></p>
  </body>
</html>
"""


@app.post("/admin/refresh-models")
async def admin_refresh_models(request: Request):
    require_panel_session_json(request)
    wants_json = "application/json" in request.headers.get("accept", "")

    try:
        snapshot = refresh_dynamic_models(raise_on_error=True)
        dashboard_state = build_models_dashboard_state()
        payload = {
            "ok": True,
            "count": dashboard_state["count"],
            "dynamic_count": dashboard_state["dynamic_count"],
            "source": snapshot.get("last_source"),
            "last_refresh_at": snapshot.get("last_refresh_at"),
        }
        if wants_json:
            return payload

        notice = (
            f"Catalogo atualizado: {dashboard_state['dynamic_count']} modelos dinamicos, "
            f"{dashboard_state['count']} expostos em /v1/models."
        )
        redirect_query = urlencode(
            {
                "models_notice": notice,
                "models_notice_kind": "success",
            }
        )
    except HTTPException as exc:
        if wants_json:
            raise

        redirect_query = urlencode(
            {
                "models_notice": str(exc.detail),
                "models_notice_kind": "error",
            }
        )

    return RedirectResponse(url=f"/?{redirect_query}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/models")
@app.get("/v1/models")
async def list_models(request: Request) -> dict[str, Any]:
    require_proxy_api_key(request)
    models_snapshot = ensure_models_catalog()
    return {
        "object": "list",
        "data": build_public_model_entries(models_snapshot.get("dynamic_models", [])),
    }


@app.post("/chat/completions")
@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    require_proxy_api_key(request)
    body = await request.json()
    payload, response_model = build_chat_payload(body)
    upstream_response = post_upstream(payload)

    if body.get("stream"):
        return StreamingResponse(
            chat_stream_generator(upstream_response, response_model),
            media_type="text/event-stream",
        )

    content, upstream_usage = collect_text_response(upstream_response)
    return build_chat_completion_response(response_model, content, upstream_usage)


@app.post("/responses")
@app.post("/v1/responses")
async def responses(request: Request):
    require_proxy_api_key(request)
    body = await request.json()
    payload, response_model = build_responses_payload(body)
    upstream_response = post_upstream(payload)

    if body.get("stream"):
        return StreamingResponse(
            responses_stream_generator(
                upstream_response,
                response_model=response_model,
                instructions=body.get("instructions"),
                tools=body.get("tools") if isinstance(body.get("tools"), list) else None,
            ),
            media_type="text/event-stream",
        )

    content, upstream_usage = collect_text_response(upstream_response)
    return build_responses_response(
        model=response_model,
        content=content,
        upstream_usage=upstream_usage,
        instructions=body.get("instructions"),
        tools=body.get("tools") if isinstance(body.get("tools"), list) else None,
    )


if __name__ == "__main__":
    import uvicorn

    print(f"Proxy OpenAI compativel rodando em {PUBLIC_BASE_URL}")
    print(f"Base URL para clientes: {PUBLIC_BASE_URL}/v1")
    print(f"Painel local: {PUBLIC_BASE_URL}/")
    if PANEL_TOKEN_WAS_GENERATED:
        print("PANEL_ACCESS_TOKEN nao definido; token administrativo temporario gerado para este boot:")
        print(PANEL_ACCESS_TOKEN)
    else:
        print("Painel administrativo protegido por PANEL_ACCESS_TOKEN fornecido via ambiente.")
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)
