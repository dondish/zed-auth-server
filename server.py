"""Self-hosted auth + cloud-API stand-in for Zed, built with FastAPI.

Zed's production backend is split across three services:

  * the zed.dev website     — serves the browser sign-in page
  * the "cloud" API service — issues/validates access tokens, user directory
  * collab (crates/collab)  — the RPC/websocket server (rooms, channels, chat)

Only collab is in the public repo. This server implements enough of the other
two for a self-hosted collab deployment to work end to end:

Client-facing endpoints (Zed reaches these at `server_url`; for a custom
server_url the client's `build_zed_cloud_url` uses the same base URL, so both
the website-ish routes and the cloud API routes live here):

  GET  /native_app_signin            browser sign-in page (username form)
  GET  /native_app_signin/complete   issues an encrypted token, redirects to
                                     the Zed app's localhost callback
  GET  /native_app_signin_succeeded  "you're signed in" page
  GET  /rpc                          302 redirect telling the client where the
                                     collab websocket lives
  GET  /client/users/me              GetAuthenticatedUserResponse (token check)
  WS   /client/users/connect         cloud websocket (accepted and held open)
  POST /client/llm_tokens            dummy LLM token
  PATCH /client/system_settings      echoes back the settings

Collab-facing internal API (Bearer <internal api key>; collab in development
mode hardcodes this to http://localhost:8787, so we bind a plain-HTTP listener
there too):

  POST /internal/users/impersonate                        (also used by the
       ZED_IMPERSONATE + ZED_ADMIN_API_TOKEN client bypass)
  POST /internal/users/look_up_by_legacy_id
  POST /internal/users/look_up_by_github_login
  POST /internal/users/fuzzy_search
  POST /internal/channel_members/fuzzy_search_by_github_login

Identity model: username-only, no passwords. The sign-in form defaults to a
single local user; typing a different name creates another user (needed to
test collaboration between two Zed instances). Users and tokens persist in
data/state.json. This provides NO real security — anyone who can reach the
server can sign in as anyone. Local/LAN testing only.

Usage:
    python gen_certs.py --hostname zed.dondish.me   # once
    python server.py

Then in Zed's settings.json:  "server_url": "https://zed.dondish.me:8443"
"""

import argparse
import asyncio
import base64
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import uvicorn
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

try:
    import psycopg  # optional; only needed when COLLAB_DATABASE_URL is set
except ImportError:  # pragma: no cover - psycopg is optional
    psycopg = None

# ---------------------------------------------------------------------------
# Crypto helpers (must stay byte-compatible with crates/rpc/src/auth.rs)
# ---------------------------------------------------------------------------


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def parse_pkcs1_der_public_key(der: bytes) -> rsa.RSAPublicKey:
    """Parse a raw PKCS#1 RSAPublicKey DER blob: SEQUENCE { INTEGER n, INTEGER e }.

    Zed's Rust client serializes its public key with `to_pkcs1_der()`, which is
    NOT the SubjectPublicKeyInfo format Python's `load_der_public_key` expects,
    so we parse the two integers by hand.
    """

    def read_tlv(data: bytes, idx: int) -> tuple[int, bytes, int]:
        tag = data[idx]
        idx += 1
        length = data[idx]
        idx += 1
        if length & 0x80:
            num_len_bytes = length & 0x7F
            length = int.from_bytes(data[idx : idx + num_len_bytes], "big")
            idx += num_len_bytes
        return tag, data[idx : idx + length], idx + length

    tag, seq, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("expected SEQUENCE in PKCS#1 public key DER")
    tag, n_bytes, next_idx = read_tlv(seq, 0)
    if tag != 0x02:
        raise ValueError("expected INTEGER (modulus)")
    tag, e_bytes, _ = read_tlv(seq, next_idx)
    if tag != 0x02:
        raise ValueError("expected INTEGER (exponent)")
    return rsa.RSAPublicNumbers(
        int.from_bytes(e_bytes, "big"), int.from_bytes(n_bytes, "big")
    ).public_key()


def random_access_token() -> str:
    # Matches Zed's `rpc::auth::random_token`: 48 random bytes, base64url (64 chars).
    return b64url_encode(os.urandom(48))


def encrypt_for_client(public_key: rsa.RSAPublicKey, token: str) -> str:
    # Matches Zed's EncryptionFormat::V1: RSA-OAEP, SHA-256 digest + MGF1(SHA-256).
    return b64url_encode(
        public_key.encrypt(
            token.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    )


# ---------------------------------------------------------------------------
# User + token store (persisted to a JSON file)
# ---------------------------------------------------------------------------


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        if path.exists():
            state = json.loads(path.read_text(encoding="utf-8"))
        else:
            state = {"users": {}, "tokens": {}, "next_user_id": 1}
        # users: {username: {...user record...}}
        # tokens: {access_token: user_id}
        self.users: dict[str, dict] = state["users"]
        self.tokens: dict[str, int] = state["tokens"]
        self.next_user_id: int = state["next_user_id"]

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {
                    "users": self.users,
                    "tokens": self.tokens,
                    "next_user_id": self.next_user_id,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def get_or_create_user(self, username: str) -> dict:
        with self.lock:
            user = self.users.get(username)
            if user is None:
                user = {
                    "id": str(uuid.uuid4()),
                    "legacy_user_id": self.next_user_id,
                    "metrics_id": str(uuid.uuid4()),
                    "username": username,
                    "github_login": username,
                    "avatar_url": f"https://zed.dev/user_avatar/{username}.png",
                    "name": None,
                    "is_staff": True,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                self.users[username] = user
                self.next_user_id += 1
                self._save()
            return user

    def user_by_legacy_id(self, legacy_id: int) -> Optional[dict]:
        for user in self.users.values():
            if user["legacy_user_id"] == legacy_id:
                return user
        return None

    def issue_token(self, user: dict) -> str:
        token = random_access_token()
        with self.lock:
            self.tokens[token] = user["legacy_user_id"]
            self._save()
        return token

    def user_for_token(self, token: str) -> Optional[dict]:
        legacy_id = self.tokens.get(token)
        if legacy_id is None:
            return None
        return self.user_by_legacy_id(legacy_id)


# ---------------------------------------------------------------------------
# JSON shapes (must match crates/cloud_api_types)
# ---------------------------------------------------------------------------


def authenticated_user_json(user: dict) -> dict:
    """AuthenticatedUser (crates/cloud_api_types/src/cloud_api_types.rs)."""
    return {
        "id_v2": user["id"],
        "legacy_user_id": user["legacy_user_id"],
        "metrics_id": user["metrics_id"],
        "username": user["username"],
        "avatar_url": user["avatar_url"],
        "github_login": user["github_login"],
        "name": user["name"],
        "is_staff": user["is_staff"],
        # Set so the client never shows a terms-of-service gate.
        "accepted_tos_at": user["created_at"][:23] + "Z"
        if not user["created_at"].endswith("Z")
        else user["created_at"],
        "has_connected_to_collab_once": True,
    }


def internal_user_json(user: dict) -> dict:
    """internal_api::User (crates/cloud_api_types/src/internal_api.rs)."""
    return {
        "id": user["id"],
        "legacy_user_id": user["legacy_user_id"],
        "username": user["username"],
        "github_login": user["github_login"],
        "avatar_url": user["avatar_url"],
        "name": user["name"],
        "admin": user["is_staff"],
        "connected_once": True,
    }


def get_authenticated_user_response(user: dict) -> dict:
    """GetAuthenticatedUserResponse with a permissive free plan."""
    return {
        "user": authenticated_user_json(user),
        "feature_flags": [],
        "organizations": [],
        "default_organization_id": None,
        "plans_by_organization": {},
        "configuration_by_organization": {},
        "plan": {
            "plan_v3": "zed_free",
            "subscription_period": None,
            "usage": {"edit_predictions": {"used": 0, "limit": "unlimited"}},
            "trial_started_at": None,
            "is_account_too_young": False,
            "has_overdue_invoices": False,
        },
    }


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="zed-auth-server", docs_url=None, redoc_url=None)

# Filled in by main() before the servers start.
store: Store = None  # type: ignore[assignment]
INTERNAL_API_KEY = "internal-api-key-secret"
COLLAB_RPC_URL: Optional[str] = None  # override; else derived from request host
DEFAULT_USERNAME = "local"
# When set, users are mirrored into collab's own `users` table. collab has
# foreign keys from projects/rooms/contacts/etc. to users(id), so a user must
# exist there (keyed by legacy_user_id) before they can collaborate.
COLLAB_DATABASE_URL: Optional[str] = None


def ensure_collab_user(user: dict) -> None:
    """Upsert a row into collab's `users` table so FK constraints are satisfied.

    No-op unless COLLAB_DATABASE_URL is configured. Failures are logged, not
    raised, so a database hiccup never blocks sign-in itself.
    """
    if not COLLAB_DATABASE_URL:
        return
    if psycopg is None:
        print("[warn] COLLAB_DATABASE_URL set but psycopg is not installed")
        return
    try:
        with psycopg.connect(COLLAB_DATABASE_URL, connect_timeout=5) as conn:
            conn.execute(
                "INSERT INTO public.users (id, admin, connected_once) "
                "VALUES (%s, %s, TRUE) "
                "ON CONFLICT (id) DO UPDATE SET admin = EXCLUDED.admin",
                (user["legacy_user_id"], user["is_staff"]),
            )
    except Exception as exc:  # noqa: BLE001 - never let this break auth
        print(f"[warn] failed to mirror user into collab db: {exc}")

SIGNIN_PAGE = """<!doctype html>
<html><head><title>Sign in to Zed</title><style>
body {{ font-family: system-ui, sans-serif; display: grid; place-items: center;
       min-height: 90vh; background: #16161d; color: #eee; }}
form {{ background: #23232e; padding: 2.5rem 3rem; border-radius: 12px; }}
input, button {{ font-size: 1.1rem; padding: .5rem .8rem; border-radius: 6px;
                 border: 1px solid #444; }}
input {{ background: #16161d; color: #eee; }}
button {{ background: #4b6bfb; color: white; border: none; cursor: pointer;
          margin-left: .5rem; }}
p.warn {{ color: #999; font-size: .85rem; max-width: 28rem; }}
</style></head><body>
<form action="/native_app_signin/complete" method="get">
  <h2>Sign in to Zed</h2>
  <input type="hidden" name="native_app_port" value="{port}">
  <input type="hidden" name="native_app_public_key" value="{public_key}">
  <label for="username">Username</label><br><br>
  <input id="username" name="username" value="{default_username}" autofocus>
  <button type="submit">Sign in</button>
  <p class="warn">Local test server &mdash; no password. Typing a new name
  creates that user.</p>
</form></body></html>"""


@app.get("/native_app_signin")
async def native_app_signin(native_app_port: int, native_app_public_key: str):
    return HTMLResponse(
        SIGNIN_PAGE.format(
            port=native_app_port,
            public_key=native_app_public_key,
            default_username=DEFAULT_USERNAME,
        )
    )


@app.get("/native_app_signin/complete")
async def native_app_signin_complete(
    native_app_port: int, native_app_public_key: str, username: str
):
    username = username.strip()
    if not username:
        return HTMLResponse("<h1>Username required</h1>", status_code=400)

    try:
        public_key = parse_pkcs1_der_public_key(b64url_decode(native_app_public_key))
    except Exception as exc:  # noqa: BLE001 — surface parse errors to the browser
        return HTMLResponse(f"<h1>Invalid public key</h1><p>{exc}</p>", status_code=400)

    user = store.get_or_create_user(username)
    ensure_collab_user(user)
    token = store.issue_token(user)
    encrypted = encrypt_for_client(public_key, token)

    from urllib.parse import urlencode

    query = urlencode(
        {"user_id": str(user["legacy_user_id"]), "access_token": encrypted}
    )
    return RedirectResponse(f"http://127.0.0.1:{native_app_port}/?{query}", 302)


@app.get("/native_app_signin_succeeded")
async def native_app_signin_succeeded():
    return HTMLResponse(
        "<html><body style='font-family:system-ui;text-align:center;margin-top:20vh'>"
        "<h1>Signed in</h1><p>You can close this window and return to Zed.</p>"
        "</body></html>"
    )


@app.get("/rpc")
async def rpc_redirect(request: Request):
    """The client GETs /rpc and expects a redirect to the collab websocket URL."""
    if COLLAB_RPC_URL:
        location = COLLAB_RPC_URL
    else:
        host = request.url.hostname or "127.0.0.1"
        location = f"http://{host}:8080/rpc"
    return RedirectResponse(location, 302)


# --- Cloud client API ------------------------------------------------------


def user_from_auth_header(request_headers) -> Optional[dict]:
    """Validate `Authorization: <user_id> <access_token>`."""
    auth = request_headers.get("authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) != 2:
        return None
    user_id_str, token = parts
    user = store.user_for_token(token)
    if user is None or str(user["legacy_user_id"]) != user_id_str:
        return None
    return user


@app.get("/client/users/me")
async def get_me(request: Request):
    user = user_from_auth_header(request.headers)
    if user is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return get_authenticated_user_response(user)


@app.websocket("/client/users/connect")
async def cloud_websocket(ws: WebSocket):
    """The client opens a cloud websocket after sign-in to receive user-update
    pings (MessageToClient::UserUpdated, CBOR). We never need to push updates,
    so we just hold the connection open."""
    if user_from_auth_header(ws.headers) is None:
        await ws.close(code=4401)
        return
    await ws.accept()
    try:
        while True:
            await ws.receive()
    except (WebSocketDisconnect, RuntimeError):
        pass


@app.post("/client/llm_tokens")
async def create_llm_token(request: Request):
    if user_from_auth_header(request.headers) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"token": "unsupported-llm-token"}


@app.patch("/client/system_settings")
async def update_system_settings(request: Request):
    if user_from_auth_header(request.headers) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    return {"selected_organization_id": body.get("selected_organization_id")}


# --- Internal API (used by collab, Bearer-authenticated) -------------------


def check_internal_key(request: Request) -> bool:
    return request.headers.get("authorization") == f"Bearer {INTERNAL_API_KEY}"


class ImpersonateBody(BaseModel):
    github_login: str


@app.post("/internal/users/impersonate")
async def impersonate(request: Request, body: ImpersonateBody):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    user = store.get_or_create_user(body.github_login)
    ensure_collab_user(user)
    token = store.issue_token(user)
    return {"user_id": user["legacy_user_id"], "access_token": token}


class LookUpByLegacyIdBody(BaseModel):
    legacy_user_ids: list[int]


@app.post("/internal/users/look_up_by_legacy_id")
async def look_up_by_legacy_id(request: Request, body: LookUpByLegacyIdBody):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    users = [
        internal_user_json(user)
        for legacy_id in body.legacy_user_ids
        if (user := store.user_by_legacy_id(legacy_id)) is not None
    ]
    return {"users": users}


class LookUpByGithubLoginBody(BaseModel):
    github_login: str


@app.post("/internal/users/look_up_by_github_login")
async def look_up_by_github_login(request: Request, body: LookUpByGithubLoginBody):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    user = store.users.get(body.github_login)
    return {"user": internal_user_json(user) if user else None}


class FuzzySearchBody(BaseModel):
    query: str
    limit: int


@app.post("/internal/users/fuzzy_search")
async def fuzzy_search_users(request: Request, body: FuzzySearchBody):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    query = body.query.lower()
    matches = [
        internal_user_json(user)
        for username, user in store.users.items()
        if query in username.lower()
    ][: body.limit]
    return {"users": matches}


class FuzzySearchChannelMembersBody(BaseModel):
    channel_id: int
    query: str
    limit: int


@app.post("/internal/channel_members/fuzzy_search_by_github_login")
async def fuzzy_search_channel_members(
    request: Request, body: FuzzySearchChannelMembersBody
):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    # Channel membership lives in collab's own database; we don't have it here.
    # Returning matching users with no member records keeps the search usable.
    query = body.query.lower()
    matches = [
        internal_user_json(user)
        for username, user in store.users.items()
        if query in username.lower()
    ][: body.limit]
    return {"channel_members": [], "users": matches}


@app.get("/healthz")
async def healthz():
    return {"ok": True}


# ---------------------------------------------------------------------------
# Entry point: one app, two listeners
#   * HTTPS on --port      — what Zed's `server_url` points at
#   * HTTP  on --internal-port (loopback) — what collab's development
#     zed_cloud_url (http://localhost:8787) points at
# ---------------------------------------------------------------------------


async def serve(args: argparse.Namespace) -> None:
    servers = []

    https_config = uvicorn.Config(
        app,
        host=args.host,
        port=args.port,
        ssl_certfile=str(Path(args.cert_dir) / "server.crt"),
        ssl_keyfile=str(Path(args.cert_dir) / "server.key"),
        log_level="info",
    )
    servers.append(uvicorn.Server(https_config))

    if args.internal_port:
        http_config = uvicorn.Config(
            app, host="127.0.0.1", port=args.internal_port, log_level="info"
        )
        servers.append(uvicorn.Server(http_config))

    print(f"client-facing (server_url):  https://{args.host}:{args.port}")
    if args.internal_port:
        print(f"collab-facing (zed_cloud_url): http://127.0.0.1:{args.internal_port}")
    await asyncio.gather(*(server.serve() for server in servers))


def main() -> None:
    global store, INTERNAL_API_KEY, COLLAB_RPC_URL, DEFAULT_USERNAME
    global COLLAB_DATABASE_URL

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443, help="HTTPS port for Zed clients")
    parser.add_argument(
        "--internal-port",
        type=int,
        default=8787,
        help="Loopback HTTP port for collab's zed_cloud_url (0 to disable)",
    )
    parser.add_argument("--cert-dir", default="certs")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument(
        "--internal-api-key",
        default=os.environ.get("ZED_CLOUD_INTERNAL_API_KEY", "internal-api-key-secret"),
        help="Must match collab's ZED_CLOUD_INTERNAL_API_KEY",
    )
    parser.add_argument(
        "--collab-rpc-url",
        default=os.environ.get("COLLAB_RPC_URL"),
        help="Where GET /rpc redirects Zed clients "
        "(default: http://<request-host>:8080/rpc)",
    )
    parser.add_argument(
        "--collab-database-url",
        default=os.environ.get("COLLAB_DATABASE_URL"),
        help="If set, mirror users into collab's Postgres `users` table "
        "(required for collaboration; FK constraints reference users.id)",
    )
    parser.add_argument("--default-username", default="local")
    args = parser.parse_args()

    cert_dir = Path(args.cert_dir)
    if not (cert_dir / "server.crt").exists():
        raise SystemExit(f"Missing {cert_dir}/server.crt — run gen_certs.py first.")

    store = Store(Path(args.data_dir) / "state.json")
    INTERNAL_API_KEY = args.internal_api_key
    COLLAB_RPC_URL = args.collab_rpc_url
    COLLAB_DATABASE_URL = args.collab_database_url
    DEFAULT_USERNAME = args.default_username

    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
