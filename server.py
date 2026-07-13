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

  GET  /native_app_signin            starts sign-in: redirects to GitLab OAuth
                                     when configured, else a username form
  GET  /native_app_signin/complete   username-form fallback: issues an
                                     encrypted token, redirects to the Zed
                                     app's localhost callback
  GET  /auth/gitlab/callback         GitLab OAuth callback: maps the GitLab
                                     identity to a user, then issues the token
  GET  /native_app_signin_succeeded  "you're signed in" page
  GET  /rpc                          302 redirect telling the client where the
                                     collab websocket lives
  GET  /client/users/me              GetAuthenticatedUserResponse (token check)
  WS   /client/users/connect         cloud websocket (accepted and held open)
  POST /client/llm_tokens            dummy LLM token
  PATCH /client/system_settings      echoes back the settings
  GET  /extensions[...]              extension store (list/updates/download);
                                     mirror populated by scrape_extensions.py

Collab-facing internal API (Bearer <internal api key>; collab in development
mode hardcodes this to http://localhost:8787, so we bind a plain-HTTP listener
there too):

  POST /internal/users/impersonate                        (also used by the
       ZED_IMPERSONATE + ZED_ADMIN_API_TOKEN client bypass)
  POST /internal/users/look_up_by_legacy_id
  POST /internal/users/look_up_by_github_login
  POST /internal/users/fuzzy_search
  POST /internal/channel_members/fuzzy_search_by_github_login

Identity model: GitLab OAuth when GITLAB_CLIENT_ID/SECRET are configured (any
gitlab.com or self-hosted instance via GITLAB_URL) — the GitLab username, name
and avatar become the Zed identity, keyed by the stable GitLab user id. Without
GitLab configured it falls back to a password-less username form (typing a name
creates that user), which is handy for local multi-instance testing. Users and
tokens persist in Postgres when AUTH_DATABASE_URL is set (an `auth` schema),
otherwise in data/state.json. Even with GitLab, this grants everyone a zed_free
plan and admin — it is a self-hosted test backend, not a hardened one.

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
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import httpx
import uvicorn
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from pydantic import BaseModel

from blobstore import BlobStore, EXTENSIONS_INDEX_KEY, RELEASES_INDEX_KEY

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
# User + token store
#
# Two interchangeable backends with the same interface: JsonStore (a single
# state.json file, the default for a standalone `python server.py`) and
# PostgresStore (used when AUTH_DATABASE_URL is set — e.g. the docker-compose
# stack). The user dict shape is identical across both.
#
# `identity` is the stable storage key: a bare username for the legacy form /
# impersonation, or "gitlab:<id>" for an OAuth identity (so a GitLab user
# survives a username change). `profile`, when given to get_or_create_user,
# supplies/refreshes the display fields on each login.
# ---------------------------------------------------------------------------

# Fields refreshed from the OAuth profile on each subsequent login.
_MUTABLE_USER_FIELDS = ("username", "github_login", "avatar_url", "name", "is_staff")


def default_avatar(username: str) -> str:
    return f"https://zed.dev/user_avatar/{username}.png"


class JsonStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        if path.exists():
            state = json.loads(path.read_text(encoding="utf-8"))
        else:
            state = {"users": {}, "tokens": {}, "next_user_id": 1}
        # users: {identity: {...user record...}}
        # tokens: {access_token: legacy_user_id}
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

    def get_or_create_user(
        self, identity: str, profile: Optional[dict] = None
    ) -> dict:
        profile = profile or {}
        with self.lock:
            user = self.users.get(identity)
            if user is None:
                username = profile.get("username") or identity
                user = {
                    "id": str(uuid.uuid4()),
                    "legacy_user_id": self.next_user_id,
                    "metrics_id": str(uuid.uuid4()),
                    "username": username,
                    "github_login": profile.get("github_login") or username,
                    "avatar_url": profile.get("avatar_url") or default_avatar(username),
                    "name": profile.get("name"),
                    "is_staff": profile.get("is_staff", True),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                self.users[identity] = user
                self.next_user_id += 1
                self._save()
            elif profile:
                changed = False
                for field in _MUTABLE_USER_FIELDS:
                    if (
                        profile.get(field) is not None
                        and user.get(field) != profile[field]
                    ):
                        user[field] = profile[field]
                        changed = True
                if changed:
                    self._save()
            return user

    def user_by_legacy_id(self, legacy_id: int) -> Optional[dict]:
        for user in self.users.values():
            if user["legacy_user_id"] == legacy_id:
                return user
        return None

    def user_by_github_login(self, github_login: str) -> Optional[dict]:
        for user in self.users.values():
            if user.get("github_login") == github_login:
                return user
        return None

    def search_users(self, query: str, limit: int) -> list[dict]:
        q = query.lower()
        return [
            user
            for user in self.users.values()
            if q in user["username"].lower()
            or q in (user.get("github_login") or "").lower()
        ][:limit]

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


class PostgresStore:
    """Postgres-backed store. Tables live in their own `auth` schema so they
    coexist with collab's `public` tables in the same database."""

    def __init__(self, dsn: str):
        if psycopg is None:
            raise SystemExit(
                "AUTH_DATABASE_URL is set but psycopg is not installed "
                "(pip install 'psycopg[binary,pool]')."
            )
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._dict_row = dict_row
        self.pool = ConnectionPool(
            dsn,
            min_size=1,
            max_size=8,
            kwargs={"autocommit": True, "row_factory": dict_row},
            open=True,
        )
        self._init_schema()

    def _init_schema(self) -> None:
        with self.pool.connection() as conn:
            conn.execute("CREATE SCHEMA IF NOT EXISTS auth")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth.users (
                    identity       TEXT PRIMARY KEY,
                    id             UUID NOT NULL DEFAULT gen_random_uuid(),
                    legacy_user_id INTEGER GENERATED BY DEFAULT AS IDENTITY UNIQUE,
                    metrics_id     UUID NOT NULL DEFAULT gen_random_uuid(),
                    username       TEXT NOT NULL,
                    github_login   TEXT,
                    avatar_url     TEXT,
                    name           TEXT,
                    is_staff       BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth.tokens (
                    token          TEXT PRIMARY KEY,
                    legacy_user_id INTEGER NOT NULL
                        REFERENCES auth.users(legacy_user_id) ON DELETE CASCADE,
                    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS users_github_login_idx "
                "ON auth.users (github_login)"
            )

    @staticmethod
    def _to_user(row: Optional[dict]) -> Optional[dict]:
        if row is None:
            return None
        user = dict(row)
        user.pop("identity", None)
        user["id"] = str(user["id"])
        user["metrics_id"] = str(user["metrics_id"])
        # Callers expect created_at as an ISO-8601 string (see
        # authenticated_user_json), matching JsonStore.
        user["created_at"] = user["created_at"].isoformat()
        return user

    def get_or_create_user(
        self, identity: str, profile: Optional[dict] = None
    ) -> dict:
        profile = profile or {}
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                "SELECT * FROM auth.users WHERE identity = %s FOR UPDATE",
                (identity,),
            ).fetchone()
            if row is None:
                username = profile.get("username") or identity
                row = conn.execute(
                    """
                    INSERT INTO auth.users
                        (identity, username, github_login, avatar_url, name, is_staff)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (
                        identity,
                        username,
                        profile.get("github_login") or username,
                        profile.get("avatar_url") or default_avatar(username),
                        profile.get("name"),
                        profile.get("is_staff", True),
                    ),
                ).fetchone()
            elif profile:
                updates = {
                    field: profile[field]
                    for field in _MUTABLE_USER_FIELDS
                    if profile.get(field) is not None and row[field] != profile[field]
                }
                if updates:
                    set_clause = ", ".join(f"{col} = %s" for col in updates)
                    row = conn.execute(
                        f"UPDATE auth.users SET {set_clause} "
                        "WHERE identity = %s RETURNING *",
                        (*updates.values(), identity),
                    ).fetchone()
            return self._to_user(row)

    def user_by_legacy_id(self, legacy_id: int) -> Optional[dict]:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT * FROM auth.users WHERE legacy_user_id = %s", (legacy_id,)
            ).fetchone()
        return self._to_user(row)

    def user_by_github_login(self, github_login: str) -> Optional[dict]:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT * FROM auth.users WHERE github_login = %s LIMIT 1",
                (github_login,),
            ).fetchone()
        return self._to_user(row)

    def search_users(self, query: str, limit: int) -> list[dict]:
        like = f"%{query}%"
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM auth.users "
                "WHERE username ILIKE %s OR github_login ILIKE %s "
                "ORDER BY legacy_user_id LIMIT %s",
                (like, like, limit),
            ).fetchall()
        return [self._to_user(r) for r in rows]

    def issue_token(self, user: dict) -> str:
        token = random_access_token()
        with self.pool.connection() as conn:
            conn.execute(
                "INSERT INTO auth.tokens (token, legacy_user_id) VALUES (%s, %s)",
                (token, user["legacy_user_id"]),
            )
        return token

    def user_for_token(self, token: str) -> Optional[dict]:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT u.* FROM auth.tokens t "
                "JOIN auth.users u ON u.legacy_user_id = t.legacy_user_id "
                "WHERE t.token = %s",
                (token,),
            ).fetchone()
        return self._to_user(row)


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

# Filled in by main() before the servers start (JsonStore or PostgresStore).
store = None  # type: ignore[assignment]
INTERNAL_API_KEY = "internal-api-key-secret"
COLLAB_RPC_URL: Optional[str] = None  # override; else derived from request host
DEFAULT_USERNAME = "local"
# When set, users are mirrored into collab's own `users` table. collab has
# foreign keys from projects/rooms/contacts/etc. to users(id), so a user must
# exist there (keyed by legacy_user_id) before they can collaborate.
COLLAB_DATABASE_URL: Optional[str] = None
# Directory holding scraped release installers + index.json (see
# scrape_releases.py). Served by the /releases auto-update API.
RELEASES_DIR: Path = Path("releases")
# Directory holding scraped extension archives + index.json (see
# scrape_extensions.py). Served by the /extensions API.
EXTENSIONS_DIR: Path = Path("extensions")
# When configured (S3_ENDPOINT_URL / S3_BUCKET), releases and extensions are
# read from S3 / MinIO instead of the local *_DIR paths above. The server still
# streams the bytes through its own HTTPS listener.
BLOBS: Optional[BlobStore] = None

# --- GitLab OAuth ----------------------------------------------------------
# When GITLAB_CLIENT_ID and GITLAB_CLIENT_SECRET are set, sign-in is backed by
# GitLab's OAuth (authorization code flow) instead of the password-less
# username form. GITLAB_URL points at any GitLab instance (gitlab.com or a
# self-hosted one). GITLAB_REDIRECT_URI, when set, must exactly match the
# callback registered on the GitLab application; otherwise it is derived from
# the incoming request as <base>/auth/gitlab/callback.
GITLAB_URL = "https://gitlab.com"
GITLAB_CLIENT_ID: Optional[str] = None
GITLAB_CLIENT_SECRET: Optional[str] = None
GITLAB_REDIRECT_URI: Optional[str] = None
GITLAB_SCOPE = "read_user"


def gitlab_enabled() -> bool:
    return bool(GITLAB_CLIENT_ID and GITLAB_CLIENT_SECRET)


class PendingSignins:
    """Short-lived store correlating an OAuth `state` back to the Zed app's
    localhost callback port + public key across the GitLab round-trip."""

    TTL_SECONDS = 600

    def __init__(self):
        self.lock = threading.Lock()
        self.pending: dict[str, dict] = {}

    def create(self, port: int, public_key: str, redirect_uri: str) -> str:
        state = secrets.token_urlsafe(24)
        with self.lock:
            self._evict_expired()
            self.pending[state] = {
                "port": port,
                "public_key": public_key,
                "redirect_uri": redirect_uri,
                "created_at": time.monotonic(),
            }
        return state

    def take(self, state: str) -> Optional[dict]:
        with self.lock:
            self._evict_expired()
            return self.pending.pop(state, None)

    def _evict_expired(self) -> None:
        now = time.monotonic()
        stale = [
            s for s, r in self.pending.items()
            if now - r["created_at"] > self.TTL_SECONDS
        ]
        for s in stale:
            del self.pending[s]


pending_signins = PendingSignins()


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


def _gitlab_redirect_uri(request: Request) -> str:
    if GITLAB_REDIRECT_URI:
        return GITLAB_REDIRECT_URI
    return str(request.base_url).rstrip("/") + "/auth/gitlab/callback"


def finish_signin(port: int, public_key_b64: str, user: dict):
    """Issue a Zed token for `user`, encrypt it with the app's public key, and
    redirect back to the Zed desktop app's localhost callback."""
    public_key = parse_pkcs1_der_public_key(b64url_decode(public_key_b64))
    ensure_collab_user(user)
    token = store.issue_token(user)
    encrypted = encrypt_for_client(public_key, token)
    query = urlencode(
        {"user_id": str(user["legacy_user_id"]), "access_token": encrypted}
    )
    return RedirectResponse(f"http://127.0.0.1:{port}/?{query}", 302)


@app.get("/native_app_signin")
async def native_app_signin(
    request: Request, native_app_port: int, native_app_public_key: str
):
    if gitlab_enabled():
        # Validate the public key up front so a bad key fails here, not after
        # the GitLab round-trip.
        try:
            parse_pkcs1_der_public_key(b64url_decode(native_app_public_key))
        except Exception as exc:  # noqa: BLE001
            return HTMLResponse(
                f"<h1>Invalid public key</h1><p>{exc}</p>", status_code=400
            )
        redirect_uri = _gitlab_redirect_uri(request)
        state = pending_signins.create(
            native_app_port, native_app_public_key, redirect_uri
        )
        authorize = f"{GITLAB_URL.rstrip('/')}/oauth/authorize?" + urlencode(
            {
                "client_id": GITLAB_CLIENT_ID,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "state": state,
                "scope": GITLAB_SCOPE,
            }
        )
        return RedirectResponse(authorize, 302)

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
    # Password-less fallback form. Disabled when GitLab OAuth is configured.
    if gitlab_enabled():
        return HTMLResponse("<h1>Sign-in is handled by GitLab</h1>", status_code=404)

    username = username.strip()
    if not username:
        return HTMLResponse("<h1>Username required</h1>", status_code=400)

    try:
        user = store.get_or_create_user(username)
        return finish_signin(native_app_port, native_app_public_key, user)
    except Exception as exc:  # noqa: BLE001 — surface parse errors to the browser
        return HTMLResponse(f"<h1>Invalid public key</h1><p>{exc}</p>", status_code=400)


async def fetch_gitlab_identity(code: str, redirect_uri: str) -> dict:
    """Exchange an OAuth code for a token and return the GitLab user profile."""
    base = GITLAB_URL.rstrip("/")
    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            f"{base}/oauth/token",
            data={
                "client_id": GITLAB_CLIENT_ID,
                "client_secret": GITLAB_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
        )
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]

        user_resp = await client.get(
            f"{base}/api/v4/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_resp.raise_for_status()
        return user_resp.json()


@app.get("/auth/gitlab/callback")
async def gitlab_callback(
    request: Request,
    state: str,
    code: str = "",
    error: str = "",
    error_description: str = "",
):
    if error:
        return HTMLResponse(
            f"<h1>GitLab sign-in failed</h1><p>{error}: {error_description}</p>",
            status_code=400,
        )

    record = pending_signins.take(state)
    if record is None:
        return HTMLResponse(
            "<h1>Sign-in expired</h1><p>Please start again from Zed.</p>",
            status_code=400,
        )

    try:
        gl = await fetch_gitlab_identity(code, record["redirect_uri"])
    except httpx.HTTPError as exc:
        return HTMLResponse(
            f"<h1>GitLab sign-in failed</h1><p>{exc}</p>", status_code=502
        )

    profile = {
        "username": gl.get("username"),
        "github_login": gl.get("username"),
        "name": gl.get("name"),
        "avatar_url": gl.get("avatar_url"),
    }
    user = store.get_or_create_user(f"gitlab:{gl['id']}", profile)

    try:
        return finish_signin(record["port"], record["public_key"], user)
    except Exception as exc:  # noqa: BLE001
        return HTMLResponse(f"<h1>Invalid public key</h1><p>{exc}</p>", status_code=400)


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


# --- Release / auto-update API ---------------------------------------------
#
# Zed's auto-updater (crates/auto_update) calls
#   GET /releases/{channel}/{version}/asset?asset=zed&os=..&arch=..
# and expects JSON {"version": "..", "url": ".."}. It then downloads `url`,
# and on Windows runs it as an installer. `version` may be "latest".
#
# We serve installers scraped by scrape_releases.py into releases/index.json,
# and host the binaries ourselves via /releases/download/... below.


# Small TTL cache so the index isn't re-fetched from S3 on every request.
_index_cache: dict[str, tuple[float, dict]] = {}
_INDEX_TTL = 30.0


def _load_index(local_path: Path, s3_key: str) -> dict:
    if BLOBS is None:
        if not local_path.exists():
            return {}
        try:
            return json.loads(local_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    now = time.monotonic()
    cached = _index_cache.get(s3_key)
    if cached and now - cached[0] < _INDEX_TTL:
        return cached[1]
    data = BLOBS.get_json(s3_key) or {}
    _index_cache[s3_key] = (now, data)
    return data


def _stream_blob(key: str, filename: Optional[str], media_type: str):
    """Stream an object from S3 back through this server."""
    result = BLOBS.open_stream(key)
    if result is None:
        return JSONResponse({"error": "asset file missing"}, status_code=404)
    chunks, length, _content_type = result
    headers = {}
    if length:
        headers["Content-Length"] = str(length)
    if filename:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return StreamingResponse(chunks, media_type=media_type, headers=headers)


def load_release_index() -> dict:
    return _load_index(RELEASES_DIR / "index.json", RELEASES_INDEX_KEY)


def _semver_key(version: str) -> tuple:
    # Compare only the numeric release fields (matches the client, which
    # strips pre-release/build metadata before comparing).
    parts = version.split("-")[0].split(".")
    return tuple(int(p) if p.isdigit() else 0 for p in parts)


@app.get("/releases/{channel}/{version}/asset")
async def release_asset(
    channel: str,
    version: str,
    request: Request,
    asset: str = "zed",
    os: str = "",
    arch: str = "",
):
    index = load_release_index()
    key = f"{channel}/{os}/{arch}/{asset}"
    entries = index.get(key, [])
    if not entries:
        return JSONResponse(
            {"error": f"no releases for {key}"}, status_code=404
        )

    if version == "latest":
        entry = max(entries, key=lambda e: _semver_key(e["version"]))
    else:
        wanted = _semver_key(version)
        entry = next(
            (e for e in entries if _semver_key(e["version"]) == wanted), None
        )
        if entry is None:
            return JSONResponse(
                {"error": f"version {version} not found for {key}"}, status_code=404
            )

    # Point the download URL back at this server so updates are self-hosted.
    base = str(request.base_url).rstrip("/")
    download_url = f"{base}/releases/download/{channel}/{os}/{arch}/{asset}/{entry['file']}"
    return {"version": entry["version"], "url": download_url}


@app.get("/releases/download/{channel}/{os}/{arch}/{asset}/{filename}")
async def release_download(
    channel: str, os: str, arch: str, asset: str, filename: str
):
    # Guard against path traversal: only serve files named in the index.
    key = f"{channel}/{os}/{arch}/{asset}"
    entries = load_release_index().get(key, [])
    entry = next((e for e in entries if e["file"] == filename), None)
    if entry is None:
        return JSONResponse({"error": "unknown asset"}, status_code=404)
    if BLOBS is not None:
        return _stream_blob(entry["key"], filename, "application/octet-stream")
    path = RELEASES_DIR / filename
    if not path.exists():
        return JSONResponse({"error": "asset file missing"}, status_code=404)
    return FileResponse(path, media_type="application/octet-stream", filename=filename)


# --- Extensions API ---------------------------------------------------------
#
# Zed's extension store (crates/extension_host) reaches these routes via
# `build_zed_api_url`, which for a custom server_url uses the same base URL —
# so they live on the client-facing HTTPS listener alongside /client/*.
#
#   GET /extensions?max_schema_version=&filter=&provides=   catalog / search
#   GET /extensions/updates?ids=&min_schema_version=&...     update check
#   GET /extensions/{id}                                     versions of one ext
#   GET /extensions/{id}/download                            latest archive.tar.gz
#   GET /extensions/{id}/{version}/download                  a specific archive
#
# The JSON routes return {"data": [ExtensionMetadata]} (matching collab /
# cloud_api_types::GetExtensionsResponse). The download routes serve the
# gzipped tar the client unpacks into its extensions dir. Populate the mirror
# with scrape_extensions.py.


def load_extension_index() -> dict:
    return _load_index(
        EXTENSIONS_DIR / "index.json", EXTENSIONS_INDEX_KEY
    ).get("extensions", {})


# Fields that are internal to the mirror and must not leak into API responses
# (the client deserializes into a strict ExtensionMetadata struct).
_EXT_INTERNAL_FIELDS = ("archive", "key", "size")


def _public_metadata(entry: dict) -> dict:
    return {k: v for k, v in entry.items() if k not in _EXT_INTERNAL_FIELDS}


def _latest_version(entries: list[dict]) -> dict:
    return max(entries, key=lambda e: _semver_key(e["version"]))


@app.get("/extensions")
async def list_extensions(
    max_schema_version: int = 1,
    filter: str = "",
    provides: str = "",
):
    index = load_extension_index()
    provides_filter = {p for p in provides.split(",") if p} if provides else set()
    needle = filter.lower().strip()

    data = []
    for entries in index.values():
        if not entries:
            continue
        entry = _latest_version(entries)
        if (entry.get("schema_version") or 0) > max_schema_version:
            continue
        if provides_filter and not provides_filter.issubset(set(entry.get("provides", []))):
            continue
        if needle:
            haystack = " ".join(
                str(entry.get(k, "")) for k in ("id", "name", "description")
            ).lower()
            if needle not in haystack:
                continue
        data.append(_public_metadata(entry))

    data.sort(key=lambda e: e.get("download_count", 0), reverse=True)
    return {"data": data}


@app.get("/extensions/updates")
async def extension_updates(
    ids: str = "",
    min_schema_version: int = 0,
    max_schema_version: int = 1,
    min_wasm_api_version: str = "",
    max_wasm_api_version: str = "",
):
    index = load_extension_index()
    wanted = [i.strip() for i in ids.split(",") if i.strip()]
    data = []
    for ext_id in wanted:
        entries = index.get(ext_id)
        if not entries:
            continue
        entry = _latest_version(entries)
        schema = entry.get("schema_version") or 0
        if not (min_schema_version <= schema <= max_schema_version):
            continue
        data.append(_public_metadata(entry))
    return {"data": data}


@app.get("/extensions/{extension_id}")
async def extension_versions(extension_id: str):
    entries = load_extension_index().get(extension_id, [])
    data = [
        _public_metadata(e)
        for e in sorted(entries, key=lambda e: _semver_key(e["version"]), reverse=True)
    ]
    return {"data": data}


def _serve_extension_archive(extension_id: str, entry: dict):
    archive = entry.get("archive")
    if BLOBS is not None:
        key = entry.get("key")
        if not key:
            return JSONResponse({"error": "no archive for version"}, status_code=404)
        return _stream_blob(key, archive, "application/gzip")
    if not archive:
        return JSONResponse({"error": "no archive for version"}, status_code=404)
    path = EXTENSIONS_DIR / archive
    if not path.exists():
        return JSONResponse({"error": "archive file missing"}, status_code=404)
    return FileResponse(path, media_type="application/gzip", filename=archive)


@app.get("/extensions/{extension_id}/download")
async def download_latest_extension(extension_id: str):
    entries = load_extension_index().get(extension_id)
    if not entries:
        return JSONResponse({"error": "unknown extension"}, status_code=404)
    return _serve_extension_archive(extension_id, _latest_version(entries))


@app.get("/extensions/{extension_id}/{version}/download")
async def download_extension(extension_id: str, version: str):
    entries = load_extension_index().get(extension_id, [])
    entry = next((e for e in entries if e["version"] == version), None)
    if entry is None:
        return JSONResponse({"error": "unknown extension version"}, status_code=404)
    return _serve_extension_archive(extension_id, entry)


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


INDEX_PAGE_HEAD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zed release server</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, sans-serif; margin: 0;
         background: #f6f6f8; color: #1a1a1f; }
  @media (prefers-color-scheme: dark) {
    body { background: #16161d; color: #e7e7ea; }
    .card { background: #23232e !important; border-color: #33333f !important; }
    th { color: #9a9aa8 !important; border-color: #33333f !important; }
    td { border-color: #2a2a35 !important; }
    a.btn { background: #4b6bfb !important; }
    code { background: #2a2a35 !important; }
  }
  .wrap { max-width: 860px; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
  h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
  p.sub { color: #6a6a78; margin: 0 0 2rem; }
  .card { background: #fff; border: 1px solid #e3e3e8; border-radius: 12px;
          padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
  .card h2 { font-size: 1rem; margin: 0 0 .9rem; font-weight: 600; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: .72rem; text-transform: uppercase;
       letter-spacing: .04em; color: #8a8a98; font-weight: 600;
       padding: 0 .6rem .5rem; border-bottom: 1px solid #e3e3e8; }
  td { padding: .7rem .6rem; border-bottom: 1px solid #f0f0f3; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .ver { font-weight: 600; font-variant-numeric: tabular-nums; }
  .tag { font-size: .7rem; font-weight: 600; color: #fff; background: #22a06b;
         padding: .1rem .4rem; border-radius: 5px; margin-left: .45rem; }
  .size { color: #8a8a98; font-variant-numeric: tabular-nums; }
  a.btn { display: inline-block; background: #4b6bfb; color: #fff;
          text-decoration: none; padding: .4rem .9rem; border-radius: 7px;
          font-size: .85rem; font-weight: 500; }
  a.btn:hover { filter: brightness(1.08); }
  code { background: #eee; padding: .1rem .35rem; border-radius: 4px; font-size: .85em; }
  .empty { color: #8a8a98; }
</style></head><body><div class="wrap">
<h1>Zed release server</h1>
<p class="sub">Self-hosted installers served from this machine. On Windows,
run the downloaded <code>.exe</code> to install that version.</p>
"""

INDEX_PAGE_FOOT = "</div></body></html>"


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    index = load_release_index()
    base = str(request.base_url).rstrip("/")
    sections = []

    for key in sorted(index):
        entries = index[key]
        if not entries:
            continue
        channel, os_, arch, asset = key.split("/")
        # Highest semver is "latest".
        latest = max(entries, key=lambda e: _semver_key(e["version"]))["version"]
        rows = []
        for entry in sorted(entries, key=lambda e: _semver_key(e["version"]), reverse=True):
            if entry.get("size"):
                size = _human_size(entry["size"])
            else:
                file_path = RELEASES_DIR / entry["file"]
                size = _human_size(file_path.stat().st_size) if file_path.exists() else "—"
            tag = '<span class="tag">latest</span>' if entry["version"] == latest else ""
            dl = f"{base}/releases/download/{channel}/{os_}/{arch}/{asset}/{entry['file']}"
            rows.append(
                f"<tr><td><span class='ver'>{entry['version']}</span>{tag}</td>"
                f"<td class='size'>{size}</td>"
                f"<td style='text-align:right'><a class='btn' href='{dl}'>Download</a></td></tr>"
            )
        sections.append(
            f"<div class='card'><h2>{asset} &middot; {channel} &middot; {os_}/{arch}</h2>"
            f"<table><thead><tr><th>Version</th><th>Size</th><th></th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )

    body = "".join(sections) if sections else (
        "<p class='empty'>No installers scraped yet. Run "
        "<code>python scrape_releases.py</code>.</p>"
    )
    return HTMLResponse(INDEX_PAGE_HEAD + body + INDEX_PAGE_FOOT)


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
    user = store.user_by_github_login(body.github_login)
    return {"user": internal_user_json(user) if user else None}


class FuzzySearchBody(BaseModel):
    query: str
    limit: int


@app.post("/internal/users/fuzzy_search")
async def fuzzy_search_users(request: Request, body: FuzzySearchBody):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    matches = [internal_user_json(u) for u in store.search_users(body.query, body.limit)]
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
    matches = [internal_user_json(u) for u in store.search_users(body.query, body.limit)]
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
    global COLLAB_DATABASE_URL, RELEASES_DIR, EXTENSIONS_DIR, BLOBS
    global GITLAB_URL, GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET
    global GITLAB_REDIRECT_URI, GITLAB_SCOPE

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
        "--database-url",
        default=os.environ.get("AUTH_DATABASE_URL"),
        help="Postgres DSN for the user/token store (uses an `auth` schema). "
        "When unset, users persist to <data-dir>/state.json.",
    )
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
    parser.add_argument(
        "--releases-dir",
        default=os.environ.get("RELEASES_DIR", "releases"),
        help="Directory with scraped installers + index.json for /releases",
    )
    parser.add_argument(
        "--extensions-dir",
        default=os.environ.get("EXTENSIONS_DIR", "extensions"),
        help="Directory with scraped extension archives + index.json for /extensions",
    )
    parser.add_argument(
        "--gitlab-url",
        default=os.environ.get("GITLAB_URL", "https://gitlab.com"),
        help="GitLab instance base URL (gitlab.com or a self-hosted instance)",
    )
    parser.add_argument(
        "--gitlab-client-id",
        default=os.environ.get("GITLAB_CLIENT_ID"),
        help="OAuth application id; enables GitLab-backed sign-in when set with the secret",
    )
    parser.add_argument(
        "--gitlab-client-secret",
        default=os.environ.get("GITLAB_CLIENT_SECRET"),
        help="OAuth application secret",
    )
    parser.add_argument(
        "--gitlab-redirect-uri",
        default=os.environ.get("GITLAB_REDIRECT_URI"),
        help="OAuth callback URL registered on the GitLab app "
        "(default: <request-base>/auth/gitlab/callback)",
    )
    parser.add_argument(
        "--gitlab-scope",
        default=os.environ.get("GITLAB_SCOPE", "read_user"),
        help="OAuth scopes to request",
    )
    args = parser.parse_args()

    cert_dir = Path(args.cert_dir)
    if not (cert_dir / "server.crt").exists():
        raise SystemExit(f"Missing {cert_dir}/server.crt — run gen_certs.py first.")

    if args.database_url:
        store = PostgresStore(args.database_url)
        print("store: Postgres (auth schema)")
    else:
        store = JsonStore(Path(args.data_dir) / "state.json")
        print(f"store: JSON file ({args.data_dir}/state.json)")
    INTERNAL_API_KEY = args.internal_api_key
    COLLAB_RPC_URL = args.collab_rpc_url
    COLLAB_DATABASE_URL = args.collab_database_url
    RELEASES_DIR = Path(args.releases_dir)
    EXTENSIONS_DIR = Path(args.extensions_dir)
    BLOBS = BlobStore.from_env()
    if BLOBS is not None:
        print(f"assets: S3 bucket '{BLOBS.bucket}' (releases + extensions)")
    else:
        print("assets: local dirs (set S3_ENDPOINT_URL/S3_BUCKET for S3/MinIO)")
    DEFAULT_USERNAME = args.default_username
    GITLAB_URL = args.gitlab_url
    GITLAB_CLIENT_ID = args.gitlab_client_id
    GITLAB_CLIENT_SECRET = args.gitlab_client_secret
    GITLAB_REDIRECT_URI = args.gitlab_redirect_uri
    GITLAB_SCOPE = args.gitlab_scope
    if gitlab_enabled():
        print(f"auth: GitLab OAuth via {GITLAB_URL}")
    else:
        print("auth: password-less username form (set GITLAB_CLIENT_ID/SECRET for GitLab)")

    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
