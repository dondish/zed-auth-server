"""Browser sign-in: GitLab OAuth when configured, else a username form.

For a custom server_url the Zed client's `build_zed_cloud_url` uses the same
base URL, so these website-ish routes live on the client-facing listener.
"""

import secrets
import threading
import time
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .collab_db import ensure_collab_user
from .config import config
from .crypto import b64url_decode, encrypt_for_client, parse_pkcs1_der_public_key

router = APIRouter()

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


def _gitlab_redirect_uri(request: Request) -> str:
    if config.gitlab_redirect_uri:
        return config.gitlab_redirect_uri
    return str(request.base_url).rstrip("/") + "/auth/gitlab/callback"


def finish_signin(port: int, public_key_b64: str, user: dict):
    """Issue a Zed token for `user`, encrypt it with the app's public key, and
    redirect back to the Zed desktop app's localhost callback."""
    public_key = parse_pkcs1_der_public_key(b64url_decode(public_key_b64))
    ensure_collab_user(user)
    token = config.store.issue_token(user)
    encrypted = encrypt_for_client(public_key, token)
    query = urlencode(
        {"user_id": str(user["legacy_user_id"]), "access_token": encrypted}
    )
    return RedirectResponse(f"http://127.0.0.1:{port}/?{query}", 302)


@router.get("/native_app_signin")
async def native_app_signin(
    request: Request, native_app_port: int, native_app_public_key: str
):
    if config.gitlab_enabled():
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
        authorize = f"{config.gitlab_url.rstrip('/')}/oauth/authorize?" + urlencode(
            {
                "client_id": config.gitlab_client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "state": state,
                "scope": config.gitlab_scope,
            }
        )
        return RedirectResponse(authorize, 302)

    return HTMLResponse(
        SIGNIN_PAGE.format(
            port=native_app_port,
            public_key=native_app_public_key,
            default_username=config.default_username,
        )
    )


@router.get("/native_app_signin/complete")
async def native_app_signin_complete(
    native_app_port: int, native_app_public_key: str, username: str
):
    # Password-less fallback form. Disabled when GitLab OAuth is configured.
    if config.gitlab_enabled():
        return HTMLResponse("<h1>Sign-in is handled by GitLab</h1>", status_code=404)

    username = username.strip()
    if not username:
        return HTMLResponse("<h1>Username required</h1>", status_code=400)

    try:
        user = config.store.get_or_create_user(username)
        return finish_signin(native_app_port, native_app_public_key, user)
    except Exception as exc:  # noqa: BLE001 — surface parse errors to the browser
        return HTMLResponse(f"<h1>Invalid public key</h1><p>{exc}</p>", status_code=400)


async def fetch_gitlab_identity(code: str, redirect_uri: str) -> dict:
    """Exchange an OAuth code for a token and return the GitLab user profile."""
    base = config.gitlab_url.rstrip("/")
    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            f"{base}/oauth/token",
            data={
                "client_id": config.gitlab_client_id,
                "client_secret": config.gitlab_client_secret,
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


@router.get("/auth/gitlab/callback")
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
    user = config.store.get_or_create_user(f"gitlab:{gl['id']}", profile)

    try:
        return finish_signin(record["port"], record["public_key"], user)
    except Exception as exc:  # noqa: BLE001
        return HTMLResponse(f"<h1>Invalid public key</h1><p>{exc}</p>", status_code=400)


@router.get("/native_app_signin_succeeded")
async def native_app_signin_succeeded():
    return HTMLResponse(
        "<html><body style='font-family:system-ui;text-align:center;margin-top:20vh'>"
        "<h1>Signed in</h1><p>You can close this window and return to Zed.</p>"
        "</body></html>"
    )
