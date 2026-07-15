"""Self-hosted auth + cloud-API stand-in for Zed — FastAPI app assembly.

Zed's production backend is split across three services:

  * the zed.dev website     — serves the browser sign-in page
  * the "cloud" API service — issues/validates access tokens, user directory
  * collab (crates/collab)  — the RPC/websocket server (rooms, channels, chat)

Only collab is in the public repo. This server implements enough of the other
two for a self-hosted collab deployment to work end to end. The routes are
grouped into routers:

  auth_routes       browser sign-in (GitLab OAuth or username form)
  client_routes     the cloud API the Zed client calls (/rpc, /client/*)
  internal_routes   collab's Bearer-authenticated user directory (/internal/*)
  releases_routes   auto-update API + installer web UI (/, /releases/*)
  extensions_routes extension store (/extensions/*)
  registry_routes   ACP agent registry (/registry/*)

Runtime configuration lives in `config.config`, populated by server.main().
"""

from fastapi import FastAPI

from . import (
    auth_routes,
    client_routes,
    extensions_routes,
    internal_routes,
    registry_routes,
    releases_routes,
)

app = FastAPI(title="zed-auth-server", docs_url=None, redoc_url=None)

app.include_router(auth_routes.router)
app.include_router(client_routes.router)
app.include_router(internal_routes.router)
app.include_router(extensions_routes.router)
app.include_router(registry_routes.router)
# Releases router owns "/" (the web UI); include it last.
app.include_router(releases_routes.router)


@app.get("/healthz")
async def healthz():
    return {"ok": True}
