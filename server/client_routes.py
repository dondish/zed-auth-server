"""Cloud client API — the routes the Zed client calls after sign-in."""

from typing import Optional

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, RedirectResponse

from .config import config
from .schemas import get_authenticated_user_response

router = APIRouter()


def user_from_auth_header(request_headers) -> Optional[dict]:
    """Validate `Authorization: <user_id> <access_token>`."""
    auth = request_headers.get("authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) != 2:
        return None
    user_id_str, token = parts
    user = config.store.user_for_token(token)
    if user is None or str(user["legacy_user_id"]) != user_id_str:
        return None
    return user


@router.get("/rpc")
async def rpc_redirect(request: Request):
    """The client GETs /rpc and expects a redirect to the collab websocket URL."""
    if config.collab_rpc_url:
        location = config.collab_rpc_url
    else:
        host = request.url.hostname or "127.0.0.1"
        location = f"http://{host}:8080/rpc"
    return RedirectResponse(location, 302)


@router.get("/client/users/me")
async def get_me(request: Request):
    user = user_from_auth_header(request.headers)
    if user is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return get_authenticated_user_response(user)


@router.websocket("/client/users/connect")
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


@router.post("/client/llm_tokens")
async def create_llm_token(request: Request):
    if user_from_auth_header(request.headers) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"token": "unsupported-llm-token"}


@router.patch("/client/system_settings")
async def update_system_settings(request: Request):
    if user_from_auth_header(request.headers) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    return {"selected_organization_id": body.get("selected_organization_id")}
