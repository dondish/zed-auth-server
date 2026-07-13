"""Internal API used by collab (Bearer-authenticated with the shared key).

collab in development mode hardcodes the cloud URL to http://localhost:8787, so
these are served on the loopback HTTP listener too (see server.serve)."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .collab_db import ensure_collab_user
from .config import config
from .schemas import internal_user_json

router = APIRouter(prefix="/internal")


def check_internal_key(request: Request) -> bool:
    return request.headers.get("authorization") == f"Bearer {config.internal_api_key}"


class ImpersonateBody(BaseModel):
    github_login: str


@router.post("/users/impersonate")
async def impersonate(request: Request, body: ImpersonateBody):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    user = config.store.get_or_create_user(body.github_login)
    ensure_collab_user(user)
    token = config.store.issue_token(user)
    return {"user_id": user["legacy_user_id"], "access_token": token}


class LookUpByLegacyIdBody(BaseModel):
    legacy_user_ids: list[int]


@router.post("/users/look_up_by_legacy_id")
async def look_up_by_legacy_id(request: Request, body: LookUpByLegacyIdBody):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    users = [
        internal_user_json(user)
        for legacy_id in body.legacy_user_ids
        if (user := config.store.user_by_legacy_id(legacy_id)) is not None
    ]
    return {"users": users}


class LookUpByGithubLoginBody(BaseModel):
    github_login: str


@router.post("/users/look_up_by_github_login")
async def look_up_by_github_login(request: Request, body: LookUpByGithubLoginBody):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    user = config.store.user_by_github_login(body.github_login)
    return {"user": internal_user_json(user) if user else None}


class FuzzySearchBody(BaseModel):
    query: str
    limit: int


@router.post("/users/fuzzy_search")
async def fuzzy_search_users(request: Request, body: FuzzySearchBody):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    matches = [
        internal_user_json(u) for u in config.store.search_users(body.query, body.limit)
    ]
    return {"users": matches}


class FuzzySearchChannelMembersBody(BaseModel):
    channel_id: int
    query: str
    limit: int


@router.post("/channel_members/fuzzy_search_by_github_login")
async def fuzzy_search_channel_members(
    request: Request, body: FuzzySearchChannelMembersBody
):
    if not check_internal_key(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    # Channel membership lives in collab's own database; we don't have it here.
    # Returning matching users with no member records keeps the search usable.
    matches = [
        internal_user_json(u) for u in config.store.search_users(body.query, body.limit)
    ]
    return {"channel_members": [], "users": matches}
