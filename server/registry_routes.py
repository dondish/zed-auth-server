"""ACP registry API — the Agent Client Protocol registry Zed installs from.

As of Zed v1.5.0, external ("ACP") agents are installed from the ACP registry
(https://agentclientprotocol.com/registry) rather than from extensions. Zed's
`AgentRegistryStore` (crates/project/src/agent_registry_store.rs) fetches a
single `registry.json` from a **hardcoded** URL —

    https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json

— then, when the user installs a binary agent, downloads the per-platform
`archive` URL named inside it. Neither URL is derived from `server_url`, so to
self-host the registry you point Zed at this server by intercepting that host
(hosts entry + a cert SAN for cdn.agentclientprotocol.com) or by patching
`REGISTRY_URL`. See the README.

This router mirrors the registry the same way extensions_routes mirrors the
extension store: the JSON is served from a local `acp/index.json` manifest (or
S3), and the agent archives + icons are streamed back through this server, so
clients only ever talk to the auth server. Populate it with
`python -m scripts.scrape_acp_registry`.

  GET /registry/v1/latest/registry.json          the registry index
  GET /registry/archives/{id}/{version}/{platform}/{filename}   an agent archive
  GET /registry/icons/{id}                        an agent icon (SVG)

Archive/icon URLs in the served index point back at the request's own base URL
(like GET /rpc), so the same manifest works whether Zed reaches this server via
the intercepted CDN host or a patched registry URL.
"""

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse

from .assets import load_acp_index, stream_blob
from .config import config

router = APIRouter(prefix="/registry")


def _agent_public(agent_id: str, entry: dict, base: str) -> dict:
    """Build one ACP RegistryEntry from a mirror index entry.

    Shapes match crates/project/src/agent_registry_store.rs: a flat entry with
    a `distribution` holding `binary` (per-platform {archive,cmd,args,env}) and
    optionally `npx` ({package,args,env}).
    """
    out: dict = {
        "id": agent_id,
        "name": entry.get("name", agent_id),
        "version": entry.get("version", ""),
        "description": entry.get("description", ""),
    }
    for optional in ("repository", "website"):
        if entry.get(optional):
            out[optional] = entry[optional]
    if entry.get("icon"):
        out["icon"] = f"{base}/registry/icons/{agent_id}"

    distribution: dict = {}
    binary = entry.get("binary") or {}
    if binary:
        version = entry.get("version", "")
        targets = {}
        for platform, target in binary.items():
            targets[platform] = {
                "archive": (
                    f"{base}/registry/archives/{agent_id}/{version}"
                    f"/{platform}/{target['archive']}"
                ),
                "cmd": target.get("cmd", ""),
                "args": target.get("args", []),
                "env": target.get("env", {}),
            }
        distribution["binary"] = targets
    if entry.get("npx"):
        # npx agents install straight from the npm registry — pass through.
        distribution["npx"] = entry["npx"]

    out["distribution"] = distribution
    return out


@router.get("/v1/latest/registry.json")
async def registry_index(request: Request):
    index = load_acp_index()
    agents = index.get("agents", {})
    base = str(request.base_url).rstrip("/")
    data = [
        _agent_public(agent_id, entry, base)
        for agent_id, entry in sorted(agents.items())
    ]
    return {"version": index.get("version", "1"), "agents": data}


@router.get("/archives/{agent_id}/{version}/{platform}/{filename}")
async def registry_archive(agent_id: str, version: str, platform: str, filename: str):
    entry = load_acp_index().get("agents", {}).get(agent_id)
    if entry is None:
        return JSONResponse({"error": "unknown agent"}, status_code=404)
    target = (entry.get("binary") or {}).get(platform)
    # Validate every component against the index to guard against traversal:
    # only serve the exact filename recorded for this agent/version/platform.
    if (
        target is None
        or entry.get("version") != version
        or target.get("archive") != filename
    ):
        return JSONResponse({"error": "unknown agent archive"}, status_code=404)

    if config.blobs is not None:
        key = f"acp/{agent_id}/{version}/{platform}/{filename}"
        return stream_blob(key, filename, "application/octet-stream")
    path = config.acp_dir / agent_id / version / platform / filename
    if not path.exists():
        return JSONResponse({"error": "archive file missing"}, status_code=404)
    return FileResponse(path, media_type="application/octet-stream", filename=filename)


@router.get("/icons/{agent_id}")
async def registry_icon(agent_id: str):
    entry = load_acp_index().get("agents", {}).get(agent_id)
    if entry is None or not entry.get("icon"):
        return JSONResponse({"error": "unknown agent icon"}, status_code=404)

    if config.blobs is not None:
        return stream_blob(f"acp/{agent_id}/icon.svg", None, "image/svg+xml")
    path = config.acp_dir / agent_id / "icon.svg"
    if not path.exists():
        return JSONResponse({"error": "icon file missing"}, status_code=404)
    return FileResponse(path, media_type="image/svg+xml")
