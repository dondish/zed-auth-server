"""Shared helpers for serving release installers + extension archives.

Assets live in S3/MinIO when config.blobs is set, otherwise on the local
filesystem; either way the server streams the bytes back through its own HTTPS
listener. Index manifests are cached briefly to avoid re-fetching from S3 on
every request.
"""

import json
import time
from pathlib import Path
from typing import Optional

from fastapi.responses import JSONResponse, StreamingResponse

from .blobstore import ACP_INDEX_KEY, EXTENSIONS_INDEX_KEY, RELEASES_INDEX_KEY
from .config import config

# Small TTL cache so the index isn't re-fetched from S3 on every request.
_index_cache: dict[str, tuple[float, dict]] = {}
_INDEX_TTL = 30.0


def semver_key(version: str) -> tuple:
    # Compare only the numeric release fields (matches the client, which
    # strips pre-release/build metadata before comparing).
    parts = version.split("-")[0].split(".")
    return tuple(int(p) if p.isdigit() else 0 for p in parts)


def _load_index(local_path: Path, s3_key: str) -> dict:
    if config.blobs is None:
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
    data = config.blobs.get_json(s3_key) or {}
    _index_cache[s3_key] = (now, data)
    return data


def load_release_index() -> dict:
    return _load_index(config.releases_dir / "index.json", RELEASES_INDEX_KEY)


def load_extension_index() -> dict:
    return _load_index(
        config.extensions_dir / "index.json", EXTENSIONS_INDEX_KEY
    ).get("extensions", {})


def load_acp_index() -> dict:
    """The mirrored ACP registry: {"version": str, "agents": {<id>: entry}}."""
    return _load_index(config.acp_dir / "index.json", ACP_INDEX_KEY)


def stream_blob(key: str, filename: Optional[str], media_type: str):
    """Stream an object from S3 back through this server."""
    result = config.blobs.open_stream(key)
    if result is None:
        return JSONResponse({"error": "asset file missing"}, status_code=404)
    chunks, length, _content_type = result
    headers = {}
    if length:
        headers["Content-Length"] = str(length)
    if filename:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return StreamingResponse(chunks, media_type=media_type, headers=headers)


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"
