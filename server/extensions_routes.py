"""Extensions API.

Zed's extension store (crates/extension_host) reaches these routes via
`build_zed_api_url`, which for a custom server_url uses the same base URL — so
they live on the client-facing HTTPS listener alongside /client/*.

  GET /extensions?max_schema_version=&filter=&provides=   catalog / search
  GET /extensions/updates?ids=&min_schema_version=&...     update check
  GET /extensions/{id}                                     versions of one ext
  GET /extensions/{id}/download                            latest archive.tar.gz
  GET /extensions/{id}/{version}/download                  a specific archive

The JSON routes return {"data": [ExtensionMetadata]} (matching collab /
cloud_api_types::GetExtensionsResponse). Populate with scrape_extensions.py.
"""

from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse

from .assets import load_extension_index, semver_key, stream_blob
from .config import config

router = APIRouter(prefix="/extensions")

# Fields that are internal to the mirror and must not leak into API responses
# (the client deserializes into a strict ExtensionMetadata struct).
_EXT_INTERNAL_FIELDS = ("archive", "key", "size")


def _public_metadata(entry: dict) -> dict:
    return {k: v for k, v in entry.items() if k not in _EXT_INTERNAL_FIELDS}


def _latest_version(entries: list[dict]) -> dict:
    return max(entries, key=lambda e: semver_key(e["version"]))


def _serve_extension_archive(entry: dict):
    archive = entry.get("archive")
    if config.blobs is not None:
        key = entry.get("key")
        if not key:
            return JSONResponse({"error": "no archive for version"}, status_code=404)
        return stream_blob(key, archive, "application/gzip")
    if not archive:
        return JSONResponse({"error": "no archive for version"}, status_code=404)
    path = config.extensions_dir / archive
    if not path.exists():
        return JSONResponse({"error": "archive file missing"}, status_code=404)
    return FileResponse(path, media_type="application/gzip", filename=archive)


@router.get("")
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


@router.get("/updates")
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


@router.get("/{extension_id}")
async def extension_versions(extension_id: str):
    entries = load_extension_index().get(extension_id, [])
    data = [
        _public_metadata(e)
        for e in sorted(entries, key=lambda e: semver_key(e["version"]), reverse=True)
    ]
    return {"data": data}


@router.get("/{extension_id}/download")
async def download_latest_extension(extension_id: str):
    entries = load_extension_index().get(extension_id)
    if not entries:
        return JSONResponse({"error": "unknown extension"}, status_code=404)
    return _serve_extension_archive(_latest_version(entries))


@router.get("/{extension_id}/{version}/download")
async def download_extension(extension_id: str, version: str):
    entries = load_extension_index().get(extension_id, [])
    entry = next((e for e in entries if e["version"] == version), None)
    if entry is None:
        return JSONResponse({"error": "unknown extension version"}, status_code=404)
    return _serve_extension_archive(entry)
