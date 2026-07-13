"""Release / auto-update API + the installer web UI.

Zed's auto-updater (crates/auto_update) calls
  GET /releases/{channel}/{version}/asset?asset=zed&os=..&arch=..
and expects JSON {"version": "..", "url": ".."}. It then downloads `url`, and
on Windows runs it as an installer. `version` may be "latest". We host the
installers ourselves (S3/MinIO or local) so updates come from this machine.
Populate the store with scrape_releases.py.
"""

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from .assets import human_size, load_release_index, semver_key, stream_blob
from .config import config

router = APIRouter()


@router.get("/releases/{channel}/{version}/asset")
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
        return JSONResponse({"error": f"no releases for {key}"}, status_code=404)

    if version == "latest":
        entry = max(entries, key=lambda e: semver_key(e["version"]))
    else:
        wanted = semver_key(version)
        entry = next(
            (e for e in entries if semver_key(e["version"]) == wanted), None
        )
        if entry is None:
            return JSONResponse(
                {"error": f"version {version} not found for {key}"}, status_code=404
            )

    # Point the download URL back at this server so updates are self-hosted.
    base = str(request.base_url).rstrip("/")
    download_url = f"{base}/releases/download/{channel}/{os}/{arch}/{asset}/{entry['file']}"
    return {"version": entry["version"], "url": download_url}


@router.get("/releases/download/{channel}/{os}/{arch}/{asset}/{filename}")
async def release_download(
    channel: str, os: str, arch: str, asset: str, filename: str
):
    # Guard against path traversal: only serve files named in the index.
    key = f"{channel}/{os}/{arch}/{asset}"
    entries = load_release_index().get(key, [])
    entry = next((e for e in entries if e["file"] == filename), None)
    if entry is None:
        return JSONResponse({"error": "unknown asset"}, status_code=404)
    if config.blobs is not None:
        return stream_blob(entry["key"], filename, "application/octet-stream")
    path = config.releases_dir / filename
    if not path.exists():
        return JSONResponse({"error": "asset file missing"}, status_code=404)
    return FileResponse(path, media_type="application/octet-stream", filename=filename)


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


@router.get("/", response_class=HTMLResponse)
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
        latest = max(entries, key=lambda e: semver_key(e["version"]))["version"]
        rows = []
        for entry in sorted(entries, key=lambda e: semver_key(e["version"]), reverse=True):
            if entry.get("size"):
                size = human_size(entry["size"])
            else:
                file_path = config.releases_dir / entry["file"]
                size = human_size(file_path.stat().st_size) if file_path.exists() else "—"
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
        "<code>python -m scripts.scrape_releases</code>.</p>"
    )
    return HTMLResponse(INDEX_PAGE_HEAD + body + INDEX_PAGE_FOOT)
