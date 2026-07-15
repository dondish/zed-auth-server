"""Mirror the ACP agent registry for this server's /registry API.

Fetches the real ACP registry index (cdn.agentclientprotocol.com), downloads
each selected agent's per-platform binary archive + icon, and records the
metadata in acp/index.json so the server can serve the registry — and stream
the archives — from this machine. See server/registry_routes.py.

The mirror index keeps the registry's shape but stores local filenames instead
of upstream URLs (the server rewrites them to absolute URLs at request time):

    index = {
        "version": "<registry schema version>",
        "agents": {
            "<id>": {
                "id", "name", "version", "description", "repository", "website",
                "icon": true,                       # present iff an icon was mirrored
                "binary": {
                    "<platform>": {"archive": "<filename>", "cmd", "args", "env"}
                },
                "npx": {"package", "args", "env"}   # passthrough (installs from npm)
            }
        }
    }

npx-only agents need no download — their npm package is fetched by Zed at
install time — so they are recorded even when no platform is mirrored.

Usage:
    python -m scripts.scrape_acp_registry                    # all agents, host platform
    python -m scripts.scrape_acp_registry --ids gemini codex
    python -m scripts.scrape_acp_registry --platforms all    # every platform's binary
    python -m scripts.scrape_acp_registry --platforms linux-x86_64 darwin-aarch64
"""

import argparse
import json
import platform as _platform
import urllib.parse
import urllib.request
from pathlib import Path

from server.blobstore import ACP_INDEX_KEY, BlobStore

REGISTRY_URL = "https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json"
ICON_RAW_BASE = "https://raw.githubusercontent.com/agentclientprotocol/registry/main"
USER_AGENT = "zed-auth-server-scraper/1.0"

ALL_PLATFORMS = [
    "darwin-aarch64",
    "darwin-x86_64",
    "linux-aarch64",
    "linux-x86_64",
    "windows-aarch64",
    "windows-x86_64",
]


def _open(url: str, timeout: int):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def current_platform() -> str | None:
    os_map = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}
    arch_map = {
        "arm64": "aarch64",
        "aarch64": "aarch64",
        "x86_64": "x86_64",
        "amd64": "x86_64",
    }
    os_ = os_map.get(_platform.system())
    arch = arch_map.get(_platform.machine().lower())
    if not os_ or not arch:
        return None
    return f"{os_}-{arch}"


def fetch_registry() -> dict:
    with _open(REGISTRY_URL, timeout=30) as resp:
        return json.loads(resp.read().decode())


def archive_filename(url: str, agent_id: str, platform: str) -> str:
    """The last path segment of the archive URL, preserving its suffix."""
    name = Path(urllib.parse.urlparse(url).path).name
    return urllib.parse.unquote(name) or f"{agent_id}-{platform}"


def resolve_icon_url(agent_id: str, icon: str) -> str:
    # Mirrors resolve_icon_url() in agent_registry_store.rs.
    if icon.startswith("https://") or icon.startswith("http://"):
        return icon
    return f"{ICON_RAW_BASE}/{agent_id}/{icon.lstrip('./')}"


def download(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"    already have {dest.name} ({dest.stat().st_size // 1024}KB)")
        return
    print(f"    downloading {dest.name}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with _open(url, timeout=180) as resp:
        with open(tmp, "wb") as f:
            while chunk := resp.read(1 << 20):
                f.write(chunk)
    tmp.rename(dest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ids", nargs="+", help="agent ids to mirror (default: all)")
    parser.add_argument(
        "--platforms",
        nargs="+",
        help="platform keys to mirror binaries for, or 'all' "
        f"(default: the host platform). One of: {', '.join(ALL_PLATFORMS)}",
    )
    parser.add_argument("--out-dir", default="acp")
    args = parser.parse_args()

    if args.platforms and "all" in args.platforms:
        platforms = ALL_PLATFORMS
    elif args.platforms:
        platforms = args.platforms
    else:
        host = current_platform()
        if host is None:
            raise SystemExit("could not detect host platform; pass --platforms")
        platforms = [host]
    print(f"mirroring binaries for: {', '.join(platforms)}")

    registry = fetch_registry()
    agents = registry.get("agents", [])
    if args.ids:
        wanted = set(args.ids)
        found = {a["id"] for a in agents if a["id"] in wanted}
        for missing in sorted(wanted - found):
            print(f"  warning: agent {missing!r} not found in registry")
        agents = [a for a in agents if a["id"] in wanted]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    index_path = out_dir / "index.json"

    blobs = BlobStore.from_env()
    if blobs is not None:
        blobs.ensure_bucket()
        index = blobs.get_json(ACP_INDEX_KEY) or {}
        print(f"uploading to S3 bucket '{blobs.bucket}'")
    else:
        index = json.loads(index_path.read_text()) if index_path.exists() else {}
    index["version"] = registry.get("version", "1")
    mirror = index.setdefault("agents", {})

    for agent in agents:
        agent_id = agent["id"]
        version = agent.get("version", "")
        print(f"{agent_id} @ {version}")
        entry: dict = {
            "id": agent_id,
            "name": agent.get("name", agent_id),
            "version": version,
            "description": agent.get("description", ""),
        }
        for optional in ("repository", "website"):
            if agent.get(optional):
                entry[optional] = agent[optional]

        # Icon (SVG only — Zed renders registry icons as SVG).
        icon = agent.get("icon")
        if icon:
            icon_url = resolve_icon_url(agent_id, icon)
            if icon_url.lower().split("?")[0].endswith(".svg"):
                dest = out_dir / agent_id / "icon.svg"
                try:
                    download(icon_url, dest)
                    if blobs is not None:
                        blobs.put_file(
                            f"acp/{agent_id}/icon.svg", dest, "image/svg+xml"
                        )
                    entry["icon"] = True
                except Exception as exc:  # noqa: BLE001 - best-effort icon
                    print(f"    warning: icon download failed: {exc}")
            else:
                print(f"    skipping non-SVG icon: {icon_url}")

        distribution = agent.get("distribution", {})

        # Binary targets for the selected platforms.
        binary_in = distribution.get("binary") or {}
        binary_out = {}
        for platform in platforms:
            target = binary_in.get(platform)
            if not target:
                continue
            filename = archive_filename(target["archive"], agent_id, platform)
            dest = out_dir / agent_id / version / platform / filename
            download(target["archive"], dest)
            if blobs is not None:
                blobs.put_file(
                    f"acp/{agent_id}/{version}/{platform}/{filename}",
                    dest,
                    "application/octet-stream",
                )
            binary_out[platform] = {
                "archive": filename,
                "cmd": target.get("cmd", ""),
                "args": target.get("args", []),
                "env": target.get("env", {}),
            }
        if binary_out:
            entry["binary"] = binary_out

        # npx distribution installs from npm directly — pass through.
        npx = distribution.get("npx")
        if npx:
            entry["npx"] = {
                "package": npx["package"],
                "args": npx.get("args", []),
                "env": npx.get("env", {}),
            }

        if not entry.get("binary") and not entry.get("npx"):
            print("    no mirrorable distribution for selected platforms — skipped")
            continue
        mirror[agent_id] = entry

    if blobs is not None:
        blobs.put_json(ACP_INDEX_KEY, index)
        print(f"\nWrote s3://{blobs.bucket}/{ACP_INDEX_KEY} ({len(mirror)} agents)")
    else:
        index_path.write_text(json.dumps(index, indent=2))
        print(f"\nWrote {index_path} ({len(mirror)} agents)")


if __name__ == "__main__":
    main()
