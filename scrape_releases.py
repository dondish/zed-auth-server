"""Scrape Zed release installers and build a local index for the /releases API.

Queries Zed's real release endpoint (cloud.zed.dev) for a set of versions,
downloads the platform installer for each, and records everything in
releases/index.json so server.py can serve updates from this machine.

The index is keyed by (channel, os, arch, asset) -> list of {version, file}.
server.py resolves "latest" by picking the highest semver in the matching list.

Usage:
    python scrape_releases.py                          # default: last 3 stable
    python scrape_releases.py --versions 1.10.2 1.9.0
    python scrape_releases.py --os windows --arch x86_64 --asset zed
"""

import argparse
import json
import urllib.request
from pathlib import Path

from blobstore import RELEASES_INDEX_KEY, BlobStore

UPSTREAM = "https://cloud.zed.dev"
DEFAULT_VERSIONS = ["1.10.2", "1.10.1", "1.10.0"]
# GitHub's asset CDN returns 403 for requests without a browser-like UA.
USER_AGENT = "zed-auth-server-scraper/1.0"


def _open(url: str, timeout: int):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def fetch_metadata(channel: str, version: str, os_: str, arch: str, asset: str) -> dict:
    url = (
        f"{UPSTREAM}/releases/{channel}/{version}/asset"
        f"?asset={asset}&os={os_}&arch={arch}"
    )
    with _open(url, timeout=30) as resp:
        return json.loads(resp.read().decode())


def download(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"  already have {dest.name} ({dest.stat().st_size // 1024 // 1024}MB)")
        return
    print(f"  downloading {url}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    with _open(url, timeout=120) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        read = 0
        with open(tmp, "wb") as f:
            while chunk := resp.read(1 << 20):
                f.write(chunk)
                read += len(chunk)
                if total:
                    pct = read * 100 // total
                    print(f"\r    {read // 1024 // 1024}/{total // 1024 // 1024}MB "
                          f"({pct}%)", end="", flush=True)
        print()
    tmp.rename(dest)


def ext_for(os_: str, asset: str) -> str:
    """File extension the Zed client expects for a given os/asset."""
    if asset == "zed-remote-server":
        return "gz" if os_ in ("macos", "linux") else "zip"
    return {"windows": "exe", "macos": "dmg", "linux": "tar.gz"}[os_]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--os", dest="os_", default="windows")
    parser.add_argument("--arch", default="x86_64")
    parser.add_argument("--asset", default="zed")
    parser.add_argument("--versions", nargs="+", default=DEFAULT_VERSIONS)
    parser.add_argument("--out-dir", default="releases")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    index_path = out_dir / "index.json"

    # When S3 is configured, the authoritative index lives in the bucket.
    blobs = BlobStore.from_env()
    if blobs is not None:
        blobs.ensure_bucket()
        index = blobs.get_json(RELEASES_INDEX_KEY) or {}
        print(f"uploading to S3 bucket '{blobs.bucket}'")
    else:
        index = json.loads(index_path.read_text()) if index_path.exists() else {}

    # Key groups entries by everything except version.
    key = f"{args.channel}/{args.os_}/{args.arch}/{args.asset}"
    entries = {e["version"]: e for e in index.get(key, [])}

    for version in args.versions:
        print(f"{key} @ {version}")
        meta = fetch_metadata(args.channel, version, args.os_, args.arch, args.asset)
        real_version = meta["version"]
        ext = ext_for(args.os_, args.asset)
        filename = f"{args.asset}-{real_version}-{args.os_}-{args.arch}.{ext}"
        dest = out_dir / filename
        download(meta["url"], dest)
        entry = {
            "version": real_version,
            "file": filename,
            "source_url": meta["url"],
            "size": dest.stat().st_size,
        }
        if blobs is not None:
            s3_key = f"releases/{key}/{real_version}/{filename}"
            blobs.put_file(s3_key, dest, "application/octet-stream")
            entry["key"] = s3_key
        entries[real_version] = entry

    index[key] = sorted(entries.values(), key=lambda e: e["version"])
    if blobs is not None:
        blobs.put_json(RELEASES_INDEX_KEY, index)
        print(f"\nWrote s3://{blobs.bucket}/{RELEASES_INDEX_KEY} "
              f"({sum(len(v) for v in index.values())} entries total)")
    else:
        index_path.write_text(json.dumps(index, indent=2))
        print(f"\nWrote {index_path} ({sum(len(v) for v in index.values())} entries total)")


if __name__ == "__main__":
    main()
