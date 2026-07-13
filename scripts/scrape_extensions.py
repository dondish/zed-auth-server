"""Scrape Zed extensions and build a local index for the /extensions API.

Queries Zed's real extension API (api.zed.dev) for a set of extensions,
downloads each one's `archive.tar.gz`, and records the metadata in
extensions/index.json so server.py can serve them from this machine.

The index mirrors the shape Zed expects back from the API — each entry is an
`ExtensionMetadata` (id + flattened manifest + published_at + download_count),
plus an `archive` field naming the local tarball.

    index = {
        "extensions": {
            "<id>": [ { ...ExtensionMetadata, "archive": "<id>-<version>.tar.gz" } ],
            ...
        }
    }

The list endpoint only returns the latest version of each extension, so each
id maps to a single-version list here (which is all the client needs to
install / update).

Usage:
    python -m scripts.scrape_extensions                       # default curated set
    python -m scripts.scrape_extensions --filter toml         # everything matching "toml"
    python -m scripts.scrape_extensions --ids toml dockerfile git-firefly
    python -m scripts.scrape_extensions --all --limit 50      # top 50 by downloads
"""

import argparse
import json
import urllib.parse
import urllib.request
from pathlib import Path

from server.blobstore import EXTENSIONS_INDEX_KEY, BlobStore

UPSTREAM = "https://api.zed.dev"
# The client's CURRENT_SCHEMA_VERSION (crates/extension_host). Extensions
# published against a newer schema than the client understands are skipped.
MAX_SCHEMA_VERSION = 1
USER_AGENT = "zed-auth-server-scraper/1.0"

# A small, broadly-useful default set so a fresh mirror isn't empty.
DEFAULT_IDS = [
    "toml",
    "dockerfile",
    "html",
    "make",
    "log",
    "nix",
]


def _open(url: str, timeout: int):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def fetch_list(filter_: str | None) -> list[dict]:
    query = {"max_schema_version": MAX_SCHEMA_VERSION}
    if filter_:
        query["filter"] = filter_
    url = f"{UPSTREAM}/extensions?" + urllib.parse.urlencode(query)
    with _open(url, timeout=30) as resp:
        return json.loads(resp.read().decode())["data"]


def download(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"  already have {dest.name} ({dest.stat().st_size // 1024}KB)")
        return
    print(f"  downloading {dest.name}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    with _open(url, timeout=120) as resp:
        with open(tmp, "wb") as f:
            while chunk := resp.read(1 << 16):
                f.write(chunk)
    tmp.rename(dest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ids", nargs="+", help="explicit extension ids to mirror")
    group.add_argument("--filter", dest="filter_", help="search term (server-side)")
    group.add_argument("--all", action="store_true", help="mirror every extension")
    parser.add_argument(
        "--limit", type=int, default=0,
        help="cap number of extensions (0 = no cap); highest download_count first",
    )
    parser.add_argument("--out-dir", default="extensions")
    args = parser.parse_args()

    # Decide which extensions to mirror.
    if args.ids:
        wanted = set(args.ids)
        catalog = [e for e in fetch_list(None) if e["id"] in wanted]
        missing = wanted - {e["id"] for e in catalog}
        for m in sorted(missing):
            print(f"  warning: extension {m!r} not found upstream")
    elif args.filter_:
        catalog = fetch_list(args.filter_)
    elif args.all:
        catalog = fetch_list(None)
    else:
        wanted = set(DEFAULT_IDS)
        catalog = [e for e in fetch_list(None) if e["id"] in wanted]

    catalog.sort(key=lambda e: e.get("download_count", 0), reverse=True)
    if args.limit:
        catalog = catalog[: args.limit]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    index_path = out_dir / "index.json"

    # When S3 is configured, the authoritative index lives in the bucket.
    blobs = BlobStore.from_env()
    if blobs is not None:
        blobs.ensure_bucket()
        index = blobs.get_json(EXTENSIONS_INDEX_KEY) or {}
        print(f"uploading to S3 bucket '{blobs.bucket}'")
    else:
        index = json.loads(index_path.read_text()) if index_path.exists() else {}
    extensions = index.setdefault("extensions", {})

    for meta in catalog:
        ext_id = meta["id"]
        version = meta["version"]
        print(f"{ext_id} @ {version}")
        archive = f"{ext_id}-{version}.tar.gz"
        url = f"{UPSTREAM}/extensions/{ext_id}/download"
        dest = out_dir / archive
        download(url, dest)
        entry = dict(meta)
        entry["archive"] = archive
        entry["size"] = dest.stat().st_size
        if blobs is not None:
            s3_key = f"extensions/{ext_id}/{version}/archive.tar.gz"
            blobs.put_file(s3_key, dest, "application/gzip")
            entry["key"] = s3_key
        # Replace any prior entry for this exact version; keep others.
        versions = [e for e in extensions.get(ext_id, []) if e["version"] != version]
        versions.append(entry)
        versions.sort(key=lambda e: e["version"])
        extensions[ext_id] = versions

    total = sum(len(v) for v in extensions.values())
    if blobs is not None:
        blobs.put_json(EXTENSIONS_INDEX_KEY, index)
        print(f"\nWrote s3://{blobs.bucket}/{EXTENSIONS_INDEX_KEY} "
              f"({len(extensions)} extensions, {total} versions)")
    else:
        index_path.write_text(json.dumps(index, indent=2))
        print(f"\nWrote {index_path} ({len(extensions)} extensions, {total} versions)")


if __name__ == "__main__":
    main()
