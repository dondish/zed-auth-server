"""Upload an already-scraped local extensions/ folder to S3.

`scrape_extensions.py` fetches from api.zed.dev and can upload as it goes; this
utility instead pushes a folder you already have on disk (its index.json + the
`<id>-<version>.tar.gz` archives) into the bucket, without re-downloading.

It merges into the existing S3 index (existing entries are kept) and skips
archives already present in the bucket, so it is safe to re-run.

Usage (S3_* env must point at the bucket, e.g. MinIO on localhost:9000):
    python -m scripts.upload_extensions
    python -m scripts.upload_extensions --extensions-dir extensions --limit 50
"""

import argparse
import json
from pathlib import Path

from server.blobstore import EXTENSIONS_INDEX_KEY, BlobStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extensions-dir", default="extensions")
    parser.add_argument(
        "--limit", type=int, default=0,
        help="cap number of extensions uploaded (0 = no cap)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="re-upload archives even if already present in the bucket",
    )
    args = parser.parse_args()

    blobs = BlobStore.from_env()
    if blobs is None:
        raise SystemExit(
            "S3 is not configured — set S3_ENDPOINT_URL/S3_BUCKET (and keys)."
        )

    src = Path(args.extensions_dir)
    local = json.loads((src / "index.json").read_text(encoding="utf-8"))
    local_exts = local.get("extensions", {})

    blobs.ensure_bucket()
    index = blobs.get_json(EXTENSIONS_INDEX_KEY) or {}
    extensions = index.setdefault("extensions", {})

    ids = sorted(local_exts)
    if args.limit:
        ids = ids[: args.limit]

    uploaded = skipped = missing = 0
    for i, ext_id in enumerate(ids, 1):
        merged = {e["version"]: e for e in extensions.get(ext_id, [])}
        for entry in local_exts[ext_id]:
            version = entry["version"]
            archive = entry.get("archive") or f"{ext_id}-{version}.tar.gz"
            path = src / archive
            if not path.exists():
                print(f"  ! missing archive on disk: {archive}")
                missing += 1
                continue
            key = f"extensions/{ext_id}/{version}/archive.tar.gz"
            if args.force or not blobs.exists(key):
                blobs.put_file(key, path, "application/gzip")
                uploaded += 1
            else:
                skipped += 1
            e = dict(entry)
            e["key"] = key
            e["size"] = path.stat().st_size
            merged[version] = e
        extensions[ext_id] = sorted(merged.values(), key=lambda e: e["version"])
        if i % 100 == 0:
            print(f"  {i}/{len(ids)} extensions processed…")

    blobs.put_json(EXTENSIONS_INDEX_KEY, index)
    total = sum(len(v) for v in extensions.values())
    print(
        f"\nDone. uploaded={uploaded} skipped(existing)={skipped} missing={missing}\n"
        f"Bucket now indexes {len(extensions)} extensions ({total} versions)."
    )


if __name__ == "__main__":
    main()
