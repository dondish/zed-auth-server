"""S3 / MinIO blob storage shared by the server and the scrapers.

Stores the release installers and extension archives (plus their index.json
manifests) in an S3 bucket instead of the local filesystem. The server streams
the bytes back through its own HTTPS listener, so clients only ever talk to the
auth server — MinIO/S3 never has to be exposed to them.

Enabled when `S3_ENDPOINT_URL` or `S3_BUCKET` is set. Config (env):

    S3_ENDPOINT_URL        e.g. http://minio:9000 (unset = real AWS S3)
    S3_BUCKET              bucket name (default "zed-assets")
    S3_REGION              default "us-east-1"
    S3_ACCESS_KEY_ID       access key (falls back to AWS_ACCESS_KEY_ID)
    S3_SECRET_ACCESS_KEY   secret key (falls back to AWS_SECRET_ACCESS_KEY)
    S3_FORCE_PATH_STYLE    "1"/"0"; defaults to on when an endpoint is set
                           (MinIO needs path-style addressing)

Bucket layout:
    releases/index.json
    releases/<channel>/<os>/<arch>/<asset>/<version>/<filename>
    extensions/index.json
    extensions/<id>/<version>/archive.tar.gz
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator, Optional

RELEASES_INDEX_KEY = "releases/index.json"
EXTENSIONS_INDEX_KEY = "extensions/index.json"

_CHUNK = 1 << 20  # 1 MiB streaming chunks


def _truthy(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class BlobStore:
    def __init__(
        self,
        *,
        bucket: str,
        endpoint_url: Optional[str] = None,
        region: str = "us-east-1",
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        path_style: Optional[bool] = None,
    ):
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover
            raise SystemExit(
                "S3 storage is configured but boto3 is not installed "
                "(pip install boto3)."
            ) from exc

        self.bucket = bucket
        if path_style is None:
            path_style = endpoint_url is not None
        config = Config(
            signature_version="s3v4",
            s3={"addressing_style": "path" if path_style else "auto"},
            retries={"max_attempts": 3, "mode": "standard"},
        )
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=config,
        )

    @classmethod
    def from_env(cls) -> Optional["BlobStore"]:
        endpoint = os.environ.get("S3_ENDPOINT_URL")
        bucket = os.environ.get("S3_BUCKET")
        if not endpoint and not bucket:
            return None
        return cls(
            bucket=bucket or "zed-assets",
            endpoint_url=endpoint,
            region=os.environ.get("S3_REGION", "us-east-1"),
            access_key=os.environ.get("S3_ACCESS_KEY_ID")
            or os.environ.get("AWS_ACCESS_KEY_ID"),
            secret_key=os.environ.get("S3_SECRET_ACCESS_KEY")
            or os.environ.get("AWS_SECRET_ACCESS_KEY"),
            path_style=_truthy(os.environ.get("S3_FORCE_PATH_STYLE"), endpoint is not None),
        )

    # --- reads -------------------------------------------------------------

    def get_json(self, key: str) -> Optional[dict]:
        from botocore.exceptions import ClientError

        try:
            obj = self._client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None
            raise
        return json.loads(obj["Body"].read().decode("utf-8"))

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError:
            return False

    def open_stream(self, key: str) -> Optional[tuple[Iterator[bytes], int, str]]:
        """Return (chunk iterator, content length, content type) or None."""
        from botocore.exceptions import ClientError

        try:
            obj = self._client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "NoSuchKey",
                "404",
                "NoSuchBucket",
            ):
                return None
            raise

        body = obj["Body"]

        def chunks() -> Iterator[bytes]:
            try:
                yield from body.iter_chunks(_CHUNK)
            finally:
                body.close()

        length = int(obj.get("ContentLength", 0))
        content_type = obj.get("ContentType") or "application/octet-stream"
        return chunks(), length, content_type

    # --- writes (used by the scrapers) -------------------------------------

    def ensure_bucket(self) -> None:
        from botocore.exceptions import ClientError

        try:
            self._client.head_bucket(Bucket=self.bucket)
        except ClientError:
            self._client.create_bucket(Bucket=self.bucket)

    def put_json(self, key: str, obj: dict) -> None:
        self._client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(obj, indent=2).encode("utf-8"),
            ContentType="application/json",
        )

    def put_file(self, key: str, path: Path, content_type: str) -> None:
        self._client.upload_file(
            str(path),
            self.bucket,
            key,
            ExtraArgs={"ContentType": content_type},
        )
