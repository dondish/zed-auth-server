"""Entry point for the self-hosted Zed auth + cloud-API stand-in.

Parses CLI flags / env, populates `config.config`, and runs the FastAPI app
(see app.py for the architecture overview) on two listeners:

  * HTTPS on --port           — what Zed's `server_url` points at
  * HTTP  on --internal-port   — loopback; what collab's development
    zed_cloud_url (http://localhost:8787) points at

Identity is GitLab OAuth when GITLAB_CLIENT_ID/SECRET are set (any gitlab.com or
self-hosted instance via GITLAB_URL), else a password-less username form. Users
and tokens persist in Postgres when AUTH_DATABASE_URL is set (an `auth` schema),
otherwise in data/state.json. Releases and extensions are stored in S3/MinIO
when S3_ENDPOINT_URL/S3_BUCKET are set, otherwise in local dirs. This grants
every user a zed_free plan and admin — a self-hosted test backend, not a
hardened one.

Usage:
    python -m scripts.gen_certs --hostname zed.dondish.me   # once
    python -m server
"""

import argparse
import asyncio
import os
from pathlib import Path

import uvicorn

from .app import app
from .blobstore import BlobStore
from .config import config
from .stores import JsonStore, PostgresStore


async def serve(args: argparse.Namespace) -> None:
    servers = []

    https_config = uvicorn.Config(
        app,
        host=args.host,
        port=args.port,
        ssl_certfile=str(Path(args.cert_dir) / "server.crt"),
        ssl_keyfile=str(Path(args.cert_dir) / "server.key"),
        log_level="info",
    )
    servers.append(uvicorn.Server(https_config))

    if args.internal_port:
        http_config = uvicorn.Config(
            app, host="127.0.0.1", port=args.internal_port, log_level="info"
        )
        servers.append(uvicorn.Server(http_config))

    print(f"client-facing (server_url):  https://{args.host}:{args.port}")
    if args.internal_port:
        print(f"collab-facing (zed_cloud_url): http://127.0.0.1:{args.internal_port}")
    await asyncio.gather(*(server.serve() for server in servers))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443, help="HTTPS port for Zed clients")
    parser.add_argument(
        "--internal-port",
        type=int,
        default=8787,
        help="Loopback HTTP port for collab's zed_cloud_url (0 to disable)",
    )
    parser.add_argument("--cert-dir", default="certs")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("AUTH_DATABASE_URL"),
        help="Postgres DSN for the user/token store (uses an `auth` schema). "
        "When unset, users persist to <data-dir>/state.json.",
    )
    parser.add_argument(
        "--internal-api-key",
        default=os.environ.get("ZED_CLOUD_INTERNAL_API_KEY", "internal-api-key-secret"),
        help="Must match collab's ZED_CLOUD_INTERNAL_API_KEY",
    )
    parser.add_argument(
        "--collab-rpc-url",
        default=os.environ.get("COLLAB_RPC_URL"),
        help="Where GET /rpc redirects Zed clients "
        "(default: http://<request-host>:8080/rpc)",
    )
    parser.add_argument(
        "--collab-database-url",
        default=os.environ.get("COLLAB_DATABASE_URL"),
        help="If set, mirror users into collab's Postgres `users` table "
        "(required for collaboration; FK constraints reference users.id)",
    )
    parser.add_argument("--default-username", default="local")
    parser.add_argument(
        "--releases-dir",
        default=os.environ.get("RELEASES_DIR", "releases"),
        help="Directory with scraped installers + index.json for /releases",
    )
    parser.add_argument(
        "--extensions-dir",
        default=os.environ.get("EXTENSIONS_DIR", "extensions"),
        help="Directory with scraped extension archives + index.json for /extensions",
    )
    parser.add_argument(
        "--gitlab-url",
        default=os.environ.get("GITLAB_URL", "https://gitlab.com"),
        help="GitLab instance base URL (gitlab.com or a self-hosted instance)",
    )
    parser.add_argument(
        "--gitlab-client-id",
        default=os.environ.get("GITLAB_CLIENT_ID"),
        help="OAuth application id; enables GitLab-backed sign-in when set with the secret",
    )
    parser.add_argument(
        "--gitlab-client-secret",
        default=os.environ.get("GITLAB_CLIENT_SECRET"),
        help="OAuth application secret",
    )
    parser.add_argument(
        "--gitlab-redirect-uri",
        default=os.environ.get("GITLAB_REDIRECT_URI"),
        help="OAuth callback URL registered on the GitLab app "
        "(default: <request-base>/auth/gitlab/callback)",
    )
    parser.add_argument(
        "--gitlab-scope",
        default=os.environ.get("GITLAB_SCOPE", "read_user"),
        help="OAuth scopes to request",
    )
    return parser.parse_args()


def configure(args: argparse.Namespace) -> None:
    """Populate the shared config object from parsed args."""
    if args.database_url:
        config.store = PostgresStore(args.database_url)
        print("store: Postgres (auth schema)")
    else:
        config.store = JsonStore(Path(args.data_dir) / "state.json")
        print(f"store: JSON file ({args.data_dir}/state.json)")

    config.internal_api_key = args.internal_api_key
    config.collab_rpc_url = args.collab_rpc_url
    config.collab_database_url = args.collab_database_url
    config.releases_dir = Path(args.releases_dir)
    config.extensions_dir = Path(args.extensions_dir)
    config.blobs = BlobStore.from_env()
    if config.blobs is not None:
        print(f"assets: S3 bucket '{config.blobs.bucket}' (releases + extensions)")
    else:
        print("assets: local dirs (set S3_ENDPOINT_URL/S3_BUCKET for S3/MinIO)")

    config.default_username = args.default_username
    config.gitlab_url = args.gitlab_url
    config.gitlab_client_id = args.gitlab_client_id
    config.gitlab_client_secret = args.gitlab_client_secret
    config.gitlab_redirect_uri = args.gitlab_redirect_uri
    config.gitlab_scope = args.gitlab_scope
    if config.gitlab_enabled():
        print(f"auth: GitLab OAuth via {config.gitlab_url}")
    else:
        print("auth: password-less username form (set GITLAB_CLIENT_ID/SECRET for GitLab)")


def main() -> None:
    args = parse_args()

    cert_dir = Path(args.cert_dir)
    if not (cert_dir / "server.crt").exists():
        raise SystemExit(f"Missing {cert_dir}/server.crt — run gen_certs.py first.")

    configure(args)
    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
