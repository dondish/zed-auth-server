"""Runtime configuration shared across the server's modules.

A single mutable `config` object is populated by `server.main()` before the
listeners start; every router reads its fields at request time. Keeping it in
one place (rather than per-module globals) is what lets the code split cleanly
across files.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .blobstore import BlobStore


class Config:
    def __init__(self) -> None:
        # User/token store (JsonStore or PostgresStore); set in main().
        self.store = None
        # Shared secret with collab's internal API.
        self.internal_api_key: str = "internal-api-key-secret"
        # Explicit Location for GET /rpc; else derived from the request host.
        self.collab_rpc_url: Optional[str] = None
        # Username prefilled on the fallback sign-in form.
        self.default_username: str = "local"
        # When set, users are mirrored into collab's own `users` table (its FKs
        # from projects/rooms/contacts reference users(id) = legacy_user_id).
        self.collab_database_url: Optional[str] = None
        # Local-mode asset dirs (used only when S3 is not configured).
        self.releases_dir: Path = Path("releases")
        self.extensions_dir: Path = Path("extensions")
        self.acp_dir: Path = Path("acp")
        # S3/MinIO store for releases + extensions; None = local dirs.
        self.blobs: Optional["BlobStore"] = None
        # GitLab OAuth. Sign-in is GitLab-backed when client id + secret are
        # both set; otherwise the password-less username form is used.
        self.gitlab_url: str = "https://gitlab.com"
        self.gitlab_client_id: Optional[str] = None
        self.gitlab_client_secret: Optional[str] = None
        self.gitlab_redirect_uri: Optional[str] = None
        self.gitlab_scope: str = "read_user"

    def gitlab_enabled(self) -> bool:
        return bool(self.gitlab_client_id and self.gitlab_client_secret)


config = Config()
