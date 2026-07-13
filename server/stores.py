"""User + token store.

Two interchangeable backends with the same interface: JsonStore (a single
state.json file, the default for a standalone `python server.py`) and
PostgresStore (used when AUTH_DATABASE_URL is set — e.g. the docker-compose
stack). The user dict shape is identical across both.

`identity` is the stable storage key: a bare username for the legacy form /
impersonation, or "gitlab:<id>" for an OAuth identity (so a GitLab user
survives a username change). `profile`, when given to get_or_create_user,
supplies/refreshes the display fields on each login.
"""

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .crypto import random_access_token

try:
    import psycopg  # optional; only needed for PostgresStore
except ImportError:  # pragma: no cover - psycopg is optional
    psycopg = None

# Fields refreshed from the OAuth profile on each subsequent login.
_MUTABLE_USER_FIELDS = ("username", "github_login", "avatar_url", "name", "is_staff")


def default_avatar(username: str) -> str:
    return f"https://zed.dev/user_avatar/{username}.png"


class JsonStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        if path.exists():
            state = json.loads(path.read_text(encoding="utf-8"))
        else:
            state = {"users": {}, "tokens": {}, "next_user_id": 1}
        # users: {identity: {...user record...}}
        # tokens: {access_token: legacy_user_id}
        self.users: dict[str, dict] = state["users"]
        self.tokens: dict[str, int] = state["tokens"]
        self.next_user_id: int = state["next_user_id"]

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {
                    "users": self.users,
                    "tokens": self.tokens,
                    "next_user_id": self.next_user_id,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def get_or_create_user(
        self, identity: str, profile: Optional[dict] = None
    ) -> dict:
        profile = profile or {}
        with self.lock:
            user = self.users.get(identity)
            if user is None:
                username = profile.get("username") or identity
                user = {
                    "id": str(uuid.uuid4()),
                    "legacy_user_id": self.next_user_id,
                    "metrics_id": str(uuid.uuid4()),
                    "username": username,
                    "github_login": profile.get("github_login") or username,
                    "avatar_url": profile.get("avatar_url") or default_avatar(username),
                    "name": profile.get("name"),
                    "is_staff": profile.get("is_staff", True),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                self.users[identity] = user
                self.next_user_id += 1
                self._save()
            elif profile:
                changed = False
                for field in _MUTABLE_USER_FIELDS:
                    if (
                        profile.get(field) is not None
                        and user.get(field) != profile[field]
                    ):
                        user[field] = profile[field]
                        changed = True
                if changed:
                    self._save()
            return user

    def user_by_legacy_id(self, legacy_id: int) -> Optional[dict]:
        for user in self.users.values():
            if user["legacy_user_id"] == legacy_id:
                return user
        return None

    def user_by_github_login(self, github_login: str) -> Optional[dict]:
        for user in self.users.values():
            if user.get("github_login") == github_login:
                return user
        return None

    def search_users(self, query: str, limit: int) -> list[dict]:
        q = query.lower()
        return [
            user
            for user in self.users.values()
            if q in user["username"].lower()
            or q in (user.get("github_login") or "").lower()
        ][:limit]

    def issue_token(self, user: dict) -> str:
        token = random_access_token()
        with self.lock:
            self.tokens[token] = user["legacy_user_id"]
            self._save()
        return token

    def user_for_token(self, token: str) -> Optional[dict]:
        legacy_id = self.tokens.get(token)
        if legacy_id is None:
            return None
        return self.user_by_legacy_id(legacy_id)


class PostgresStore:
    """Postgres-backed store. Tables live in their own `auth` schema so they
    coexist with collab's `public` tables in the same database."""

    def __init__(self, dsn: str):
        if psycopg is None:
            raise SystemExit(
                "AUTH_DATABASE_URL is set but psycopg is not installed "
                "(pip install 'psycopg[binary,pool]')."
            )
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._dict_row = dict_row
        self.pool = ConnectionPool(
            dsn,
            min_size=1,
            max_size=8,
            kwargs={"autocommit": True, "row_factory": dict_row},
            open=True,
        )
        self._init_schema()

    def _init_schema(self) -> None:
        with self.pool.connection() as conn:
            conn.execute("CREATE SCHEMA IF NOT EXISTS auth")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth.users (
                    identity       TEXT PRIMARY KEY,
                    id             UUID NOT NULL DEFAULT gen_random_uuid(),
                    legacy_user_id INTEGER GENERATED BY DEFAULT AS IDENTITY UNIQUE,
                    metrics_id     UUID NOT NULL DEFAULT gen_random_uuid(),
                    username       TEXT NOT NULL,
                    github_login   TEXT,
                    avatar_url     TEXT,
                    name           TEXT,
                    is_staff       BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth.tokens (
                    token          TEXT PRIMARY KEY,
                    legacy_user_id INTEGER NOT NULL
                        REFERENCES auth.users(legacy_user_id) ON DELETE CASCADE,
                    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS users_github_login_idx "
                "ON auth.users (github_login)"
            )

    @staticmethod
    def _to_user(row: Optional[dict]) -> Optional[dict]:
        if row is None:
            return None
        user = dict(row)
        user.pop("identity", None)
        user["id"] = str(user["id"])
        user["metrics_id"] = str(user["metrics_id"])
        # Callers expect created_at as an ISO-8601 string (see
        # authenticated_user_json), matching JsonStore.
        user["created_at"] = user["created_at"].isoformat()
        return user

    def get_or_create_user(
        self, identity: str, profile: Optional[dict] = None
    ) -> dict:
        profile = profile or {}
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                "SELECT * FROM auth.users WHERE identity = %s FOR UPDATE",
                (identity,),
            ).fetchone()
            if row is None:
                username = profile.get("username") or identity
                row = conn.execute(
                    """
                    INSERT INTO auth.users
                        (identity, username, github_login, avatar_url, name, is_staff)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (
                        identity,
                        username,
                        profile.get("github_login") or username,
                        profile.get("avatar_url") or default_avatar(username),
                        profile.get("name"),
                        profile.get("is_staff", True),
                    ),
                ).fetchone()
            elif profile:
                updates = {
                    field: profile[field]
                    for field in _MUTABLE_USER_FIELDS
                    if profile.get(field) is not None and row[field] != profile[field]
                }
                if updates:
                    set_clause = ", ".join(f"{col} = %s" for col in updates)
                    row = conn.execute(
                        f"UPDATE auth.users SET {set_clause} "
                        "WHERE identity = %s RETURNING *",
                        (*updates.values(), identity),
                    ).fetchone()
            return self._to_user(row)

    def user_by_legacy_id(self, legacy_id: int) -> Optional[dict]:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT * FROM auth.users WHERE legacy_user_id = %s", (legacy_id,)
            ).fetchone()
        return self._to_user(row)

    def user_by_github_login(self, github_login: str) -> Optional[dict]:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT * FROM auth.users WHERE github_login = %s LIMIT 1",
                (github_login,),
            ).fetchone()
        return self._to_user(row)

    def search_users(self, query: str, limit: int) -> list[dict]:
        like = f"%{query}%"
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM auth.users "
                "WHERE username ILIKE %s OR github_login ILIKE %s "
                "ORDER BY legacy_user_id LIMIT %s",
                (like, like, limit),
            ).fetchall()
        return [self._to_user(r) for r in rows]

    def issue_token(self, user: dict) -> str:
        token = random_access_token()
        with self.pool.connection() as conn:
            conn.execute(
                "INSERT INTO auth.tokens (token, legacy_user_id) VALUES (%s, %s)",
                (token, user["legacy_user_id"]),
            )
        return token

    def user_for_token(self, token: str) -> Optional[dict]:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT u.* FROM auth.tokens t "
                "JOIN auth.users u ON u.legacy_user_id = t.legacy_user_id "
                "WHERE t.token = %s",
                (token,),
            ).fetchone()
        return self._to_user(row)
