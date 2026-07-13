"""Mirror signed-in users into collab's own `users` table.

collab has foreign keys from projects/rooms/contacts/etc. to users(id), so a
user must exist there (keyed by legacy_user_id) before they can collaborate.
No-op unless config.collab_database_url is set.
"""

from .config import config

try:
    import psycopg  # optional; only needed when collab_database_url is set
except ImportError:  # pragma: no cover - psycopg is optional
    psycopg = None


def ensure_collab_user(user: dict) -> None:
    """Upsert a row into collab's `users` table so FK constraints are satisfied.

    Failures are logged, not raised, so a database hiccup never blocks sign-in.
    """
    if not config.collab_database_url:
        return
    if psycopg is None:
        print("[warn] COLLAB_DATABASE_URL set but psycopg is not installed")
        return
    try:
        with psycopg.connect(config.collab_database_url, connect_timeout=5) as conn:
            conn.execute(
                "INSERT INTO public.users (id, admin, connected_once) "
                "VALUES (%s, %s, TRUE) "
                "ON CONFLICT (id) DO UPDATE SET admin = EXCLUDED.admin",
                (user["legacy_user_id"], user["is_staff"]),
            )
    except Exception as exc:  # noqa: BLE001 - never let this break auth
        print(f"[warn] failed to mirror user into collab db: {exc}")
