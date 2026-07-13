# zed-auth-server

A self-hosted stand-in for the two closed pieces of Zed's backend — the
zed.dev sign-in page and the "cloud" API service — so that a Zed client plus a
self-hosted [collab server](https://github.com/zed-industries/zed/tree/main/crates/collab)
can work end to end without zed.dev.

Sign-in is backed by **GitLab OAuth** (gitlab.com or any self-hosted instance)
when configured; otherwise it falls back to a password-less username form for
local testing. Either way this is a self-hosted test backend — it grants every
signed-in user a `zed_free` plan and admin — not a hardened one.

## What it implements

| Route | Consumer | Purpose |
|---|---|---|
| `GET /native_app_signin` | browser | starts sign-in — redirects to GitLab OAuth, or shows the username form |
| `GET /auth/gitlab/callback` | browser (from GitLab) | maps the GitLab identity to a user, issues the token |
| `GET /native_app_signin/complete` | browser | username-form fallback: issues RSA-OAEP-encrypted token, redirects to Zed's localhost callback |
| `GET /native_app_signin_succeeded` | browser | post-sign-in landing page |
| `GET /rpc` | Zed client | 302 redirect to the collab websocket URL |
| `GET /client/users/me` | Zed client + collab | token validation, returns `GetAuthenticatedUserResponse` |
| `WS /client/users/connect` | Zed client | cloud websocket (held open, no messages) |
| `POST /client/llm_tokens` | Zed client | dummy token (LLM features are not proxied) |
| `PATCH /client/system_settings` | Zed client | echo stub |
| `GET /releases/{channel}/{version}/asset` | Zed auto-updater | returns `{version, url}` for an install |
| `GET /releases/download/...` | Zed auto-updater | serves the installer binary itself |
| `GET /extensions`, `/extensions/updates`, `/extensions/{id}` | Zed extension store | catalog / update-check / versions (`{data:[…]}`) |
| `GET /extensions/{id}[/{version}]/download` | Zed extension store | serves the extension's `archive.tar.gz` |
| `POST /internal/users/*`, `/internal/channel_members/*` | collab | user directory (Bearer-authenticated internal API) |

Users and tokens persist in `data/state.json` (or Postgres — see below).

## Project layout

```
server/     the app package — run with `python -m server`
            app.py (assembly) + routers (auth/client/internal/releases/extensions)
            + config, stores, schemas, crypto, blobstore, assets, collab_db
scripts/    utilities — `python -m scripts.gen_certs`,
            `python -m scripts.scrape_releases`, `python -m scripts.scrape_extensions`
tests/      `python tests/test_server.py` (end-to-end against a live instance)
```

Run everything from the repo root so the `server` / `scripts` packages resolve.

## Authentication (GitLab OAuth)

When `GITLAB_CLIENT_ID` and `GITLAB_CLIENT_SECRET` are set, sign-in is backed by
GitLab's OAuth authorization-code flow:

1. Zed opens `GET /native_app_signin`; the server stashes the app's callback
   port + public key under a random `state` and redirects the browser to
   `{GITLAB_URL}/oauth/authorize`.
2. After the user approves, GitLab redirects to `GET /auth/gitlab/callback`,
   which exchanges the `code` for a token, fetches `GET /api/v4/user`, and maps
   the GitLab **username / name / avatar** onto a Zed user (keyed by the stable
   GitLab user id, so it survives a username change).
3. The server issues a Zed access token, RSA-OAEP-encrypts it with the app's
   public key, and redirects back to Zed's `127.0.0.1` callback — same as the
   username form.

`state` is single-use and expires after 10 minutes; the GitLab token never
reaches the Zed client. **Any custom GitLab instance** works — just point
`GITLAB_URL` at it. If the credentials are unset, the password-less username
form is used instead (handy for local multi-instance collaboration testing).

Set up an OAuth application on GitLab (redirect URI
`https://zed.dondish.me:8443/auth/gitlab/callback`, scope `read_user`), then
copy `.env.example` to `.env` and fill it in — `docker compose` picks it up
automatically. Standalone, pass `--gitlab-client-id/-secret/-url/-redirect-uri`.

## Asset storage (S3 / MinIO)

Release installers and extension archives live in an **S3 bucket**; the server
streams the bytes back through its own HTTPS listener, so clients only ever
talk to the auth server and the object store is never exposed to them. The
`docker compose` stack runs a **MinIO** service for this (bucket auto-created on
first boot); point `S3_*` at real AWS S3 instead by unsetting `S3_ENDPOINT_URL`.

Layout in the bucket:

```
releases/index.json
releases/<channel>/<os>/<arch>/<asset>/<version>/<filename>
extensions/index.json
extensions/<id>/<version>/archive.tar.gz          # matches collab's convention
```

The scrapers upload to S3 when `S3_ENDPOINT_URL`/`S3_BUCKET` are set (run them
from the host against MinIO's published `localhost:9000`); otherwise they write
the local `releases/`/`extensions/` dirs and the server serves those. MinIO's
web console is at `http://localhost:9001` (`minioadmin`/`minioadmin` by default).

```sh
export S3_ENDPOINT_URL=http://localhost:9000 S3_BUCKET=zed-assets
export S3_ACCESS_KEY_ID=minioadmin S3_SECRET_ACCESS_KEY=minioadmin
python -m scripts.scrape_extensions --ids toml dockerfile
python -m scripts.scrape_releases --versions 1.10.2
```

## Auto-updates (releases API)

Zed's auto-updater ([`crates/auto_update`](../zed/crates/auto_update)) calls
`GET /releases/{channel}/{version}/asset?asset=zed&os=..&arch=..` and expects
`{"version": "..", "url": ".."}`, then downloads `url` (on Windows, it runs the
result as an installer). `version` may be `latest`.

`scripts/scrape_releases.py` queries Zed's real endpoint (`cloud.zed.dev`), downloads
the installer for each version, and stores it (S3 or `releases/`) with a
`releases/index.json` manifest. The server then hosts those binaries itself, so
updates come from this machine, not GitHub.

```sh
# Default: last 3 stable Windows x86_64 builds (~83MB each)
python -m scripts.scrape_releases

# Other platforms / versions:
python -m scripts.scrape_releases --os macos --arch aarch64 --versions 1.10.2 1.10.1
```

The server resolves `latest` to the highest scraped semver for the requested
`channel/os/arch/asset`. To see an update actually download, the served
`latest` must be **newer** than the Zed you're running. (The local `releases/`
dir is git-ignored — the binaries live in S3 or are regenerated by the scraper.)

## Extensions

Zed's extension store ([`crates/extension_host`](../zed/crates/extension_host))
reaches the API via `build_zed_api_url`, which for a custom `server_url` uses
that same base URL — so the extension routes are served on the client-facing
HTTPS listener (8443), not the internal collab port. It calls:

- `GET /extensions?max_schema_version=&filter=&provides=` — catalog / search
- `GET /extensions/updates?ids=&min_schema_version=&…` — update check
- `GET /extensions/{id}` — all versions of one extension
- `GET /extensions/{id}/download` and `/extensions/{id}/{version}/download` —
  the extension's `archive.tar.gz`, which Zed unpacks into its extensions dir

The JSON routes return `{"data": [ExtensionMetadata]}`, matching
`cloud_api_types::GetExtensionsResponse`.

`scripts/scrape_extensions.py` mirrors extensions from Zed's real API (`api.zed.dev`)
into `extensions/` (git-ignored, regenerate with the scraper):

```sh
python -m scripts.scrape_extensions                     # small curated default set
python -m scripts.scrape_extensions --filter toml       # everything matching a term
python -m scripts.scrape_extensions --ids toml dockerfile nix
python -m scripts.scrape_extensions --all --limit 50    # top 50 by download count
```

Only mirrored extensions appear in the in-app store; install/update works
entirely from this machine.

## Setup

```sh
pip install -r requirements.txt

# 1. Generate a self-signed CA + server certificate
python -m scripts.gen_certs --hostname zed.dondish.me

# 2. Trust the CA (Windows, elevated prompt):
certutil -addstore -f Root certs\ca.crt
#    (macOS: security add-trusted-cert -d -k /Library/Keychains/System.keychain certs/ca.crt)
#    (Linux: copy to /usr/local/share/ca-certificates and run update-ca-certificates)

# 3. Make the hostname resolve (e.g. hosts-file entry) and run
python -m server
```

Listeners:
- **`https://0.0.0.0:8443`** — what Zed's `server_url` points at
- **`http://127.0.0.1:8787`** — what collab (in `ZED_ENVIRONMENT=development`)
  hardcodes as its cloud URL (`Config::zed_cloud_url`), used to validate tokens
  and look up users

## Zed client configuration

`settings.json`:

```json
{ "server_url": "https://zed.dondish.me:8443" }
```

For a custom `server_url` the client derives its cloud-API base from the same
URL (`build_zed_cloud_url` in `crates/http_client`), so everything lands here.

## Running with collab (Docker Compose)

`docker-compose.yml` brings up the whole stack: Postgres, this server, and
Zed's collab server built from `../zed`.

```sh
# 0. The Zed repo must be checked out at ../zed (sibling of this project).
# 1. Generate certs (once)
python -m scripts.gen_certs --hostname zed.dondish.me

# 2. Build + start everything (first build of collab is very heavy — it
#    compiles the whole Zed workspace; expect 20-40 min and several GB)
docker compose up --build

# 3. Point zed.dondish.me at your machine (hosts file):
#    127.0.0.1  zed.dondish.me
```

Then set `"server_url": "https://zed.dondish.me:8443"` in Zed and sign in.
Launch a second Zed instance, sign in as a different username, and they can
collaborate.

### How the pieces connect

| Service | Port | Role |
|---|---|---|
| `postgres` | 5432 (internal) | collab's DB + this server's `auth` schema; collab schema auto-loaded from `../zed/crates/collab/migrations` on first boot |
| `cloud` | 8443 (host) | this server — sign-in + cloud API over HTTPS |
| `collab` | 8080 (host) | Zed collaboration RPC websocket (plain `ws`) |
| `minio` | 9000 API / 9001 console (host) | S3 store for release + extension assets |
| `createbuckets` | — | one-shot: creates the bucket, then exits |

collab's cloud URL is **hardcoded** to `http://localhost:8787` in development
mode ([`crates/collab/src/lib.rs`](../zed/crates/collab/src/lib.rs)), so the
`collab` container shares the `cloud` container's network namespace
(`network_mode: service:cloud`). That's why collab's 8080 is published by the
`cloud` service, and why both must run on the same machine.

> **Gotcha:** because collab shares cloud's namespace, recreating the `cloud`
> container (e.g. `docker compose up --build cloud`) orphans collab's network.
> After rebuilding cloud, recreate collab too:
> `docker compose up -d --force-recreate collab`.

### Users and the collab database

collab has foreign keys from projects/rooms/contacts to its own `users` table.
This server mirrors every signed-in user into that table (keyed by
`legacy_user_id`) via `COLLAB_DATABASE_URL`, which the compose file wires up
automatically — so newly-created usernames can collaborate with no manual
seeding.

### Known limitation: the cloud websocket warning

Zed's cloud websocket (`/client/users/connect`) is the one TLS path that uses
a **compiled-in Mozilla CA list** (`webpki-roots`) instead of the OS trust
store, so a self-signed cert produces a repeating
`cloud websocket connect failed: invalid peer certificate: UnknownIssuer`
warning. This does **not** affect sign-in or collaboration (which use the OS
trust store / plain `ws`). To silence it, serve 8443 with a publicly-trusted
certificate (e.g. Let's Encrypt for `zed.dondish.me`) instead of the
self-signed CA.

### Standalone (no Docker)

You can still run just the auth server: `python -m server`. Pair it with a
collab server started however you like (`cargo run -p collab serve all`) as
long as collab reaches this server at `localhost:8787` and
`ZED_CLOUD_INTERNAL_API_KEY` matches `--internal-api-key`. Pass
`--collab-database-url` so users are mirrored into collab's DB.

## Flags

```
--host 0.0.0.0            HTTPS bind address
--port 8443               HTTPS port (client-facing)
--internal-port 8787      loopback HTTP port for collab (0 disables)
--cert-dir certs          where server.crt / server.key live
--data-dir data           where state.json is stored
--internal-api-key ...    must match collab's ZED_CLOUD_INTERNAL_API_KEY
--collab-rpc-url ...      explicit Location for GET /rpc
--collab-database-url ... mirror users into collab's Postgres (for FK constraints)
--default-username local  username prefilled on the sign-in form (fallback only)
--releases-dir releases   scraped installers + index.json for /releases
--extensions-dir extensions  scraped extension archives + index.json for /extensions
--gitlab-url https://gitlab.com   GitLab instance (custom / self-hosted ok)
--gitlab-client-id ...    OAuth app id (enables GitLab sign-in with the secret)
--gitlab-client-secret ...  OAuth app secret
--gitlab-redirect-uri ... callback registered on the GitLab app (else derived)
--gitlab-scope read_user  OAuth scopes to request
```

## Tests

```sh
python tests/test_server.py
```

Simulates the Zed client (keypair generation, PKCS#1 public key, OAEP token
decryption) and collab (token validation, internal user lookups) against a
live server instance.
