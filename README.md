# zed-auth-server

A self-hosted stand-in for the two closed pieces of Zed's backend — the
zed.dev sign-in page and the "cloud" API service — so that a Zed client plus a
self-hosted [collab server](https://github.com/zed-industries/zed/tree/main/crates/collab)
can work end to end without zed.dev.

**No real security**: identity is username-only with no passwords. Anyone who
can reach the server can sign in as anyone. Local/LAN testing only.

## What it implements

| Route | Consumer | Purpose |
|---|---|---|
| `GET /native_app_signin` | browser | sign-in page (opened by Zed) |
| `GET /native_app_signin/complete` | browser | issues RSA-OAEP-encrypted token, redirects to Zed's localhost callback |
| `GET /native_app_signin_succeeded` | browser | post-sign-in landing page |
| `GET /rpc` | Zed client | 302 redirect to the collab websocket URL |
| `GET /client/users/me` | Zed client + collab | token validation, returns `GetAuthenticatedUserResponse` |
| `WS /client/users/connect` | Zed client | cloud websocket (held open, no messages) |
| `POST /client/llm_tokens` | Zed client | dummy token (LLM features are not proxied) |
| `PATCH /client/system_settings` | Zed client | echo stub |
| `POST /internal/users/*`, `/internal/channel_members/*` | collab | user directory (Bearer-authenticated internal API) |

Users and tokens persist in `data/state.json`.

## Setup

```sh
pip install -r requirements.txt

# 1. Generate a self-signed CA + server certificate
python gen_certs.py --hostname zed.dondish.me

# 2. Trust the CA (Windows, elevated prompt):
certutil -addstore -f Root certs\ca.crt
#    (macOS: security add-trusted-cert -d -k /Library/Keychains/System.keychain certs/ca.crt)
#    (Linux: copy to /usr/local/share/ca-certificates and run update-ca-certificates)

# 3. Make the hostname resolve (e.g. hosts-file entry) and run
python server.py
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
python gen_certs.py --hostname zed.dondish.me

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
| `postgres` | 5432 (internal) | collab's DB; schema auto-loaded from `../zed/crates/collab/migrations` on first boot |
| `cloud` | 8443 (host) | this server — sign-in + cloud API over HTTPS |
| `collab` | 8080 (host) | Zed collaboration RPC websocket (plain `ws`) |

collab's cloud URL is **hardcoded** to `http://localhost:8787` in development
mode ([`crates/collab/src/lib.rs`](../zed/crates/collab/src/lib.rs)), so the
`collab` container shares the `cloud` container's network namespace
(`network_mode: service:cloud`). That's why collab's 8080 is published by the
`cloud` service, and why both must run on the same machine.

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

You can still run just the auth server: `python server.py`. Pair it with a
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
--default-username local  username prefilled on the sign-in form
```

## Tests

```sh
python test_server.py
```

Simulates the Zed client (keypair generation, PKCS#1 public key, OAEP token
decryption) and collab (token validation, internal user lookups) against a
live server instance.
