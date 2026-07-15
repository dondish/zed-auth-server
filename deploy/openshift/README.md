# OpenShift deployment

Runs the whole stack on OpenShift: Postgres, MinIO, and a single Pod holding
the **cloud** (this FastAPI server) and **collab** containers together.

## Why cloud + collab share a Pod

collab, in `ZED_ENVIRONMENT=development`, hardcodes its cloud URL to
`http://localhost:8787` (`crates/collab/src/lib.rs`). Containers in one Pod
share a network namespace, so collab's `localhost:8787` reaches the cloud
sidecar — the Kubernetes equivalent of docker-compose's
`network_mode: service:cloud`. Keep the Deployment at **1 replica** (collab
holds in-memory room state).

## Files

| File | Contents |
|---|---|
| `01-postgres.yaml` | Postgres Deployment + PVC + Service (initdb loads collab's schema) |
| `02-minio.yaml` | MinIO Deployment + PVC + Service + bucket-create Job |
| `03-zed.yaml` | cloud+collab Deployment, its Service, and `zed-config` ConfigMap |
| `04-routes.yaml` | passthrough Route (cloud 8443) + edge Route (collab 8080) |
| `secrets.example.yaml` | template for the `zed-secrets` Secret |
| `kustomization.yaml` | `oc apply -k` entrypoint |

## Prerequisites

### 1. Project

```sh
oc new-project zed
```

### 2. Images in a registry the cluster can pull

The two images you exported are `zed-auth-server-cloud` and
`zed-auth-server-collab`. Push them to OpenShift's internal registry (the paths
in `03-zed.yaml` assume project `zed` — adjust if different):

```sh
oc registry login
REG=$(oc registry info)
for img in cloud collab; do
  docker tag zed-auth-server-$img:latest $REG/zed/zed-auth-server-$img:latest
  docker push $REG/zed/zed-auth-server-$img:latest
done
```

Air-gapped: `skopeo copy docker-archive:zed-images.tar.gz:zed-auth-server-cloud:latest docker://$REG/zed/zed-auth-server-cloud:latest` (repeat for collab).

### 3. Secrets and config-from-files

```sh
# App + DB + MinIO credentials
cp secrets.example.yaml secrets.local.yaml   # edit the CHANGE-ME values
oc apply -f secrets.local.yaml

# TLS cert served by the app on 8443. Keys MUST be named server.crt/server.key.
# Use a PUBLICLY-TRUSTED cert (see "TLS" below) — e.g. Let's Encrypt:
oc create secret generic zed-tls \
  --from-file=server.crt=fullchain.pem \
  --from-file=server.key=privkey.pem

# collab's schema dump (loaded by Postgres initdb on first boot).
# Run from the repo root, with the Zed source checked out at ../zed:
oc create configmap collab-schema \
  --from-file=20251208000000_test_schema.sql=../zed/crates/collab/migrations/20251208000000_test_schema.sql
```

### 4. SCC for the stock Postgres/MinIO images

Those images run as their own baked UID, which the default `restricted-v2` SCC
forbids. Grant `anyuid` to the project's default ServiceAccount (needs
cluster-admin):

```sh
oc adm policy add-scc-to-user anyuid -z default -n zed
```

The `cloud` and `collab` containers need **no** special SCC — they run fine
under `restricted-v2` (they write nothing to the filesystem; `/certs` is a
read-only mount and the store is Postgres + S3).

## Deploy

```sh
oc apply -k .
oc get pods -w
```

Order isn't critical — the `zed-cloud` Pod has an init container that waits for
Postgres and MinIO, and the bucket Job retries until MinIO is up.

## DNS + TLS

- Point `zed.dondish.me` and `collab.zed.dondish.me` at the OpenShift router
  (the Routes' hostnames — change them to your domain).
- **The cloud cert must be publicly trusted.** Zed's cloud websocket
  (`/client/users/connect`) validates against compiled-in Mozilla roots
  (`webpki-roots`), not the OS store, so a self-signed cert is rejected there.
  Use Let's Encrypt (cert-manager can populate `zed-tls` automatically).

## Point Zed at it

Because the cloud Route is on 443 (no `:8443`), the client config drops the port:

```json
{ "server_url": "https://zed.dondish.me" }
```

Update the GitLab OAuth app's redirect URI to
`https://zed.dondish.me/auth/gitlab/callback` (already the default in
`zed-config`), and set `GITLAB_CLIENT_ID`/`GITLAB_CLIENT_SECRET` in the Secret
to enable GitLab sign-in.

## Populate assets

The scrapers/uploader run from your workstation against the bucket. Port-forward
MinIO and run them as in the top-level README:

```sh
oc port-forward svc/minio 9000:9000 &
export S3_ENDPOINT_URL=http://localhost:9000 S3_BUCKET=zed-assets
export S3_ACCESS_KEY_ID=minioadmin S3_SECRET_ACCESS_KEY=<your-minio-password>
python -m scripts.scrape_releases --versions 1.10.2
python -m scripts.upload_extensions        # if you have a local extensions/ folder
```

## Notes / trade-offs

- **Real S3 instead of MinIO:** delete `02-minio.yaml`, drop `S3_ENDPOINT_URL`
  from `zed-config`, and put your AWS keys/region/bucket in the Secret/ConfigMap.
- **Managed Postgres:** delete `01-postgres.yaml` and point the `*_DATABASE_URL`
  values at your database. You still need collab's schema loaded there once.
- **Edge TLS for the app** (terminate at the Route instead of passthrough) would
  need the server to serve the client port over plain HTTP — not supported today
  (`python -m server` always wraps `--port` in TLS). Passthrough is the path.
