"""End-to-end test: simulates a Zed client and a collab server against server.py.

Run (from the repo root):  python tests/test_server.py
"""

import base64
import json
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

BASE_HTTPS = "https://localhost:8443"
BASE_HTTP = "http://127.0.0.1:8787"
INTERNAL_KEY = "internal-api-key-secret"


def request(url, method="GET", headers=None, body=None, follow_redirects=False):
    ctx = ssl.create_default_context(cafile="certs/ca.crt")
    req = urllib.request.Request(url, method=method, headers=headers or {})
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow_redirects:
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        resp = opener.open(req)
        headers_out = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, headers_out, resp.read().decode()
    except urllib.error.HTTPError as e:
        headers_out = {k.lower(): v for k, v in e.headers.items()}
        return e.code, headers_out, e.read().decode()


def main():
    proc = subprocess.Popen(
        [sys.executable, "-m", "server"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        time.sleep(2.5)
        if proc.poll() is not None:
            print(proc.stdout.read().decode())
            raise SystemExit("server exited early")

        # --- 1. Zed client: keypair + sign-in page ---
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_der = priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
        pub_b64 = base64.urlsafe_b64encode(pub_der).decode()

        q = urllib.parse.urlencode(
            {"native_app_port": 9999, "native_app_public_key": pub_b64}
        )
        status, _, body = request(f"{BASE_HTTPS}/native_app_signin?{q}")
        assert status == 200 and "Sign in to Zed" in body, (status, body[:200])
        print("PASS sign-in page")

        # --- 2. Submit the form (as the browser would) ---
        q2 = urllib.parse.urlencode(
            {
                "native_app_port": 9999,
                "native_app_public_key": pub_b64,
                "username": "alice",
            }
        )
        status, headers, _ = request(f"{BASE_HTTPS}/native_app_signin/complete?{q2}")
        assert status == 302, status
        loc = headers["location"]
        assert loc.startswith("http://127.0.0.1:9999/?"), loc
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
        user_id = params["user_id"][0]
        enc_token = params["access_token"][0]

        # --- 3. Decrypt token like the Rust client (OAEP-SHA256) ---
        token = priv.decrypt(
            base64.urlsafe_b64decode(enc_token + "=" * ((-len(enc_token)) % 4)),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ).decode()
        assert len(token) == 64, len(token)
        print(f"PASS sign-in redirect + token decrypt (user_id={user_id})")

        auth = {"Authorization": f"{user_id} {token}"}

        # --- 4. /client/users/me over HTTPS (as the Zed client calls it) ---
        status, _, body = request(f"{BASE_HTTPS}/client/users/me", headers=auth)
        assert status == 200, (status, body)
        me = json.loads(body)
        assert me["user"]["github_login"] == "alice"
        assert me["user"]["legacy_user_id"] == int(user_id)
        assert me["plan"]["plan_v3"] == "zed_free"
        assert me["plan"]["usage"]["edit_predictions"]["limit"] == "unlimited"
        assert me["user"]["accepted_tos_at"] is not None
        print("PASS /client/users/me (HTTPS, client-style)")

        # --- 5. Same endpoint over plain HTTP :8787 (as collab validates) ---
        status, _, body = request(f"{BASE_HTTP}/client/users/me", headers=auth)
        assert status == 200, (status, body)
        print("PASS /client/users/me (HTTP :8787, collab-style)")

        # --- 6. Bad token is rejected ---
        status, _, _ = request(
            f"{BASE_HTTPS}/client/users/me",
            headers={"Authorization": f"{user_id} wrong"},
        )
        assert status == 401, status
        print("PASS bad token -> 401")

        # --- 7. /rpc redirect ---
        status, headers, _ = request(f"{BASE_HTTPS}/rpc")
        assert status == 302 and headers["location"].endswith(":8080/rpc"), (
            status,
            headers.get("location"),
        )
        print(f"PASS /rpc -> {headers['location']}")

        # --- 8. Internal API (collab-side), Bearer auth ---
        bearer = {"Authorization": f"Bearer {INTERNAL_KEY}"}
        status, _, body = request(
            f"{BASE_HTTP}/internal/users/look_up_by_github_login",
            method="POST",
            headers=bearer,
            body={"github_login": "alice"},
        )
        assert status == 200, (status, body)
        found = json.loads(body)["user"]
        assert found["legacy_user_id"] == int(user_id) and found["admin"] is True
        print("PASS /internal/users/look_up_by_github_login")

        status, _, body = request(
            f"{BASE_HTTP}/internal/users/look_up_by_legacy_id",
            method="POST",
            headers=bearer,
            body={"legacy_user_ids": [int(user_id), 999]},
        )
        users = json.loads(body)["users"]
        assert status == 200 and len(users) == 1, (status, body)
        print("PASS /internal/users/look_up_by_legacy_id")

        status, _, body = request(
            f"{BASE_HTTP}/internal/users/fuzzy_search",
            method="POST",
            headers=bearer,
            body={"query": "ali", "limit": 10},
        )
        assert status == 200 and len(json.loads(body)["users"]) == 1, (status, body)
        print("PASS /internal/users/fuzzy_search")

        status, _, body = request(
            f"{BASE_HTTP}/internal/users/impersonate",
            method="POST",
            headers=bearer,
            body={"github_login": "bob"},
        )
        imp = json.loads(body)
        assert status == 200 and imp["user_id"] != int(user_id), (status, body)
        print("PASS /internal/users/impersonate (created second user)")

        # --- 9. Internal API rejects a wrong key ---
        status, _, _ = request(
            f"{BASE_HTTP}/internal/users/fuzzy_search",
            method="POST",
            headers={"Authorization": "Bearer nope"},
            body={"query": "a", "limit": 1},
        )
        assert status == 401, status
        print("PASS wrong internal key -> 401")

        # --- 10. LLM token + system settings stubs ---
        status, _, body = request(
            f"{BASE_HTTPS}/client/llm_tokens", method="POST", headers=auth, body={}
        )
        assert status == 200 and "token" in json.loads(body), (status, body)
        status, _, body = request(
            f"{BASE_HTTPS}/client/system_settings",
            method="PATCH",
            headers=auth,
            body={"selected_organization_id": None},
        )
        assert status == 200, (status, body)
        print("PASS /client/llm_tokens + /client/system_settings")

        print("\nALL TESTS PASSED")
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
