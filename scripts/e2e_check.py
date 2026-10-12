"""End-to-end verification against a running server (default http://localhost:8000).

Exercises the live HTTP path: authorization boundaries, refusal reasons, and a
true concurrent-edit race where both writers start from the same ETag —
exactly one must win.

Run inside the app container:  docker compose exec app python scripts/e2e_check.py
"""
import concurrent.futures
import os
import sys

import httpx
from jose import jwt

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
SECRET = os.environ["JWT_SECRET"]

ACME = "a1000000-0000-0000-0000-000000000001"
GLOBEX = "b2000000-0000-0000-0000-000000000002"
ALICE = "c3000000-0000-0000-0000-000000000001"  # acme user
BOB = "c3000000-0000-0000-0000-000000000002"    # acme user
CAROL = "c3000000-0000-0000-0000-000000000003"  # acme admin
DAVE = "d4000000-0000-0000-0000-000000000001"   # globex user


def token(user, tenant, role="user"):
    payload = {"user_id": user, "tenant_id": tenant, "role": role}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def bearer(user, tenant, role="user"):
    return {"Authorization": f"Bearer {token(user, tenant, role)}"}


def url(user):
    return f"{BASE_URL}/api/v1/users/{user}/preferences"


failures = []


def check(name, ok, evidence=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {evidence}")
    if not ok:
        failures.append(name)


def main():
    client = httpx.Client(timeout=10)

    # --- authorization boundaries -----------------------------------------
    r = client.get(url(ALICE), headers=bearer(ALICE, ACME))
    check("owner can read own prefs", r.status_code == 200, f"-> {r.status_code}, etag={r.headers.get('etag')}")

    r = client.get(url(BOB), headers=bearer(ALICE, ACME))
    check("user cannot read peer in same tenant", r.status_code == 403, f"-> {r.status_code}: {r.json().get('detail', '')[:70]}")

    r = client.get(url(ALICE), headers=bearer(CAROL, ACME, "admin"))
    check("admin can read within own tenant", r.status_code == 200, f"-> {r.status_code}")

    r = client.get(url(DAVE), headers=bearer(CAROL, ACME, "admin"))
    check("admin cannot reach across tenants", r.status_code == 403, f"-> {r.status_code}: {r.json().get('detail', '')[:70]}")

    r = client.get(url(DAVE), headers=bearer(ALICE, ACME))
    check("user cannot reach across tenants", r.status_code == 403, f"-> {r.status_code}")

    r = client.get(url("00000000-0000-0000-0000-000000009999"), headers=bearer(ALICE, ACME))
    check("missing record is 404", r.status_code == 404, f"-> {r.status_code}")

    # --- concurrency protocol ---------------------------------------------
    r = client.put(url(ALICE), json={"sms_enabled": True}, headers=bearer(ALICE, ACME))
    check("PUT without If-Match is 428", r.status_code == 428, f"-> {r.status_code}: {r.json().get('detail', '')[:70]}")

    r = client.get(url(ALICE), headers=bearer(ALICE, ACME))
    etag = r.headers["etag"]
    version_before = int(etag.strip('"'))

    def writer(field, value):
        return client.put(
            url(ALICE),
            json={field: value},
            headers={**bearer(ALICE, ACME), "If-Match": etag},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        w1 = pool.submit(writer, "sms_enabled", True)
        w2 = pool.submit(writer, "push_enabled", False)
        results = sorted([w1.result().status_code, w2.result().status_code])

    check("concurrent race: exactly one 200 and one 412", results == [200, 412], f"-> {results}")

    r = client.get(url(ALICE), headers=bearer(ALICE, ACME))
    version_after = int(r.headers["etag"].strip('"'))
    check("version advanced exactly once", version_after == version_before + 1,
          f"-> {version_before} -> {version_after}")

    r = client.put(
        url(ALICE),
        json={"email_enabled": False},
        headers={**bearer(ALICE, ACME), "If-Match": etag},
    )
    check("stale ETag replay is 412", r.status_code == 412, f"-> {r.status_code}: {r.json().get('detail', '')[:70]}")

    r = client.put(
        url(DAVE),
        json={"email_enabled": False},
        headers={**bearer(CAROL, ACME, "admin"), "If-Match": "*"},
    )
    check("cross-tenant PUT refused even with valid ETag", r.status_code == 403, f"-> {r.status_code}")

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        sys.exit(1)
    print("All end-to-end checks passed.")


if __name__ == "__main__":
    main()
