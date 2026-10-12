import time

from fastapi.testclient import TestClient
from jose import jwt

from app.config import settings
from app.main import app

client = TestClient(app)

ACME_TENANT = "a1000000-0000-0000-0000-000000000001"
ALICE_ID = "c3000000-0000-0000-0000-000000000001"
ALICE_URL = f"/api/v1/users/{ALICE_ID}/preferences"


def make_token(user_id=ALICE_ID, tenant_id=ACME_TENANT, role="user", **extra):
    payload = {"user_id": user_id, "tenant_id": tenant_id, "role": role}
    payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def get_with(token: str):
    return client.get(ALICE_URL, headers={"Authorization": f"Bearer {token}"})


class TestJwtBoundary:
    def test_missing_header_is_401(self):
        resp = client.get(ALICE_URL)
        assert resp.status_code == 401
        assert "Authorization" in resp.json()["detail"]

    def test_non_bearer_scheme_is_401(self):
        resp = client.get(ALICE_URL, headers={"Authorization": f"Basic {make_token()}"})
        assert resp.status_code == 401

    def test_garbage_token_is_401(self):
        resp = get_with("not-a-jwt")
        assert resp.status_code == 401

    def test_wrong_secret_is_401(self):
        forged = jwt.encode(
            {"user_id": ALICE_ID, "tenant_id": ACME_TENANT, "role": "user"},
            "a-different-secret",
            algorithm=settings.jwt_algorithm,
        )
        assert get_with(forged).status_code == 401

    def test_expired_token_is_401(self):
        expired = make_token(exp=int(time.time()) - 3600)
        assert get_with(expired).status_code == 401

    def test_malformed_claims_are_401_not_500(self):
        # Regression: a syntactically valid token whose user_id is not a UUID
        # used to escape as a 500.
        bad = make_token(user_id="not-a-uuid")
        assert get_with(bad).status_code == 401

    def test_missing_claim_is_401(self):
        bad = jwt.encode(
            {"user_id": ALICE_ID, "role": "user"},
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        assert get_with(bad).status_code == 401

    def test_bearer_scheme_is_case_insensitive(self):
        resp = client.get(ALICE_URL, headers={"Authorization": f"bearer {make_token()}"})
        assert resp.status_code == 200


class TestRefusalReasons:
    """A refusal must say why it was refused — distinct detail per cause."""

    def test_401_detail_mentions_authentication(self):
        assert "authorization" in client.get(ALICE_URL).json()["detail"].lower()

    def test_403_cross_tenant_detail_mentions_tenant(self):
        globex_admin = make_token(
            user_id="c3000000-0000-0000-0000-000000000003",
            tenant_id="b2000000-0000-0000-0000-000000000002",
            role="admin",
        )
        resp = get_with(globex_admin)
        assert resp.status_code == 403
        assert "tenant" in resp.json()["detail"].lower()

    def test_412_detail_mentions_version_or_change(self):
        get_with(make_token())  # warm read
        resp = client.put(
            ALICE_URL,
            json={"sms_enabled": True},
            headers={"Authorization": f"Bearer {make_token()}", "If-Match": '"999999"'},
        )
        assert resp.status_code == 412
        detail = resp.json()["detail"].lower()
        assert "changed" in detail or "version" in detail or "concurrent" in detail

    def test_428_detail_mentions_if_match(self):
        resp = client.put(
            ALICE_URL,
            json={"sms_enabled": True},
            headers={"Authorization": f"Bearer {make_token()}"},
        )
        assert resp.status_code == 428
        assert "if-match" in resp.json()["detail"].lower()
