from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from app.config import get_settings
from app.security import require_operator
from app.main import app


def test_missing_operator_token_is_rejected(monkeypatch):
    monkeypatch.setenv("OPERATOR_API_TOKEN", "operator-secret")
    get_settings.cache_clear()
    with pytest.raises(HTTPException) as exc:
        require_operator(None, None)
    assert exc.value.status_code == 401
    get_settings.cache_clear()


def test_internal_token_is_not_operator_token(monkeypatch):
    monkeypatch.setenv("OPERATOR_API_TOKEN", "operator-secret")
    monkeypatch.setenv("INTERNAL_API_TOKEN", "internal-secret")
    get_settings.cache_clear()
    with pytest.raises(HTTPException):
        require_operator("Bearer internal-secret", None)
    assert require_operator("Bearer operator-secret", None) == "operator"
    get_settings.cache_clear()



def test_http_authentication_boundaries(monkeypatch):
    monkeypatch.setenv("OPERATOR_API_TOKEN", "operator-secret")
    monkeypatch.setenv("INTERNAL_API_TOKEN", "internal-secret")
    get_settings.cache_clear()
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/engagements").status_code == 401
    # Auth runs before database access, so a valid token must get past 401.
    response = client.get("/tools/capabilities", headers={"Authorization": "Bearer operator-secret"})
    assert response.status_code != 401
    assert client.get("/internal/llm-config").status_code == 403
    get_settings.cache_clear()


# The legacy POST /auth/session bootstrap-cookie endpoint is retired
# (REQ-IAM-002/010): individual accounts log in via /auth/login -> /auth/login/mfa,
# which sets the HttpOnly session cookie - covered in
# tests/integration/test_auth_flows.py against a real database.
