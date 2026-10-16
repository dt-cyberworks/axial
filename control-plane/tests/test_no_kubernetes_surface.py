"""REQ-COMPOSE-001: Docker Compose is the only deployment model. The control plane no longer
offers anything that exists only for a Kubernetes NetworkPolicy."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from app.config import get_settings
from app.gateway import raw_egress_policy
from app.main import app


def test_the_networkpolicy_endpoint_is_gone():
    headers = {"X-ASM-Internal-Token": get_settings().internal_api_token}
    resp = TestClient(app).get(f"/internal/engagements/{uuid.uuid4()}/raw-egress-policy", headers=headers)
    assert resp.status_code == 404
    paths = {getattr(route, "path", "") for route in app.routes}
    assert not any("raw-egress-policy" in path for path in paths)


def test_the_computation_returns_ip_blocks_and_no_kubernetes_object():
    rendered = raw_egress_policy.build_raw_egress_policy(uuid.uuid4(), [])
    assert not hasattr(rendered, "policy")
    assert rendered.ip_blocks == []
    source = open(raw_egress_policy.__file__, encoding="utf-8").read()
    assert "networking.k8s.io" not in source and "NetworkPolicy" not in source
