"""Integration tests for the APIsec scan-target demo API.

These tests hit the app via FastAPI's TestClient so they exercise the real
routing, validation, and response contracts that an APIsec scan will see.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client() -> Iterator[TestClient]:
    # Using TestClient as a context manager is required to trigger FastAPI's
    # lifespan events (which seed the in-memory store).
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_headers(client: TestClient) -> dict[str, str]:
    resp = client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": "password123"},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_healthz_returns_ok(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_login_happy_path_returns_token(client: TestClient) -> None:
    resp = client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": "password123"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert isinstance(body["access_token"], str)
    assert body["access_token"].count(".") == 2  # JWT-shaped


def test_get_user_happy_path(client: TestClient, auth_headers: dict[str, str]) -> None:
    resp = client.get("/users/1", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 1
    assert "email" in body
    assert "name" in body


def test_get_user_returns_404_when_missing(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    resp = client.get("/users/99999", headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "User not found"


def test_create_user_validation_error_missing_field(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # name is required; omit it
    resp = client.post(
        "/users",
        headers=auth_headers,
        json={"email": "new@example.com"},
    )
    assert resp.status_code == 422


def test_list_products_public_is_accessible(client: TestClient) -> None:
    resp = client.get("/products")
    assert resp.status_code == 200
    products = resp.json()
    assert isinstance(products, list)
    assert len(products) >= 4
    assert all("id" in p and "name" in p and "price" in p for p in products)


def test_protected_route_without_auth_returns_401(client: TestClient) -> None:
    resp = client.get("/orders/1")
    assert resp.status_code == 401


def test_openapi_spec_exposes_endpoints_and_bearer_scheme(client: TestClient) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    spec = resp.json()
    assert spec["openapi"].startswith("3.")

    # Bearer scheme must be declared so APIsec detects it
    schemes = spec["components"]["securitySchemes"]
    assert any(
        s.get("type") == "http" and s.get("scheme") == "bearer" for s in schemes.values()
    )

    # Spot-check that key paths are registered
    paths = spec["paths"]
    for required in ["/healthz", "/auth/login", "/users", "/users/{user_id}", "/products"]:
        assert required in paths, f"missing {required} in OpenAPI spec"
