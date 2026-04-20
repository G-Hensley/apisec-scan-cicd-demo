"""FastAPI demo target for APIsec CI/CD scanning.

Single-file app with in-memory storage. Exposes an auth endpoint, users,
products, and orders so APIsec's scanner has meaningful surface area to
exercise. No real authentication, no real persistence -- this is a scan
target, not a real service.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.models import (
    LoginRequest,
    LogoutResponse,
    Order,
    OrderCreate,
    Product,
    ProductCreate,
    TokenResponse,
    User,
    UserCreate,
    UserUpdate,
)

logger = logging.getLogger("apisec-scan-target")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------


class _Store:
    """Simple in-memory data store. Not thread-safe; adequate for a scan target."""

    def __init__(self) -> None:
        self.users: dict[int, User] = {}
        self.products: dict[int, Product] = {}
        self.orders: dict[int, Order] = {}
        self._user_seq = 0
        self._product_seq = 0
        self._order_seq = 0

    def next_user_id(self) -> int:
        self._user_seq += 1
        return self._user_seq

    def next_product_id(self) -> int:
        self._product_seq += 1
        return self._product_seq

    def next_order_id(self) -> int:
        self._order_seq += 1
        return self._order_seq


store = _Store()


def _seed(store: _Store) -> None:
    """Seed the store with a handful of records for scanners to exercise."""
    store.users.clear()
    store.products.clear()
    store.orders.clear()
    store._user_seq = 0
    store._product_seq = 0
    store._order_seq = 0

    for name, email in [
        ("Alice", "alice@example.com"),
        ("Bob", "bob@example.com"),
        ("Carol", "carol@example.com"),
    ]:
        uid = store.next_user_id()
        store.users[uid] = User(id=uid, name=name, email=email)

    for name, price, desc in [
        ("Keyboard", 89.99, "Mechanical keyboard"),
        ("Mouse", 39.50, "Wireless mouse"),
        ("Monitor", 299.00, "27-inch display"),
        ("Desk Mat", 24.00, "Large cloth desk mat"),
    ]:
        pid = store.next_product_id()
        store.products[pid] = Product(id=pid, name=name, price=price, description=desc)

    for user_id, items in [
        (1, [{"product_id": 1, "quantity": 1}, {"product_id": 2, "quantity": 2}]),
        (2, [{"product_id": 3, "quantity": 1}]),
    ]:
        oid = store.next_order_id()
        total = sum(store.products[i["product_id"]].price * i["quantity"] for i in items)
        store.orders[oid] = Order(id=oid, user_id=user_id, items=items, total=round(total, 2))


# ---------------------------------------------------------------------------
# Auth (fake but OpenAPI-visible)
# ---------------------------------------------------------------------------


bearer_scheme = HTTPBearer(auto_error=True, description="Fake bearer token from /auth/login")


def _fake_jwt(subject: str) -> str:
    """Produce a JWT-shaped string. Not a real JWT -- no verification happens."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(
        b"="
    )
    payload = base64.urlsafe_b64encode(json.dumps({"sub": subject}).encode()).rstrip(b"=")
    sig = secrets.token_urlsafe(16).encode()
    return f"{header.decode()}.{payload.decode()}.{sig.decode()}"


def require_bearer(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> str:
    """Dependency that marks a route as Bearer-protected in OpenAPI.

    Implementation is permissive: any non-empty token is accepted. This is a
    scan target -- we just need the security requirement visible in the spec
    and an enforceable 401 when credentials are missing.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token"
        )
    return credentials.credentials


# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(_: FastAPI):
    _seed(store)
    logger.info(
        "seeded store",
        extra={
            "users": len(store.users),
            "products": len(store.products),
            "orders": len(store.orders),
        },
    )
    yield


app = FastAPI(
    title="APIsec Scan Target",
    description="Demo FastAPI service for APIsec CI/CD scanning.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):  # type: ignore[no-untyped-def]
    response = await call_next(request)
    logger.info(
        "request",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
        },
    )
    return response


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get(
    "/healthz",
    tags=["health"],
    summary="Liveness check",
    response_model=dict[str, str],
)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@app.post(
    "/auth/login",
    tags=["auth"],
    summary="Log in and receive a bearer token",
    response_model=TokenResponse,
)
def login(body: LoginRequest) -> TokenResponse:
    # Permissive: any syntactically valid email + non-empty password is accepted.
    logger.info("login", extra={"email": body.email})
    return TokenResponse(access_token=_fake_jwt(body.email))


@app.post(
    "/auth/logout",
    tags=["auth"],
    summary="Log out the current session",
    response_model=LogoutResponse,
    dependencies=[Depends(require_bearer)],
)
def logout() -> LogoutResponse:
    return LogoutResponse(status="logged_out")


# ---------------------------------------------------------------------------
# Users (GETs public; mutations Bearer-protected)
# ---------------------------------------------------------------------------


@app.get("/users", tags=["users"], summary="List all users", response_model=list[User])
def list_users() -> list[User]:
    return list(store.users.values())


@app.get(
    "/users/{user_id}",
    tags=["users"],
    summary="Get a user by id",
    response_model=User,
    responses={404: {"description": "User not found"}},
)
def get_user(user_id: int) -> User:
    user = store.users.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.post(
    "/users",
    tags=["users"],
    summary="Create a user",
    response_model=User,
    status_code=201,
    dependencies=[Depends(require_bearer)],
)
def create_user(body: UserCreate) -> User:
    uid = store.next_user_id()
    user = User(id=uid, email=body.email, name=body.name)
    store.users[uid] = user
    return user


@app.patch(
    "/users/{user_id}",
    tags=["users"],
    summary="Update a user",
    response_model=User,
    responses={404: {"description": "User not found"}},
    dependencies=[Depends(require_bearer)],
)
def update_user(user_id: int, body: UserUpdate) -> User:
    user = store.users.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    updated = user.model_copy(
        update={k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    )
    store.users[user_id] = updated
    return updated


@app.delete(
    "/users/{user_id}",
    tags=["users"],
    summary="Delete a user",
    status_code=204,
    responses={404: {"description": "User not found"}},
    dependencies=[Depends(require_bearer)],
)
def delete_user(user_id: int) -> None:
    if user_id not in store.users:
        raise HTTPException(status_code=404, detail="User not found")
    del store.users[user_id]
    return None


@app.get(
    "/users/{user_id}/orders",
    tags=["users"],
    summary="List orders for a user",
    response_model=list[Order],
    responses={404: {"description": "User not found"}},
    dependencies=[Depends(require_bearer)],
)
def list_user_orders(user_id: int) -> list[Order]:
    if user_id not in store.users:
        raise HTTPException(status_code=404, detail="User not found")
    return [o for o in store.orders.values() if o.user_id == user_id]


# ---------------------------------------------------------------------------
# Products (GET public; POST Bearer-protected)
# ---------------------------------------------------------------------------


@app.get("/products", tags=["products"], summary="List all products", response_model=list[Product])
def list_products() -> list[Product]:
    return list(store.products.values())


@app.get(
    "/products/{product_id}",
    tags=["products"],
    summary="Get a product by id",
    response_model=Product,
    responses={404: {"description": "Product not found"}},
)
def get_product(product_id: int) -> Product:
    product = store.products.get(product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


@app.post(
    "/products",
    tags=["products"],
    summary="Create a product",
    response_model=Product,
    status_code=201,
    dependencies=[Depends(require_bearer)],
)
def create_product(body: ProductCreate) -> Product:
    pid = store.next_product_id()
    product = Product(id=pid, **body.model_dump())
    store.products[pid] = product
    return product


# ---------------------------------------------------------------------------
# Orders (Bearer-protected)
# ---------------------------------------------------------------------------


@app.get(
    "/orders/{order_id}",
    tags=["orders"],
    summary="Get an order by id",
    response_model=Order,
    responses={404: {"description": "Order not found"}},
    dependencies=[Depends(require_bearer)],
)
def get_order(order_id: int) -> Order:
    order = store.orders.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order


@app.post(
    "/orders",
    tags=["orders"],
    summary="Create an order",
    response_model=Order,
    status_code=201,
    dependencies=[Depends(require_bearer)],
)
def create_order(body: OrderCreate) -> Order:
    if body.user_id not in store.users:
        raise HTTPException(status_code=404, detail="User not found")
    total = 0.0
    for item in body.items:
        product = store.products.get(item.product_id)
        if product is None:
            raise HTTPException(
                status_code=404, detail=f"Product {item.product_id} not found"
            )
        total += product.price * item.quantity
    oid = store.next_order_id()
    order = Order(id=oid, user_id=body.user_id, items=body.items, total=round(total, 2))
    store.orders[oid] = order
    return order


# ---------------------------------------------------------------------------
# Error hygiene: never leak internals to clients
# ---------------------------------------------------------------------------


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> Any:  # noqa: ARG001
    logger.exception("unhandled exception", extra={"path": request.url.path})
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
