"""Pydantic models for the APIsec scan-target demo API.

Kept deliberately simple and explicit so that the generated OpenAPI schema
gives scanners a clear picture of every request and response shape.
"""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field

# ---------- Auth ----------


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LogoutResponse(BaseModel):
    status: str


# ---------- Users ----------


class UserBase(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=120)


class UserCreate(UserBase):
    pass


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    name: str | None = Field(default=None, min_length=1, max_length=120)


class User(UserBase):
    id: int


# ---------- Products ----------


class ProductBase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    price: float = Field(ge=0)
    description: str | None = Field(default=None, max_length=500)


class ProductCreate(ProductBase):
    pass


class Product(ProductBase):
    id: int


# ---------- Orders ----------


class OrderItem(BaseModel):
    product_id: int
    quantity: int = Field(ge=1)


class OrderCreate(BaseModel):
    user_id: int
    items: list[OrderItem] = Field(min_length=1)


class Order(BaseModel):
    id: int
    user_id: int
    items: list[OrderItem]
    total: float
