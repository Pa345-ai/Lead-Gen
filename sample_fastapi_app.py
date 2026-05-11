"""
Test fixture: a realistic FastAPI e-commerce / order management API
with several intentional vulnerabilities planted for the extractor to find.

Vulnerabilities planted:
  1. IDOR on GET /orders/{order_id} — auth required, no ownership check
  2. MissingAuthentication on DELETE /orders/{order_id} — no auth at all
  3. PathAsymmetry on /admin/users — GET has auth, POST does not
  4. MassAssignment on POST /orders — body includes 'owner_id' field
  5. UnauthenticatedWrite on POST /webhook — writes to DB, no auth
"""

FIXTURE_MODELS = '''
from pydantic import BaseModel
from typing import Optional

class OrderCreate(BaseModel):
    item_id: int
    quantity: int
    owner_id: int          # mass assignment risk — should be set server-side
    shipping_address: str

class OrderResponse(BaseModel):
    id: int
    owner_id: int
    item_id: int
    total: float
    status: str

class UserProfile(BaseModel):
    user_id: int
    email: str
    account_id: int        # ownership marker
    role: str

class WebhookPayload(BaseModel):
    event: str
    order_id: int
    amount: float
'''

FIXTURE_ROUTES = '''
from fastapi import FastAPI, Depends, HTTPException, Query, Path, Body
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Auth dependency — verifies JWT and returns user."""
    return {"user_id": 1, "role": "user"}


async def require_admin(token: str = Depends(oauth2_scheme)):
    """Admin-only dependency."""
    return {"user_id": 1, "role": "admin"}


# ── Orders ─────────────────────────────────────────────────────────────

@app.get("/orders/{order_id}")
async def get_order(
    order_id: int = Path(...),
    current_user: dict = Depends(get_current_user),
):
    """
    IDOR: auth is required, but no check that order.owner_id == current_user.user_id.
    Attacker can enumerate any order_id.
    """
    # db.query("SELECT * FROM orders WHERE id = ?", order_id)
    return {"order_id": order_id, "owner_id": 99}


@app.post("/orders")
async def create_order(
    order: OrderCreate,
    current_user: dict = Depends(get_current_user),
):
    """
    Mass assignment: owner_id comes from request body, not from current_user.
    Attacker can set owner_id = any user's ID.
    """
    # db.session.add(Order(**order.dict()))
    return {"status": "created"}


@app.delete("/orders/{order_id}")
async def delete_order(
    order_id: int = Path(...),
):
    """
    MissingAuthentication: DELETE endpoint with no Depends(get_current_user).
    Any anonymous caller can delete any order.
    """
    # db.query("DELETE FROM orders WHERE id = ?", order_id)
    return {"status": "deleted"}


@app.get("/orders")
async def list_orders(
    status: str = Query(None),
    current_user: dict = Depends(get_current_user),
):
    """Authenticated. Returns all orders — missing per-user filter."""
    return []


# ── Admin ──────────────────────────────────────────────────────────────

@app.get("/admin/users")
async def list_users(
    current_user: dict = Depends(require_admin),
):
    """Admin-only. Correctly gated."""
    return []


@app.post("/admin/users")
async def create_user(
    email: str = Body(...),
    role: str = Body("user"),
):
    """
    PathAsymmetry: GET /admin/users requires admin, POST does not.
    Attacker can create users without any admin credential.
    """
    return {"status": "created"}


# ── Webhooks ───────────────────────────────────────────────────────────

@app.post("/webhook")
async def handle_webhook(payload: WebhookPayload):
    """
    UnauthenticatedWrite: no auth, but performs INSERT into DB.
    External actor can forge webhook events.
    """
    # db.query("INSERT INTO events (order_id, amount) VALUES (?, ?)", ...)
    return {"status": "received"}


# ── Public / safe endpoints ────────────────────────────────────────────

@app.get("/products/{product_id}")
async def get_product(product_id: int):
    """No auth needed — public catalog. Correct."""
    return {"product_id": product_id}


@app.get("/health")
async def healthcheck():
    """No auth needed. Correct."""
    return {"status": "ok"}
'''
