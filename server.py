from __future__ import annotations

import base64
import json
import os
import sqlite3
from datetime import datetime
from typing import Optional

import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# =========================================================
# CONFIG (variabili ambiente sul server)
# =========================================================
# PAYPAL_MODE = "sandbox" oppure "live"
# PAYPAL_CLIENT_ID = ...
# PAYPAL_CLIENT_SECRET = ...
# PAYPAL_WEBHOOK_ID = ...   (ID del webhook creato su PayPal dashboard)
# CURRENCY = "EUR"
# UNIT_PRICE_EUR = "15.00"
# DB_PATH = "credits.db"

PAYPAL_MODE = os.getenv("PAYPAL_MODE", "sandbox").strip().lower()
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID", "")
CURRENCY = os.getenv("CURRENCY", "EUR")
UNIT_PRICE_EUR = os.getenv("UNIT_PRICE_EUR", "15.00")
DB_PATH = os.getenv("DB_PATH", "credits.db")

PAYPAL_API_BASE = "https://api-m.sandbox.paypal.com" if PAYPAL_MODE == "sandbox" else "https://api-m.paypal.com"

app = FastAPI(title="PayPal Credits Server")


# =========================================================
# DB (sqlite)
# =========================================================
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS credits (
            installation_id TEXT PRIMARY KEY,
            credits INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            paypal_order_id TEXT PRIMARY KEY,
            installation_id TEXT NOT NULL,
            credits INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            installation_id TEXT,
            credits_delta INTEGER,
            paypal_order_id TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def now_utc() -> str:
    return datetime.utcnow().isoformat()


def get_credits(installation_id: str) -> int:
    conn = db()
    cur = conn.execute("SELECT credits FROM credits WHERE installation_id = ?", (installation_id,))
    row = cur.fetchone()
    return int(row[0]) if row else 0


def set_credits(installation_id: str, credits: int) -> None:
    conn = db()
    conn.execute(
        """
        INSERT INTO credits(installation_id, credits, updated_at)
        VALUES(?,?,?)
        ON CONFLICT(installation_id) DO UPDATE SET credits=excluded.credits, updated_at=excluded.updated_at
        """,
        (installation_id, int(credits), now_utc()),
    )
    conn.commit()


def add_credits(installation_id: str, delta: int, paypal_order_id: Optional[str] = None) -> None:
    cur = get_credits(installation_id)
    new_val = max(0, cur + int(delta))
    set_credits(installation_id, new_val)

    conn = db()
    conn.execute(
        "INSERT INTO events(type, installation_id, credits_delta, paypal_order_id, created_at) VALUES(?,?,?,?,?)",
        ("credit_add", installation_id, int(delta), paypal_order_id or "", now_utc()),
    )
    conn.commit()


def consume_one(installation_id: str) -> bool:
    cur = get_credits(installation_id)
    if cur <= 0:
        return False
    set_credits(installation_id, cur - 1)

    conn = db()
    conn.execute(
        "INSERT INTO events(type, installation_id, credits_delta, paypal_order_id, created_at) VALUES(?,?,?,?,?)",
        ("consume", installation_id, -1, "", now_utc()),
    )
    conn.commit()
    return True


def save_order(paypal_order_id: str, installation_id: str, credits: int) -> None:
    conn = db()
    conn.execute(
        """
        INSERT INTO orders(paypal_order_id, installation_id, credits, status, created_at)
        VALUES(?,?,?,?,?)
        ON CONFLICT(paypal_order_id) DO NOTHING
        """,
        (paypal_order_id, installation_id, int(credits), "CREATED", now_utc()),
    )
    conn.execute(
        "INSERT INTO events(type, installation_id, credits_delta, paypal_order_id, created_at) VALUES(?,?,?,?,?)",
        ("order_created", installation_id, 0, paypal_order_id, now_utc()),
    )
    conn.commit()


def mark_order_completed(paypal_order_id: str) -> None:
    conn = db()
    conn.execute(
        "UPDATE orders SET status=?, completed_at=? WHERE paypal_order_id=?",
        ("COMPLETED", now_utc(), paypal_order_id),
    )
    conn.commit()


def get_order_row(paypal_order_id: str):
    conn = db()
    cur = conn.execute(
        "SELECT paypal_order_id, installation_id, credits, status FROM orders WHERE paypal_order_id=?",
        (paypal_order_id,),
    )
    return cur.fetchone()


# =========================================================
# PayPal helpers (OAuth token + verify webhook + create order)
# =========================================================
_token_cache = {"access_token": None, "expires_at": 0}


def get_access_token() -> str:
    """
    OAuth2 client_credentials -> /v1/oauth2/token
    """
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET:
        raise RuntimeError("Missing PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET")

    # cache semplice (non perfetto, ma sufficiente)
    import time
    if _token_cache["access_token"] and time.time() < _token_cache["expires_at"] - 30:
        return str(_token_cache["access_token"])

    auth = base64.b64encode(f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}".encode("utf-8")).decode("ascii")

    url = f"{PAYPAL_API_BASE}/v1/oauth2/token"
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = "grant_type=client_credentials"

    r = requests.post(url, headers=headers, data=data, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"PayPal token error: {r.status_code} {r.text}")

    j = r.json()
    access_token = j.get("access_token")
    expires_in = int(j.get("expires_in", 300))

    _token_cache["access_token"] = access_token
    _token_cache["expires_at"] = time.time() + expires_in
    return str(access_token)


def create_paypal_order(installation_id: str, credits: int, return_url: str, cancel_url: str) -> tuple[str, str]:
    """
    POST /v2/checkout/orders
    Ritorna (order_id, approve_url)
    """
    token = get_access_token()
    url = f"{PAYPAL_API_BASE}/v2/checkout/orders"

    # totale = crediti * 15.00
    unit = float(UNIT_PRICE_EUR)
    total = unit * int(credits)
    total_str = f"{total:.2f}"

    payload = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "reference_id": "REPORTS",
                "description": f"Report credits x{credits}",
                "custom_id": installation_id,  # <- QUI colleghiamo il pagamento all'installazione
                "amount": {
                    "currency_code": CURRENCY,
                    "value": total_str,
                    "breakdown": {
                        "item_total": {"currency_code": CURRENCY, "value": total_str}
                    },
                },
                "items": [
                    {
                        "name": "Report credits",
                        "quantity": str(int(credits)),
                        "unit_amount": {"currency_code": CURRENCY, "value": f"{unit:.2f}"},
                    }
                ],
            }
        ],
        "application_context": {
            "return_url": return_url,
            "cancel_url": cancel_url,
            "user_action": "PAY_NOW",
        },
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code not in (201, 200):
        raise RuntimeError(f"PayPal create order error: {r.status_code} {r.text}")

    j = r.json()
    order_id = j.get("id", "")
    approve_url = ""
    for link in j.get("links", []):
        if link.get("rel") == "approve":
            approve_url = link.get("href", "")
            break

    if not order_id or not approve_url:
        raise RuntimeError("PayPal order response missing id/approve link")

    return order_id, approve_url


def verify_webhook_postback(raw_body: bytes, headers_in: dict) -> bool:
    """
    Metodo "postback": chiamiamo /v1/notifications/verify-webhook-signature
    (PayPal docs mostrano esattamente i campi richiesti)
    """
    if not PAYPAL_WEBHOOK_ID:
        raise RuntimeError("Missing PAYPAL_WEBHOOK_ID")

    token = get_access_token()

    transmission_id = headers_in.get("paypal-transmission-id", "")
    transmission_time = headers_in.get("paypal-transmission-time", "")
    cert_url = headers_in.get("paypal-cert-url", "")
    auth_algo = headers_in.get("paypal-auth-algo", "")
    transmission_sig = headers_in.get("paypal-transmission-sig", "")

    if not transmission_id or not transmission_time or not cert_url or not auth_algo or not transmission_sig:
        return False

    event_obj = json.loads(raw_body.decode("utf-8", errors="ignore"))

    url = f"{PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature"
    payload = {
        "transmission_id": transmission_id,
        "transmission_time": transmission_time,
        "cert_url": cert_url,
        "auth_algo": auth_algo,
        "transmission_sig": transmission_sig,
        "webhook_id": PAYPAL_WEBHOOK_ID,
        "webhook_event": event_obj,
    }
    r = requests.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    if r.status_code != 200:
        return False

    j = r.json()
    # "verification_status": "SUCCESS"
    return j.get("verification_status") == "SUCCESS"


# =========================================================
# API
# =========================================================
@app.get("/health")
def health():
    return {"ok": True, "mode": PAYPAL_MODE}


@app.get("/credits")
def api_credits(installation_id: str):
    if not installation_id:
        raise HTTPException(status_code=400, detail="installation_id required")
    return {"installation_id": installation_id, "credits": get_credits(installation_id)}


@app.post("/consume")
async def api_consume(req: Request):
    body = await req.json()
    installation_id = (body.get("installation_id") or "").strip()
    if not installation_id:
        raise HTTPException(status_code=400, detail="installation_id required")

    ok = consume_one(installation_id)
    if not ok:
        return JSONResponse({"ok": False, "credits": get_credits(installation_id)}, status_code=402)
    return {"ok": True, "credits": get_credits(installation_id)}


@app.post("/create-paypal-order")
async def api_create_paypal_order(req: Request):
    """
    L'app chiama qui per creare un ordine PayPal e ottenere il link di pagamento.
    """
    body = await req.json()
    installation_id = (body.get("installation_id") or "").strip()
    credits = int(body.get("credits") or 1)

    if not installation_id:
        raise HTTPException(status_code=400, detail="installation_id required")
    if credits < 1 or credits > 1000:
        raise HTTPException(status_code=400, detail="credits out of range")

    return_url = body.get("return_url") or "https://example.com/success"
    cancel_url = body.get("cancel_url") or "https://example.com/cancel"

    try:
        order_id, approve_url = create_paypal_order(installation_id, credits, return_url, cancel_url)
        save_order(order_id, installation_id, credits)
        return {"order_id": order_id, "approve_url": approve_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/paypal/webhook")
async def paypal_webhook(request: Request):
    """
    PayPal manda qui gli eventi (es. PAYMENT.CAPTURE.COMPLETED).
    Noi verifichiamo firma + aggiungiamo crediti.
    """
    raw = await request.body()
    headers_in = {k.lower(): v for k, v in request.headers.items()}

    # Verifica autenticità webhook
    try:
        ok = verify_webhook_postback(raw, headers_in)
    except Exception:
        ok = False

    if not ok:
        return JSONResponse({"ok": False}, status_code=400)

    event = json.loads(raw.decode("utf-8", errors="ignore"))
    event_type = event.get("event_type", "")

    # Evento pagamento incassato
    if event_type == "PAYMENT.CAPTURE.COMPLETED":
        resource = event.get("resource") or {}
        # In molti eventi è presente order_id in supplementary_data.related_ids.order_id
        order_id = (((resource.get("supplementary_data") or {}).get("related_ids") or {}).get("order_id")) or ""

        if order_id:
            row = get_order_row(order_id)
            if row:
                _, installation_id, credits, status = row
                # idempotenza: se già completato, non ricaricare due volte
                if status != "COMPLETED":
                    add_credits(installation_id, int(credits), paypal_order_id=order_id)
                    mark_order_completed(order_id)

    return {"ok": True}
