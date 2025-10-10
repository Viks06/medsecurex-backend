import re
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules
from incident_logger import (
    database, setup_database, log_incident, get_incidents,
    log_request, get_api_usage, get_detected_ttps
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI(title="MedSecureX Backend", version="2.0")

# --- Allow frontend access (update this later to restrict origins) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your frontend URL for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_KEY = "supersecretadminkey"

def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

# --- Startup / Shutdown Hooks ---
@app.on_event("startup")
async def startup():
    await database.connect()
    await setup_database()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# --- Security Middleware ---
@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith(("/api/", "/admin", "/health")):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    try:
        body_bytes = await request.body()
        payload_text = body_bytes.decode("utf-8", errors="ignore")
        full_payload = payload_text + (request.url.query or "")
    except Exception:
        full_payload = request.url.query or ""

    # --- Check OWASP Rules ---
    for rule_name, rule_fn in OWASP_RULES.items():
        try:
            if callable(rule_fn) and rule_fn(full_payload):
                await log_incident(client_ip, full_payload, rule_name)
                return JSONResponse(status_code=403, content={"detail": f"Blocked by WAF rule: {rule_name}"})
        except Exception as e:
            logging.error(f"Rule {rule_name} error: {e}")

    # --- Check Regex Rules ---
    triggered_rules = check_regex_rules(full_payload)
    if triggered_rules:
        for r in triggered_rules:
            await log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered_rules)}"})

    # --- Otherwise log success ---
    await log_request(status="success", client_ip=client_ip)
    return await call_next(request)

# --- Public API Routes ---
@app.get("/")
async def root():
    return {"message": "✅ MedSecureX Backend is running!"}

@app.get("/api/blocked-requests")
async def blocked_requests():
    return await get_api_usage()

@app.get("/api/api-usage")
async def api_usage():
    return await get_api_usage()

@app.get("/api/ttp-detected")
async def ttp_detected():
    return await get_detected_ttps()

@app.get("/admin/incidents")
async def admin_list_incidents(key: str):
    admin_auth(key)
    return await get_incidents()

@app.get("/health")
def health():
    return {"status": "ok"}
