# main.py (FINAL ASYNC VERSION + DEBUG ENDPOINT)
import re
import os
from typing import Dict, List
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response
import httpx
from datetime import datetime
from collections import defaultdict

from incident_logger import (
    database,
    setup_database,
    log_incident,
    get_incidents,
    mark_incident_handled
)
from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules

app = FastAPI()

# --- App Lifecycle Events ---
@app.on_event("startup")
async def startup():
    print("--- SERVER STARTUP SEQUENCE ---")
    await database.connect()
    await setup_database()
    print("--- STARTUP COMPLETE ---")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    print("--- SERVER SHUTDOWN COMPLETE ---")

# --- Configuration ---
ADMIN_KEY = "supersecretadminkey"
BLOCK_RULES = [
    (r"<script.*?>.*?</script>", "XSS Script Tag"),
    (r"select.*from.*", "SQL Injection Attempt"),
    (r"union.*select", "SQL Injection Attempt"),
]
ROUTE_MAP = {
    "/auth": "http://backend-auth:9100",
    "/users": "http://backend-users:9200",
    "/orders": "http://backend-orders:9300",
}
DEFAULT_BACKEND = "http://backend-default:9000"
CLIENT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# --- Helper Functions ---
def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

def resolve_backend(path: str) -> str:
    for prefix, backend_url in ROUTE_MAP.items():
        if path.startswith(prefix):
            return backend_url
    return DEFAULT_BACKEND

# --- WAF Middleware ---
@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") or path.startswith("/health") or path.startswith("/admin"):
        return await call_next(request)

    try: body_bytes = await request.body()
    except Exception: body_bytes = b""
    payload_text = body_bytes.decode("utf-8", errors="ignore")
    full_payload = payload_text + request.url.query
    client_ip = request.client.host if request.client else "unknown"

    for pattern, description in BLOCK_RULES:
        if re.search(pattern, full_payload, re.IGNORECASE):
            await log_incident(client_ip, full_payload, description)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by WAF: {description}"})

    for rule_name, rule_fn in OWASP_RULES.items():
        if rule_fn(full_payload):
            await log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by OWASP rule: {rule_name}"})
    
    triggered = check_regex_rules(full_payload)
    if triggered:
        for r in triggered: await log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered)}"})

    backend_base_url = resolve_backend(path)
    target_url = f"{backend_base_url}{path}?{request.url.query}"
    headers = dict(request.headers
