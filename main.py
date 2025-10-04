import re
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
from collections import defaultdict
from fastapi.middleware.cors import CORSMiddleware

from incident_logger import (
    database,
    setup_database,
    log_incident,
    get_incidents,
    mark_incident_handled,
    log_request, # Import the new function
    get_api_usage  # Import the new function
)
from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

# --- Configuration & Helpers ---
ADMIN_KEY = "supersecretadminkey"

def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

# --- WAF Middleware ---
@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith(("/api/", "/admin", "/health")):
        return await call_next(request)

    try: body_bytes = await request.body()
    except Exception: body_bytes = b""
    payload_text = body_bytes.decode("utf-8", errors="ignore")
    full_payload = payload_text + request.url.query
    client_ip = request.client.host if request.client else "unknown"
    
    # Run security checks
    for rule_name, rule_fn in OWASP_RULES.items():
        if callable(rule_fn) and rule_fn(full_payload):
            await log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by WAF rule: {rule_name}"})
    
    triggered_regex = check_regex_rules(full_payload)
    if triggered_regex:
        for r in triggered_regex: await log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered_regex)}"})

    # If the request was not blocked, log it as a success for the usage chart
    await log_request(status='success', client_ip=client_ip)
    
    # Allow the request to proceed
    return await call_next(request)

# --- API Endpoints (async) ---
@app.get("/api/blocked-requests")
async def blocked_requests():
    incidents = await get_incidents()
    buckets = defaultdict(int)
    for inc in incidents:
        try:
            dt = datetime.fromisoformat(inc["timestamp"])
            minute = (dt.minute // 5) * 5
            time_key = f"{dt.hour:02d}:{minute:02d}"
            buckets[time_key] += 1
        except (ValueError, KeyError, TypeError): continue
    sorted_buckets = sorted(buckets.items())
    return [{"time": t, "blocked": c} for t, c in sorted_buckets]

# NEW: Endpoint for the API Usage Chart
@app.get("/api/api-usage")
async def api_usage():
    return await get_api_usage()

@app.get("/admin/incidents")
async def admin_list_incidents(key: str):
    admin_auth(key)
    return await get_incidents()
    
@app.get("/health")
def health():
    return {"status": "ok"}

# --- Dummy endpoint for non-blocked requests to go to ---
@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str):
    return {"message": "Request was not blocked by WAF and was processed.", "path": f"/{path_name}"}
