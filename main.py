import re
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
from collections import defaultdict
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)

from incident_logger import (
    database,
    setup_database,
    log_incident,
    get_incidents,
    mark_incident_handled,
    log_request,
    get_api_usage,
    get_detected_ttps # Import the new function
)
from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await database.connect()
    await setup_database()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

ADMIN_KEY = "supersecretadminkey"

def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith(("/api/", "/admin", "/health")):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    full_payload = ""
    try:
        body_bytes = await request.body()
        payload_text = body_bytes.decode("utf-8", errors="ignore")
        full_payload = payload_text + request.url.query
    except Exception:
        full_payload = request.url.query

    # Security checks
    for rule_name, rule_fn in OWASP_RULES.items():
        if callable(rule_fn) and rule_fn(full_payload):
            await log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by WAF rule: {rule_name}"})
    
    triggered_regex = check_regex_rules(full_payload)
    if triggered_regex:
        for r in triggered_regex:
            await log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered_regex)}"})

    # If not blocked, log as success and proceed
    await log_request(status='success', client_ip=client_ip)
    response = await call_next(request)
    return response

# --- API Endpoints ---
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
        except (ValueError, KeyError, TypeError):
            continue
    sorted_buckets = sorted(buckets.items())
    return [{"time": t, "blocked": c} for t, c in sorted_buckets]

@app.get("/api/api-usage")
async def api_usage():
    return await get_api_usage()

# NEW: Endpoint for the TTPs Table
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

@app.get("/admin/reset-db")
async def reset_db(key: str):
    admin_auth(key)
    try:
        async with database.transaction():
            await database.execute(text("DROP TABLE IF EXISTS requests;"))
            await database.execute(text("DROP TABLE IF EXISTS incidents;"))
            await database.execute(text("DROP TABLE IF EXISTS ttps;"))
        return {"message": "All database tables dropped."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Catch-all Dummy Endpoint ---
@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str):
    return {"message": "Request processed successfully.", "path": f"/{path_name}"}
