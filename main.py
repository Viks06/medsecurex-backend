import re
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
from collections import defaultdict
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from incident_logger import (
    database,
    setup_database,
    log_incident,
    get_incidents,
    mark_incident_handled,
    log_request,
    get_api_usage
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
    print("--- SERVER STARTUP SEQUENCE ---")
    await database.connect()
    await setup_database()
    print("--- STARTUP COMPLETE ---")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    print("--- SERVER SHUTDOWN COMPLETE ---")

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
    try:
        body_bytes = await request.body()
        payload_text = body_bytes.decode("utf-8", errors="ignore")
        full_payload = payload_text + request.url.query
    except Exception:
        full_payload = request.url.query

    for rule_name, rule_fn in OWASP_RULES.items():
        if callable(rule_fn) and rule_fn(full_payload):
            await log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by WAF rule: {rule_name}"})
    
    triggered_regex = check_regex_rules(full_payload)
    if triggered_regex:
        for r in triggered_regex:
            await log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered_regex)}"})

    await log_request(status='success', client_ip=client_ip)
    response = await call_next(request)
    return response

# --- API Endpoints ---
@app.get("/api/blocked-requests")
async def blocked_requests():
    return await get_incidents()

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

# --- NEW: Temporary Debug Endpoint to Reset the Database ---
@app.get("/admin/reset-db")
async def reset_db(key: str):
    admin_auth(key)
    try:
        print("--- [ADMIN] Attempting to reset database ---")
        async with database.transaction():
            await database.execute(text("DROP TABLE IF EXISTS requests;"))
            await database.execute(text("DROP TABLE IF EXISTS incidents;"))
        print("--- [ADMIN] Tables dropped successfully. The server will now restart. ---")
        return {"message": "Database tables dropped. Server is restarting to recreate them."}
    except Exception as e:
        print(f"--- [ADMIN] ERROR dropping tables: {e} ---")
        raise HTTPException(status_code=500, detail=str(e))

# --- Catch-all Dummy Endpoint ---
@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str):
    return {"message": "Request processed successfully.", "path": f"/{path_name}"}
