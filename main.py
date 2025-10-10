import re
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
from collections import defaultdict
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
import logging

# Use a standard logger with a clear format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
    logging.info("--- SERVER STARTUP SEQUENCE ---")
    await database.connect()
    await setup_database()
    logging.info("--- STARTUP COMPLETE ---")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    logging.info("--- SERVER SHUTDOWN COMPLETE ---")

ADMIN_KEY = "supersecretadminkey"

def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path
    logging.info(f"[WAF] New request received for path: {path}")

    if path.startswith(("/api/", "/admin", "/health")):
        logging.info(f"[WAF] Skipping WAF for internal path: {path}")
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    full_payload = ""
    try:
        logging.info("[WAF] Reading request body...")
        body_bytes = await request.body()
        payload_text = body_bytes.decode("utf-8", errors="ignore")
        full_payload = payload_text + request.url.query
        logging.info(f"[WAF] Full payload to inspect (truncated): {full_payload[:200]}")
    except Exception as e:
        logging.error(f"[WAF] Error reading request body: {e}", exc_info=True)
        full_payload = request.url.query

    # --- Security Checks ---
    logging.info("[WAF] Starting security rule checks...")
    for rule_name, rule_fn in OWASP_RULES.items():
        if callable(rule_fn) and rule_fn(full_payload):
            logging.warning(f"[WAF] BLOCKED by OWASP rule: {rule_name}")
            await log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by WAF rule: {rule_name}"})
    
    triggered_regex = check_regex_rules(full_payload)
    if triggered_regex:
        logging.warning(f"[WAF] BLOCKED by Regex rule(s): {', '.join(triggered_regex)}")
        for r in triggered_regex:
            await log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered_regex)}"})

    # If not blocked, log as success and proceed
    logging.info("[WAF] No rules matched. Request is safe. Logging as 'success'.")
    await log_request(status='success', client_ip=client_ip)
    
    response = await call_next(request)
    logging.info(f"[WAF] Request to {path} processed with status: {response.status_code}")
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

@app.get("/admin/reset-db")
async def reset_db(key: str):
    admin_auth(key)
    try:
        async with database.transaction():
            await database.execute(text("DROP TABLE IF EXISTS requests;"))
            await database.execute(text("DROP TABLE IF EXISTS incidents;"))
            await database.execute(text("DROP TABLE IF EXISTS ttps;"))
        return {"message": "All database tables dropped. Server will restart to recreate them."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Catch-all Dummy Endpoint ---
@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str):
    return {"message": "Request processed successfully.", "path": f"/{path_name}"}
