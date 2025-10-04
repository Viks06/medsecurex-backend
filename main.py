# main.py (FINAL CORRECTED VERSION)
import re
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
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


from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development. In production, set to your Vercel domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



app = FastAPI()

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
BLOCK_RULES = [
    (r"<script.*?>.*?</script>", "XSS Script Tag"),
    (r"select.*from.*", "SQL Injection Attempt"),
]

def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

# --- WAF Middleware ---
@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path
    # Skip internal, admin, and health check endpoints
    if path.startswith(("/api/", "/admin", "/health")):
        return await call_next(request)

    try: body_bytes = await request.body()
    except Exception: body_bytes = b""
    payload_text = body_bytes.decode("utf-8", errors="ignore")
    full_payload = payload_text + request.url.query
    client_ip = request.client.host if request.client else "unknown"
    
    # Combine all rules for a single check
    all_rules = {
        "XSS Script Tag": re.compile(r"<script.*?>.*?</script>", re.IGNORECASE),
        "SQL Injection Attempt": re.compile(r"select.*from.*", re.IGNORECASE),
        **OWASP_RULES
    }

    for rule_name, rule_logic in all_rules.items():
        is_match = False
        if isinstance(rule_logic, re.Pattern): # Check if it's a compiled regex
            if rule_logic.search(full_payload):
                is_match = True
        elif callable(rule_logic): # Check if it's a function
            if rule_logic(full_payload):
                is_match = True
        
        if is_match:
            await log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by WAF rule: {rule_name}"})

    # Check separate regex rules
    triggered_regex = check_regex_rules(full_payload)
    if triggered_regex:
        for r in triggered_regex: await log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered_regex)}"})

    # If no rules are matched, allow the request to proceed to the destination endpoints
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

@app.get("/admin/incidents")
async def admin_list_incidents(key: str):
    admin_auth(key)
    return await get_incidents()
    
@app.get("/health")
def health():
    return {"status": "ok"}

# --- Dummy endpoint for non-blocked requests to go to ---
# The WAF middleware will block requests before they reach this.
@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str):
    # This endpoint now represents all your backend services (e.g., /submit, /users)
    return {"message": "Request was not blocked by WAF and was processed.", "path": f"/{path_name}"}

