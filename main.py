import re
import asyncio
import os
from typing import Dict, List
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response
import httpx
import logging
from datetime import datetime
from collections import defaultdict

# Import functions from our other files
from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules
from incident_logger import log_incident, get_incidents, mark_incident_handled, setup_database

# Basic logging configuration
logging.basicConfig(level=logging.INFO)

# --- App Initialization and Startup Event ---
app = FastAPI()

@app.on_event("startup")
def on_startup():
    """This function runs when the application starts up."""
    print("--- SERVER STARTUP SEQUENCE ---")
    
    # Check for the DATABASE_URL environment variable
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        print("✅ SUCCESS: DATABASE_URL environment variable was found.")
    else:
        print("❌ CRITICAL ERROR: DATABASE_URL environment variable was NOT FOUND.")
    
    # Proceed with database setup
    setup_database()
    
    print("--- STARTUP COMPLETE ---")


# --- Configuration ---
ADMIN_KEY = "supersecretadminkey"

BLOCK_RULES = [
    (r"<script.*?>.*?</script>", "XSS Script Tag"),
    (r"select.*from.*", "SQL Injection Attempt"),
    (r"union.*select", "SQL Injection Attempt"),
]

# Use Render's internal service URLs
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

    # Skip internal/admin endpoints to prevent loops
    if path.startswith("/api/") or path.startswith("/health") or path.startswith("/admin"):
        return await call_next(request)

    try:
        body_bytes = await request.body()
    except Exception:
        body_bytes = b""

    payload_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
    full_payload = payload_text + request.url.query

    client_ip = request.client.host if request.client else "unknown"

    # Check against basic malicious patterns
    for pattern, description in BLOCK_RULES:
        if re.search(pattern, full_payload, re.IGNORECASE):
            log_incident(client_ip, full_payload, description)
            return JSONResponse(
                status_code=403,
                content={"detail": f"Blocked by WAF: {description}"}
            )

    # OWASP rules
    for rule_name, rule_fn in OWASP_RULES.items():
        if rule_fn(full_payload):
            log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by OWASP rule: {rule_name}"})

    # Regex rules
    triggered = check_regex_rules(full_payload)
    if triggered:
        for r in triggered:
            log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered)}"})

    # Forward to appropriate backend if no rule matched
    backend_base_url = resolve_backend(path)
    target_url = f"{backend_base_url}{path}?{request.url.query}" if request.url.query else f"{backend_base_url}{path}"
    
    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient(timeout=CLIENT_TIMEOUT) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body_bytes
            )
            return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))
        except httpx.RequestError:
            return JSONResponse(status_code=502, content={"detail": "Bad Gateway: Upstream service is unreachable"})


# --- API Endpoints ---
@app.get("/api/blocked-requests")
def blocked_requests():
    """Return blocked request counts grouped by 5-minute intervals for the frontend chart."""
    incidents = get_incidents()
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

@app.post("/api/incidents")
def receive_incident(data: dict, key: str):
    """Endpoint for external tools to submit new incidents."""
    admin_auth(key)
    ip = data.get("ip", "unknown")
    payload = data.get("payload", "")
    rule = data.get("rule", "external_alert")
    log_incident(ip, payload, rule)
    return {"status": "incident logged"}

@app.get("/admin/incidents")
def admin_list_incidents(key: str):
    admin_auth(key)
    return get_incidents()

@app.post("/admin/incidents/{incident_id}/handle")
def admin_handle_incident(incident_id: int, key: str):
    admin_auth(key)
    if mark_incident_handled(incident_id):
        return {"message": f"Incident {incident_id} marked as handled"}
    raise HTTPException(status_code=404, detail="Incident not found")

@app.get("/health")
def health():
    return {"status": "ok"}


# --- Uvicorn Runner ---
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
