import os
import logging
from datetime import datetime
from collections import defaultdict

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from incident_logger import (
    database,
    setup_database,
    log_incident,
    get_incidents,
    log_request,
    get_api_usage
)
from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules

# ----------------------------
# Logging setup
# ----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------------------
# FastAPI App
# ----------------------------
app = FastAPI(title="MEDSecureX API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Startup / Shutdown
# ----------------------------
@app.on_event("startup")
async def startup():
    try:
        await database.connect()
        logger.info("Connected to database.")
        await setup_database()
    except Exception as e:
        logger.exception("Startup error (DB): %s", e)
        raise

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    logger.info("Disconnected from database.")

# ----------------------------
# Admin key
# ----------------------------
ADMIN_KEY = os.getenv("ADMIN_KEY", "supersecretadminkey")

def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

# ----------------------------
# Middleware: Payload Inspection
# ----------------------------
@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith(("/api/", "/admin", "/health")):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    full_payload = ""
    try:
        body_bytes = await request.body()
        full_payload = body_bytes.decode("utf-8", errors="ignore") + request.url.query
    except Exception:
        full_payload = request.url.query

    # OWASP Rules
    for rule_name, rule_fn in OWASP_RULES.items():
        if callable(rule_fn) and rule_fn(full_payload):
            await log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by WAF rule: {rule_name}"})

    # Regex Rules
    triggered_regex = check_regex_rules(full_payload)
    if triggered_regex:
        for r in triggered_regex:
            await log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered_regex)}"})

    # Log success
    await log_request(status="success", client_ip=client_ip)

    response = await call_next(request)
    return response

# ----------------------------
# API Endpoints
# ----------------------------
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
        except Exception:
            continue
    sorted_buckets = sorted(buckets.items())
    return [{"time": t, "blocked": c} for t, c in sorted_buckets]

@app.get("/api/api-usage")
async def api_usage():
    return await get_api_usage()

@app.get("/api/alerts")
async def get_alerts_list():
    incidents_from_db = await get_incidents()
    formatted_alerts = []

    for inc in incidents_from_db:
        rule = inc.get("rule_triggered") or inc.get("payload") or "Unknown"

        severity = "Medium"
        if any(x in rule.upper() for x in ["SQL", "SQLI", "DROP"]):
            severity = "Critical"
        elif any(x in rule.upper() for x in ["XSS", "<SCRIPT"]):
            severity = "Critical"
        elif any(x in rule.upper() for x in ["SSRF", "METADATA"]):
            severity = "High"

        status_map = {
            "open": "New",
            "new": "New",
            "in_progress": "In Progress",
            "inprogress": "In Progress",
            "resolved": "Resolved",
            "dismissed": "Dismissed"
        }
        raw_status = (inc.get("status") or "open").lower()
        ui_status = status_map.get(raw_status, "New")

        formatted_alerts.append({
            "description": rule,
            "ttp_id": inc.get("ttp_id", "T1190"),
            "severity": severity,
            "status": ui_status,
            "timestamp": inc.get("timestamp"),
        })

    sorted_alerts = sorted(formatted_alerts, key=lambda x: x.get("timestamp") or "", reverse=True)
    return sorted_alerts

@app.get("/api/ttps")
async def get_ttps_endpoint():
    # Just return unique TTPs from incidents
    incidents = await get_incidents()
    ttps = list({inc.get("ttp_id", "T1190") for inc in incidents})
    return {"ttps": ttps}

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
        return {"message": "Database tables dropped. Server will recreate them on next startup."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Catch-all dummy endpoint
@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str):
    return {"message": "Request processed successfully.", "path": f"/{path_name}"}
