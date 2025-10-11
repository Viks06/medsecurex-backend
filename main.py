import os
import logging
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

# === Local modules ===
from incident_logger import (
    database,
    setup_database,
    log_incident,
    log_request,
    get_incidents,
    get_api_usage,
)
from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules

# ==============================================================
# 🌍 APP CONFIGURATION
# ==============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = FastAPI(title="MedSecureX Backend", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You can restrict this to your frontend domain later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_KEY = os.getenv("ADMIN_KEY", "supersecretadminkey")

# ==============================================================
# 🚀 STARTUP & SHUTDOWN
# ==============================================================

@app.on_event("startup")
async def startup():
    try:
        await database.connect()
        await setup_database()
        logging.info("✅ Database connected and verified successfully.")
    except Exception as e:
        logging.error(f"❌ Failed to initialize database: {e}", exc_info=True)
        raise

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    logging.info("🛑 Database disconnected successfully.")


# ==============================================================
# 🔐 ADMIN AUTH
# ==============================================================

def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized access.")


# ==============================================================
# 🧱 PAYLOAD INSPECTION MIDDLEWARE
# ==============================================================

@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    """Inspect incoming payloads for malicious patterns (OWASP + regex)."""
    path = request.url.path
    method = request.method

    if path.startswith(("/api/", "/admin", "/health")):
        # Skip internal endpoints
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    try:
        body_bytes = await request.body()
        payload_text = body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        payload_text = ""

    # Combine query string and body for rule matching
    payload = payload_text + (request.url.query or "")

    # --- OWASP RULE DETECTION ---
    for rule_name, rule_fn in OWASP_RULES.items():
        try:
            if callable(rule_fn) and rule_fn(payload):
                logging.warning(f"🚨 OWASP rule triggered: {rule_name} from {client_ip}")
                await log_incident(client_ip, payload, rule_name)
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"Blocked by OWASP rule: {rule_name}"},
                )
        except Exception as e:
            logging.error(f"Error evaluating rule {rule_name}: {e}", exc_info=True)

    # --- REGEX RULE DETECTION ---
    triggered = check_regex_rules(payload)
    if triggered:
        logging.warning(f"🚨 Regex rule(s) triggered: {triggered}")
        for r in triggered:
            await log_incident(client_ip, payload, r)
        return JSONResponse(
            status_code=403,
            content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered)}"},
        )

    # --- If Safe Request ---
    await log_request(status="success", client_ip=client_ip)
    response = await call_next(request)
    return response


# ==============================================================
# 📊 API ENDPOINTS
# ==============================================================

@app.get("/api/blocked-requests", response_model=List[Dict[str, Any]])
async def blocked_requests():
    """Return number of blocked requests grouped by 5-minute intervals."""
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

    return [{"time": t, "blocked": c} for t, c in sorted(buckets.items())]


@app.get("/api/api-usage")
async def api_usage():
    """Return API usage statistics over time."""
    return await get_api_usage()


@app.get("/admin/incidents")
async def admin_list_incidents(key: str):
    """Admin view for all incidents."""
    admin_auth(key)
    return await get_incidents()


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "MedSecureX Backend"}


# ==============================================================
# 🧠 MITRE TTP AGGREGATION (CACHED)
# ==============================================================

MITRE_MAP = {
    "SQL Injection": {"id": "T1190", "tactic": "Execution"},
    "XSS": {"id": "T1059.007", "tactic": "Execution"},
    "Path Traversal": {"id": "T1083", "tactic": "Discovery"},
    "Brute Force": {"id": "T1110", "tactic": "Credential Access"},
}

@app.get("/api/ttps")
async def get_ttp_data(limit: int = 100):
    """Aggregate incidents by rule and return MITRE-mapped objects."""
    try:
        query = """
            SELECT
                rule_triggered,
                COUNT(*) AS count,
                MAX(timestamp) AS last_seen,
                (array_agg(payload ORDER BY timestamp DESC))[1] AS sample_payload,
                (array_agg(ip ORDER BY timestamp DESC))[1] AS sample_ip
            FROM incidents
            WHERE rule_triggered IS NOT NULL
            GROUP BY rule_triggered
            ORDER BY count DESC
            LIMIT :limit;
        """
        results = await database.fetch_all(query, values={"limit": limit})

        ttps = []
        for row in results:
            data = dict(row._mapping)
            rule = data["rule_triggered"]
            mapping = MITRE_MAP.get(rule, {"id": "Unknown", "tactic": "Unmapped"})

            snippet = data.get("sample_payload")
            if snippet and len(snippet) > 250:
                snippet = snippet[:250] + "..."

            ttps.append({
                "id": mapping["id"],
                "name": rule,
                "tactic": mapping["tactic"],
                "count": data["count"],
                "lastSeen": (
                    data["last_seen"].isoformat()
                    if isinstance(data["last_seen"], datetime)
                    else data["last_seen"]
                ),
                "description": f"Latest detection of {rule} from {data.get('sample_ip', 'N/A')}",
                "example": snippet or "N/A",
            })

        return ttps
    except Exception as e:
        logging.error(f"❌ Could not fetch TTP data: {e}", exc_info=True)
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ==============================================================
# 🧩 FALLBACK ROUTE
# ==============================================================

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str):
    """Handles non-API routes safely."""
    return {"message": "Request processed successfully.", "path": f"/{path_name}"}
