# main.py (Updated)
import re
import asyncio
from typing import Dict, List
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response
import httpx
import logging
from datetime import datetime
from collections import defaultdict

from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules
from incident_logger import log_incident, get_incidents, mark_incident_handled

app = FastAPI()
logging.basicConfig(level=logging.INFO)

# Admin key (demo) - Consider using an environment variable for production
ADMIN_KEY = "supersecretadminkey"

# Example block rules (add your own)
BLOCK_RULES = [
    (r"<script.*?>.*?</script>", "XSS Script Tag"),
    (r"select.*from.*", "SQL Injection Attempt"),
    (r"union.*select", "SQL Injection Attempt"),
]

# Route map - map path prefixes to backend base URLs
ROUTE_MAP = {
    "/auth": "http://127.0.0.1:9100",
    "/users": "http://127.0.0.1:9200",
    "/orders": "http://127.0.0.1:9300",
}
DEFAULT_BACKEND = "http://127.0.0.1:9000"  # fallback backend

# httpx client timeout
CLIENT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# -------------------- Auth helper --------------------
def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

def resolve_backend(path: str) -> str:
    prefixes = sorted(ROUTE_MAP.keys(), key=len, reverse=True)
    for p in prefixes:
        if path.startswith(p):
            return ROUTE_MAP[p]
    return DEFAULT_BACKEND

# -------------------- Middleware --------------------
@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path

    # Skip internal endpoints to prevent loops
    if path.startswith("/api/") or path.startswith("/health") or path.startswith("/admin"):
        return await call_next(request)

    try:
        body_bytes = await request.body()
    except Exception:
        body_bytes = b""

    payload_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
    qs = request.url.query or ""
    full_payload = payload_text + ("?" + qs if qs else "")

    client_ip = request.client.host if request.client else "unknown"

    # 🔹 Check against basic malicious patterns
    for pattern, description in BLOCK_RULES:
        if re.search(pattern, full_payload, re.IGNORECASE):
            log_incident(client_ip, full_payload, description)
            return JSONResponse(
                status_code=403,
                content={"detail": f"Blocked by WAF: {description}"}
            )

    # OWASP rules
    for rule_name, rule_fn in OWASP_RULES.items():
        try:
            if rule_fn(full_payload):
                log_incident(client_ip, full_payload, rule_name)
                return JSONResponse(status_code=403, content={"detail": f"Blocked by OWASP rule: {rule_name}"})
        except Exception:
            logging.exception("Error evaluating OWASP rule %s", rule_name)

    # Regex rules
    try:
        triggered = check_regex_rules(full_payload)
    except Exception:
        triggered = []
    if triggered:
        for r in triggered:
            log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered)}"})

    # Forward to appropriate backend if no rule matched
    backend_base = resolve_backend(request.url.path)
    target = backend_base.rstrip("/") + request.url.path
    if request.url.query:
        target = f"{target}?{request.url.query}"

    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient(timeout=CLIENT_TIMEOUT) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target,
                headers=headers,
                content=body_bytes,
                params=None
            )
        except httpx.RequestError as exc:
            logging.exception("Upstream request failed: %s", exc)
            return JSONResponse(status_code=502, content={"detail": "Bad Gateway: upstream unreachable"})

    content_type = resp.headers.get("content-type", "application/json")
    try:
        if "application/json" in content_type:
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        else:
            return Response(content=resp.content, status_code=resp.status_code, media_type=content_type)
    except Exception:
        return Response(content=resp.content, status_code=resp.status_code, media_type=content_type)

# -------------------- Admin endpoints --------------------
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

# -------------------- Frontend and External Tool Endpoints --------------------
@app.get("/api/blocked-requests")
def blocked_requests():
    """
    Return blocked request counts grouped by 5-minute intervals for the frontend chart.
    """
    incidents = get_incidents()
    buckets = defaultdict(int)

    for inc in incidents:
        try:
            dt = datetime.fromisoformat(inc["timestamp"])
            minute = (dt.minute // 5) * 5
            time_key = f"{dt.hour:02d}:{minute:02d}"
            buckets[time_key] += 1
        except (ValueError, KeyError):
            continue

    sorted_buckets = sorted(buckets.items())
    return [{"time": t, "blocked": c} for t, c in sorted_buckets]

@app.post("/api/incidents")
def receive_incident(data: dict, key: str):
    """
    Endpoint for external tools like Suricata to submit new incidents.
    """
    admin_auth(key)
    ip = data.get("ip", "unknown")
    payload = data.get("payload", "")
    rule = data.get("rule", "external_alert")
    log_incident(ip, payload, rule)
    return {"status": "incident logged"}

# -------------------- Health check --------------------
@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
