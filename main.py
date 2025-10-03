import asyncio
from typing import Dict, List
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response
import httpx
import logging
from datetime import datetime
from fastapi.responses import JSONResponse
from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules, detect_email
from incident_logger import log_incident, get_incidents, mark_incident_handled

app = FastAPI()
logging.basicConfig(level=logging.INFO)

# Admin key (demo)
ADMIN_KEY = "supersecretadminkey"

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
from fastapi.responses import JSONResponse

@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path

    # Skip internal endpoints
    if path.startswith("/api/blocked-requests") or path.startswith("/health") or path.startswith("/admin"):
        return await call_next(request)

    try:
        body_bytes = await request.body()
    except Exception:
        body_bytes = b""

    payload_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
    qs = request.url.query or ""
    full_payload = payload_text + ("?" + qs if qs else "")

    client_ip = request.client.host if request.client else "unknown"

    # 🔹 Check against malicious patterns
    for pattern, description in BLOCK_RULES:
        if re.search(pattern, full_payload, re.IGNORECASE):
            log_incident(client_ip, full_payload, description)
            # ❌ Instead of proxying → return a clear blocked response
            return JSONResponse(
                status_code=403,
                content={"detail": f"Blocked by WAF: {description}"}
            )

    # If no rule matched → forward request as usual
    backend_base = resolve_backend(request.url.path)
    target = backend_base.rstrip("/") + request.url.path
    ...

    # ... keep the rest of your inspection + forwarding logic below ...


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

    # Forward to appropriate backend
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

# -------------------- New endpoint for frontend chart --------------------
@app.get("/api/blocked-requests")
def blocked_requests():
    """
    Return blocked request counts grouped by minute.
    Example response:
    [
      {"time": "14:00", "blocked": 5},
      {"time": "14:01", "blocked": 2}
    ]
    """
    incidents = get_incidents()
    counts: Dict[str, int] = {}

    for inc in incidents:
        ts = inc.get("timestamp")
        try:
            dt = datetime.fromisoformat(ts)
            time_label = dt.strftime("%H:%M")
        except Exception:
            time_label = "unknown"

        counts[time_label] = counts.get(time_label, 0) + 1

    return [{"time": t, "blocked": counts[t]} for t in sorted(counts.keys())]

# -------------------- Health check --------------------
@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)



