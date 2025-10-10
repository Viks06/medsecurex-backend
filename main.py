import re
import asyncio
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from incident_logger import (
    setup_database,
    database,
    log_incident,
    log_request,
    get_detected_ttps,
    get_api_usage,
)
import logging

logging.basicConfig(level=logging.INFO)

app = FastAPI()

# --------------------------
# 🔹 Enable CORS for frontend
# --------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace * with your Vercel frontend URL later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------
# 🔹 FastAPI lifecycle events
# --------------------------
@app.on_event("startup")
async def startup():
    await database.connect()
    await setup_database()
    logging.info("✅ Database connected and tables checked.")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    logging.info("🛑 Database disconnected.")

# --------------------------
# 🔹 Security Rules
# --------------------------
BLOCK_RULES = [
    (r"<script.*?>.*?</script>", "XSS"),
    (r"('|\"|;|\bDROP\b|\bDELETE\b|\bINSERT\b|\bUPDATE\b)", "SQL Injection"),
    (r"(\.\./)+", "Path Traversal"),
    (r"password=.*&", "Brute Force"),
]

# --------------------------
# 🔹 Middleware for inspection
# --------------------------
@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    path = request.url.path

    # Skip internal endpoints
    if path.startswith("/api/") or path.startswith("/health"):
        return await call_next(request)

    try:
        body_bytes = await request.body()
    except Exception:
        body_bytes = b""

    payload_text = body_bytes.decode("utf-8", errors="ignore")
    qs = request.url.query or ""
    full_payload = payload_text + ("?" + qs if qs else "")
    client_ip = request.client.host if request.client else "unknown"

    # 🔎 Detect malicious payload
    for pattern, rule_name in BLOCK_RULES:
        if re.search(pattern, full_payload, re.IGNORECASE):
            await log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(status_code=403, content={"detail": f"Blocked by WAF: {rule_name}"})

    # No threat detected — log as safe
    await log_request(status="success", client_ip=client_ip)
    response = await call_next(request)
    return response

# --------------------------
# 🔹 API Endpoints
# --------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/api/blocked-requests")
async def blocked_requests():
    data = await get_api_usage()
    return data

@app.get("/api/ttp-detected")
async def ttp_detected():
    data = await get_detected_ttps()
    return data

@app.get("/")
async def root():
    return {"message": "MedSecureX Backend running successfully 🚀"}
