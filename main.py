from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from collections import defaultdict
from datetime import datetime
from incident_logger import get_incidents, log_incident

app = FastAPI()

# ✅ Allow your frontend (Vercel site) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://medsecurex-58j5.vercel.app"],  # frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ New endpoint for frontend chart
@app.get("/api/blocked-requests")
def blocked_requests():
    incidents = get_incidents()
    buckets = defaultdict(int)

    for inc in incidents:
        ts = datetime.fromisoformat(inc["timestamp"])
        minute = (ts.minute // 5) * 5  # round to nearest 5 min
        time_key = f"{ts.hour:02d}:{minute:02d}"
        buckets[time_key] += 1

    return [{"time": t, "blocked": c} for t, c in sorted(buckets.items())]

# ✅ Test endpoint (optional) to simulate incidents
@app.post("/simulate-block")
def simulate_block(ip: str, payload: str, rule: str):
    log_incident(ip, payload, rule)
    return {"message": "Incident logged"}
