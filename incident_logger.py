import os
from datetime import datetime
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL")

try:
    engine = create_engine(DATABASE_URL)
except Exception as e:
    print(f"FATAL: Could not create database engine. {e}")
    engine = None

def setup_database():
    if not engine:
        print("ERROR: Database engine not available. Cannot set up table.")
        return
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    ip VARCHAR(45),
                    payload TEXT,
                    rule_triggered VARCHAR(255),
                    status VARCHAR(50)
                );
            """))
            conn.commit()
    except Exception as e:
        print(f"ERROR: Could not create incidents table. {e}")

def log_incident(ip: str, payload: str, rule: str):
    if not engine:
        print("ERROR: Database engine not available. Cannot log incident.")
        return
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO incidents (timestamp, ip, payload, rule_triggered, status)
                VALUES (:ts, :ip, :payload, :rule, :status)
            """), {
                "ts": datetime.utcnow(),
                "ip": ip,
                "payload": payload,
                "rule": rule,
                "status": "open"
            })
            conn.commit()
        print(f"🚨 Incident logged to DB: {rule} from {ip}")
    except Exception as e:
        print(f"ERROR: Could not log incident to DB. {e}")

def get_incidents():
    if not engine:
        print("ERROR: Database engine not available. Cannot get incidents.")
        return []
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 500"))
            incidents = [dict(row._mapping) for row in result]
            for inc in incidents:
                if isinstance(inc.get('timestamp'), datetime):
                    inc['timestamp'] = inc['timestamp'].isoformat()
            return incidents
    except Exception as e:
        print(f"ERROR: Could not get incidents from DB. {e}")
        return []

def mark_incident_handled(index: int):
    print(f"NOTE: mark_incident_handled({index}) needs to be updated for database use.")
    return True
