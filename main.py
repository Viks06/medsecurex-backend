import os
from datetime import datetime, timezone
from databases import Database
from sqlalchemy import MetaData, Table, Column, Integer, String, DateTime, Text
import logging

logging.basicConfig(level=logging.INFO)

DATABASE_URL = os.getenv("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is required")

database = Database(DATABASE_URL)
metadata = MetaData()

# --- Tables ---
incidents_table = Table(
    "incidents", metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("ip", String(45)),
    Column("payload", Text),
    Column("rule_triggered", String(255)),
    Column("status", String(50), default="open"),
    Column("ttp_id", String(10)),
)

requests_table = Table(
    "requests", metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("status", String(50)),
    Column("client_ip", String(45)),
)


# --- DB Setup ---
async def setup_database():
    logging.info("[DB Setup] Starting...")
    try:
        async with database.transaction():
            await database.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    ip VARCHAR(45),
                    payload TEXT,
                    rule_triggered VARCHAR(255),
                    status VARCHAR(50),
                    ttp_id VARCHAR(10)
                );
            """)
            await database.execute("""
                CREATE TABLE IF NOT EXISTS requests (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    status VARCHAR(50),
                    client_ip VARCHAR(45)
                );
            """)
        logging.info("✅ Tables ready")
    except Exception as e:
        logging.error(f"❌ DB Setup failed: {e}", exc_info=True)


# --- Logging ---
async def log_request(status: str, client_ip: str):
    try:
        query = requests_table.insert().values(
            status=status, client_ip=client_ip, timestamp=datetime.now(timezone.utc)
        )
        await database.execute(query)
        logging.info(f"✅ Request logged: {status}")
    except Exception as e:
        logging.error(f"❌ Could not log request: {e}", exc_info=True)


async def log_incident(ip: str, payload: str, rule: str):
    try:
        TTP_MAP = {
            "Broken Access Control": "T1548",
            "Cryptographic Failures": "T1600",
            "Injection": "T1055",
            "SQL Injection": "T1055",
            "Insecure Design": "T1601",
            "Security Misconfiguration": "T1547",
            "Vulnerable and Outdated Components": "T1555",
            "Identification and Authentication Failures": "T1078",
            "Software and Data Integrity Failures": "T1553",
            "Server-Side Request Forgery (SSRF)": "T1595",
            "Logging and Monitoring Failures": "T1562",
            "XSS": "T1059",
            "Directory Traversal": "T1083",
        }

        ttp_id_to_log = TTP_MAP.get(rule, "T1190")
        query_incident = incidents_table.insert().values(
            ip=ip,
            payload=payload,
            rule_triggered=rule,
            status="open",
            ttp_id=ttp_id_to_log,
            timestamp=datetime.now(timezone.utc)
        )
        await database.execute(query_incident)
        logging.info(f"🚨 Incident logged ({rule}) with TTP ID {ttp_id_to_log}")
        await log_request(status='error', client_ip=ip)
    except Exception as e:
        logging.error(f"❌ Could not log incident: {e}", exc_info=True)


# --- Fetch ---
async def get_api_usage():
    try:
        results = await database.fetch_all("""
            SELECT
                to_char(date_trunc('hour', timestamp) + floor(extract(minute from timestamp)/5) * interval '5 minutes','HH24:MI') as time,
                COUNT(CASE WHEN status='success' THEN 1 END) as success,
                COUNT(CASE WHEN status='error' THEN 1 END) as errors
            FROM requests
            WHERE timestamp > NOW() - INTERVAL '1 hour'
            GROUP BY time
            ORDER BY time;
        """)
        usage_data = []
        for row in results:
            row_dict = dict(row._mapping)
            success_count = int(row_dict.get('success', 0))
            error_count = int(row_dict.get('errors', 0))
            total_requests = success_count + error_count
            usage_data.append({
                "time": row_dict['time'],
                "rps": total_requests,
                "success": success_count,
                "errors": error_count
            })
        return usage_data
    except Exception as e:
        logging.error(f"❌ Could not get API usage: {e}", exc_info=True)
        return []


async def get_incidents():
    try:
        results = await database.fetch_all(
            incidents_table.select().order_by(incidents_table.c.timestamp.desc()).limit(500)
        )
        incidents = [dict(row._mapping) for row in results]
        for inc in incidents:
            if isinstance(inc.get('timestamp'), datetime):
                inc['timestamp'] = inc['timestamp'].isoformat()
        return incidents
    except Exception as e:
        logging.error(f"❌ Could not get incidents: {e}", exc_info=True)
        return []


async def mark_incident_handled(incident_id: int):
    try:
        q = incidents_table.update().where(incidents_table.c.id == incident_id).values(status='resolved')
        await database.execute(q)
        logging.info(f"✅ Incident {incident_id} marked as resolved")
        return True
    except Exception as e:
        logging.error(f"❌ Could not mark incident handled: {e}", exc_info=True)
        return False
