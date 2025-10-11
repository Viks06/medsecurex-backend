import os
import logging
from datetime import datetime, timezone
from databases import Database
from sqlalchemy import MetaData, Table, Column, Integer, String, DateTime, Text

# --- Logger setup ---
logging.basicConfig(level=logging.INFO)

# --- Database URL ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

database = Database(DATABASE_URL)
metadata = MetaData()

# --- Table definitions ---
incidents_table = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("ip", String(45)),
    Column("payload", Text),
    Column("rule_triggered", String(255)),
    Column("status", String(50), default="open"),
    Column("ttp_id", String(10)),
)

requests_table = Table(
    "requests",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("status", String(50)),
    Column("client_ip", String(45)),
)

# --- Setup database ---
async def setup_database():
    logging.info("[DB Setup] Creating tables if not exists...")
    async with database.transaction():
        # SQLAlchemy Table create statements with IF NOT EXISTS
        await database.execute(f"""
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
        await database.execute(f"""
            CREATE TABLE IF NOT EXISTS requests (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                status VARCHAR(50),
                client_ip VARCHAR(45)
            );
        """)
    logging.info("✅ Tables are ready.")

# --- Log API request usage ---
async def log_request(status: str, client_ip: str):
    try:
        query = requests_table.insert().values(
            status=status, client_ip=client_ip, timestamp=datetime.now(timezone.utc)
        )
        await database.execute(query)
        logging.info(f"✅ Logged API request: {status} from {client_ip}")
    except Exception as e:
        logging.error(f"❌ Failed to log request: {e}", exc_info=True)

# --- Log incidents ---
async def log_incident(ip: str, payload: str, rule: str):
    try:
        # Map rule to MITRE TTP
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
        ttp_id = TTP_MAP.get(rule, "T1190")

        query = incidents_table.insert().values(
            ip=ip,
            payload=payload,
            rule_triggered=rule,
            status="open",
            ttp_id=ttp_id,
            timestamp=datetime.now(timezone.utc)
        )
        await database.execute(query)
        logging.info(f"🚨 Incident logged: {rule} (TTP: {ttp_id})")
        await log_request(status='error', client_ip=ip)
    except Exception as e:
        logging.error(f"❌ Failed to log incident: {e}", exc_info=True)

# --- Fetch incidents ---
async def get_incidents():
    try:
        query = incidents_table.select().order_by(incidents_table.c.timestamp.desc()).limit(500)
        results = await database.fetch_all(query)
        incidents = [dict(row._mapping) for row in results]
        for inc in incidents:
            if isinstance(inc.get("timestamp"), datetime):
                inc["timestamp"] = inc["timestamp"].isoformat()
        return incidents
    except Exception as e:
        logging.error(f"❌ Failed to fetch incidents: {e}", exc_info=True)
        return []

# --- Mark incident handled ---
async def mark_incident_handled(incident_id: int):
    try:
        query = incidents_table.update().where(incidents_table.c.id == incident_id).values(status="resolved")
        await database.execute(query)
        logging.info(f"Marked incident {incident_id} as resolved")
        return True
    except Exception as e:
        logging.error(f"❌ Failed to mark incident handled: {e}", exc_info=True)
        return False

# --- Get API usage ---
async def get_api_usage():
    try:
        query = """
            SELECT
                to_char(date_trunc('hour', timestamp) + floor(extract(minute from timestamp)/5)* interval '5 minutes','HH24:MI') as time,
                COUNT(CASE WHEN status='success' THEN 1 END) as success,
                COUNT(CASE WHEN status='error' THEN 1 END) as errors
            FROM requests
            WHERE timestamp > NOW() - INTERVAL '1 hour'
            GROUP BY time
            ORDER BY time;
        """
        results = await database.fetch_all(query)
        usage_data = []
        for row in results:
            row_dict = dict(row._mapping)
            success_count = int(row_dict.get('success', 0))
            error_count = int(row_dict.get('errors', 0))
            usage_data.append({
                "time": row_dict['time'],
                "rps": success_count + error_count,
                "success": success_count,
                "errors": error_count
            })
        return usage_data
    except Exception as e:
        logging.error(f"❌ Failed to fetch API usage: {e}", exc_info=True)
        return []
