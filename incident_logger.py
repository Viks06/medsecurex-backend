import os
from datetime import datetime, timezone
from databases import Database
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, DateTime, Text
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Config ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("❌ DATABASE_URL not set in environment.")

database = Database(DATABASE_URL)
metadata = MetaData()

# --- Table Definitions ---
incidents_table = Table(
    "incidents", metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True)),
    Column("ip", String(45)),
    Column("payload", Text),
    Column("rule_triggered", String(255)),
    Column("status", String(50), default="open")
)

requests_table = Table(
    "requests", metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True)),
    Column("status", String(50)),
    Column("client_ip", String(45))
)

ttps_table = Table(
    "ttps", metadata,
    Column("id", String(20), primary_key=True),
    Column("name", String(255)),
    Column("tactic", String(100)),
    Column("description", Text)
)

# --- MITRE ATT&CK Mappings ---
TTP_MAPPING = {
    "SQL Injection": {
        "id": "T1505", "name": "Server Software Component", "tactic": "Persistence",
        "description": "SQL injection is an attack in which an attacker submits malicious SQL commands to the backend database."
    },
    "XSS": {
        "id": "T1059.007", "name": "JavaScript/JScript", "tactic": "Execution",
        "description": "Cross-site scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by others."
    },
    "Path Traversal": {
        "id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery",
        "description": "Path traversal allows attackers to read arbitrary files on the server."
    },
    "Brute Force": {
        "id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
        "description": "Adversaries may attempt multiple passwords to gain unauthorized access to accounts."
    },
}

# --- Database Setup ---
async def setup_database():
    """
    Creates tables synchronously (for Render compatibility) and seeds TTP data.
    """
    try:
        engine = create_engine(DATABASE_URL)
        metadata.create_all(engine)  # Ensures tables exist before async queries
        logging.info("✅ Tables ensured in database.")

        # Connect to async DB
        async with database.transaction():
            # Seed MITRE ATT&CK TTP data if empty
            count_result = await database.fetch_one("SELECT COUNT(*) FROM ttps;")
            if count_result and count_result[0] == 0:
                logging.info("🌱 Seeding TTP table...")
                for ttp_data in TTP_MAPPING.values():
                    await database.execute(ttps_table.insert().values(
                        id=ttp_data["id"],
                        name=ttp_data["name"],
                        tactic=ttp_data["tactic"],
                        description=ttp_data["description"]
                    ))
                logging.info("✅ TTP table seeded successfully.")
    except Exception as e:
        logging.error(f"❌ Database setup failed: {e}", exc_info=True)

# --- Incident Logging ---
async def log_incident(ip: str, payload: str, rule: str):
    try:
        await database.execute(
            incidents_table.insert().values(
                ip=ip,
                payload=payload,
                rule_triggered=rule,
                timestamp=datetime.now(timezone.utc)
            )
        )
        logging.info(f"🚨 Incident logged ({rule}) from {ip}")
        await log_request(status="error", client_ip=ip)
    except Exception as e:
        logging.error(f"❌ Failed to log incident: {e}", exc_info=True)

# --- API Request Logging ---
async def log_request(status: str, client_ip: str):
    try:
        await database.execute(
            requests_table.insert().values(
                timestamp=datetime.now(timezone.utc),
                status=status,
                client_ip=client_ip
            )
        )
    except Exception as e:
        logging.error(f"❌ Failed to log API request: {e}", exc_info=True)

# --- Query Functions ---
async def get_incidents():
    try:
        query = "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 500;"
        results = await database.fetch_all(query)
        return [dict(r._mapping) for r in results]
    except Exception as e:
        logging.error(f"❌ Could not fetch incidents: {e}", exc_info=True)
        return []

async def get_detected_ttps():
    try:
        query = """
            SELECT rule_triggered, COUNT(*) AS count, MAX(timestamp) AS last_seen
            FROM incidents GROUP BY rule_triggered ORDER BY last_seen DESC;
        """
        results = await database.fetch_all(query)
        detected_ttps = []
        for row in results:
            rule_name = row["rule_triggered"]
            ttp = TTP_MAPPING.get(rule_name)
            if ttp:
                detected_ttps.append({
                    **ttp,
                    "source": rule_name,
                    "count": row["count"],
                    "lastSeen": row["last_seen"].isoformat() if row["last_seen"] else None
                })
        return detected_ttps
    except Exception as e:
        logging.error(f"❌ Could not fetch TTPs: {e}", exc_info=True)
        return []

async def get_api_usage():
    try:
        query = """
            SELECT to_char(date_trunc('hour', timestamp)
            + floor(extract(minute from timestamp) / 5) * interval '5 minutes', 'HH24:MI') as time,
            COUNT(CASE WHEN status = 'success' THEN 1 END) as success,
            COUNT(CASE WHEN status = 'error' THEN 1 END) as errors
            FROM requests
            WHERE timestamp > NOW() - INTERVAL '1 hour'
            GROUP BY time ORDER BY time;
        """
        results = await database.fetch_all(query)
        return [
            {"time": r["time"], "blocked": int(r["errors"] or 0), "success": int(r["success"] or 0)}
            for r in results
        ]
    except Exception as e:
        logging.error(f"❌ Could not fetch API usage: {e}", exc_info=True)
        return []
