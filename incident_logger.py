import os
from datetime import datetime, timezone
from databases import Database
from sqlalchemy import create_engine, text, MetaData, Table, Column, Integer, String, DateTime, Text
import logging

logging.basicConfig(level=logging.INFO)

DATABASE_URL = os.getenv("DATABASE_URL")

database = Database(DATABASE_URL)
metadata = MetaData()

# --- TTP Mapping ---
TTP_MAPPING = {
    "SQL Injection": {
        "id": "T1505", "name": "Server Software Component", "tactic": "Persistence",
        "description": "SQL injection is an attack in which an attacker is able to submit a database SQL command to be executed by the back-end database."
    },
    "XSS": {
        "id": "T1059.007", "name": "JavaScript/JScript", "tactic": "Execution",
        "description": "Cross-site scripting (XSS) is a type of security vulnerability that allows an attacker to inject malicious scripts into web pages viewed by other users."
    },
    "Path Traversal": {
        "id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery",
        "description": "Path traversal (also known as directory traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application."
    },
    "Command Injection": {
        "id": "T1059", "name": "Command-Line Interface", "tactic": "Execution",
        "description": "Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application."
    },
    "Brute Force": {
        "id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained."
    },
}


# --- Table Definitions ---
incidents_table = Table(
    "incidents", metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True)), Column("ip", String(45)),
    Column("payload", Text), Column("rule_triggered", String(255)),
    Column("status", String(50), default="open"),
)

requests_table = Table(
    "requests", metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True)), Column("status", String(50)),
    Column("client_ip", String(45)),
)

ttps_table = Table(
    "ttps", metadata,
    Column("id", String(20), primary_key=True),
    Column("name", String(255)),
    Column("tactic", String(100)),
    Column("description", Text),
)

# --- Database Functions ---
async def setup_database():
    """Creates all tables and seeds the TTP table if it's empty."""
    try:
        engine = create_engine(DATABASE_URL)
        metadata.create_all(engine)
        logging.info("✅ All tables setup check complete.")

        async with database.transaction():
            count_result = await database.fetch_one("SELECT COUNT(*) FROM ttps;")
            if count_result[0] == 0:
                logging.info("Seeding TTPs table with initial data...")
                for ttp_data in TTP_MAPPING.values():
                    query = ttps_table.insert().values(
                        id=ttp_data["id"], name=ttp_data["name"],
                        tactic=ttp_data["tactic"], description=ttp_data["description"]
                    )
                    await database.execute(query)
                logging.info("✅ TTPs table seeded successfully.")
    except Exception as e:
        logging.error(f"❌ ERROR: Could not create/seed tables. {e}", exc_info=True)


async def get_detected_ttps():
    """Queries and aggregates incidents, joining them with TTP info."""
    logging.info("[get_detected_ttps] Attempting to fetch TTP stats.")
    try:
        query = text("""
            SELECT
                rule_triggered,
                COUNT(*) as count,
                MAX(timestamp) as last_seen,
                (array_agg(payload ORDER BY timestamp DESC))[1] as example_payload
            FROM incidents
            GROUP BY rule_triggered
            ORDER BY last_seen DESC;
        """)
        results = await database.fetch_all(query)
        
        detected_ttps = []
        for row in results:
            row_dict = dict(row._mapping)
            rule_name = row_dict.get("rule_triggered")
            ttp_details = TTP_MAPPING.get(rule_name)
            
            if ttp_details:
                detected_ttps.append({
                    "id": ttp_details["id"], "name": ttp_details["name"],
                    "tactic": ttp_details["tactic"], "description": ttp_details["description"],
                    "source": rule_name, "endpoint": row_dict.get("example_payload"),
                    "count": int(row_dict.get("count", 0)),
                    "lastSeen": row_dict.get("last_seen").isoformat() if row_dict.get("last_seen") else datetime.now(timezone.utc).isoformat(),
                })
        return detected_ttps
    except Exception as e:
        logging.error(f"❌ ERROR: Could not get detected TTPs. {e}", exc_info=True)
        return []

async def log_request(status: str, client_ip: str):
    try:
        query = requests_table.insert().values(
            status=status, client_ip=client_ip, timestamp=datetime.now(timezone.utc)
        )
        await database.execute(query)
    except Exception as e:
        logging.error(f"❌ ERROR: Could not log API usage request. {e}", exc_info=True)

async def log_incident(ip: str, payload: str, rule: str):
    try:
        query_incident = incidents_table.insert().values(
            ip=ip, payload=payload, rule_triggered=rule, timestamp=datetime.now(timezone.utc)
        )
        await database.execute(query_incident)
        logging.info(f"🚨 Incident logged to incidents table.")
        await log_request(status='error', client_ip=ip)
    except Exception as e:
        logging.error(f"❌ ERROR: Could not log incident. {e}", exc_info=True)

async def get_api_usage():
    try:
        query = text("""
            SELECT
                to_char(date_trunc('hour', timestamp) + floor(extract(minute from timestamp) / 5) * interval '5 minutes', 'HH24:MI') as time,
                COUNT(CASE WHEN status = 'success' THEN 1 END) as success,
                COUNT(CASE WHEN status = 'error' THEN 1 END) as errors
            FROM requests WHERE timestamp > NOW() - INTERVAL '1 hour' GROUP BY time ORDER BY time;
        """)
        results = await database.fetch_all(query)
        usage_data = []
        for row in results:
            row_dict = dict(row._mapping)
            success_count = int(row_dict.get('success', 0)); error_count = int(row_dict.get('errors', 0))
            usage_data.append({
                "time": row_dict['time'], "rps": success_count + error_count,
                "success": success_count, "errors": error_count
            })
        return usage_data
    except Exception as e:
        logging.error(f"❌ ERROR: Could not get API usage data. {e}", exc_info=True)
        return []

# CORRECTED: Restored the original, working function for the BlockedRequestsChart
async def get_incidents():
    """Fetch all raw incidents from the database for the blocked requests chart."""
    try:
        query = incidents_table.select().order_by(incidents_table.c.timestamp.desc()).limit(500)
        results = await database.fetch_all(query)
        incidents = [dict(row._mapping) for row in results]
        for inc in incidents:
            if isinstance(inc.get('timestamp'), datetime):
                inc['timestamp'] = inc['timestamp'].isoformat()
        return incidents
    except Exception as e:
        logging.error(f"ERROR: Could not get raw incidents from DB. {e}", exc_info=True)
        return []

async def mark_incident_handled(incident_id: int):
    return True

