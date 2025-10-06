import os
from datetime import datetime, timezone
from databases import Database
from sqlalchemy import create_engine, text, MetaData, Table, Column, Integer, String, DateTime, Text
import logging

logging.basicConfig(level=logging.INFO)

DATABASE_URL = os.getenv("DATABASE_URL")

database = Database(DATABASE_URL)
metadata = MetaData()

# --- Table Definitions ---
incidents_table = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("ip", String(45)),
    Column("payload", Text),
    Column("rule_triggered", String(255)),
    Column("status", String(50), default="open"),
)

requests_table = Table(
    "requests",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("status", String(50)),
    Column("client_ip", String(45)),
)

# --- Database Functions ---
async def setup_database():
    """
    Creates both tables using 'IF NOT EXISTS' to prevent errors on restart.
    """
    logging.info("[DB Setup] Starting setup...")
    try:
        async with database.transaction():
            # Use raw SQL with 'IF NOT EXISTS' for maximum compatibility
            await database.execute(text("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    ip VARCHAR(45),
                    payload TEXT,
                    rule_triggered VARCHAR(255),
                    status VARCHAR(50)
                );
            """))
            await database.execute(text("""
                CREATE TABLE IF NOT EXISTS requests (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    status VARCHAR(50),
                    client_ip VARCHAR(45)
                );
            """))
        logging.info("✅ All tables setup check complete.")
    except Exception as e:
        logging.error(f"❌ ERROR: Could not create tables. {e}", exc_info=True)


async def log_request(status: str, client_ip: str):
    try:
        query = requests_table.insert().values(
            status=status, client_ip=client_ip, timestamp=datetime.now(timezone.utc)
        )
        await database.execute(query)
        logging.info(f"✅ API usage logged. Status: {status}")
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
            FROM requests
            WHERE timestamp > NOW() - INTERVAL '1 hour'
            GROUP BY time
            ORDER BY time;
        """)
        results = await database.fetch_all(query)
        usage_data = []
        for row in results:
            row_dict = dict(row._mapping)
            success_count = int(row_dict.get('success', 0))
            error_count = int(row_dict.get('errors', 0))
            total_requests = success_count + error_count
            usage_data.append({
                "time": row_dict['time'], "rps": total_requests,
                "success": success_count, "errors": error_count
            })
        return usage_data
    except Exception as e:
        logging.error(f"❌ ERROR: Could not get API usage data. {e}", exc_info=True)
        return []

async def get_incidents():
    try:
        query = incidents_table.select().order_by(incidents_table.c.timestamp.desc()).limit(500)
        results = await database.fetch_all(query)
        incidents = [dict(row._mapping) for row in results]
        for inc in incidents:
            if isinstance(inc.get('timestamp'), datetime):
                inc['timestamp'] = inc['timestamp'].isoformat()
        return incidents
    except Exception as e:
        logging.error(f"ERROR: Could not get incidents from DB. {e}", exc_info=True)
        return []

async def mark_incident_handled(incident_id: int):
    return True

