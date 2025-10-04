import os
from datetime import datetime
from databases import Database
from sqlalchemy import create_engine, text, MetaData, Table, Column, Integer, String, DateTime, Text

DATABASE_URL = os.getenv("DATABASE_URL")

database = Database(DATABASE_URL)
metadata = MetaData()

# --- Table Definitions ---
# Your existing table for detailed incident reports
incidents_table = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime, default=datetime.utcnow),
    Column("ip", String(45)),
    Column("payload", Text),
    Column("rule_triggered", String(255)),
    Column("status", String(50), default="open"),
)

# NEW: Table to log every request for usage stats
requests_table = Table(
    "requests",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime, default=datetime.utcnow),
    Column("status", String(50)), # 'success' or 'error'
    Column("client_ip", String(45)),
)

# --- Database Functions ---
async def setup_database():
    """Create both tables if they don't exist."""
    try:
        engine = create_engine(DATABASE_URL)
        metadata.create_all(engine)
        print("✅ All tables setup check complete.")
    except Exception as e:
        print(f"❌ ERROR: Could not create tables. {e}")

async def log_request(status: str, client_ip: str):
    """Logs a single request to the new requests table."""
    try:
        query = requests_table.insert().values(
            status=status,
            client_ip=client_ip,
            timestamp=datetime.utcnow()
        )
        await database.execute(query)
    except Exception as e:
        print(f"ERROR: Could not log API usage request. {e}")

async def log_incident(ip: str, payload: str, rule: str):
    """Logs a blocked request to BOTH tables."""
    try:
        # 1. Log to the detailed incidents table
        query_incident = incidents_table.insert().values(
            ip=ip, payload=payload, rule_triggered=rule, timestamp=datetime.utcnow()
        )
        await database.execute(query_incident)
        print(f"🚨 Incident logged to DB: {rule} from {ip}")
        
        # 2. ALSO log it as an 'error' to the requests table for the usage chart
        await log_request(status='error', client_ip=ip)
        
    except Exception as e:
        print(f"ERROR: Could not log incident. {e}")

async def get_incidents():
    """Fetch all incidents from the database."""
    try:
        query = incidents_table.select().order_by(incidents_table.c.timestamp.desc()).limit(500)
        results = await database.fetch_all(query)
        incidents = [dict(row._mapping) for row in results]
        for inc in incidents:
            if isinstance(inc.get('timestamp'), datetime):
                inc['timestamp'] = inc['timestamp'].isoformat()
        return incidents
    except Exception as e:
        print(f"ERROR: Could not get incidents from DB. {e}")
        return []

async def get_api_usage():
    """Fetch and aggregate API usage stats for the new chart."""
    try:
        # This SQL query groups all requests into 5-minute intervals
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
        
        # Format the data for the frontend chart
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
        print(f"ERROR: Could not get API usage data. {e}")
        return []

async def mark_incident_handled(incident_id: int):
    # This function is not the focus of this task
    return True
