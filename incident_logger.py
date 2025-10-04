# incident_logger.py (FINAL ASYNC VERSION)
import os
from datetime import datetime
from databases import Database
from sqlalchemy import create_engine, text, MetaData, Table, Column, Integer, String, DateTime, Text

DATABASE_URL = os.getenv("DATABASE_URL")

# The database object that FastAPI will use
database = Database(DATABASE_URL)

# SQLAlchemy metadata to define the table structure
metadata = MetaData()
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

async def setup_database():
    """Create the incidents table if it doesn't exist."""
    try:
        engine = create_engine(DATABASE_URL)
        metadata.create_all(engine)
        print("Table setup check complete.")
    except Exception as e:
        print(f"ERROR: Could not create incidents table. {e}")

async def log_incident(ip: str, payload: str, rule: str):
    """Insert a new incident into the database."""
    try:
        query = incidents_table.insert().values(
            ip=ip,
            payload=payload,
            rule_triggered=rule,
            timestamp=datetime.utcnow()
        )
        await database.execute(query)
        print(f"🚨 Incident logged to DB: {rule} from {ip}")
    except Exception as e:
        print(f"ERROR: Could not log incident to DB. {e}")

async def get_incidents():
    """Fetch all incidents from the database."""
    try:
        query = incidents_table.select().order_by(incidents_table.c.timestamp.desc()).limit(500)
        results = await database.fetch_all(query)
        # Convert results to a list of dicts and format the timestamp
        incidents = [dict(row) for row in results]
        for inc in incidents:
            if isinstance(inc.get('timestamp'), datetime):
                inc['timestamp'] = inc['timestamp'].isoformat()
        return incidents
    except Exception as e:
        print(f"ERROR: Could not get incidents from DB. {e}")
        return []

async def mark_incident_handled(incident_id: int):
    """Mark an incident as handled in the database."""
    try:
        query = incidents_table.update().where(incidents_table.c.id == incident_id).values(status="handled")
        await database.execute(query)
        return True
    except Exception as e:
        print(f"ERROR: Could not mark incident {incident_id} as handled. {e}")
        return False
