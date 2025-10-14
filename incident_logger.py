import os
import logging
from datetime import datetime, timezone
from databases import Database
from sqlalchemy import text, MetaData, Table, Column, Integer, String, DateTime, Text
from tenacity import retry, stop_after_attempt, wait_fixed

# ------------------------------------------------------------
# 🔧 Setup Logging
# ------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ------------------------------------------------------------
# 🌐 Database Setup
# ------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("❌ DATABASE_URL environment variable not set!")

database = Database(DATABASE_URL)
metadata = MetaData()

# ------------------------------------------------------------
# 🧱 Table Definitions
# ------------------------------------------------------------
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

ttps_table = Table(
    "ttps",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("incident_id", Integer),
    Column("technique_id", String(100)),
    Column("technique_name", String(255)),
    Column("description", Text),
)

# ------------------------------------------------------------
# 🛠 Database Setup Function
# ------------------------------------------------------------

@retry(stop=stop_after_attempt(5), wait=wait_fixed(2))
async def setup_database():
    """Ensures all tables exist. Retries up to 5 times if the DB is slow to connect."""
    logging.info("[DB Setup] Initializing tables...")

    try:
        # Avoid nested transactions (Render’s DB may block on them)
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

        await database.execute(text("""
            CREATE TABLE IF NOT EXISTS ttps (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                incident_id INTEGER,
                technique_id VARCHAR(100),
                technique_name VARCHAR(255),
                description TEXT
            );
        """))

        logging.info("✅ Database tables confirmed / created successfully.")
    except Exception as e:
        logging.error(f"❌ Database setup failed: {e}", exc_info=True)
        raise


# ------------------------------------------------------------
# 🧾 Logging Functions
# ------------------------------------------------------------

async def log_request(status: str, client_ip: str):
    """Logs a single API request."""
    try:
        query = requests_table.insert().values(
            status=status,
            client_ip=client_ip,
            timestamp=datetime.now(timezone.utc),
        )
        await database.execute(query)
        logging.info(f"✅ Request logged: {status} from {client_ip}")
    except Exception as e:
        logging.error(f"❌ Failed to log request: {e}", exc_info=True)


async def log_ttp(incident_id: int, technique_id: str, technique_name: str, description: str):
    """Logs a MITRE ATT&CK TTP related to a detected incident."""
    try:
        query = ttps_table.insert().values(
            incident_id=incident_id,
            technique_id=technique_id,
            technique_name=technique_name,
            description=description,
            timestamp=datetime.now(timezone.utc),
        )
        await database.execute(query)
        logging.info(f"🧠 Logged TTP: {technique_id} - {technique_name}")
    except Exception as e:
        logging.error(f"❌ Failed to log TTP: {e}", exc_info=True)


async def log_incident(ip: str, payload: str, rule: str):
    """Logs a detected security incident and links it to a TTP if applicable."""
    try:
        insert_query = incidents_table.insert().values(
            ip=ip,
            payload=payload,
            rule_triggered=rule,
            timestamp=datetime.now(timezone.utc),
        ).returning(incidents_table.c.id)

        incident_id = await database.execute(insert_query)
        logging.warning(f"🚨 Incident logged (ID={incident_id}) - Rule: {rule} from {ip}")

        # --- Optional auto-linking to MITRE ATT&CK ---
        if "SQL" in rule.upper():
            await log_ttp(
                incident_id=incident_id,
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                description="SQL Injection attempt detected.",
            )
        elif "XSS" in rule.upper():
            await log_ttp(
                incident_id=incident_id,
                technique_id="T1059.007",
                technique_name="Cross-Site Scripting (XSS)",
                description="Potential XSS attack via <script> payload.",
            )

        await log_request(status="error", client_ip=ip)
    except Exception as e:
        logging.error(f"❌ Failed to log incident: {e}", exc_info=True)


# ------------------------------------------------------------
# 📊 Query Functions
# ------------------------------------------------------------

async def get_api_usage():
    """Aggregates API usage over 5-minute intervals."""
    try:
        query = text("""
            SELECT
                to_char(date_trunc('hour', timestamp) + floor(extract(minute from timestamp) / 5) * interval '5 minutes', 'HH24:MI') AS time,
                COUNT(CASE WHEN status = 'success' THEN 1 END) AS success,
                COUNT(CASE WHEN status = 'error' THEN 1 END) AS errors
            FROM requests
            WHERE timestamp > NOW() - INTERVAL '1 hour'
            GROUP BY time
            ORDER BY time;
        """)
        results = await database.fetch_all(query)

        usage = []
        for row in results:
            row_dict = dict(row._mapping)
            total = int(row_dict.get("success", 0)) + int(row_dict.get("errors", 0))
            usage.append({
                "time": row_dict["time"],
                "rps": total,
                "success": int(row_dict.get("success", 0)),
                "errors": int(row_dict.get("errors", 0)),
            })
        return usage
    except Exception as e:
        logging.error(f"❌ Failed to fetch API usage: {e}", exc_info=True)
        return []


async def get_incidents():
    """Returns the latest security incidents."""
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


async def get_ttps():
    """Returns logged MITRE ATT&CK TTPs."""
    try:
        query = ttps_table.select().order_by(ttps_table.c.timestamp.desc()).limit(500)
        results = await database.fetch_all(query)

        ttps = [dict(row._mapping) for row in results]
        for ttp in ttps:
            if isinstance(ttp.get("timestamp"), datetime):
                ttp["timestamp"] = ttp["timestamp"].isoformat()
        return ttps
    except Exception as e:
        logging.error(f"❌ Failed to fetch TTPs: {e}", exc_info=True)
        return []

#alert's endpoint code
import logging
from datetime import datetime
from sqlalchemy import text
from app.db import database # Assuming 'database' is your database connection instance

# --- Define Metadata for Security Rules ---
# This dictionary maps the 'rule_triggered' from your database to the rich
# information needed by the frontend UI.
RULE_METADATA = {
    "ransomware_behavior": {
        "severity": "Critical",
        "description": "Ransomware behavior detected on an endpoint",
        "ttp_id": "T1486"
    },
    "c2_outbound": {
        "severity": "High",
        "description": "Unusual outbound traffic to known C2 server",
        "ttp_id": "T1071.001"
    },
    "suspicious_task_creation": {
        "severity": "Medium",
        "description": "Suspicious scheduled task creation",
        "ttp_id": "T1053.005"
    },
    "sensitive_group_add": {
        "severity": "Low",
        "description": "User added to sensitive security group",
        "ttp_id": "T1098"
    },
    "sql_injection": {
        "severity": "Critical",
        "description": "SQL Injection attempt detected",
        "ttp_id": "T1190"
    },
    # Fallback for any rule not explicitly defined above
    "default": {
        "severity": "Medium",
        "description": "A generic security alert was triggered",
        "ttp_id": "T1204"
    }
}

async def get_alerts(limit: int = 100):
    """
    Fetches and transforms recent incidents to match the MedSecureX Alerts UI template.
    """
    try:
        # The query remains the same as it fetches the necessary base data
        query = text("""
            SELECT 
                id, 
                timestamp, 
                ip, 
                rule_triggered, 
                status
            FROM incidents
            WHERE rule_triggered IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT :limit;
        """)
        results = await database.fetch_all(query, values={"limit": limit})

        alerts = []
        for row in results:
            data = dict(row._mapping)
            rule_id = data.get("rule_triggered")
            
            # Get metadata for the rule, using the default if the rule is unknown
            metadata = RULE_METADATA.get(rule_id, RULE_METADATA["default"])

            # Format the status to be more readable (e.g., 'in_progress' -> 'In Progress')
            status = data.get("status", "New").replace("_", " ").title()

            alerts.append({
                "id": f"SH-{data['id']}", # Prefixed ID to match UI examples
                "timestamp": data["timestamp"].isoformat(),
                "severity": metadata["severity"],
                "description": f"{metadata['description']} from IP: {data['ip']}",
                "ttp_id": metadata["ttp_id"],
                "status": status,
            })

        return alerts
        
    except Exception as e:
        logging.error(f"❌ Failed to fetch and transform alerts: {e}", exc_info=True)
        # CRITICAL: Return an empty list on error to prevent frontend crashes
        return []

#alert's endpoint code ends
async def mark_incident_handled(incident_id: int):
    """Marks an incident as handled."""
    try:
        query = text("UPDATE incidents SET status = 'handled' WHERE id = :id")
        await database.execute(query, values={"id": incident_id})
        logging.info(f"✅ Incident {incident_id} marked as handled.")
        return True
    except Exception as e:
        logging.error(f"❌ Failed to mark incident as handled: {e}", exc_info=True)
        return False

