"""
Database Activity Monitoring (DAM) Agent
Monitors MySQL general log and sends activities to the DAM backend
"""

import time
import mysql.connector
import requests
import binascii
from datetime import datetime
import re

# ===== MySQL (sensor source) =====
MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "1234",     # Your MySQL password
    "database": "mysql"
}

# ===== DAM backend (collector) =====
BACKEND_URL = "http://localhost:5000/api/agent/activity"

# Track last seen event time
last_event_time = None

# Skip system queries and internal monitoring
SKIP_PATTERNS = [
    r"SET GLOBAL",
    r"SELECT.*FROM mysql\.general_log",
    r"general_log",
    r"information_schema",
    r"performance_schema",
    r"mysql\.",
    r"SHOW",
    r"USE `?mysql`?",
    r"COMMIT",
    r"BEGIN",
    r"ROLLBACK",
    r"SET AUTOCOMMIT",
    r"SET NAMES",
    r"SET CHARACTER SET"
]


def decode_hex(value):
    """
    Decode MySQL general_log argument safely
    Handles both bytes and string
    """
    if value is None:
        return ""

    # If MySQL returned bytes
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return str(value)

    # If MySQL returned hex string like 0x53454C...
    if isinstance(value, str) and value.startswith("0x"):
        try:
            hex_str = value[2:]  # Remove '0x' prefix
            # Make sure hex string has even length
            if len(hex_str) % 2 != 0:
                hex_str = '0' + hex_str
            return binascii.unhexlify(hex_str).decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"Hex decode error: {e}")
            return value

    return str(value)


def detect_operation(sql):
    """Detect the type of SQL operation"""
    sql = sql.strip().upper()
    
    # Check for common SQL operations
    if sql.startswith("SELECT"):
        return "SELECT"
    elif sql.startswith("INSERT"):
        return "INSERT"
    elif sql.startswith("UPDATE"):
        return "UPDATE"
    elif sql.startswith("DELETE"):
        return "DELETE"
    elif sql.startswith("CREATE"):
        return "CREATE"
    elif sql.startswith("DROP"):
        return "DROP"
    elif sql.startswith("ALTER"):
        return "ALTER"
    elif sql.startswith("TRUNCATE"):
        return "TRUNCATE"
    elif sql.startswith("GRANT"):
        return "GRANT"
    elif sql.startswith("REVOKE"):
        return "REVOKE"
    elif sql.startswith("CALL"):
        return "PROCEDURE"
    else:
        return "OTHER"


def extract_table_name(sql):
    """Extract table name from SQL query"""
    sql_lower = sql.lower()
    
    # Common patterns
    patterns = [
        r'(?:from|into|update|table|join)\s+`?(\w+)`?',
        r'(?:drop|truncate|alter)\s+table\s+`?(\w+)`?',
        r'create\s+table\s+`?(\w+)`?'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, sql_lower)
        if match:
            return match.group(1)
    
    return "unknown"


def should_skip_query(sql):
    """Check if query should be skipped (system queries)"""
    sql_lower = sql.lower()
    for pattern in SKIP_PATTERNS:
        if re.search(pattern, sql_lower, re.IGNORECASE):
            return True
    return False


def extract_username(user_host):
    """Extract username from user_host string (e.g., 'root[root] @ localhost []')"""
    if not user_host:
        return "SYSTEM"
    
    # Try to extract username before first [
    match = re.search(r'^([^\[]+)', user_host)
    if match:
        return match.group(1).strip()
    
    return user_host.split('@')[0].strip()


def setup_mysql_general_log():
    """Enable MySQL general log if not already enabled"""
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        
        # Enable general log
        cursor.execute("SET GLOBAL general_log = ON")
        cursor.execute("SET GLOBAL log_output = 'TABLE'")
        
        # Check if enabled
        cursor.execute("SHOW VARIABLES LIKE 'general_log'")
        result = cursor.fetchone()
        if result and result[1] == 'ON':
            print("✓ MySQL general log is enabled")
        else:
            print("⚠ Warning: Could not enable MySQL general log")
        
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"✗ Error enabling MySQL general log: {e}")
        print("  Make sure MySQL is running and you have SUPER privileges")
        return False


def monitor_mysql_activity():
    """Main monitoring function"""
    global last_event_time
    
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Query to get recent queries from general log
        query = """
            SELECT event_time, user_host, argument
            FROM mysql.general_log
            WHERE command_type = 'Query'
            AND argument IS NOT NULL
            ORDER BY event_time DESC
            LIMIT 50
        """

        cursor.execute(query)
        rows = cursor.fetchall()

        new_activities = 0
        
        for row in rows:
            # Skip if we've already seen this event
            if last_event_time and row["event_time"] <= last_event_time:
                continue

            # Decode and clean SQL
            sql_text = decode_hex(row["argument"])
            
            # Skip system queries
            if should_skip_query(sql_text):
                continue

            # Extract information
            operation = detect_operation(sql_text)
            table_name = extract_table_name(sql_text)
            username = extract_username(row["user_host"])
            
            # Skip monitoring queries
            if "general_log" in sql_text.lower():
                continue

            # Prepare payload for backend
            payload = {
                "username": username,
                "operation": operation,
                "query": sql_text[:1000],  # Limit query length
                "table": table_name,
                "rows_affected": None,  # Can't get this from general log
                "session_id": None,
                "client_ip": None,  # Can't get client IP from general log
                "timestamp": row["event_time"].isoformat() if row["event_time"] else None
            }

            # Send to DAM backend
            try:
                resp = requests.post(BACKEND_URL, json=payload, timeout=3)
                if resp.status_code == 200:
                    new_activities += 1
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Sent: {operation:8} on {table_name:15} -> Status: {resp.status_code}")
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Failed: {operation} -> Status: {resp.status_code}")
            except requests.exceptions.ConnectionError:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: Cannot connect to DAM backend at {BACKEND_URL}")
            except Exception as e:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Error sending: {e}")

            # Update last event time
            if not last_event_time or row["event_time"] > last_event_time:
                last_event_time = row["event_time"]

        if new_activities > 0:
            print(f"  → Sent {new_activities} new activities")

        cursor.close()
        conn.close()

    except mysql.connector.Error as e:
        print(f"MySQL Error: {e}")
        if "Access denied" in str(e):
            print("  Check your MySQL username and password in MYSQL_CONFIG")
        elif "Unknown database" in str(e):
            print("  Make sure MySQL is running and the 'mysql' database exists")
    except Exception as e:
        print(f"Unexpected error: {e}")


def test_connection():
    """Test connection to MySQL and DAM backend"""
    print("\n" + "=" * 60)
    print("DAM Agent - Connection Test")
    print("=" * 60)
    
    # Test MySQL connection
    print("\n1. Testing MySQL connection...")
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()
        print(f"   ✓ Connected to MySQL (Version: {version[0]})")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"   ✗ MySQL connection failed: {e}")
        return False
    
    # Test DAM backend connection
    print("\n2. Testing DAM backend connection...")
    try:
        resp = requests.get("http://localhost:5000/api/health", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            print(f"   ✓ Connected to DAM backend (Version: {data.get('version', 'unknown')})")
        else:
            print(f"   ✗ DAM backend returned status {resp.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("   ✗ Cannot connect to DAM backend at http://localhost:5000")
        print("     Make sure app.py is running first")
        return False
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("✓ All connections successful! Starting monitoring...")
    print("=" * 60)
    return True


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":
    print("=" * 60)
    print("DATABASE ACTIVITY MONITORING (DAM) AGENT")
    print("IBM Guardium-style MySQL Monitor")
    print("=" * 60)
    print(f"MySQL Config: {MYSQL_CONFIG['user']}@{MYSQL_CONFIG['host']}")
    print(f"DAM Backend: {BACKEND_URL}")
    print("=" * 60)
    
    # Test connections first
    if not test_connection():
        print("\n✗ Connection test failed. Please fix the issues and try again.")
        exit(1)
    
    # Setup MySQL general log
    if not setup_mysql_general_log():
        print("\n✗ Failed to setup MySQL general log. Continuing anyway...")
    
    # Main monitoring loop
    print("\n🔍 Monitoring MySQL activities... (Press Ctrl+C to stop)\n")
    
    try:
        while True:
            monitor_mysql_activity()
            time.sleep(3)  # Check every 3 seconds
    except KeyboardInterrupt:
        print("\n\n👋 Agent stopped by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
    
    print("\nDAM Agent terminated.")