"""
Database Activity Monitoring (DAM) Agent - Enterprise Edition
Monitors MySQL general log, parses real client IPs, batches telemetry,
and transmits securely to the DAM backend with exponential backoff & retry handling.
"""

import binascii
import os
import re
import time
from datetime import datetime
import mysql.connector
import requests

# ===== Configuration =====
MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST", os.getenv("DAM_DB_HOST", "localhost")),
    "user": os.getenv("MYSQL_USER", os.getenv("DAM_DB_USER", "root")),
    "password": os.getenv("MYSQL_PASSWORD", os.getenv("DAM_DB_PASSWORD", "1234")),
    "database": os.getenv("MYSQL_DB", os.getenv("DAM_DB_NAME", "mysql")),
    "port": int(os.getenv("MYSQL_PORT", os.getenv("DAM_DB_PORT", "3306")))
}

BACKEND_BASE = os.getenv("DAM_BACKEND_URL", "http://localhost:5000")
BACKEND_BULK_URL = f"{BACKEND_BASE}/api/agent/bulk"
BACKEND_SINGLE_URL = f"{BACKEND_BASE}/api/agent/activity"
BACKEND_HEALTH_URL = f"{BACKEND_BASE}/api/health"

# Batching & Retry limits
BATCH_SIZE = 50
MAX_PENDING_QUEUE = 500
BASE_BACKOFF_SECONDS = 2
MAX_BACKOFF_SECONDS = 60

# Track state
last_event_time = None
pending_queue = []
fail_streak = 0

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
    """Decode MySQL general_log argument safely (handles bytes, hex string, or plain text)"""
    if value is None:
        return ""

    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return str(value)

    if isinstance(value, str) and value.startswith("0x"):
        try:
            hex_str = value[2:]
            if len(hex_str) % 2 != 0:
                hex_str = '0' + hex_str
            return binascii.unhexlify(hex_str).decode("utf-8", errors="ignore")
        except Exception:
            return value

    return str(value)


def detect_operation(sql):
    """Detect the SQL operation type"""
    sql = sql.strip().upper()
    operations = [
        "SELECT", "INSERT", "UPDATE", "DELETE",
        "CREATE", "DROP", "ALTER", "TRUNCATE",
        "GRANT", "REVOKE", "CALL"
    ]
    for op in operations:
        if sql.startswith(op):
            return "PROCEDURE" if op == "CALL" else op
    return "OTHER"


def extract_table_name(sql):
    """Extract target table name from SQL query"""
    sql_lower = sql.lower()
    patterns = [
        r'(?:from|into|update|table|join)\s+`?([a-zA-Z0-9_]+)`?',
        r'(?:drop|truncate|alter)\s+table\s+`?([a-zA-Z0-9_]+)`?',
        r'create\s+table\s+`?([a-zA-Z0-9_]+)`?'
    ]
    for pattern in patterns:
        match = re.search(pattern, sql_lower)
        if match:
            return match.group(1)
    return "unknown"


def should_skip_query(sql):
    """Check if query should be skipped (internal/noise queries)"""
    sql_lower = sql.lower()
    for pattern in SKIP_PATTERNS:
        if re.search(pattern, sql_lower, re.IGNORECASE):
            return True
    return False


def extract_username(user_host):
    """Extract username from user_host string (e.g., 'root[root] @ 192.168.1.50 []')"""
    if not user_host:
        return "SYSTEM"
    match = re.search(r'^([^\[@]+)', user_host)
    if match:
        uname = match.group(1).strip()
        if uname:
            return uname
    return user_host.split('@')[0].strip() or "SYSTEM"


def extract_client_ip(user_host):
    """
    Extract real client IP from MySQL user_host string.
    Examples:
      - 'root[root] @ 192.168.1.50 []' -> 192.168.1.50
      - 'app[app] @ localhost [10.0.0.5]' -> 10.0.0.5
      - 'root[root] @ [172.18.0.4]' -> 172.18.0.4
      - 'guest @ localhost []' -> 127.0.0.1
    """
    if not user_host:
        return "127.0.0.1"

    # 1. Look for IP inside brackets after '@' or at end
    bracket_match = re.search(r'@.*\[([\d\.:]+)\]', user_host)
    if bracket_match:
        ip = bracket_match.group(1).strip()
        if ip and ip != "::1":
            return ip

    # 2. Match any bracket with IP format
    bracket_ip = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9:]+)\]', user_host)
    if bracket_ip:
        ip = bracket_ip.group(1).strip()
        if ip and ip != "::1":
            return ip

    # 3. Look for IP address immediately after '@'
    host_match = re.search(r'@\s*([a-zA-Z0-9\.\-]+)', user_host)
    if host_match:
        candidate = host_match.group(1).strip()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', candidate):
            return candidate
        if candidate.lower() not in ("localhost", "localhost.localdomain", "127.0.0.1", "::1"):
            return candidate

    return "127.0.0.1"


def setup_mysql_general_log():
    """Enable MySQL general log if not already enabled"""
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SET GLOBAL general_log = ON")
        cursor.execute("SET GLOBAL log_output = 'TABLE'")
        cursor.execute("SHOW VARIABLES LIKE 'general_log'")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result and result[1] == 'ON':
            print("✓ MySQL general log is verified: ON")
            return True
        return False
    except Exception as e:
        print(f"✗ Error configuring MySQL general log: {e}")
        return False


def transmit_batch_with_retry(activities):
    """
    Sends batched activities to DAM backend with exponential backoff and retry.
    """
    global fail_streak
    if not activities:
        return True

    payload = {"activities": activities}
    try:
        resp = requests.post(BACKEND_BULK_URL, json=payload, timeout=6)
        if resp.status_code in (200, 201, 202):
            if fail_streak > 0:
                print(f"✓ Reconnected to DAM backend. Flushed {len(activities)} activities.")
            fail_streak = 0
            return True
        else:
            print(f"⚠ Backend rejected bulk payload with status {resp.status_code}: {resp.text[:120]}")
            fail_streak += 1
            return False
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as ex:
        fail_streak += 1
        backoff = min(MAX_BACKOFF_SECONDS, BASE_BACKOFF_SECONDS * (2 ** (fail_streak - 1)))
        print(f"⚠ Cannot reach DAM backend ({ex.__class__.__name__}). Fail streak: {fail_streak}. Backoff: {backoff}s")
        time.sleep(min(backoff, 5))
        return False
    except Exception as ex:
        fail_streak += 1
        print(f"✗ Unexpected transmission error: {ex}")
        return False


def monitor_mysql_activity():
    """Main monitoring iteration: reads general_log, batches, and sends telemetry"""
    global last_event_time, pending_queue

    # If pending items exist from previous failures, attempt to flush first
    if pending_queue:
        chunk = pending_queue[:BATCH_SIZE]
        if transmit_batch_with_retry(chunk):
            pending_queue = pending_queue[len(chunk):]

    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT event_time, user_host, argument
            FROM mysql.general_log
            WHERE command_type = 'Query'
              AND argument IS NOT NULL
            ORDER BY event_time DESC
            LIMIT 100
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        new_batch = []
        max_seen_time = last_event_time

        # Process in chronological order (oldest to newest)
        for row in reversed(rows):
            event_time = row["event_time"]
            if last_event_time and event_time <= last_event_time:
                continue

            sql_text = decode_hex(row["argument"])
            if should_skip_query(sql_text) or "general_log" in sql_text.lower():
                continue

            operation = detect_operation(sql_text)
            table_name = extract_table_name(sql_text)
            username = extract_username(row["user_host"])
            client_ip = extract_client_ip(row["user_host"])

            activity_item = {
                "username": username,
                "operation": operation,
                "query": sql_text[:1500],
                "table": table_name,
                "rows_affected": None,
                "session_id": None,
                "client_ip": client_ip,
                "ip": client_ip,
                "status": "Success",
                "timestamp": event_time.isoformat() if event_time else datetime.now().isoformat()
            }
            new_batch.append(activity_item)

            if not max_seen_time or event_time > max_seen_time:
                max_seen_time = event_time

        if max_seen_time:
            last_event_time = max_seen_time

        if new_batch:
            pending_queue.extend(new_batch)
            if len(pending_queue) > MAX_PENDING_QUEUE:
                dropped = len(pending_queue) - MAX_PENDING_QUEUE
                pending_queue = pending_queue[dropped:]
                print(f"⚠ Warning: Queue full. Dropped {dropped} oldest activities.")

            while pending_queue:
                chunk = pending_queue[:BATCH_SIZE]
                if transmit_batch_with_retry(chunk):
                    pending_queue = pending_queue[len(chunk):]
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Transmitted batch of {len(chunk)} activities to DAM backend")
                else:
                    break

    except mysql.connector.Error as e:
        print(f"MySQL Error: {e}")
    except Exception as e:
        print(f"Unexpected monitor error: {e}")


def test_connection():
    """Test connection to MySQL and DAM backend on startup"""
    print("\n" + "=" * 60)
    print("DAM Agent - Connection Test")
    print("=" * 60)

    print("\n1. Testing MySQL connection...")
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()
        print(f"   ✓ Connected to MySQL (Version: {version[0]}) at {MYSQL_CONFIG['host']}")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"   ✗ MySQL connection failed: {e}")
        return False

    print("\n2. Testing DAM backend connection...")
    try:
        resp = requests.get(BACKEND_HEALTH_URL, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            print(f"   ✓ Connected to DAM backend ({BACKEND_BASE}) - Status: {data.get('status')}")
        else:
            print(f"   ⚠ Backend returned HTTP {resp.status_code}. Retrying during run loop.")
    except Exception as e:
        print(f"   ⚠ Backend not immediately reachable ({e}). Agent will use exponential retry.")

    print("\n" + "=" * 60)
    print("✓ Pre-flight tests complete. Starting sensor loop...")
    print("=" * 60)
    return True


if __name__ == "__main__":
    print("=" * 65)
    print("DATABASE ACTIVITY MONITORING (DAM) AGENT · ENTERPRISE")
    print("IBM Guardium-style Real-Time Sniffer with Bulk & Backoff")
    print("=" * 65)
    print(f"Sensor Target: {MYSQL_CONFIG['user']}@{MYSQL_CONFIG['host']}:{MYSQL_CONFIG['port']}")
    print(f"Bulk Endpoint: {BACKEND_BULK_URL}")
    print("=" * 65)

    test_connection()
    setup_mysql_general_log()

    print("\n🔍 Monitoring MySQL activities... (Press Ctrl+C to stop)\n")
    try:
        while True:
            monitor_mysql_activity()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\n👋 Agent stopped by user")
    except Exception as e:
        print(f"\n❌ Unexpected agent crash: {e}")
