import time
import mysql.connector
import requests
import binascii
from datetime import datetime

# ===== MySQL (sensor source) =====
MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "1234",     # <-- your MySQL password
    "database": "mysql"
}

# ===== DAM backend (collector) =====
BACKEND_URL = "http://localhost:5000/api/agent/activity"

last_event_time = None


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
            return binascii.unhexlify(value[2:]).decode("utf-8", errors="ignore")
        except Exception:
            return value

    return str(value)



def detect_operation(sql):
    sql = sql.strip().upper()
    for op in ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP"]:
        if sql.startswith(op):
            return op
    return "OTHER"


while True:
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT event_time, user_host, argument
            FROM mysql.general_log
            WHERE command_type = 'Query'
            ORDER BY event_time DESC
            LIMIT 10
        """

        cursor.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            if last_event_time and row["event_time"] <= last_event_time:
                continue

            sql_text = decode_hex(row["argument"])
            operation = detect_operation(sql_text)

            payload = {
                "username": row["user_host"],
                "operation": operation,
                "query": sql_text,
                "timestamp": row["event_time"].isoformat()
            }

            resp = requests.post(BACKEND_URL, json=payload)
            print("Sent:", operation, "Status:", resp.status_code)


            last_event_time = row["event_time"]

        cursor.close()
        conn.close()

    except Exception as e:
        print("Agent error:", e)

    time.sleep(2)
