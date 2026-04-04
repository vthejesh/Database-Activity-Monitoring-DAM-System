"""
╔══════════════════════════════════════════════════════════════════╗
║   DATABASE ACTIVITY MONITORING (DAM) SYSTEM  ·  v3.0 FULL      ║
║   IBM Guardium-style · All Features Merged · Single File        ║
╚══════════════════════════════════════════════════════════════════╝

Features:
  • Role-based access  (Admin / User / Guest)
  • Real-time activity logging & threat detection
  • Email + SMS alerting  (SMTP + Twilio)
  • PDF & CSV export
  • IP Geolocation tracking
  • Dashboard chart data API
  • Two-Factor Authentication (TOTP)
  • Query Firewall (rule-based blocking)
  • Scheduled compliance reports  (daily / weekly / monthly)
  • Webhook integrations
  • Anomaly detection & user-behaviour analytics
  • Compliance reporting  (GDPR / SOX / HIPAA / PCI-DSS)
"""

# ─── stdlib ────────────────────────────────────────────────────────────────────
import csv
import hashlib
import io
import json
import os
import re
import smtplib
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

# ─── third-party ──────────────────────────────────────────────────────────────
import pyotp
import pytz
import qrcode
import qrcode.image.svg
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import (
    Flask, Blueprint, request, jsonify,
    render_template, session, redirect, send_file, g
)
from flask_cors import CORS
from mysql.connector import pooling
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle,
    Paragraph, Spacer, HRFlowable
)
from werkzeug.security import generate_password_hash, check_password_hash


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

class Config:
    # ── Database ───────────────────────────────────────────────────────────────
    DB_HOST     = os.getenv("DAM_DB_HOST",     "localhost")
    DB_USER     = os.getenv("DAM_DB_USER",     "root")
    DB_PASSWORD = os.getenv("DAM_DB_PASSWORD", "1234")
    DB_NAME     = os.getenv("DAM_DB_NAME",     "dam_system")
    SECRET_KEY  = os.getenv("DAM_SECRET_KEY",  "dam-secret-key-change-me")

    # ── Working hours ──────────────────────────────────────────────────────────
    WORKING_HOURS_START = 9
    WORKING_HOURS_END   = 18

    # ── Security thresholds ────────────────────────────────────────────────────
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION   = 30   # minutes
    SENSITIVE_TABLES   = ["users", "customers", "accounts", "payments", "credit_cards"]
    SENSITIVE_COLUMNS  = ["password", "ssn", "credit_card", "bank_account", "salary"]

    # ── SQL threat patterns ────────────────────────────────────────────────────
    SUSPICIOUS_QUERY_PATTERNS = [
        (r"union.*select",               "SQL Injection - UNION"),
        (r"select.*from.*information_schema", "Schema Enumeration"),
        (r"drop\s+table",                "DROP Table Attempt"),
        (r"truncate\s+table",            "TRUNCATE Attempt"),
        (r"alter\s+table",               "ALTER Table Attempt"),
        (r"create\s+user",               "CREATE User Attempt"),
        (r"grant\s+.*\s+to",             "Privilege Escalation"),
        (r"exec\s+xp_cmdshell",          "xp_cmdshell Attempt"),
        (r"waitfor\s+delay",             "Time-based Injection"),
        (r"load_file\s*\(",              "File Read Attempt"),
        (r"into\s+outfile",              "File Write Attempt"),
        (r"0x[0-9a-f]{10,}",            "Hex Encoding Evasion"),
        (r"sleep\s*\(",                  "Time-based Attack"),
        (r"benchmark\s*\(",              "Benchmark Attack"),
        (r"pg_sleep\s*\(",              "PostgreSQL Sleep Attack"),
    ]

    # ── Rate limiting ──────────────────────────────────────────────────────────
    RATE_LIMIT = {
        "max_queries_per_min": 100,
        "max_failed_per_hour": 10,
    }


class FeatureConfig:
    # ── Email ──────────────────────────────────────────────────────────────────
    SMTP_HOST     = os.getenv("DAM_SMTP_HOST",     "smtp.gmail.com")
    SMTP_PORT     = int(os.getenv("DAM_SMTP_PORT", "587"))
    SMTP_USER     = os.getenv("DAM_SMTP_USER",     "your@gmail.com")
    SMTP_PASSWORD = os.getenv("DAM_SMTP_PASS",     "app-password-here")
    ALERT_EMAILS  = [e for e in os.getenv("DAM_ALERT_EMAILS", "admin@company.com").split(",") if e]
    EMAIL_ENABLED = os.getenv("DAM_EMAIL_ENABLED", "false").lower() == "true"

    # ── SMS (Twilio) ───────────────────────────────────────────────────────────
    TWILIO_SID    = os.getenv("TWILIO_SID",    "")
    TWILIO_TOKEN  = os.getenv("TWILIO_TOKEN",  "")
    TWILIO_FROM   = os.getenv("TWILIO_FROM",   "+10000000000")
    ALERT_PHONES  = [p for p in os.getenv("DAM_ALERT_PHONES", "").split(",") if p]
    SMS_ENABLED   = os.getenv("DAM_SMS_ENABLED", "false").lower() == "true"

    # ── Webhooks ───────────────────────────────────────────────────────────────
    WEBHOOK_URLS  = [u for u in os.getenv("DAM_WEBHOOKS", "").split(",") if u]

    # ── Geo ────────────────────────────────────────────────────────────────────
    GEO_API = "http://ip-api.com/json/{ip}?fields=country,regionName,city,lat,lon,isp,org,query"

    # ── Scheduled reports ──────────────────────────────────────────────────────
    REPORT_CRON   = {"hour": "7", "minute": "0"}
    REPORT_OUTPUT = os.getenv("DAM_REPORT_DIR", "/tmp/dam_reports")

    # ── Firewall ───────────────────────────────────────────────────────────────
    FIREWALL_TTL  = 60   # seconds between rule cache refreshes


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE CONNECTION POOL
# ══════════════════════════════════════════════════════════════════════════════

class DatabaseConnection:
    _instance = None
    _lock     = threading.Lock()

    def __new__(cls):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_pool()
        return cls._instance

    def _init_pool(self):
        self.pool = pooling.MySQLConnectionPool(
            pool_name="dam_pool",
            pool_size=10,
            host=Config.DB_HOST,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            autocommit=True
        )
        print("✓ Database connection pool initialized")

    def get_conn(self):
        return self.pool.get_connection()


# ══════════════════════════════════════════════════════════════════════════════
# BASE MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class BaseManager:
    def __init__(self):
        self.db = DatabaseConnection()

    def execute(self, query, params=None, one=False, all=False):
        conn = cur = None
        try:
            conn = self.db.get_conn()
            cur  = conn.cursor(dictionary=True)
            cur.execute(query, params or ())
            if one:  return cur.fetchone()
            if all:  return cur.fetchall()
            return cur.lastrowid
        except Exception as e:
            print(f"[DB Error] {e}")
            raise
        finally:
            if cur:  cur.close()
            if conn: conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# USER MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class UserManager(BaseManager):

    def authenticate(self, username: str, password: str):
        user = self.execute(
            """SELECT user_id, username, password_hash, role, account_status,
                      COALESCE(failed_attempts,0) AS failed_attempts, locked_until
               FROM users WHERE username=%s""",
            (username,), one=True
        )
        if not user:
            return None

        # Locked?
        if user.get("locked_until") and user["locked_until"] > datetime.now():
            return {"locked": True, "locked_until": user["locked_until"]}

        if user["account_status"] == "Active":
            self.execute(
                "UPDATE users SET last_login=NOW(), failed_attempts=0, locked_until=NULL WHERE user_id=%s",
                (user["user_id"],)
            )
            return user

        return None

    def get_by_id(self, user_id):
        return self.execute(
            "SELECT user_id, username, role, account_status FROM users WHERE user_id=%s",
            (user_id,), one=True
        )

    def create_user(self, username: str, password: str, role: str = "Guest"):
        return self.execute(
            "INSERT INTO users (username, password_hash, role, account_status, created_at) VALUES (%s,%s,%s,'Active',NOW())",
            (username, generate_password_hash(password), role)
        )

    def get_all_users(self):
        return self.execute(
            "SELECT user_id, username, role, account_status, last_login, COALESCE(failed_attempts,0) AS failed_attempts FROM users",
            all=True
        )

    def update_status(self, user_id: int, status: str):
        self.execute("UPDATE users SET account_status=%s WHERE user_id=%s", (status, user_id))


# ══════════════════════════════════════════════════════════════════════════════
# ACTIVITY LOGGER
# ══════════════════════════════════════════════════════════════════════════════

class ActivityLogger(BaseManager):

    def log_activity(self, user_id, username, operation_type, table_name,
                     status, details, ip, session_id=None, rows_affected=None):
        ts = datetime.now(pytz.timezone("Asia/Kolkata"))
        query_hash = hashlib.md5(details.encode()).hexdigest() if details else None
        return self.execute(
            """INSERT INTO activity_logs
               (user_id, username, operation_type, table_name, operation_status,
                operation_details, ip_address, access_timestamp,
                session_id, rows_affected, query_hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (user_id, username, operation_type, table_name, status,
             details, ip, ts, session_id, rows_affected, query_hash)
        )

    def get_latest(self, limit=50, filters=None):
        q      = "SELECT al.*, u.role FROM activity_logs al LEFT JOIN users u ON al.user_id=u.user_id WHERE 1=1"
        params = []
        if filters:
            if filters.get("severity") and filters["severity"] != "All":
                if filters["severity"] == "Critical":
                    q += " AND al.is_suspicious=1"
                elif filters["severity"] == "Failed":
                    q += " AND al.operation_status='Failed'"
            if filters.get("database") and filters["database"] != "All Databases":
                q += " AND al.table_name LIKE %s"; params.append(f"%{filters['database']}%")
            if filters.get("time_range"):
                q += " AND al.access_timestamp >= NOW() - INTERVAL %s HOUR"
                params.append(int(filters["time_range"]))
        q += " ORDER BY al.access_timestamp DESC LIMIT %s"
        params.append(limit)
        return self.execute(q, tuple(params), all=True)

    def get_by_user(self, user_id):
        return self.execute(
            "SELECT * FROM activity_logs WHERE user_id=%s ORDER BY access_timestamp DESC LIMIT 50",
            (user_id,), all=True
        )

    def count_all(self):
        r = self.execute("SELECT COUNT(*) AS count FROM activity_logs", one=True)
        return r["count"] if r else 0

    def get_stats(self):
        stats = {}
        stats["total"]      = self.count_all()
        stats["suspicious"] = (self.execute("SELECT COUNT(*) AS c FROM activity_logs WHERE is_suspicious=1",    one=True) or {}).get("c", 0)
        stats["failed"]     = (self.execute("SELECT COUNT(*) AS c FROM activity_logs WHERE operation_status='Failed'", one=True) or {}).get("c", 0)
        stats["today"]      = (self.execute("SELECT COUNT(*) AS c FROM activity_logs WHERE DATE(access_timestamp)=CURDATE()", one=True) or {}).get("c", 0)
        stats["by_type"]    = self.execute("SELECT operation_type, COUNT(*) AS count FROM activity_logs GROUP BY operation_type", all=True) or []
        stats["top_users"]  = self.execute("SELECT username, COUNT(*) AS count FROM activity_logs GROUP BY username ORDER BY count DESC LIMIT 5", all=True) or []
        stats["recent_threats"] = self.execute("SELECT * FROM activity_logs WHERE is_suspicious=1 ORDER BY access_timestamp DESC LIMIT 10", all=True) or []
        return stats

    def get_timeline_data(self, hours=24):
        return self.execute(
            """SELECT DATE_FORMAT(access_timestamp,'%%Y-%%m-%%d %%H:00') AS hour,
                      COUNT(*) AS total,
                      SUM(is_suspicious) AS suspicious,
                      SUM(CASE WHEN operation_status='Failed' THEN 1 ELSE 0 END) AS failed
               FROM activity_logs
               WHERE access_timestamp >= NOW() - INTERVAL %s HOUR
               GROUP BY hour ORDER BY hour""",
            (hours,), all=True
        ) or []


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

class SecurityDetector(BaseManager):
    def __init__(self):
        super().__init__()
        self.user_activity_cache = defaultdict(list)
        self.ip_blacklist        = set()
        self._load_blacklist()

    def _load_blacklist(self):
        try:
            rows = self.execute("SELECT ip_address FROM ip_blacklist WHERE expires_at > NOW()", all=True)
            self.ip_blacklist = {r["ip_address"] for r in rows} if rows else set()
        except Exception:
            self.ip_blacklist = set()

    def check_activity(self, activity_id: int):
        a = self.execute(
            "SELECT al.*, u.role FROM activity_logs al LEFT JOIN users u ON al.user_id=u.user_id WHERE al.activity_id=%s",
            (activity_id,), one=True
        )
        if not a:
            return

        reasons    = []
        suspicious = False
        severity   = "Low"

        # 1. IP blacklist
        if a["ip_address"] in self.ip_blacklist:
            suspicious = True; severity = "Critical"
            reasons.append("IP address is blacklisted")

        # 2. Role-based violations
        if a["role"] == "Guest" and a["operation_type"] in ("INSERT","UPDATE","DELETE","DROP","ALTER"):
            suspicious = True; severity = "High"
            reasons.append("Guest attempting write operation")

        if a["role"] == "User" and a["table_name"] in Config.SENSITIVE_TABLES:
            if a["operation_type"] in ("SELECT","INSERT","UPDATE"):
                suspicious = True
                if severity == "Low": severity = "Medium"
                reasons.append(f"User accessing sensitive table: {a['table_name']}")

        # 3. Outside working hours
        if a["access_timestamp"]:
            h = a["access_timestamp"].hour
            if h < Config.WORKING_HOURS_START or h >= Config.WORKING_HOURS_END:
                suspicious = True
                if severity == "Low": severity = "Medium"
                reasons.append("Access outside working hours")

        # 4. SQL injection patterns + sensitive columns
        if a["operation_details"]:
            ql = a["operation_details"].lower()
            for pattern, desc in Config.SUSPICIOUS_QUERY_PATTERNS:
                if re.search(pattern, ql, re.IGNORECASE):
                    suspicious = True; severity = "Critical"
                    reasons.append(f"Suspicious pattern: {desc}")
                    break
            for col in Config.SENSITIVE_COLUMNS:
                if col.lower() in ql:
                    suspicious = True
                    if severity not in ("Critical",): severity = "High"
                    reasons.append(f"Access to sensitive column: {col}")

        # 5. Large data extraction
        if a.get("rows_affected") and int(a["rows_affected"]) > 1000:
            suspicious = True
            if severity == "Low": severity = "High"
            reasons.append(f"Large data extraction: {a['rows_affected']} rows")

        # 6. Rate limiting
        if a["user_id"]:
            self.user_activity_cache[a["user_id"]].append(datetime.now())
            recent = [t for t in self.user_activity_cache[a["user_id"]]
                      if (datetime.now() - t).seconds < 60]
            if len(recent) > Config.RATE_LIMIT["max_queries_per_min"]:
                suspicious = True
                if severity == "Low": severity = "Medium"
                reasons.append(f"Rate limit exceeded: {len(recent)} queries/min")

        if suspicious:
            self.execute(
                "UPDATE activity_logs SET is_suspicious=1, suspicious_reasons=%s, severity_level=%s WHERE activity_id=%s",
                ("; ".join(reasons), severity, activity_id)
            )
            if severity in ("High","Critical"):
                self._create_alert(a, reasons, severity)

    def _create_alert(self, activity: dict, reasons: list, severity: str):
        rstr = " ".join(reasons)
        alert_type = (
            "SQL Injection"   if "SQL Injection"   in rstr else
            "Data Leakage"    if "sensitive"        in rstr else
            "DoS Attempt"     if "rate limit"       in rstr else
            "Security Violation"
        )
        alert_id = self.execute(
            "INSERT INTO security_alerts (activity_id,alert_type,severity,description,status,created_at) VALUES (%s,%s,%s,%s,'New',NOW())",
            (activity["activity_id"], alert_type, severity, "; ".join(reasons))
        )
        # Fire notifications in background
        alert_payload = {
            "alert_id":   alert_id,
            "alert_type": alert_type,
            "severity":   severity,
            "description":"; ".join(reasons),
            "username":   activity.get("username", "unknown"),
        }
        threading.Thread(target=AlertNotifier.dispatch_alert, args=(alert_payload,), daemon=True).start()

    def get_active_alerts(self):
        try:
            return self.execute(
                """SELECT sa.*, al.username, al.operation_type, al.table_name
                   FROM security_alerts sa
                   JOIN activity_logs al ON sa.activity_id=al.activity_id
                   WHERE sa.status='New'
                   ORDER BY sa.created_at DESC LIMIT 20""",
                all=True
            ) or []
        except Exception as e:
            print(f"[Alerts] {e}"); return []

    def analyze_user_behavior(self, user_id: int, days: int = 7):
        activities = self.execute(
            """SELECT HOUR(access_timestamp) AS hour, COUNT(*) AS count, operation_type
               FROM activity_logs
               WHERE user_id=%s AND access_timestamp >= NOW() - INTERVAL %s DAY
               GROUP BY hour, operation_type ORDER BY hour""",
            (user_id, days), all=True
        ) or []
        return {
            "user_id":          user_id,
            "total_activities": sum(a["count"] for a in activities),
            "peak_hours":       dict(Counter({a["hour"]: a["count"] for a in activities})),
            "operation_types":  dict(Counter({a["operation_type"]: a["count"] for a in activities})),
        }


# ══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class ComplianceManager(BaseManager):
    STANDARDS = {
        "GDPR":    ["data_access","data_modification","user_consent"],
        "SOX":     ["financial_data_access","audit_trail","access_controls"],
        "HIPAA":   ["phi_access","phi_modification","phi_view"],
        "PCI_DSS": ["cardholder_data","auth_logs","access_monitoring"],
    }

    def check_compliance(self, activity: dict) -> list:
        findings = []
        if activity["table_name"] in Config.SENSITIVE_TABLES:
            if not activity.get("user_id"):
                findings.append({"standard":"GDPR","status":"Non-compliant","issue":"Personal data access without user identification"})
        if activity["table_name"] in ["accounts","financial","transactions"]:
            if activity["operation_type"] in ("UPDATE","DELETE"):
                findings.append({"standard":"SOX","status":"Compliant" if activity.get("rows_affected") else "Review needed","issue":"Financial data modification"})
        if activity["table_name"] in ["payments","credit_cards"]:
            findings.append({"standard":"PCI_DSS","status":"Monitored","issue":"Cardholder data access detected"})
        return findings

    def generate_report(self, report_type: str = "daily") -> dict:
        interval = {"daily":"CURDATE()","weekly":"NOW() - INTERVAL 7 DAY","monthly":"NOW() - INTERVAL 30 DAY"}.get(report_type,"CURDATE()")
        if report_type == "daily":
            activities = self.execute("SELECT * FROM activity_logs WHERE DATE(access_timestamp)=CURDATE()", all=True) or []
        elif report_type == "weekly":
            activities = self.execute("SELECT * FROM activity_logs WHERE access_timestamp >= NOW() - INTERVAL 7 DAY", all=True) or []
        else:
            activities = self.execute("SELECT * FROM activity_logs WHERE access_timestamp >= NOW() - INTERVAL 30 DAY", all=True) or []

        findings = []
        for a in activities:
            findings.extend(self.check_compliance(a))

        return {
            "generated_at": datetime.now().isoformat(),
            "report_type":  report_type,
            "findings":     findings,
            "statistics": {
                "total_activities":   len(activities),
                "non_compliant_count":len(findings),
                "standards_covered":  list(self.STANDARDS.keys()),
            },
        }


# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector(BaseManager):
    def __init__(self):
        super().__init__()
        self.baselines = {}

    def establish_baseline(self, user_id=None):
        if user_id:
            stats = self.execute(
                """SELECT AVG(queries_per_hour) AS avg_queries, STDDEV(queries_per_hour) AS std_queries
                   FROM (SELECT DATE(access_timestamp) AS day, HOUR(access_timestamp) AS hour,
                                COUNT(*) AS queries_per_hour
                         FROM activity_logs WHERE user_id=%s GROUP BY day,hour) AS s""",
                (user_id,), one=True
            )
            self.baselines[f"user_{user_id}"] = stats
        return self.baselines

    def detect_anomalies(self, activity: dict) -> list:
        anomalies = []
        if activity and activity.get("user_id"):
            bl = self.baselines.get(f"user_{activity['user_id']}")
            if bl and bl.get("avg_queries"):
                recent = self.execute(
                    "SELECT COUNT(*) AS count FROM activity_logs WHERE user_id=%s AND access_timestamp >= NOW() - INTERVAL 1 HOUR",
                    (activity["user_id"],), one=True
                )
                if recent and recent["count"] > bl["avg_queries"] + 3 * (bl["std_queries"] or 1):
                    anomalies.append({"type":"Statistical Anomaly","description":f"Unusual activity volume: {recent['count']} queries/hour","severity":"Medium"})

        if activity and activity.get("operation_type") == "LOGIN" and activity.get("username"):
            logins = self.execute(
                "SELECT ip_address FROM activity_logs WHERE username=%s AND operation_type='LOGIN' AND access_timestamp >= NOW() - INTERVAL 1 HOUR ORDER BY access_timestamp DESC LIMIT 2",
                (activity["username"],), all=True
            ) or []
            if len(logins) >= 2 and logins[0]["ip_address"] != logins[1]["ip_address"]:
                anomalies.append({"type":"Impossible Travel","description":f"Multiple logins from different IPs: {logins[0]['ip_address']} and {logins[1]['ip_address']}","severity":"High"})
        return anomalies


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 1 — ALERT NOTIFIER  (Email + SMS + Webhooks)
# ══════════════════════════════════════════════════════════════════════════════

class AlertNotifier:

    @staticmethod
    def send_email(subject: str, body: str, recipients: list = None):
        if not FeatureConfig.EMAIL_ENABLED:
            print(f"[Email-disabled] {subject}"); return
        recipients = recipients or FeatureConfig.ALERT_EMAILS
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = FeatureConfig.SMTP_USER
        msg["To"]      = ", ".join(recipients)
        html = f"""<html><body style="font-family:monospace;background:#0f172a;color:#e2e8f0;padding:24px">
          <div style="max-width:600px;margin:auto;background:#1e293b;border-radius:8px;padding:24px;border:1px solid #ef4444">
            <h2 style="color:#ef4444;margin:0 0 16px">🚨 DAM Security Alert</h2>
            <pre style="background:#0f172a;padding:16px;border-radius:6px;color:#94a3b8;white-space:pre-wrap;font-size:13px">{body}</pre>
            <p style="color:#475569;font-size:11px;margin-top:16px">DAM v3.0 · {datetime.now().isoformat()}</p>
          </div></body></html>"""
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html,  "html"))
        try:
            with smtplib.SMTP(FeatureConfig.SMTP_HOST, FeatureConfig.SMTP_PORT) as s:
                s.starttls()
                s.login(FeatureConfig.SMTP_USER, FeatureConfig.SMTP_PASSWORD)
                s.sendmail(FeatureConfig.SMTP_USER, recipients, msg.as_string())
            print(f"[Email] Sent: {subject}")
        except Exception as e:
            print(f"[Email] Error: {e}")

    @staticmethod
    def send_sms(message: str, phones: list = None):
        if not FeatureConfig.SMS_ENABLED:
            print(f"[SMS-disabled] {message[:80]}"); return
        phones = phones or FeatureConfig.ALERT_PHONES
        url = f"https://api.twilio.com/2010-04-01/Accounts/{FeatureConfig.TWILIO_SID}/Messages.json"
        for phone in phones:
            try:
                requests.post(url,
                    auth=(FeatureConfig.TWILIO_SID, FeatureConfig.TWILIO_TOKEN),
                    data={"From": FeatureConfig.TWILIO_FROM, "To": phone, "Body": message},
                    timeout=10
                )
            except Exception as e:
                print(f"[SMS] Error to {phone}: {e}")

    @classmethod
    def dispatch_alert(cls, alert: dict):
        if alert.get("severity") not in ("High","Critical"): return
        subject = f"[DAM {alert.get('severity')}] {alert.get('alert_type','Security Alert')}"
        body = (
            f"Severity   : {alert.get('severity')}\n"
            f"Type       : {alert.get('alert_type')}\n"
            f"Description: {alert.get('description')}\n"
            f"User       : {alert.get('username','unknown')}\n"
            f"Time       : {datetime.now().isoformat()}\n"
        )
        cls.send_email(subject, body)
        cls.send_sms(f"[DAM {alert.get('severity')}] {alert.get('description','')[:120]}")
        WebhookManager.fire_all(alert)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 2 — REPORT EXPORTER  (PDF + CSV)
# ══════════════════════════════════════════════════════════════════════════════

class ReportExporter:

    @staticmethod
    def activities_to_csv(activities: list) -> io.BytesIO:
        buf = io.StringIO()
        if not activities:
            buf.write("No data\n")
            return io.BytesIO(buf.getvalue().encode())
        writer = csv.DictWriter(buf, fieldnames=activities[0].keys())
        writer.writeheader()
        for row in activities:
            writer.writerow({k: v.isoformat() if isinstance(v, datetime) else v for k, v in row.items()})
        return io.BytesIO(buf.getvalue().encode("utf-8"))

    @staticmethod
    def activities_to_pdf(activities: list, title: str = "Activity Log Report") -> io.BytesIO:
        buf  = io.BytesIO()
        doc  = SimpleDocTemplate(buf, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=60, bottomMargin=40)
        st   = getSampleStyleSheet()
        elem = [
            Paragraph(title, ParagraphStyle("T", parent=st["Heading1"], fontSize=18, textColor=colors.HexColor("#1e293b"), spaceAfter=4)),
            Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Records: {len(activities)}",
                      ParagraphStyle("S", parent=st["Normal"], fontSize=9, textColor=colors.HexColor("#64748b"), spaceAfter=16)),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=10),
        ]
        if activities:
            cols    = ["activity_id","username","operation_type","table_name","operation_status","ip_address","access_timestamp","severity_level"]
            headers = ["ID","User","Operation","Table","Status","IP","Timestamp","Severity"]
            data    = [headers] + [[str(r.get(c,"") or "")[:38] for c in cols] for r in activities]
            tbl = Table(data, colWidths=[35,70,65,70,55,90,115,60], repeatRows=1)
            tbl.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR",    (0,0),(-1,0), colors.white),
                ("FONTNAME",     (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTSIZE",     (0,0),(-1,-1),7),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8fafc"),colors.white]),
                ("GRID",         (0,0),(-1,-1),0.4,colors.HexColor("#e2e8f0")),
                ("VALIGN",       (0,0),(-1,-1),"MIDDLE"),
                ("TOPPADDING",   (0,0),(-1,-1),3),
                ("BOTTOMPADDING",(0,0),(-1,-1),3),
                *[("BACKGROUND",(0,i+1),(-1,i+1),colors.HexColor("#fef2f2"))
                  for i,r in enumerate(activities) if r.get("is_suspicious")],
            ]))
            elem.append(tbl)
        else:
            elem.append(Paragraph("No records found.", st["Normal"]))
        doc.build(elem); buf.seek(0)
        return buf

    @staticmethod
    def compliance_to_pdf(report: dict) -> io.BytesIO:
        buf  = io.BytesIO()
        doc  = SimpleDocTemplate(buf, pagesize=letter, rightMargin=50, leftMargin=50, topMargin=60, bottomMargin=40)
        st   = getSampleStyleSheet()
        elem = [
            Paragraph("Compliance Report", st["Heading1"]),
            Paragraph(f"Type: {report.get('report_type')}   Generated: {report.get('generated_at','')}", st["Normal"]),
            Spacer(1, 0.25*inch),
        ]
        stats = report.get("statistics",{})
        sd = [["Total Activities",str(stats.get("total_activities",0))],
              ["Non-Compliant Events",str(stats.get("non_compliant_count",0))],
              ["Standards",", ".join(stats.get("standards_covered",[]))]]
        st_tbl = Table(sd, colWidths=[200,280])
        st_tbl.setStyle(TableStyle([("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
                                    ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#e2e8f0")),
                                    ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.HexColor("#f1f5f9"),colors.white])]))
        elem += [st_tbl, Spacer(1,0.25*inch)]
        findings = report.get("findings",[])
        if findings:
            elem.append(Paragraph(f"Findings ({len(findings)})", st["Heading2"]))
            fd = [["Standard","Status","Issue"]] + [[f.get("standard",""),f.get("status",""),f.get("issue","")]for f in findings[:100]]
            f_tbl = Table(fd, colWidths=[80,90,310])
            f_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1e293b")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                       ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                                       ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#e2e8f0"))]))
            elem.append(f_tbl)
        doc.build(elem); buf.seek(0)
        return buf


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 3 — IP GEOLOCATION
# ══════════════════════════════════════════════════════════════════════════════

class GeoTracker:
    _cache: dict = {}

    @classmethod
    def lookup(cls, ip: str) -> dict:
        if not ip or ip in ("127.0.0.1","::1","localhost"):
            return {"country":"Local","city":"Loopback","lat":0,"lon":0,"isp":"N/A"}
        if ip in cls._cache:
            return cls._cache[ip]
        try:
            data = requests.get(FeatureConfig.GEO_API.format(ip=ip), timeout=5).json()
            cls._cache[ip] = data
            return data
        except Exception:
            return {"country":"Unknown","city":"Unknown","lat":0,"lon":0,"isp":"Unknown"}

    @classmethod
    def get_top_countries(cls, activities: list) -> list:
        counts: Counter = Counter()
        for a in activities:
            if a.get("ip_address"):
                counts[cls.lookup(a["ip_address"]).get("country","Unknown")] += 1
        return [{"country":c,"count":n} for c,n in counts.most_common(10)]


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 4 — CHART DATA BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_chart_data(activity_logger: ActivityLogger) -> dict:
    stats    = activity_logger.get_stats()
    timeline = activity_logger.get_timeline_data(hours=24)

    def _count_sev(level):
        r = activity_logger.execute("SELECT COUNT(*) AS c FROM activity_logs WHERE severity_level=%s",(level,),one=True)
        return (r or {}).get("c",0)

    return {
        "kpis": {
            "total":      stats.get("total",0),
            "suspicious": stats.get("suspicious",0),
            "failed":     stats.get("failed",0),
            "today":      stats.get("today",0),
        },
        "operation_type_chart": {
            "labels": [r["operation_type"] for r in stats.get("by_type",[])],
            "data":   [r["count"]          for r in stats.get("by_type",[])],
            "colors": ["#3b82f6","#ef4444","#f59e0b","#10b981","#8b5cf6","#ec4899","#14b8a6","#f97316"],
        },
        "timeline_chart": {
            "labels":     [r["hour"]       for r in timeline],
            "total":      [r["total"]      for r in timeline],
            "suspicious": [r["suspicious"] for r in timeline],
            "failed":     [r["failed"]     for r in timeline],
        },
        "top_users_chart": {
            "labels": [r["username"] for r in stats.get("top_users",[])],
            "data":   [r["count"]    for r in stats.get("top_users",[])],
        },
        "severity_chart": {
            "labels": ["Low","Medium","High","Critical"],
            "data":   [_count_sev("Low"),_count_sev("Medium"),_count_sev("High"),_count_sev("Critical")],
            "colors": ["#10b981","#f59e0b","#ef4444","#7f1d1d"],
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 5 — TWO-FACTOR AUTHENTICATION (TOTP)
# ══════════════════════════════════════════════════════════════════════════════

class TwoFactorAuth:

    @staticmethod
    def setup(user_id: int, username: str, db) -> dict:
        secret = pyotp.random_base32()
        uri    = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="DAM System")
        db.execute(
            "INSERT INTO user_2fa (user_id,totp_secret,enabled,created_at) VALUES (%s,%s,0,NOW()) ON DUPLICATE KEY UPDATE totp_secret=%s,enabled=0",
            (user_id, secret, secret)
        )
        factory = qrcode.image.svg.SvgPathImage
        img     = qrcode.make(uri, image_factory=factory)
        svg_buf = io.BytesIO(); img.save(svg_buf)
        return {"secret": secret, "uri": uri, "qr_svg": svg_buf.getvalue().decode("utf-8")}

    @staticmethod
    def confirm_setup(user_id: int, code: str, db) -> bool:
        row = db.execute("SELECT totp_secret FROM user_2fa WHERE user_id=%s",(user_id,),one=True)
        if not row: return False
        ok = pyotp.TOTP(row["totp_secret"]).verify(code, valid_window=1)
        if ok:
            db.execute("UPDATE user_2fa SET enabled=1,confirmed_at=NOW() WHERE user_id=%s",(user_id,))
        return ok

    @staticmethod
    def verify(user_id: int, code: str, db) -> bool:
        row = db.execute("SELECT totp_secret FROM user_2fa WHERE user_id=%s AND enabled=1",(user_id,),one=True)
        if not row: return True   # 2FA not enabled
        return pyotp.TOTP(row["totp_secret"]).verify(code, valid_window=1)

    @staticmethod
    def disable(user_id: int, db):
        db.execute("UPDATE user_2fa SET enabled=0 WHERE user_id=%s",(user_id,))


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 6 — QUERY FIREWALL
# ══════════════════════════════════════════════════════════════════════════════

class QueryFirewall:
    _rules: list  = []
    _refreshed_at = 0.0

    @classmethod
    def _refresh(cls, db):
        if time.time() - cls._refreshed_at > FeatureConfig.FIREWALL_TTL:
            cls._rules       = db.execute("SELECT * FROM firewall_rules WHERE is_active=1 ORDER BY priority ASC", all=True) or []
            cls._refreshed_at = time.time()

    @classmethod
    def check(cls, query: str, username: str, ip: str, db) -> dict:
        cls._refresh(db)
        ql = query.lower()
        for rule in cls._rules:
            if rule.get("applies_to_user") and rule["applies_to_user"] != username: continue
            if rule.get("applies_to_ip")   and rule["applies_to_ip"]   != ip:       continue
            pat  = rule.get("pattern","")
            mt   = rule.get("match_type","regex")
            hit  = False
            if   mt == "contains":    hit = pat.lower() in ql
            elif mt == "starts_with": hit = ql.startswith(pat.lower())
            else:
                try: hit = bool(re.search(pat, ql, re.IGNORECASE))
                except re.error: pass
            if hit:
                db.execute(
                    "INSERT INTO firewall_blocks (rule_id,username,ip_address,query_snippet,blocked_at) VALUES (%s,%s,%s,%s,NOW())",
                    (rule["rule_id"], username, ip, query[:500])
                )
                return {"blocked":True,"rule_id":rule["rule_id"],"reason":rule.get("description","Blocked by firewall"),"action":rule.get("action","block")}
        return {"blocked": False}

    @classmethod
    def add_rule(cls, pattern, description, match_type, action, priority, db,
                 applies_to_user=None, applies_to_ip=None) -> int:
        rid = db.execute(
            "INSERT INTO firewall_rules (pattern,description,match_type,action,priority,applies_to_user,applies_to_ip,is_active,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,1,NOW())",
            (pattern,description,match_type,action,priority,applies_to_user,applies_to_ip)
        )
        cls._refreshed_at = 0; return rid

    @classmethod
    def delete_rule(cls, rule_id: int, db):
        db.execute("UPDATE firewall_rules SET is_active=0 WHERE rule_id=%s",(rule_id,))
        cls._refreshed_at = 0


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 7 — SCHEDULED COMPLIANCE REPORTS
# ══════════════════════════════════════════════════════════════════════════════

class ScheduledReporter:
    _scheduler = None

    @classmethod
    def start(cls, compliance_manager: ComplianceManager, activity_logger: ActivityLogger):
        os.makedirs(FeatureConfig.REPORT_OUTPUT, exist_ok=True)
        cls._scheduler = BackgroundScheduler(daemon=True)
        for rtype, kwargs in [
            ("daily",   {"hour":int(FeatureConfig.REPORT_CRON["hour"]), "minute":int(FeatureConfig.REPORT_CRON["minute"])}),
            ("weekly",  {"day_of_week":"mon","hour":7,"minute":30}),
            ("monthly", {"day":1,"hour":8,"minute":0}),
        ]:
            cls._scheduler.add_job(
                cls._run, args=(compliance_manager,activity_logger,rtype),
                trigger=CronTrigger(**kwargs), id=f"{rtype}_report", replace_existing=True
            )
        cls._scheduler.start()
        print("✓ Scheduled reporter started")

    @staticmethod
    def _run(comp, logger, rtype):
        try:
            report  = comp.generate_report(rtype)
            pdf_buf = ReportExporter.compliance_to_pdf(report)
            fname   = f"{rtype}_compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            path    = os.path.join(FeatureConfig.REPORT_OUTPUT, fname)
            with open(path,"wb") as f: f.write(pdf_buf.read())
            print(f"[Scheduler] Report saved: {path}")
            st = report.get("statistics",{})
            AlertNotifier.send_email(
                f"[DAM] {rtype.capitalize()} Compliance Report",
                f"Type: {rtype}\nTotal: {st.get('total_activities',0)}\nNon-compliant: {st.get('non_compliant_count',0)}\nFile: {path}"
            )
        except Exception as e:
            print(f"[Scheduler] Error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 8 — WEBHOOK MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class WebhookManager:

    @classmethod
    def fire_all(cls, payload: dict):
        for url in FeatureConfig.WEBHOOK_URLS:
            threading.Thread(target=cls._fire, args=(url,payload), daemon=True).start()

    @staticmethod
    def _fire(url: str, payload: dict):
        try:
            r = requests.post(url, json={"source":"DAM-v3","timestamp":datetime.now().isoformat(),"payload":payload},
                              timeout=10, headers={"Content-Type":"application/json","X-DAM-Event":"security-alert"})
            print(f"[Webhook] {url} → {r.status_code}")
        except Exception as e:
            print(f"[Webhook] Error {url}: {e}")

    @staticmethod
    def register(url: str, db) -> int:
        rid = db.execute("INSERT INTO webhooks (url,is_active,created_at) VALUES (%s,1,NOW()) ON DUPLICATE KEY UPDATE is_active=1",(url,))
        if url not in FeatureConfig.WEBHOOK_URLS:
            FeatureConfig.WEBHOOK_URLS.append(url)
        return rid

    @staticmethod
    def list_webhooks(db) -> list:
        return db.execute("SELECT * FROM webhooks WHERE is_active=1",all=True) or []


# ══════════════════════════════════════════════════════════════════════════════
# FLASK APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__, template_folder="templates")
app.secret_key = Config.SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=8)
CORS(app)

# Global manager references (populated in main)
user_mgr           = None
activity_logger    = None
security_detector  = None
compliance_manager = None
anomaly_detector   = None


@app.before_request
def _ensure_managers():
    global user_mgr, activity_logger, security_detector, compliance_manager, anomaly_detector
    if not user_mgr:
        user_mgr           = UserManager()
        activity_logger    = ActivityLogger()
        security_detector  = SecurityDetector()
        compliance_manager = ComplianceManager()
        anomaly_detector   = AnomalyDetector()


# ── Auth decorators ────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                return jsonify({"error":"Access denied"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ══════════════════════════════════════════════════════════════════════════════
# WEB ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")
    if role == "Admin":   return render_template("dashboard_admin.html")
    if role == "User":    return render_template("dashboard_user.html")
    if role == "Guest":   return render_template("dashboard_guest.html")
    return redirect("/")

@app.route("/analytics")
@login_required
@role_required("Admin")
def analytics():
    return render_template("analytics.html")

@app.route("/compliance")
@login_required
@role_required("Admin")
def compliance():
    return render_template("compliance.html")

@app.route("/alerts")
@login_required
@role_required("Admin")
def alerts():
    return render_template("alerts.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ══════════════════════════════════════════════════════════════════════════════
# CORE API ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/health")
def api_health():
    return jsonify({"status":"ok","timestamp":datetime.now().isoformat(),"version":"3.0"})


@app.route("/api/login", methods=["POST"])
def api_login():
    data   = request.json or {}
    result = user_mgr.authenticate(data.get("username"), data.get("password"))

    if isinstance(result, dict) and result.get("locked"):
        return jsonify({"success":False,"locked":True,"locked_until":result["locked_until"].isoformat()}), 403
    if not result:
        return jsonify({"success":False}), 401

    session.permanent   = True
    session["user_id"]  = result["user_id"]
    session["role"]     = result["role"]
    session["username"] = result["username"]

    aid = activity_logger.log_activity(result["user_id"], result["username"], "LOGIN", "users",
                                        "Success", "Login success", request.remote_addr)
    if aid: security_detector.check_activity(aid)

    return jsonify({"success":True, "redirect":"/dashboard", "role":result["role"]})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    if "user_id" in session:
        activity_logger.log_activity(session["user_id"], session.get("username"),
                                     "LOGOUT","users","Success","Logout",request.remote_addr)
    session.clear()
    return jsonify({"success":True})


@app.route("/api/dashboard-data")
@login_required
def api_dashboard_data():
    filters = {
        "severity":   request.args.get("severity"),
        "database":   request.args.get("database"),
        "time_range": request.args.get("time_range"),
    }
    activities = activity_logger.get_latest(50, filters)
    stats      = activity_logger.get_stats()
    al         = security_detector.get_active_alerts() if session["role"] == "Admin" else []

    return jsonify({
        "success":    True,
        "user":       user_mgr.get_by_id(session["user_id"]),
        "activities": activities,
        "stats":      stats,
        "alerts":     al,
        "timestamp":  datetime.now().isoformat(),
    })


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify({"success":True,"stats":activity_logger.get_stats()})


@app.route("/api/timeline")
@login_required
def api_timeline():
    hours = request.args.get("hours", 24, type=int)
    return jsonify({"success":True,"timeline":activity_logger.get_timeline_data(hours)})


@app.route("/api/user/activities")
@login_required
def api_user_activities():
    return jsonify({"success":True,"activities":activity_logger.get_by_user(session["user_id"])})


@app.route("/api/guest/summary")
@login_required
def api_guest_summary():
    return jsonify({
        "success":        True,
        "total_activities":activity_logger.count_all(),
        "my_activities":  len(activity_logger.get_by_user(session["user_id"]) or []),
    })


@app.route("/api/alerts")
@login_required
@role_required("Admin")
def api_alerts():
    return jsonify({"success":True,"alerts":security_detector.get_active_alerts()})


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
@role_required("Admin")
def resolve_alert(alert_id):
    security_detector.execute("UPDATE security_alerts SET status='Resolved',resolved_at=NOW() WHERE alert_id=%s",(alert_id,))
    return jsonify({"success":True})


@app.route("/api/compliance/report")
@login_required
@role_required("Admin")
def api_compliance_report():
    return jsonify({"success":True,"report":compliance_manager.generate_report(request.args.get("type","daily"))})


@app.route("/api/users")
@login_required
@role_required("Admin")
def api_users():
    return jsonify({"success":True,"users":user_mgr.get_all_users()})


@app.route("/api/users/<int:user_id>/status", methods=["POST"])
@login_required
@role_required("Admin")
def update_user_status(user_id):
    user_mgr.update_status(user_id, (request.json or {}).get("status"))
    return jsonify({"success":True})


@app.route("/api/analyze/behavior/<int:user_id>")
@login_required
@role_required("Admin")
def analyze_user_behavior(user_id):
    return jsonify({"success":True,"profile":security_detector.analyze_user_behavior(user_id)})


# ── Agent ingest endpoints ─────────────────────────────────────────────────────

@app.route("/api/agent/activity", methods=["POST"])
def ingest_agent_activity():
    data      = request.json or {}
    username  = data.get("username","SYSTEM")
    operation = data.get("operation","QUERY")
    query     = data.get("query","")
    table     = data.get("table","unknown")
    ip        = data.get("client_ip", request.remote_addr)

    # Firewall check
    fw = QueryFirewall.check(query, username, ip, user_mgr)
    if fw["blocked"] and fw.get("action") == "block":
        return jsonify({"success":False,"blocked":True,"reason":fw["reason"]}), 403

    status = "Failed" if any(k in query.lower() for k in ("error","failed")) else "Success"
    aid    = activity_logger.log_activity(None, username, operation, table, status, query, ip,
                                          data.get("session_id"), data.get("rows_affected"))
    if aid:
        security_detector.check_activity(aid)

    activity  = activity_logger.execute("SELECT * FROM activity_logs WHERE activity_id=%s",(aid,),one=True) if aid else None
    anomalies = anomaly_detector.detect_anomalies(activity) if activity else []

    return jsonify({"success":True,"activity_id":aid,"anomalies_detected":len(anomalies)>0})


@app.route("/api/agent/bulk", methods=["POST"])
def ingest_bulk_activities():
    results = []
    for data in (request.json or {}).get("activities",[]):
        try:
            aid = activity_logger.log_activity(None, data.get("username","SYSTEM"),
                                               data.get("operation","QUERY"), data.get("table","unknown"),
                                               data.get("status","Success"), data.get("query",""),
                                               data.get("ip", request.remote_addr))
            if aid: security_detector.check_activity(aid)
            results.append({"id":aid,"status":"success"})
        except Exception as e:
            results.append({"status":"failed","error":str(e)})
    return jsonify({"success":True,"processed":len(results),"results":results})


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE API ROUTES  (prefix /api/v2/)
# ══════════════════════════════════════════════════════════════════════════════

# ── Export ─────────────────────────────────────────────────────────────────────

@app.route("/api/v2/export/activities/csv")
@login_required
@role_required("Admin")
def export_csv():
    activities = activity_logger.get_latest(1000, {
        "severity":   request.args.get("severity"),
        "database":   request.args.get("database"),
        "time_range": request.args.get("time_range",24),
    })
    buf = ReportExporter.activities_to_csv(activities); buf.seek(0)
    return send_file(buf, mimetype="text/csv", as_attachment=True,
                     download_name=f"dam_activities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")


@app.route("/api/v2/export/activities/pdf")
@login_required
@role_required("Admin")
def export_pdf():
    activities = activity_logger.get_latest(500, {"time_range": request.args.get("time_range",24)})
    buf = ReportExporter.activities_to_pdf(activities)
    return send_file(buf, mimetype="application/pdf", as_attachment=True,
                     download_name=f"dam_activities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")


@app.route("/api/v2/export/compliance/pdf")
@login_required
@role_required("Admin")
def export_compliance_pdf():
    rtype = request.args.get("type","daily")
    buf   = ReportExporter.compliance_to_pdf(compliance_manager.generate_report(rtype))
    return send_file(buf, mimetype="application/pdf", as_attachment=True,
                     download_name=f"dam_compliance_{rtype}_{datetime.now().strftime('%Y%m%d')}.pdf")


# ── Geo ────────────────────────────────────────────────────────────────────────

@app.route("/api/v2/geo/lookup")
@login_required
def geo_lookup():
    return jsonify({"success":True,"geo":GeoTracker.lookup(request.args.get("ip",request.remote_addr))})


@app.route("/api/v2/geo/top-countries")
@login_required
@role_required("Admin")
def geo_top_countries():
    return jsonify({"success":True,"countries":GeoTracker.get_top_countries(activity_logger.get_latest(500))})


# ── Charts ─────────────────────────────────────────────────────────────────────

@app.route("/api/v2/charts/all")
@login_required
@role_required("Admin")
def charts_all():
    return jsonify({"success":True,"charts":build_chart_data(activity_logger)})


# ── 2FA ────────────────────────────────────────────────────────────────────────

@app.route("/api/v2/2fa/setup", methods=["POST"])
@login_required
def twofa_setup():
    r = TwoFactorAuth.setup(session["user_id"], session["username"], user_mgr)
    return jsonify({"success":True,"uri":r["uri"],"qr_svg":r["qr_svg"]})


@app.route("/api/v2/2fa/confirm", methods=["POST"])
@login_required
def twofa_confirm():
    ok = TwoFactorAuth.confirm_setup(session["user_id"], (request.json or {}).get("code",""), user_mgr)
    return jsonify({"success":ok,"message":"2FA enabled" if ok else "Invalid code"})


@app.route("/api/v2/2fa/verify", methods=["POST"])
@login_required
def twofa_verify():
    ok = TwoFactorAuth.verify(session["user_id"], (request.json or {}).get("code",""), user_mgr)
    return jsonify({"success":ok})


@app.route("/api/v2/2fa/disable", methods=["POST"])
@login_required
def twofa_disable():
    TwoFactorAuth.disable(session["user_id"], user_mgr)
    return jsonify({"success":True,"message":"2FA disabled"})


# ── Firewall ───────────────────────────────────────────────────────────────────

@app.route("/api/v2/firewall/check", methods=["POST"])
def firewall_check():
    d = request.json or {}
    return jsonify(QueryFirewall.check(d.get("query",""), d.get("username","unknown"), d.get("ip",request.remote_addr), user_mgr))


@app.route("/api/v2/firewall/rules", methods=["GET"])
@login_required
@role_required("Admin")
def list_firewall_rules():
    return jsonify({"success":True,"rules":user_mgr.execute("SELECT * FROM firewall_rules ORDER BY priority ASC",all=True) or []})


@app.route("/api/v2/firewall/rules", methods=["POST"])
@login_required
@role_required("Admin")
def add_firewall_rule():
    d = request.json or {}
    rid = QueryFirewall.add_rule(d.get("pattern",""), d.get("description",""), d.get("match_type","regex"),
                                  d.get("action","block"), d.get("priority",100), user_mgr,
                                  d.get("applies_to_user"), d.get("applies_to_ip"))
    return jsonify({"success":True,"rule_id":rid})


@app.route("/api/v2/firewall/rules/<int:rule_id>", methods=["DELETE"])
@login_required
@role_required("Admin")
def delete_firewall_rule(rule_id):
    QueryFirewall.delete_rule(rule_id, user_mgr)
    return jsonify({"success":True})


@app.route("/api/v2/firewall/blocks")
@login_required
@role_required("Admin")
def list_firewall_blocks():
    return jsonify({"success":True,"blocks":user_mgr.execute("SELECT * FROM firewall_blocks ORDER BY blocked_at DESC LIMIT 100",all=True) or []})


# ── Webhooks ───────────────────────────────────────────────────────────────────

@app.route("/api/v2/webhooks", methods=["GET"])
@login_required
@role_required("Admin")
def list_webhooks():
    return jsonify({"success":True,"webhooks":WebhookManager.list_webhooks(user_mgr)})


@app.route("/api/v2/webhooks", methods=["POST"])
@login_required
@role_required("Admin")
def add_webhook():
    url = (request.json or {}).get("url","")
    if not url.startswith("https://"):
        return jsonify({"success":False,"error":"URL must use HTTPS"}), 400
    return jsonify({"success":True,"webhook_id":WebhookManager.register(url, user_mgr)})


@app.route("/api/v2/webhooks/test", methods=["POST"])
@login_required
@role_required("Admin")
def test_webhook():
    WebhookManager._fire((request.json or {}).get("url",""), {"test":True,"message":"DAM webhook test"})
    return jsonify({"success":True})


# ── Scheduled reports ──────────────────────────────────────────────────────────

@app.route("/api/v2/reports/trigger", methods=["POST"])
@login_required
@role_required("Admin")
def trigger_report():
    rtype = (request.json or {}).get("type","daily")
    threading.Thread(target=ScheduledReporter._run, args=(compliance_manager,activity_logger,rtype), daemon=True).start()
    return jsonify({"success":True,"message":f"{rtype} report generation started"})


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE INITIALISATION
# ══════════════════════════════════════════════════════════════════════════════

def init_database():
    conn = DatabaseConnection().get_conn()
    cur  = conn.cursor()

    tables = [
        """CREATE TABLE IF NOT EXISTS users (
            user_id        INT AUTO_INCREMENT PRIMARY KEY,
            username       VARCHAR(50) UNIQUE NOT NULL,
            password_hash  VARCHAR(255) NOT NULL,
            role           ENUM('Admin','User','Guest') DEFAULT 'Guest',
            account_status ENUM('Active','Inactive','Locked') DEFAULT 'Active',
            failed_attempts INT DEFAULT 0,
            locked_until   DATETIME NULL,
            last_login     DATETIME NULL,
            created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username),
            INDEX idx_status   (account_status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",

        """CREATE TABLE IF NOT EXISTS activity_logs (
            activity_id       INT AUTO_INCREMENT PRIMARY KEY,
            user_id           INT NULL,
            username          VARCHAR(50),
            operation_type    VARCHAR(20),
            table_name        VARCHAR(50),
            operation_status  VARCHAR(20),
            operation_details TEXT,
            ip_address        VARCHAR(45),
            access_timestamp  DATETIME,
            session_id        VARCHAR(100) NULL,
            rows_affected     INT NULL,
            query_hash        VARCHAR(64) NULL,
            is_suspicious     BOOLEAN DEFAULT FALSE,
            suspicious_reasons TEXT NULL,
            severity_level    ENUM('Low','Medium','High','Critical') DEFAULT 'Low',
            INDEX idx_timestamp  (access_timestamp),
            INDEX idx_user       (user_id),
            INDEX idx_suspicious (is_suspicious),
            INDEX idx_hash       (query_hash),
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",

        """CREATE TABLE IF NOT EXISTS security_alerts (
            alert_id    INT AUTO_INCREMENT PRIMARY KEY,
            activity_id INT,
            alert_type  VARCHAR(50),
            severity    VARCHAR(20),
            description TEXT,
            status      ENUM('New','Investigating','Resolved') DEFAULT 'New',
            created_at  DATETIME,
            resolved_at DATETIME NULL,
            INDEX idx_status  (status),
            INDEX idx_created (created_at),
            FOREIGN KEY (activity_id) REFERENCES activity_logs(activity_id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",

        """CREATE TABLE IF NOT EXISTS ip_blacklist (
            ip_id      INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) UNIQUE,
            reason     TEXT,
            created_at DATETIME,
            expires_at DATETIME,
            INDEX idx_ip      (ip_address),
            INDEX idx_expires (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",

        """CREATE TABLE IF NOT EXISTS compliance_logs (
            log_id      INT AUTO_INCREMENT PRIMARY KEY,
            activity_id INT,
            standard    VARCHAR(50),
            finding     TEXT,
            status      VARCHAR(20),
            created_at  DATETIME,
            INDEX idx_standard (standard),
            FOREIGN KEY (activity_id) REFERENCES activity_logs(activity_id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",

        # ── Feature tables ──────────────────────────────────────────────────────
        """CREATE TABLE IF NOT EXISTS user_2fa (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            user_id      INT UNIQUE NOT NULL,
            totp_secret  VARCHAR(64) NOT NULL,
            enabled      TINYINT(1) DEFAULT 0,
            created_at   DATETIME,
            confirmed_at DATETIME NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

        """CREATE TABLE IF NOT EXISTS firewall_rules (
            rule_id         INT AUTO_INCREMENT PRIMARY KEY,
            pattern         TEXT NOT NULL,
            description     VARCHAR(255),
            match_type      ENUM('regex','contains','starts_with') DEFAULT 'regex',
            action          ENUM('block','alert') DEFAULT 'block',
            priority        INT DEFAULT 100,
            applies_to_user VARCHAR(50) NULL,
            applies_to_ip   VARCHAR(45) NULL,
            is_active       TINYINT(1) DEFAULT 1,
            created_at      DATETIME,
            INDEX idx_active   (is_active),
            INDEX idx_priority (priority)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

        """CREATE TABLE IF NOT EXISTS firewall_blocks (
            block_id      INT AUTO_INCREMENT PRIMARY KEY,
            rule_id       INT,
            username      VARCHAR(50),
            ip_address    VARCHAR(45),
            query_snippet TEXT,
            blocked_at    DATETIME,
            INDEX idx_time (blocked_at),
            FOREIGN KEY (rule_id) REFERENCES firewall_rules(rule_id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

        """CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id INT AUTO_INCREMENT PRIMARY KEY,
            url        VARCHAR(512) UNIQUE NOT NULL,
            is_active  TINYINT(1) DEFAULT 1,
            created_at DATETIME,
            INDEX idx_active (is_active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

        """CREATE TABLE IF NOT EXISTS report_log (
            report_id   INT AUTO_INCREMENT PRIMARY KEY,
            report_type VARCHAR(20),
            file_path   VARCHAR(512),
            created_at  DATETIME,
            INDEX idx_created (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    ]

    for ddl in tables:
        cur.execute(ddl)

    # Default users
    for uname, pwd, role in [("admin","admin123","Admin"),("user1","user123","User"),("guest1","guest123","Guest")]:
        cur.execute("SELECT user_id FROM users WHERE username=%s",(uname,))
        if not cur.fetchone():
            
            
            cur.execute("INSERT INTO users (username,password_hash,role,account_status,created_at) VALUES (%s,%s,%s,'Active',NOW())",(uname,pwd,role))
            print(f"✓ Created user: {uname} / {pwd}")
    # Seed firewall rules
    cur.execute("SELECT COUNT(*) FROM firewall_rules"); count = cur.fetchone()[0]
    if count == 0:
        seeds = [
            ("union.*select",      "SQL Injection - UNION",       "regex",      "block", 10),
            ("drop\\s+table",      "Destructive DROP TABLE",      "regex",      "block", 10),
            ("into\\s+outfile",    "File Write via SELECT",       "regex",      "block", 10),
            ("exec\\s+xp_",        "SQL Server xp_ procedure",    "regex",      "block", 10),
            ("sleep\\s*\\(",       "Time-based Blind Injection",  "regex",      "block", 20),
            ("or\\s+1=1",          "Classic Boolean Injection",   "regex",      "block", 20),
            ("'\\s*or\\s*'1'='1",  "String Boolean Injection",    "regex",      "block", 20),
        ]
        for p,d,mt,a,pr in seeds:
            cur.execute("INSERT INTO firewall_rules (pattern,description,match_type,action,priority,is_active,created_at) VALUES (%s,%s,%s,%s,%s,1,NOW())",(p,d,mt,a,pr))
        print("✓ Firewall rules seeded")

    conn.commit(); cur.close(); conn.close()
    print("✓ Database initialised")


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("  DATABASE ACTIVITY MONITORING SYSTEM  ·  v3.0 ENTERPRISE")
    print("=" * 70)

    print("[1/3] Initialising database...")
    init_database()

    print("[2/3] Starting managers...")
    user_mgr           = UserManager()
    activity_logger    = ActivityLogger()
    security_detector  = SecurityDetector()
    compliance_manager = ComplianceManager()
    anomaly_detector   = AnomalyDetector()

    print("[3/3] Starting scheduled reporter...")
    ScheduledReporter.start(compliance_manager, activity_logger)

    print("=" * 70)
    print("  Features : Email/SMS · PDF/CSV Export · IP Geo · 2FA")
    print("           : Query Firewall · Scheduled Reports · Webhooks")
    print("           : Anomaly Detection · Compliance · Behaviour Analytics")
    print("  Server   : http://localhost:5000")
    print("  Accounts : admin/admin123  ·  user1/user123  ·  guest1/guest123")
    print("=" * 70)

    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
    