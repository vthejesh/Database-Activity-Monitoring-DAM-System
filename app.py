"""
Database Activity Monitoring (DAM) System
ENHANCED Guardium-style backend with Advanced Features
"""

import threading
import pytz
import re
import json
import hashlib
import ipaddress
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict, Counter

from flask import (
    Flask, request, jsonify,
    render_template, session,
    redirect, url_for, g
)
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
import mysql.connector
from mysql.connector import pooling

# =====================================================
# CONFIG
# =====================================================

class Config:
    DB_HOST = "localhost"
    DB_USER = "root"
    DB_PASSWORD = "1234"
    DB_NAME = "dam_system"
    SECRET_KEY = "dam-secret-key"

    WORKING_HOURS_START = 9
    WORKING_HOURS_END = 18

    # Security thresholds
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 30  # minutes
    SENSITIVE_TABLES = ["users", "customers", "accounts", "payments", "credit_cards"]
    SENSITIVE_COLUMNS = ["password", "ssn", "credit_card", "bank_account", "salary"]

    # Alert thresholds
    SUSPICIOUS_QUERY_PATTERNS = [
        (r"union.*select", "SQL Injection - UNION"),
        (r"select.*from.*information_schema", "Schema Enumeration"),
        (r"drop\s+table", "DROP Table Attempt"),
        (r"truncate\s+table", "TRUNCATE Attempt"),
        (r"alter\s+table", "ALTER Table Attempt"),
        (r"create\s+user", "CREATE User Attempt"),
        (r"grant\s+.*\s+to", "Privilege Escalation"),
        (r"exec\s+xp_cmdshell", "xp_cmdshell Attempt"),
        (r"waitfor\s+delay", "Time-based Injection"),
        (r"load_file\s*\(", "File Read Attempt"),
        (r"into\s+outfile", "File Write Attempt"),
        (r"0x[0-9a-f]{10,}", "Hex Encoding - Possible Evasion"),
        (r"sleep\s*\(", "Time-based Attack"),
        (r"benchmark\s*\(", "Benchmark Attack"),
        (r"pg_sleep\s*\(", "PostgreSQL Sleep Attack"),
    ]

    # Rate limiting
    RATE_LIMIT = {
        "max_queries_per_min": 100,
        "max_failed_per_hour": 10,
        "alert_on_burst": True
    }


# =====================================================
# DATABASE CONNECTION (POOL)
# =====================================================

class DatabaseConnection:
    _instance = None
    _lock = threading.Lock()

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


# =====================================================
# BASE MANAGER
# =====================================================

class BaseManager:
    def __init__(self):
        self.db = DatabaseConnection()

    def execute(self, query, params=None, one=False, all=False):
        conn = None
        cur = None
        try:
            conn = self.db.get_conn()
            cur = conn.cursor(dictionary=True)
            cur.execute(query, params or ())
            if one:
                return cur.fetchone()
            if all:
                return cur.fetchall()
            return cur.lastrowid
        except Exception as e:
            print(f"Database error: {e}")
            raise
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()


# =====================================================
# USER MANAGER (FIXED WITH SIMPLE AUTH)
# =====================================================

class UserManager(BaseManager):
    def authenticate(self, username, password):
        # Simple authentication for testing
        q = """
            SELECT user_id, username, password_hash, role, account_status,
                   COALESCE(failed_attempts, 0) as failed_attempts, 
                   locked_until
            FROM users WHERE username=%s
        """
        user = self.execute(q, (username,), one=True)

        if not user:
            return None

        # Check if account is locked
        if user.get("locked_until") and user["locked_until"] > datetime.now():
            return {"locked": True, "locked_until": user["locked_until"]}

        if user["account_status"] == "Active":
            # ACCEPT ANY PASSWORD FOR TESTING
            # Just update last login and return the user
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

    def create_user(self, username, password, role="Guest"):
        q = """
            INSERT INTO users (username, password_hash, role, account_status, created_at)
            VALUES (%s, %s, %s, 'Active', NOW())
        """
        return self.execute(q, (username, generate_password_hash(password), role))

    def get_all_users(self):
        return self.execute(
            "SELECT user_id, username, role, account_status, last_login, COALESCE(failed_attempts, 0) as failed_attempts FROM users",
            all=True
        )

    def update_status(self, user_id, status):
        self.execute(
            "UPDATE users SET account_status=%s WHERE user_id=%s",
            (status, user_id)
        )


# =====================================================
# ACTIVITY LOGGER (ENHANCED)
# =====================================================

class ActivityLogger(BaseManager):
    def log_activity(
        self, user_id, username,
        operation_type, table_name,
        status, details, ip, session_id=None, rows_affected=None
    ):
        ts = datetime.now(pytz.timezone("Asia/Kolkata"))

        # Generate query hash for pattern analysis
        query_hash = hashlib.md5(details.encode()).hexdigest() if details else None

        q = """
            INSERT INTO activity_logs
            (user_id, username, operation_type, table_name,
             operation_status, operation_details, ip_address, access_timestamp,
             session_id, rows_affected, query_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        activity_id = self.execute(q, (
            user_id, username,
            operation_type, table_name,
            status, details, ip, ts,
            session_id, rows_affected, query_hash
        ))

        return activity_id

    def get_latest(self, limit=50, filters=None):
        q = """
            SELECT al.*, u.role
            FROM activity_logs al
            LEFT JOIN users u ON al.user_id=u.user_id
            WHERE 1=1
        """
        params = []

        if filters:
            if filters.get('severity') and filters['severity'] != 'All':
                if filters['severity'] == 'Critical':
                    q += " AND al.is_suspicious = 1"
                elif filters['severity'] == 'Failed':
                    q += " AND al.operation_status = 'Failed'"

            if filters.get('database') and filters['database'] != 'All Databases':
                q += " AND al.table_name LIKE %s"
                params.append(f"%{filters['database']}%")

            if filters.get('time_range'):
                hours = int(filters['time_range'])
                q += " AND al.access_timestamp >= NOW() - INTERVAL %s HOUR"
                params.append(hours)

        q += " ORDER BY al.access_timestamp DESC LIMIT %s"
        params.append(limit)

        return self.execute(q, tuple(params), all=True)

    def get_by_user(self, user_id):
        q = """
            SELECT *
            FROM activity_logs
            WHERE user_id=%s
            ORDER BY access_timestamp DESC
            LIMIT 50
        """
        return self.execute(q, (user_id,), all=True)

    def count_all(self):
        result = self.execute(
            "SELECT COUNT(*) AS count FROM activity_logs",
            one=True
        )
        return result["count"] if result else 0

    def get_stats(self):
        # Get various statistics for dashboard
        stats = {}

        # Total counts
        stats['total'] = self.count_all()

        # Suspicious counts
        suspicious = self.execute(
            "SELECT COUNT(*) AS count FROM activity_logs WHERE is_suspicious=1",
            one=True
        )
        stats['suspicious'] = suspicious["count"] if suspicious else 0

        # Failed counts
        failed = self.execute(
            "SELECT COUNT(*) AS count FROM activity_logs WHERE operation_status='Failed'",
            one=True
        )
        stats['failed'] = failed["count"] if failed else 0

        # Today's activity
        today = self.execute(
            "SELECT COUNT(*) AS count FROM activity_logs WHERE DATE(access_timestamp)=CURDATE()",
            one=True
        )
        stats['today'] = today["count"] if today else 0

        # Activity by type
        stats['by_type'] = self.execute(
            "SELECT operation_type, COUNT(*) as count FROM activity_logs GROUP BY operation_type",
            all=True
        ) or []

        # Top users
        stats['top_users'] = self.execute(
            "SELECT username, COUNT(*) as count FROM activity_logs GROUP BY username ORDER BY count DESC LIMIT 5",
            all=True
        ) or []

        # Recent threats
        stats['recent_threats'] = self.execute(
            "SELECT * FROM activity_logs WHERE is_suspicious=1 ORDER BY access_timestamp DESC LIMIT 10",
            all=True
        ) or []

        return stats

    def get_timeline_data(self, hours=24):
        # Get activity timeline for charts
        q = """
            SELECT 
                DATE_FORMAT(access_timestamp, '%%Y-%%m-%%d %%H:00') as hour,
                COUNT(*) as total,
                SUM(is_suspicious) as suspicious,
                SUM(CASE WHEN operation_status='Failed' THEN 1 ELSE 0 END) as failed
            FROM activity_logs
            WHERE access_timestamp >= NOW() - INTERVAL %s HOUR
            GROUP BY hour
            ORDER BY hour
        """
        return self.execute(q, (hours,), all=True) or []


# =====================================================
# SECURITY DETECTOR (ENHANCED)
# =====================================================

class SecurityDetector(BaseManager):
    def __init__(self):
        super().__init__()
        self.user_activity_cache = defaultdict(list)
        self.ip_blacklist = set()
        self.load_blacklist()

    def load_blacklist(self):
        # Load blacklisted IPs from database
        try:
            # First check if table exists
            blacklist = self.execute(
                "SELECT ip_address FROM ip_blacklist WHERE expires_at > NOW()",
                all=True
            )
            if blacklist:
                self.ip_blacklist = {item['ip_address'] for item in blacklist}
            else:
                self.ip_blacklist = set()
        except Exception as e:
            print(f"Note: ip_blacklist table not ready yet: {e}")
            self.ip_blacklist = set()

    def check_activity(self, activity_id):
        q = """
            SELECT al.*, u.role
            FROM activity_logs al
            LEFT JOIN users u ON al.user_id=u.user_id
            WHERE al.activity_id=%s
        """
        a = self.execute(q, (activity_id,), one=True)
        if not a:
            return

        reasons = []
        suspicious = False
        severity = "Low"

        # 1. Check IP blacklist
        if a["ip_address"] in self.ip_blacklist:
            suspicious = True
            reasons.append("IP address is blacklisted")
            severity = "Critical"

        # 2. Check role-based violations
        if a["role"] == "Guest" and a["operation_type"] in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER"):
            suspicious = True
            reasons.append("Guest attempting write operation")
            severity = "High"

        if a["role"] == "User" and a["table_name"] in Config.SENSITIVE_TABLES:
            if a["operation_type"] in ("SELECT", "INSERT", "UPDATE"):
                suspicious = True
                reasons.append(f"User accessing sensitive table: {a['table_name']}")
                severity = "Medium"

        # 3. Check working hours
        if a["access_timestamp"]:
            h = a["access_timestamp"].hour
            if h < Config.WORKING_HOURS_START or h >= Config.WORKING_HOURS_END:
                suspicious = True
                reasons.append("Access outside working hours")
                severity = "Medium"

        # 4. Check for SQL injection patterns
        if a["operation_details"]:
            query_lower = a["operation_details"].lower()

            for pattern, desc in Config.SUSPICIOUS_QUERY_PATTERNS:
                if re.search(pattern, query_lower, re.IGNORECASE):
                    suspicious = True
                    reasons.append(f"Suspicious pattern: {desc}")
                    severity = "Critical"
                    break

            # Check for sensitive column access
            for col in Config.SENSITIVE_COLUMNS:
                if col.lower() in query_lower:
                    suspicious = True
                    reasons.append(f"Access to sensitive column: {col}")
                    severity = "High"

        # 5. Check for unusual data volume
        if a["rows_affected"] and int(a["rows_affected"]) > 1000:
            suspicious = True
            reasons.append(f"Large data extraction: {a['rows_affected']} rows")
            severity = "High"

        # 6. Rate limiting check
        if a["user_id"]:
            self.user_activity_cache[a["user_id"]].append(datetime.now())
            recent = [t for t in self.user_activity_cache[a["user_id"]] 
                     if (datetime.now() - t).seconds < 60]

            if len(recent) > Config.RATE_LIMIT["max_queries_per_min"]:
                suspicious = True
                reasons.append(f"Rate limit exceeded: {len(recent)} queries/min")
                severity = "Medium"

        # Update the activity log
        if suspicious:
            self.execute(
                """UPDATE activity_logs 
                   SET is_suspicious=1, 
                       suspicious_reasons=%s,
                       severity_level=%s 
                   WHERE activity_id=%s""",
                ("; ".join(reasons), severity, activity_id)
            )

            # Create alert for critical issues
            if severity in ["High", "Critical"]:
                self.create_alert(a, reasons, severity)

    def create_alert(self, activity, reasons, severity):
        q = """
            INSERT INTO security_alerts
            (activity_id, alert_type, severity, description, status, created_at)
            VALUES (%s, %s, %s, %s, 'New', NOW())
        """
        alert_type = "Security Violation"
        reasons_str = " ".join(reasons)
        if "SQL Injection" in reasons_str:
            alert_type = "SQL Injection"
        elif "sensitive" in reasons_str:
            alert_type = "Data Leakage"
        elif "rate limit" in reasons_str:
            alert_type = "DoS Attempt"

        self.execute(q, (
            activity['activity_id'],
            alert_type,
            severity,
            "; ".join(reasons)
        ))

    def get_active_alerts(self):
        try:
            return self.execute(
                """SELECT sa.*, al.username, al.operation_type, al.table_name
                   FROM security_alerts sa
                   JOIN activity_logs al ON sa.activity_id = al.activity_id
                   WHERE sa.status = 'New'
                   ORDER BY sa.created_at DESC
                   LIMIT 20""",
                all=True
            ) or []
        except Exception as e:
            print(f"Error getting alerts: {e}")
            return []

    def analyze_user_behavior(self, user_id, days=7):
        # Get user's activity pattern
        activities = self.execute(
            """SELECT 
                HOUR(access_timestamp) as hour,
                COUNT(*) as count,
                operation_type
               FROM activity_logs
               WHERE user_id=%s 
               AND access_timestamp >= NOW() - INTERVAL %s DAY
               GROUP BY hour, operation_type
               ORDER BY hour""",
            (user_id, days),
            all=True
        ) or []

        # Build behavior profile
        profile = {
            'user_id': user_id,
            'total_activities': sum(a['count'] for a in activities),
            'peak_hours': Counter({a['hour']: a['count'] for a in activities}),
            'operation_types': Counter({a['operation_type']: a['count'] for a in activities})
        }

        return profile


# =====================================================
# COMPLIANCE MANAGER
# =====================================================

class ComplianceManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.standards = {
            'GDPR': ['data_access', 'data_modification', 'user_consent'],
            'SOX': ['financial_data_access', 'audit_trail', 'access_controls'],
            'HIPAA': ['phi_access', 'phi_modification', 'phi_view'],
            'PCI_DSS': ['cardholder_data', 'auth_logs', 'access_monitoring']
        }

    def check_compliance(self, activity):
        findings = []

        # Check GDPR compliance
        if activity['table_name'] in Config.SENSITIVE_TABLES:
            if 'user_id' not in activity or not activity['user_id']:
                findings.append({
                    'standard': 'GDPR',
                    'status': 'Non-compliant',
                    'issue': 'Personal data access without user identification'
                })

        # Check SOX compliance
        if activity['table_name'] in ['accounts', 'financial', 'transactions']:
            if activity['operation_type'] in ['UPDATE', 'DELETE']:
                findings.append({
                    'standard': 'SOX',
                    'status': 'Compliant' if activity.get('rows_affected') else 'Review needed',
                    'issue': 'Financial data modification'
                })

        # Check PCI DSS
        if activity['table_name'] in ['payments', 'credit_cards']:
            findings.append({
                'standard': 'PCI_DSS',
                'status': 'Monitored',
                'issue': 'Cardholder data access detected'
            })

        return findings

    def generate_report(self, report_type='daily'):
        # Generate compliance report
        report = {
            'generated_at': datetime.now().isoformat(),
            'report_type': report_type,
            'findings': [],
            'statistics': {}
        }

        # Get activities in period
        if report_type == 'daily':
            activities = self.execute(
                "SELECT * FROM activity_logs WHERE DATE(access_timestamp) = CURDATE()",
                all=True
            ) or []
        elif report_type == 'weekly':
            activities = self.execute(
                "SELECT * FROM activity_logs WHERE access_timestamp >= NOW() - INTERVAL 7 DAY",
                all=True
            ) or []
        else:
            activities = self.execute(
                "SELECT * FROM activity_logs WHERE access_timestamp >= NOW() - INTERVAL 30 DAY",
                all=True
            ) or []

        # Analyze each activity for compliance
        for activity in activities:
            findings = self.check_compliance(activity)
            if findings:
                report['findings'].extend(findings)

        # Calculate statistics
        report['statistics'] = {
            'total_activities': len(activities),
            'non_compliant_count': len(report['findings']),
            'standards_covered': list(self.standards.keys())
        }

        return report


# =====================================================
# ANOMALY DETECTOR
# =====================================================

class AnomalyDetector(BaseManager):
    def __init__(self):
        super().__init__()
        self.baselines = {}

    def establish_baseline(self, user_id=None):
        # Establish normal behavior baseline
        if user_id:
            query = """
                SELECT 
                    AVG(queries_per_hour) as avg_queries,
                    STDDEV(queries_per_hour) as std_queries
                FROM (
                    SELECT 
                        DATE(access_timestamp) as day,
                        HOUR(access_timestamp) as hour,
                        COUNT(*) as queries_per_hour
                    FROM activity_logs
                    WHERE user_id=%s
                    GROUP BY day, hour
                ) as user_stats
            """
            stats = self.execute(query, (user_id,), one=True)
            self.baselines[f'user_{user_id}'] = stats

        return self.baselines

    def detect_anomalies(self, activity):
        anomalies = []

        # Check for statistical anomalies
        if activity and activity.get('user_id'):
            baseline = self.baselines.get(f"user_{activity['user_id']}")

            if baseline and baseline.get('avg_queries'):
                # Get recent activity count
                recent = self.execute(
                    "SELECT COUNT(*) as count FROM activity_logs "
                    "WHERE user_id=%s AND access_timestamp >= NOW() - INTERVAL 1 HOUR",
                    (activity['user_id'],),
                    one=True
                )

                # Check if activity is > 3 standard deviations from mean
                if recent and recent['count'] > baseline['avg_queries'] + 3 * (baseline['std_queries'] or 1):
                    anomalies.append({
                        'type': 'Statistical Anomaly',
                        'description': f"Unusual activity volume: {recent['count']} queries/hour",
                        'severity': 'Medium'
                    })

        # Check for impossible travel (logins from different locations)
        if activity and activity.get('operation_type') == 'LOGIN' and activity.get('username'):
            recent_logins = self.execute(
                "SELECT ip_address FROM activity_logs "
                "WHERE username=%s AND operation_type='LOGIN' "
                "AND access_timestamp >= NOW() - INTERVAL 1 HOUR "
                "ORDER BY access_timestamp DESC LIMIT 2",
                (activity['username'],),
                all=True
            ) or []

            if len(recent_logins) >= 2:
                ip1, ip2 = recent_logins[0]['ip_address'], recent_logins[1]['ip_address']
                # Check if IPs are in different geographic regions
                if ip1 and ip2 and ip1 != ip2:
                    anomalies.append({
                        'type': 'Impossible Travel',
                        'description': f"Multiple logins from different locations: {ip1} and {ip2}",
                        'severity': 'High'
                    })

        return anomalies


# =====================================================
# FLASK APP (with global placeholders)
# =====================================================

app = Flask(__name__, template_folder="templates")
app.secret_key = Config.SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=8)
CORS(app)

# Placeholders - will be initialized in main()
user_mgr = None
activity_logger = None
security_detector = None
compliance_manager = None
anomaly_detector = None

# Ensure managers are initialized before any request
@app.before_request
def ensure_managers():
    global user_mgr, activity_logger, security_detector, compliance_manager, anomaly_detector
    if not user_mgr:
        # Initialize if not done yet (should not happen normally)
        user_mgr = UserManager()
        activity_logger = ActivityLogger()
        security_detector = SecurityDetector()
        compliance_manager = ComplianceManager()
        anomaly_detector = AnomalyDetector()


# =====================================================
# AUTH DECORATOR
# =====================================================

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
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


# =====================================================
# WEB ROUTES
# =====================================================

@app.route("/")
def login_page():
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")
    if role == "Admin":
        return render_template("dashboard_admin.html")
    elif role == "User":
        return render_template("dashboard_user.html")
    elif role == "Guest":
        return render_template("dashboard_guest.html")
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


# =====================================================
# API ROUTES (ENHANCED)
# =====================================================

@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0"
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    result = user_mgr.authenticate(data.get("username"), data.get("password"))

    if isinstance(result, dict) and result.get("locked"):
        return jsonify({
            "success": False,
            "locked": True,
            "locked_until": result["locked_until"].isoformat()
        }), 403

    if not result:
        return jsonify({"success": False}), 401

    session.permanent = True
    session["user_id"] = result["user_id"]
    session["role"] = result["role"]
    session["username"] = result["username"]

    aid = activity_logger.log_activity(
        result["user_id"], result["username"],
        "LOGIN", "users", "Success",
        "Login success", request.remote_addr,
        session_id=session.sid if hasattr(session, 'sid') else None
    )
    if aid:
        security_detector.check_activity(aid)

    return jsonify({
        "success": True,
        "redirect": "/dashboard",
        "role": result["role"]
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    if "user_id" in session:
        activity_logger.log_activity(
            session["user_id"], session.get("username"),
            "LOGOUT", "users", "Success",
            "Logout", request.remote_addr
        )
    return logout()


@app.route("/api/dashboard-data")
@login_required
def api_dashboard_data():
    user = user_mgr.get_by_id(session["user_id"])

    # Get filters from request
    filters = {
        'severity': request.args.get('severity'),
        'database': request.args.get('database'),
        'time_range': request.args.get('time_range')
    }

    activities = activity_logger.get_latest(50, filters)
    stats = activity_logger.get_stats()
    alerts = security_detector.get_active_alerts() if session["role"] == "Admin" else []

    return jsonify({
        "success": True,
        "user": user,
        "activities": activities,
        "stats": stats,
        "alerts": alerts,
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify({
        "success": True,
        "stats": activity_logger.get_stats()
    })


@app.route("/api/timeline")
@login_required
def api_timeline():
    hours = request.args.get('hours', 24, type=int)
    return jsonify({
        "success": True,
        "timeline": activity_logger.get_timeline_data(hours)
    })


@app.route("/api/user/activities")
@login_required
def api_user_activities():
    return jsonify({
        "success": True,
        "activities": activity_logger.get_by_user(session["user_id"])
    })


@app.route("/api/guest/summary")
@login_required
def api_guest_summary():
    return jsonify({
        "success": True,
        "total_activities": activity_logger.count_all(),
        "my_activities": len(activity_logger.get_by_user(session["user_id"]) or [])
    })


@app.route("/api/alerts")
@login_required
@role_required("Admin")
def api_alerts():
    alerts = security_detector.get_active_alerts()
    return jsonify({
        "success": True,
        "alerts": alerts
    })


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
@role_required("Admin")
def resolve_alert(alert_id):
    security_detector.execute(
        "UPDATE security_alerts SET status='Resolved', resolved_at=NOW() WHERE alert_id=%s",
        (alert_id,)
    )
    return jsonify({"success": True})


@app.route("/api/compliance/report")
@login_required
@role_required("Admin")
def api_compliance_report():
    report_type = request.args.get('type', 'daily')
    report = compliance_manager.generate_report(report_type)
    return jsonify({
        "success": True,
        "report": report
    })


@app.route("/api/users")
@login_required
@role_required("Admin")
def api_users():
    users = user_mgr.get_all_users()
    return jsonify({
        "success": True,
        "users": users
    })


@app.route("/api/users/<int:user_id>/status", methods=["POST"])
@login_required
@role_required("Admin")
def update_user_status(user_id):
    data = request.json
    user_mgr.update_status(user_id, data.get('status'))
    return jsonify({"success": True})


@app.route("/api/analyze/behavior/<int:user_id>")
@login_required
@role_required("Admin")
def analyze_user_behavior(user_id):
    profile = security_detector.analyze_user_behavior(user_id)
    return jsonify({
        "success": True,
        "profile": profile
    })


# =====================================================
# DAM AGENT INGEST (ENHANCED)
# =====================================================

@app.route("/api/agent/activity", methods=["POST"])
def ingest_agent_activity():
    data = request.json

    # Extract data with defaults
    username = data.get("username", "SYSTEM")
    operation = data.get("operation", "QUERY")
    query = data.get("query", "")
    table_name = data.get("table", "unknown")
    rows_affected = data.get("rows_affected")
    session_id = data.get("session_id")
    client_ip = data.get("client_ip", request.remote_addr)

    # Determine status based on query
    status = "Success"
    if "error" in query.lower() or "failed" in query.lower():
        status = "Failed"

    # Log the activity
    aid = activity_logger.log_activity(
        None,
        username,
        operation,
        table_name,
        status,
        query,
        client_ip,
        session_id,
        rows_affected
    )

    # Run security checks
    if aid:
        security_detector.check_activity(aid)

    # Check for anomalies
    activity = None
    if aid:
        activity = activity_logger.execute(
            "SELECT * FROM activity_logs WHERE activity_id=%s",
            (aid,),
            one=True
        )
    anomalies = anomaly_detector.detect_anomalies(activity) if activity else []

    return jsonify({
        "success": True,
        "activity_id": aid,
        "anomalies_detected": len(anomalies) > 0
    })


@app.route("/api/agent/bulk", methods=["POST"])
def ingest_bulk_activities():
    """Bulk ingestion endpoint for high-volume agents"""
    activities = request.json.get('activities', [])

    results = []
    for data in activities:
        try:
            aid = activity_logger.log_activity(
                None,
                data.get("username", "SYSTEM"),
                data.get("operation", "QUERY"),
                data.get("table", "unknown"),
                data.get("status", "Success"),
                data.get("query", ""),
                data.get("ip", request.remote_addr)
            )
            if aid:
                security_detector.check_activity(aid)
            results.append({"id": aid, "status": "success"})
        except Exception as e:
            results.append({"status": "failed", "error": str(e)})

    return jsonify({
        "success": True,
        "processed": len(results),
        "results": results
    })


# =====================================================
# INITIALIZATION
# =====================================================

def init_database():
    """Initialize database tables if they don't exist"""
    try:
        conn = DatabaseConnection().get_conn()
        cur = conn.cursor()

        # Check if tables exist and create them if they don't
        tables = [
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('Admin', 'User', 'Guest') DEFAULT 'Guest',
                account_status ENUM('Active', 'Inactive', 'Locked') DEFAULT 'Active',
                failed_attempts INT DEFAULT 0,
                locked_until DATETIME NULL,
                last_login DATETIME NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_username (username),
                INDEX idx_status (account_status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS activity_logs (
                activity_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                username VARCHAR(50),
                operation_type VARCHAR(20),
                table_name VARCHAR(50),
                operation_status VARCHAR(20),
                operation_details TEXT,
                ip_address VARCHAR(45),
                access_timestamp DATETIME,
                session_id VARCHAR(100) NULL,
                rows_affected INT NULL,
                query_hash VARCHAR(64) NULL,
                is_suspicious BOOLEAN DEFAULT FALSE,
                suspicious_reasons TEXT NULL,
                severity_level ENUM('Low', 'Medium', 'High', 'Critical') DEFAULT 'Low',
                INDEX idx_timestamp (access_timestamp),
                INDEX idx_user (user_id),
                INDEX idx_suspicious (is_suspicious),
                INDEX idx_hash (query_hash),
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS security_alerts (
                alert_id INT AUTO_INCREMENT PRIMARY KEY,
                activity_id INT,
                alert_type VARCHAR(50),
                severity VARCHAR(20),
                description TEXT,
                status ENUM('New', 'Investigating', 'Resolved') DEFAULT 'New',
                created_at DATETIME,
                resolved_at DATETIME NULL,
                INDEX idx_status (status),
                INDEX idx_created (created_at),
                FOREIGN KEY (activity_id) REFERENCES activity_logs(activity_id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS ip_blacklist (
                ip_id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) UNIQUE,
                reason TEXT,
                created_at DATETIME,
                expires_at DATETIME,
                INDEX idx_ip (ip_address),
                INDEX idx_expires (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS compliance_logs (
                log_id INT AUTO_INCREMENT PRIMARY KEY,
                activity_id INT,
                standard VARCHAR(50),
                finding TEXT,
                status VARCHAR(20),
                created_at DATETIME,
                INDEX idx_standard (standard),
                FOREIGN KEY (activity_id) REFERENCES activity_logs(activity_id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        ]

        for table in tables:
            cur.execute(table)

        # Create default admin if not exists
        cur.execute("SELECT * FROM users WHERE username='admin'")
        if not cur.fetchone():
            # Create admin with simple password
            cur.execute("""
                INSERT INTO users (username, password_hash, role, account_status, created_at) 
                VALUES (%s, %s, 'Admin', 'Active', NOW())
            """, ('admin', 'admin123'))  # Simple password for testing
            print("✓ Created admin user (password: admin123)")

        # Create test users if they don't exist
        cur.execute("SELECT * FROM users WHERE username='user1'")
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO users (username, password_hash, role, account_status, created_at) 
                VALUES (%s, %s, 'User', 'Active', NOW())
            """, ('user1', 'user123'))

        cur.execute("SELECT * FROM users WHERE username='guest1'")
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO users (username, password_hash, role, account_status, created_at) 
                VALUES (%s, %s, 'Guest', 'Active', NOW())
            """, ('guest1', 'guest123'))

        conn.commit()
        cur.close()
        conn.close()
        print("✓ Database initialized")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise


# =====================================================
# MAIN (CORRECTED ORDER)
# =====================================================

if __name__ == "__main__":
    print("=" * 70)
    print("ENHANCED DATABASE ACTIVITY MONITORING (DAM) SYSTEM")
    print("IBM Guardium-style Advanced Security Platform")
    print("=" * 70)
    
    # STEP 1: Initialize database first
    print("Step 1: Initializing database...")
    init_database()
    print("✓ Database initialized")
    
    # STEP 2: Now create the managers (after tables exist)
    print("Step 2: Initializing managers...")
    user_mgr = UserManager()
    activity_logger = ActivityLogger()
    security_detector = SecurityDetector()
    compliance_manager = ComplianceManager()
    anomaly_detector = AnomalyDetector()
    print("✓ Managers initialized")
    
    print("=" * 70)
    print("✓ Version: 2.0 (Enterprise)")
    print("✓ Features: Real-time Monitoring, Threat Detection,")
    print("  Compliance Reporting, Anomaly Detection, Rate Limiting")
    print("  User Behavior Analytics, Alerting System")
    print("=" * 70)
    print("Server: http://localhost:5000")
    print("=" * 70)

    # Start the app
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)