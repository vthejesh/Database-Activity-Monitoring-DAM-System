"""
Database Activity Monitoring (DAM) System
REAL Guardium-style backend (STABLE VERSION)
"""

import threading
import pytz
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, jsonify,
    render_template, session,
    redirect, url_for
)
from flask_cors import CORS
from werkzeug.security import check_password_hash
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
            pool_size=5,
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
        conn = self.db.get_conn()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(query, params or ())
            if one:
                return cur.fetchone()
            if all:
                return cur.fetchall()
            return cur.lastrowid
        finally:
            cur.close()
            conn.close()


# =====================================================
# USER MANAGER
# =====================================================

class UserManager(BaseManager):
    def authenticate(self, username, password):
        q = """
            SELECT user_id, username, password_hash, role, account_status
            FROM users WHERE username=%s
        """
        user = self.execute(q, (username,), one=True)
        if user and user["account_status"] == "Active":
            if check_password_hash(user["password_hash"], password):
                self.execute(
                    "UPDATE users SET last_login=NOW() WHERE user_id=%s",
                    (user["user_id"],)
                )
                return user
        return None

    def get_by_id(self, user_id):
        return self.execute(
            "SELECT user_id, username, role FROM users WHERE user_id=%s",
            (user_id,), one=True
        )


# =====================================================
# ACTIVITY LOGGER
# =====================================================

class ActivityLogger(BaseManager):

    def log_activity(
        self, user_id, username,
        operation_type, table_name,
        status, details, ip
    ):
        ts = datetime.now(pytz.timezone("Asia/Kolkata"))
        q = """
            INSERT INTO activity_logs
            (user_id, username, operation_type, table_name,
             operation_status, operation_details, ip_address, access_timestamp)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """
        return self.execute(q, (
            user_id, username,
            operation_type, table_name,
            status, details, ip, ts
        ))

    def get_latest(self, limit=50):
        q = """
            SELECT *
            FROM activity_logs
            ORDER BY access_timestamp DESC
            LIMIT %s
        """
        return self.execute(q, (limit,), all=True)

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
        return self.execute(
            "SELECT COUNT(*) AS count FROM activity_logs",
            one=True
        )["count"]


# =====================================================
# SECURITY DETECTOR
# =====================================================

class SecurityDetector(BaseManager):
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

        if a["role"] == "Guest" and a["operation_type"] in ("INSERT","UPDATE","DELETE"):
            suspicious = True
            reasons.append("Guest write attempt")

        if a["access_timestamp"]:
            h = a["access_timestamp"].hour
            if h < Config.WORKING_HOURS_START or h >= Config.WORKING_HOURS_END:
                suspicious = True
                reasons.append("Outside working hours")

        if suspicious:
            self.execute(
                "UPDATE activity_logs SET is_suspicious=1, suspicious_reasons=%s WHERE activity_id=%s",
                ("; ".join(reasons), activity_id)
            )


# =====================================================
# FLASK APP
# =====================================================

app = Flask(__name__, template_folder="templates")
app.secret_key = Config.SECRET_KEY
CORS(app)

user_mgr = UserManager()
activity_logger = ActivityLogger()
security_detector = SecurityDetector()


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


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# =====================================================
# API ROUTES
# =====================================================

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok"})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    user = user_mgr.authenticate(data.get("username"), data.get("password"))

    if not user:
        return jsonify({"success": False}), 401

    session["user_id"] = user["user_id"]
    session["role"] = user["role"]

    aid = activity_logger.log_activity(
        user["user_id"], user["username"],
        "LOGIN", "users", "Success",
        "Login success", request.remote_addr
    )
    security_detector.check_activity(aid)

    return jsonify({"success": True, "redirect": "/dashboard"})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    return logout()


@app.route("/api/dashboard-data")
@login_required
def api_dashboard_data():
    user = user_mgr.get_by_id(session["user_id"])
    activities = activity_logger.get_latest(50)

    return jsonify({
        "success": True,
        "user": user,
        "activities": activities
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
        "total_activities": activity_logger.count_all()
    })


# =====================================================
# DAM AGENT INGEST (REAL DB MONITOR)
# =====================================================

@app.route("/api/agent/activity", methods=["POST"])
def ingest_agent_activity():
    data = request.json

    aid = activity_logger.log_activity(
        None,
        data.get("username"),
        data.get("operation"),
        "DATABASE",
        "Success",
        data.get("query"),
        request.remote_addr
    )
    security_detector.check_activity(aid)

    return jsonify({"success": True})


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":
    print("=" * 60)
    print("DATABASE ACTIVITY MONITORING (DAM) SYSTEM")
    print("Server: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
