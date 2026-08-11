import os

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
