import threading
from mysql.connector import pooling
from app.config import Config

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
