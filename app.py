"""
Database Activity Monitoring (DAM) System
Python Backend with Object-Oriented Programming
Flask Web Application + MySQL

SECURITY FEATURES:
- SQL Injection Prevention (Parameterized Queries)
- Proper Password Hashing (bcrypt via Werkzeug)
- Role-Based Access Control (RBAC)
- Brute Force Detection
- Anomalous Timing Detection
"""

from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
import pytz
from functools import wraps

# =====================================================
# CONFIGURATION
# =====================================================

class Config:
    DB_HOST = 'localhost'
    DB_USER = 'root'
    DB_PASSWORD = '1234'
    DB_NAME = 'dam_system'


    # Flask Configuration
    SECRET_KEY = 'your-secret-key-change-this'

    # Security Settings
    WORKING_HOUR_START = 9
    WORKING_HOUR_END = 18
    MAX_FAILED_ATTEMPTS = 5
    FAILED_ATTEMPTS_WINDOW = 5  # minutes

    # Severity Levels
    SEVERITY_CRITICAL = 'Critical'
    SEVERITY_HIGH = 'High'
    SEVERITY_MEDIUM = 'Medium'
    SEVERITY_LOW = 'Low'


# =====================================================
# DATABASE CONNECTION CLASS
# =====================================================

class DatabaseConnection:
    """Handles MySQL database connections with proper error handling"""
    
    def __init__(self, config):
        self.config = config
        self.connection = None
    
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = mysql.connector.connect(
                host=self.config.DB_HOST,
                user=self.config.DB_USER,
                password=self.config.DB_PASSWORD,
                database=self.config.DB_NAME,
                autocommit=False  # Explicit transaction control
            )
            if self.connection.is_connected():
                return True
        except Error as e:
            print(f"Database connection error: {e}")
            return False
    
    def disconnect(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
    
    def get_cursor(self):
        """Get database cursor"""
        if not self.connection or not self.connection.is_connected():
            self.connect()
        return self.connection.cursor(dictionary=True)
    
    def commit(self):
        """Commit transaction"""
        if self.connection:
            self.connection.commit()
    
    def rollback(self):
        """Rollback transaction"""
        if self.connection:
            self.connection.rollback()

# =====================================================
# USER MANAGEMENT CLASS
# =====================================================
def get_india_time():
    india = pytz.timezone("Asia/Kolkata")
    return datetime.now(india)

class UserManager:
    """Manages user operations and authentication with security best practices"""
    
    def __init__(self, db_connection):
        self.db = db_connection
    
    def authenticate(self, username, password):
        """
        Authenticate user credentials with proper password hashing
        SECURITY: Uses parameterized queries to prevent SQL injection
        """
        cursor = self.db.get_cursor()
        try:
            # SECURITY: Parameterized query prevents SQL injection
            query = """
                SELECT user_id, username, password_hash, role, account_status 
                FROM users 
                WHERE username = %s
            """
            cursor.execute(query, (username,))
            user = cursor.fetchone()
            
            if user and user['account_status'] == 'Active':
                # SECURITY: Use proper password hashing verification
                if check_password_hash(user['password_hash'], password):
                    # Update last login timestamp
                    update_query = "UPDATE users SET last_login = NOW() WHERE user_id = %s"
                    cursor.execute(update_query, (user['user_id'],))
                    self.db.commit()
                    return user
            return None
        except Error as e:
            print(f"Authentication error: {e}")
            return None
        finally:
            cursor.close()
    
    def get_user_by_id(self, user_id):
        """
        Get user details by ID
        SECURITY: Parameterized query
        """
        cursor = self.db.get_cursor()
        try:
            query = "SELECT user_id, username, role, account_status FROM users WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            return cursor.fetchone()
        finally:
            cursor.close()
    
    def get_user_by_username(self, username):
        """
        Get user details by username (for logging failed attempts)
        SECURITY: Parameterized query
        """
        cursor = self.db.get_cursor()
        try:
            query = "SELECT user_id, username, role FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            return cursor.fetchone()
        finally:
            cursor.close()
    
    def create_user(self, username, password, role='User'):
        """
        Create new user with proper password hashing
        SECURITY: Passwords are hashed before storage
        """
        cursor = self.db.get_cursor()
        try:
            # SECURITY: Hash password before storing
            password_hash = generate_password_hash(password)
            
            query = """
                INSERT INTO users (username, password_hash, role, account_status)
                VALUES (%s, %s, %s, 'Active')
            """
            cursor.execute(query, (username, password_hash, role))
            self.db.commit()
            return cursor.lastrowid
        except Error as e:
            self.db.rollback()
            raise e
        finally:
            cursor.close()
    
    def get_all_users(self):
        """Get all users - SECURITY: No sensitive data exposed"""
        cursor = self.db.get_cursor()
        try:
            query = """
                SELECT user_id, username, role, account_status, created_at, last_login 
                FROM users
            """
            cursor.execute(query)
            return cursor.fetchall()
        finally:
            cursor.close()

# =====================================================
# ACTIVITY LOGGING CLASS
# =====================================================

class ActivityLogger:
    """Logs and manages database activities with security focus"""
    
    def __init__(self, db_connection):
        self.db = db_connection
    
    def log_activity(self, user_id, operation_type, table_name, operation_status, operation_details='', ip_address=None):
        """Logs database activity with localized India Time"""
        cursor = self.db.get_cursor()
        try:
            # 1. Generate the correct India Time right now
            india_now = get_india_time() 

            # 2. The SQL query (Notice we added access_timestamp)
            query = """
                INSERT INTO activity_logs 
                (user_id, operation_type, table_name, operation_status, 
                 operation_details, ip_address, access_timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            
            # 3. Execute with the india_now variable at the end
            cursor.execute(query, (
                user_id, 
                operation_type, 
                table_name, 
                operation_status, 
                operation_details, 
                ip_address, 
                india_now
            ))
            
            self.db.commit()
            return cursor.lastrowid
        except Exception as e:
            if self.db.connection:
                self.db.connection.rollback()
            print(f"Logging Error: {e}")
            return None
        finally:
            cursor.close()
    
    def get_all_activities(self, limit=100):
        """
        Get all activities
        SECURITY: Parameterized query with limit to prevent resource exhaustion
        """
        cursor = self.db.get_cursor()
        try:
            query = """
                SELECT 
                    al.activity_id,
                    al.user_id,
                    u.username,
                    u.role,
                    al.operation_type,
                    al.table_name,
                    al.access_timestamp,
                    al.operation_status,
                    al.operation_details,
                    al.is_suspicious,
                    al.suspicious_reasons,
                    al.ip_address
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.user_id
                ORDER BY al.access_timestamp DESC
                LIMIT %s
            """
            cursor.execute(query, (limit,))
            return cursor.fetchall()
        finally:
            cursor.close()
    
    def get_suspicious_activities(self):
        """Get only suspicious activities"""
        cursor = self.db.get_cursor()
        try:
            query = """
                SELECT 
                    al.activity_id,
                    al.user_id,
                    u.username,
                    u.role,
                    al.operation_type,
                    al.table_name,
                    al.access_timestamp,
                    al.operation_status,
                    al.operation_details,
                    al.suspicious_reasons,
                    al.ip_address
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.user_id
                WHERE al.is_suspicious = TRUE
                ORDER BY al.access_timestamp DESC
            """
            cursor.execute(query)
            return cursor.fetchall()
        finally:
            cursor.close()
    
    def get_user_activities(self, user_id, limit=50):
        """Get activities for a specific user"""
        cursor = self.db.get_cursor()
        try:
            query = """
                SELECT * FROM activity_logs
                WHERE user_id = %s
                ORDER BY access_timestamp DESC
                LIMIT %s
            """
            cursor.execute(query, (user_id, limit))
            return cursor.fetchall()
        finally:
            cursor.close()
    
    def get_recent_failed_attempts_by_username(self, username, minutes=5):
        """
        Get recent failed login attempts by username (for brute-force detection)
        SECURITY: Tracks unauthorized access attempts even when user_id is unknown
        """
        cursor = self.db.get_cursor()
        try:
            query = """
                SELECT COUNT(*) as count
                FROM activity_logs
                WHERE operation_type = 'LOGIN'
                  AND operation_status = 'Failed'
                  AND operation_details LIKE %s
                  AND access_timestamp >= DATE_SUB(NOW(), INTERVAL %s MINUTE)
            """
            cursor.execute(query, (f'%Attempted username: {username}%', minutes))
            result = cursor.fetchone()
            return result['count'] if result else 0
        finally:
            cursor.close()

# =====================================================
# SUSPICIOUS ACTIVITY DETECTOR CLASS
# =====================================================

class SuspiciousActivityDetector:
    """
    Detects suspicious activities based on security rules
    
    SECURITY RULES IMPLEMENTED:
    1. Role-Based Access Control (RBAC): Guest users restricted to SELECT only
    2. Brute Force Detection: >5 failed attempts within 5-minute window
    3. Anomalous Timing: Access outside working hours (9 AM - 6 PM)
    """
    
    def __init__(self, db_connection, config, activity_logger):
        self.db = db_connection
        self.config = config
        self.logger = activity_logger
    
    def check_activity(self, activity_id):
        """
        Check if an activity is suspicious and assign severity level
        
        Returns:
            tuple: (is_suspicious, severity_level, reasons)
        """
        cursor = self.db.get_cursor()
        try:
            # Get activity details with parameterized query
            query = """
                SELECT al.*, u.role, u.username
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.user_id
                WHERE al.activity_id = %s
            """
            cursor.execute(query, (activity_id,))
            activity = cursor.fetchone()
            
            if not activity:
                return False, None, []
            
            is_suspicious = False
            reasons = []
            severity = self.config.SEVERITY_LOW
            
            # RULE 1: Role-Based Access Control (RBAC)
            # Guest users attempting write operations = CRITICAL
            if activity['role'] == 'Guest' and activity['operation_type'] in ['INSERT', 'UPDATE', 'DELETE']:
                is_suspicious = True
                severity = self.config.SEVERITY_CRITICAL
                reasons.append('RBAC Violation: Guest user attempting write operation (DML)')
            
            # RULE 2: Brute Force Detection
            # Multiple failed operations = HIGH severity
            if activity['operation_status'] == 'Failed':
                if activity['operation_type'] == 'LOGIN':
                    # Extract attempted username from details
                    username = self._extract_username_from_details(activity['operation_details'])
                    if username:
                        failed_count = self.logger.get_recent_failed_attempts_by_username(
                            username, 
                            self.config.FAILED_ATTEMPTS_WINDOW
                        )
                        if failed_count > self.config.MAX_FAILED_ATTEMPTS:
                            is_suspicious = True
                            severity = self.config.SEVERITY_HIGH
                            reasons.append(f'Brute Force Attack: {failed_count} failed login attempts for username "{username}"')
                else:
                    # Failed operations on data
                    failed_count = self._count_recent_failed_operations(activity['user_id'])
                    if failed_count > self.config.MAX_FAILED_ATTEMPTS:
                        is_suspicious = True
                        severity = self.config.SEVERITY_HIGH
                        reasons.append(f'Multiple Failed Operations: {failed_count} failed attempts detected')
            
            # RULE 3: Anomalous Timing Detection
            # Access outside working hours = MEDIUM severity
            hour = activity['access_timestamp'].hour
            if hour < self.config.WORKING_HOUR_START or hour >= self.config.WORKING_HOUR_END:
                is_suspicious = True
                # Only upgrade to MEDIUM if not already CRITICAL or HIGH
                if severity == self.config.SEVERITY_LOW:
                    severity = self.config.SEVERITY_MEDIUM
                reasons.append(f'Anomalous Timing: Access outside corporate hours (Hour: {hour}:00, Expected: 09:00-18:00)')
            
            # Update activity if suspicious
            if is_suspicious:
                self._mark_as_suspicious(activity_id, reasons)
                self._create_alert(activity_id, severity, reasons)
            
            return is_suspicious, severity, reasons
            
        finally:
            cursor.close()
    
    def _extract_username_from_details(self, details):
        """Extract username from operation details for failed login tracking"""
        if details and 'Attempted username:' in details:
            try:
                parts = details.split('Attempted username:')[1].split('.')[0].strip()
                return parts
            except:
                return None
        return None
    
    def _count_recent_failed_operations(self, user_id):
        """Count failed operations in the last N minutes (excluding login)"""
        cursor = self.db.get_cursor()
        try:
            query = """
                SELECT COUNT(*) as count
                FROM activity_logs
                WHERE user_id = %s 
                  AND operation_status = 'Failed'
                  AND operation_type != 'LOGIN'
                  AND access_timestamp >= DATE_SUB(NOW(), INTERVAL %s MINUTE)
            """
            cursor.execute(query, (user_id, self.config.FAILED_ATTEMPTS_WINDOW))
            result = cursor.fetchone()
            return result['count'] if result else 0
        finally:
            cursor.close()
    
    def _mark_as_suspicious(self, activity_id, reasons):
        """Mark activity as suspicious in the database"""
        cursor = self.db.get_cursor()
        try:
            reason_text = '; '.join(reasons)
            query = """
                UPDATE activity_logs
                SET is_suspicious = TRUE, suspicious_reasons = %s
                WHERE activity_id = %s
            """
            cursor.execute(query, (reason_text, activity_id))
            self.db.commit()
        except Error as e:
            self.db.rollback()
            print(f"Error marking activity as suspicious: {e}")
        finally:
            cursor.close()
    
    def _create_alert(self, activity_id, severity, reasons):
        """Create security alert with proper severity level"""
        cursor = self.db.get_cursor()
        try:
            reason_text = '; '.join(reasons)
            query = """
                INSERT INTO security_alerts 
                (activity_id, alert_type, severity, alert_message)
                VALUES (%s, 'Suspicious Activity', %s, %s)
            """
            cursor.execute(query, (activity_id, severity, reason_text))
            self.db.commit()
        except Error as e:
            self.db.rollback()
            print(f"Error creating alert: {e}")
        finally:
            cursor.close()
    
    def get_alert_summary(self):
        """Get summary of security alerts"""
        cursor = self.db.get_cursor()
        try:
            query = """
                SELECT 
                    COUNT(*) as total_alerts,
                    SUM(CASE WHEN is_resolved = FALSE THEN 1 ELSE 0 END) as unresolved_alerts,
                    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical_alerts,
                    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high_alerts,
                    SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium_alerts
                FROM security_alerts
            """
            cursor.execute(query)
            return cursor.fetchone()
        finally:
            cursor.close()

# =====================================================
# PRODUCT MANAGEMENT CLASS (Sample Data Operations)
# =====================================================

class ProductManager:
    """Manages product CRUD operations with parameterized queries"""
    
    def __init__(self, db_connection):
        self.db = db_connection
    
    def get_all_products(self):
        """Get all products - SECURITY: Parameterized query"""
        cursor = self.db.get_cursor()
        try:
            query = "SELECT * FROM products ORDER BY product_id"
            cursor.execute(query)
            return cursor.fetchall()
        finally:
            cursor.close()
    
    def add_product(self, name, category, price, stock):
        cursor = self.db.get_cursor()
        try:
            # Ensure your table column names match exactly: 
            # product_name, category, price, stock_quantity
            query = """
                INSERT INTO products (product_name, category, price, stock_quantity)
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query, (name, category, price, stock))
            self.db.commit()
            return True
        except Exception as e:
            print(f"Error adding product: {e}")
            self.db.rollback()
            return False
        finally:
            cursor.close()
    
    def get_product_by_id(self, product_id):
        """Get product by ID - SECURITY: Parameterized query"""
        cursor = self.db.get_cursor()
        try:
            query = "SELECT * FROM products WHERE product_id = %s"
            cursor.execute(query, (product_id,))
            return cursor.fetchone()
        finally:
            cursor.close()
    
    def create_product(self, name, category, price, stock):
        """Create new product - SECURITY: Parameterized query"""
        cursor = self.db.get_cursor()
        try:
            query = """
                INSERT INTO products (product_name, category, price, stock_quantity)
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query, (name, category, price, stock))
            self.db.commit()
            return cursor.lastrowid
        except Error as e:
            self.db.rollback()
            raise e
        finally:
            cursor.close()
    
    def update_product(self, product_id, name, category, price, stock):
        """Update product - SECURITY: Parameterized query"""
        cursor = self.db.get_cursor()
        try:
            query = """
                UPDATE products
                SET product_name = %s, category = %s, price = %s, stock_quantity = %s
                WHERE product_id = %s
            """
            cursor.execute(query, (name, category, price, stock, product_id))
            self.db.commit()
            return cursor.rowcount > 0
        except Error as e:
            self.db.rollback()
            raise e
        finally:
            cursor.close()
    
    def delete_product(self, product_id):
        """Delete product - SECURITY: Parameterized query"""
        cursor = self.db.get_cursor()
        try:
            query = "DELETE FROM products WHERE product_id = %s"
            cursor.execute(query, (product_id,))
            self.db.commit()
            return cursor.rowcount > 0
        except Error as e:
            self.db.rollback()
            raise e
        finally:
            cursor.close()

# =====================================================
# FLASK APPLICATION
# =====================================================

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
CORS(app)


# Initialize components
config = Config()
db_connection = DatabaseConnection(config)
user_manager = UserManager(db_connection)
activity_logger = ActivityLogger(db_connection)
detector = SuspiciousActivityDetector(db_connection, config, activity_logger)
product_manager = ProductManager(db_connection)

# =====================================================
# DECORATORS
# =====================================================

from flask import redirect, url_for

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        user = user_manager.get_user_by_id(session['user_id'])
        if user['role'] != 'Admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function
@app.route("/")
def login_page():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_form():
    username = request.form.get("username")
    password = request.form.get("password")

    user = user_manager.authenticate(username, password)

    if not user:
        return render_template("login.html", error="Invalid credentials")

    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    activity_id = activity_logger.log_activity(
        user["user_id"], "LOGIN", "users", "Success",
        f"User {username} logged in via web", request.remote_addr
    )
    detector.check_activity(activity_id)

    return redirect("/dashboard")


@app.route('/dashboard')
@login_required
def dashboard():
    users = user_manager.get_all_users()
    products = product_manager.get_all_products()
    activities = activity_logger.get_all_activities()
    suspicious = activity_logger.get_suspicious_activities()

    return render_template(
        'dashboard.html',
        username=session['username'],
        role=session['role'],
        users=users,
        products=products,
        activities=activities,
        suspicious=suspicious
    )



@app.route("/logout")
def logout_page():
    session.clear()
    return redirect("/")

# =====================================================
# AUTHENTICATION ROUTES
# =====================================================

@app.route('/api/login', methods=['POST'])
def login():
    """User login with proper security logging"""
    data = request.json
    username = data.get('username')
    password = data.get('password', 'guest123')
    is_guest = data.get('is_guest', False)
    
    if is_guest:
        username = 'guest_user'
        password = 'guest123'
    
    user = user_manager.authenticate(username, password)
    
    if user:
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        #the sec
        session['role'] = user['role']
        
        # Log successful login gt
        activity_id = activity_logger.log_activity(
            user['user_id'], 'LOGIN', 'users', 'Success',
            f"User {username} logged in successfully", request.remote_addr
        )
        detector.check_activity(activity_id)
        
        return jsonify({
            'success': True,
            'user': {
                'user_id': user['user_id'],
                'username': user['username'],
                'role': user['role']
            }
        })
    else:
        # SECURITY: Log failed login with attempted username for brute-force detection
        activity_id = activity_logger.log_activity(
            0, 'LOGIN', 'users', 'Failed',
            f"Invalid credentials", request.remote_addr, username
        )
        detector.check_activity(activity_id)
        
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """User logout"""
    user_id = session.get('user_id')
    username = session.get('username')
    
    # Log logout
    activity_id = activity_logger.log_activity(
        user_id, 'LOGOUT', 'users', 'Success',
        f"User {username} logged out", request.remote_addr
    )
    
    session.clear()
    return jsonify({'success': True})

# =====================================================
# PRODUCT ROUTES (CRUD Operations with RBAC)
# =====================================================

@app.route('/api/products', methods=['GET'])
@login_required
def get_products():
    """Get all products"""
    user_id = session['user_id']
    
    try:
        products = product_manager.get_all_products()
        
        # Log SELECT operation
        activity_id = activity_logger.log_activity(
            user_id, 'SELECT', 'products', 'Success',
            'Retrieved product list', request.remote_addr
        )
        detector.check_activity(activity_id)
        
        return jsonify({'success': True, 'products': products})
    except Exception as e:
        # Log failed operation
        activity_id = activity_logger.log_activity(
            user_id, 'SELECT', 'products', 'Failed',
            str(e), request.remote_addr
        )
        detector.check_activity(activity_id)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/products', methods=['POST'])
@login_required
def create_product():
    """Create new product - RBAC enforced"""
    user_id = session.get('user_id')
    user_role = session.get('role')
    data = request.json
    
    # 1. SECURITY: Check if user is Guest
    if user_role == 'Guest':
        activity_id = activity_logger.log_activity(
            user_id, 'INSERT', 'products', 'Failed',
            'RBAC Violation: Guest user attempted unauthorized INSERT', 
            request.remote_addr
        )
        detector.check_activity(activity_id)
        return jsonify({'success': False, 'error': 'Access Denied: Guests cannot insert data'}), 403
    
    try:
        # 2. Call the manager (Ensure these keys match your HTML: name, category, price, stock)
        product_id = product_manager.add_product(
            data['name'], 
            data['category'], 
            data['price'], 
            data['stock']
        )
        
        if product_id:
            # 3. Log success
            activity_id = activity_logger.log_activity(
                user_id, 'INSERT', 'products', 'Success',
                f"Created product: {data['name']}", request.remote_addr
            )
            detector.check_activity(activity_id)
            return jsonify({'success': True, 'product_id': product_id})
        else:
            raise Exception("Database failed to return product ID")

    except Exception as e:
        # 4. Log failed operation (e.g., database error)
        activity_id = activity_logger.log_activity(
            user_id, 'INSERT', 'products', 'Failed',
            f"Error: {str(e)}", request.remote_addr
        )
        detector.check_activity(activity_id)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@login_required
def update_product(product_id):
    """Update product - RBAC enforced"""
    user_id = session['user_id']
    user_role = session['role']
    data = request.json
    
    # SECURITY: Enforce RBAC
    if user_role == 'Guest':
        activity_id = activity_logger.log_activity(
            user_id, 'UPDATE', 'products', 'Failed',
            f'RBAC Violation: Guest user attempted unauthorized UPDATE on product {product_id}', 
            request.remote_addr
        )
        detector.check_activity(activity_id)
        return jsonify({'success': False, 'error': 'Access Denied: Guests cannot update data'}), 403
    
    try:
        success = product_manager.update_product(
            product_id, data['name'], data['category'],
            data['price'], data['stock']
        )
        
        if success:
            activity_id = activity_logger.log_activity(
                user_id, 'UPDATE', 'products', 'Success',
                f"Updated product: {data['name']} (ID: {product_id})", request.remote_addr
            )
            detector.check_activity(activity_id)
            return jsonify({'success': True})
        else:
            activity_id = activity_logger.log_activity(
                user_id, 'UPDATE', 'products', 'Failed',
                f"Product not found (ID: {product_id})", request.remote_addr
            )
            detector.check_activity(activity_id)
            return jsonify({'success': False, 'error': 'Product not found'}), 404
    except Exception as e:
        activity_id = activity_logger.log_activity(
            user_id, 'UPDATE', 'products', 'Failed',
            str(e), request.remote_addr
        )
        detector.check_activity(activity_id)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    """Delete product - RBAC enforced"""
    user_id = session['user_id']
    user_role = session['role']
    
    # SECURITY: Enforce RBAC
    if user_role == 'Guest':
        activity_id = activity_logger.log_activity(
            user_id, 'DELETE', 'products', 'Failed',
            f'RBAC Violation: Guest user attempted unauthorized DELETE on product {product_id}', 
            request.remote_addr
            # the  ujdbj
        )
        detector.check_activity(activity_id)
        return jsonify({'success': False, 'error': 'Access Denied: Guests cannot delete data'}), 403
    
    try:
        success = product_manager.delete_product(product_id)
        
        if success:
            activity_id = activity_logger.log_activity(
                user_id, 'DELETE', 'products', 'Success',
                f"Deleted product ID: {product_id}", request.remote_addr
            )
            #thi
            detector.check_activity(activity_id)
            return jsonify({'success': True})
        else:
            activity_id = activity_logger.log_activity(
                user_id, 'DELETE', 'products', 'Failed',
                f"Product not found (ID: {product_id})", request.remote_addr
            )
            detector.check_activity(activity_id)
            return jsonify({'success': False, 'error': 'Product not found'}), 404
    except Exception as e:
        activity_id = activity_logger.log_activity(
            user_id, 'DELETE', 'products', 'Failed',
            str(e), request.remote_addr
        )
        detector.check_activity(activity_id)
        return jsonify({'success': False, 'error': str(e)}), 500

# =====================================================
# MONITORING & REPORTING ROUTES
# =====================================================
@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard_data():
    user = user_manager.get_user_by_id(session['user_id'])

    # Indian time (you already added pytz + helper)
    now = get_india_time()
    within_hours = (
        Config.WORKING_HOUR_START <= now.hour < Config.WORKING_HOUR_END
    )

    data = {
        "user": {
            "user_id": user['user_id'],
            "username": user['username'],
            "role": user['role']
        },
        "current_time": now.strftime("%H:%M:%S"),
        "within_hours": within_hours
    }

    # Products → everyone can see
    data["products"] = product_manager.get_all_products()

    # Admin only data
    if user['role'] == 'Admin':
        data["activities"] = activity_logger.get_all_activities()
        data["suspicious"] = activity_logger.get_suspicious_activities()

    return jsonify(data)


@app.route('/api/activities', methods=['GET'])
@login_required
def get_activities():
    """Get all activities"""
    try:
        activities = activity_logger.get_all_activities()
        return jsonify({'success': True, 'activities': activities})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/activities/suspicious', methods=['GET'])
@login_required
def get_suspicious():
    """Get suspicious activities"""
    try:
        activities = activity_logger.get_suspicious_activities()
        return jsonify({'success': True, 'activities': activities})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts/summary', methods=['GET'])
@login_required
def get_alert_summary():
    """Get alert summary with severity breakdown"""
    try:
        summary = detector.get_alert_summary()
        all_activities = activity_logger.get_all_activities(limit=1000)
        total_activities = len(all_activities)
        failed_count = len([a for a in all_activities if a['operation_status'] == 'Failed'])
        
        return jsonify({
            'success': True,
            'summary': {
                'total_activities': total_activities,
                'total_alerts': summary['total_alerts'] or 0,
                'unresolved_alerts': summary['unresolved_alerts'] or 0,
                'critical_alerts': summary['critical_alerts'] or 0,
                'high_alerts': summary['high_alerts'] or 0,
                'medium_alerts': summary['medium_alerts'] or 0,
                'failed_operations': failed_count
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/products/latest', methods=['GET'])
@login_required
def get_latest_products():
    products = product_manager.get_all_products()
    return jsonify({'products': products})



# =====================================================
# MAIN
# =====================================================

if __name__ == '__main__':
    # Connect to database
    if db_connection.connect():
        print("=" * 50)
        print("Database Activity Monitoring (DAM) System")
        print("=" * 50)
        print("Database connected successfully!")
        print(f"Server running on http://localhost:5000")
        print("\nSECURITY FEATURES ENABLED:")
        print("✓ SQL Injection Prevention (Parameterized Queries)")
        print("✓ Password Hashing (bcrypt)")
        print("✓ Role-Based Access Control (RBAC)")
        print("✓ Brute Force Detection")
        print("✓ Anomalous Timing Detection")
        print("=" * 50)
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("ERROR: Failed to connect to database!")
        print("Please check your database configuration in the Config class.")