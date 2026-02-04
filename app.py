"""
Database Activity Monitoring (DAM) System
Complete OOP Implementation with Security Rules
"""

import mysql.connector
from mysql.connector import Error, pooling
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import pytz
import threading
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from functools import wraps

# =====================================================
# CONFIGURATION CLASS
# =====================================================

class Config:
    """Configuration class for DAM system"""
    DB_HOST = 'localhost'
    DB_USER = 'root'
    DB_PASSWORD = '1234'
    DB_NAME = 'dam_system'
    SECRET_KEY = 'dam-system-secret-key-2024'
    
    # Security parameters
    WORKING_HOURS_START = 9  # 9 AM
    WORKING_HOURS_END = 18   # 6 PM
    MAX_FAILED_ATTEMPTS = 5
    FAILED_WINDOW_MINUTES = 5

# =====================================================
# DATABASE CONNECTION MANAGER (Singleton)
# =====================================================

class DatabaseConnection:
    """Singleton database connection manager"""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize database connection pool"""
        try:
            self.pool = pooling.MySQLConnectionPool(
                pool_name="dam_pool",
                pool_size=5,
                pool_reset_session=True,
                host=Config.DB_HOST,
                database=Config.DB_NAME,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
                autocommit=True
            )
            print("✓ Database connection pool initialized")
        except Error as e:
            print(f"✗ Database connection error: {e}")
            self.pool = None
    
    def get_connection(self):
        """Get a connection from the pool"""
        if self.pool:
            try:
                return self.pool.get_connection()
            except Error as e:
                print(f"✗ Error getting connection: {e}")
                return None
        return None

# =====================================================
# BASE MANAGER CLASS
# =====================================================

class BaseManager:
    """Base class for all managers with common database operations"""
    
    def __init__(self):
        self.db = DatabaseConnection()
    
    def _execute_query(self, query, params=None, fetch_one=False, fetch_all=False):
        """Execute SQL query with proper error handling"""
        connection = None
        cursor = None
        try:
            connection = self.db.get_connection()
            if not connection:
                raise Exception("Database connection failed")
            
            cursor = connection.cursor(dictionary=True)
            cursor.execute(query, params or ())
            
            if fetch_one:
                return cursor.fetchone()
            elif fetch_all:
                return cursor.fetchall()
            else:
                connection.commit()
                return cursor.lastrowid
                
        except Error as e:
            if connection:
                connection.rollback()
            print(f"Database error: {e}")
            raise e
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

# =====================================================
# USER MANAGER CLASS
# =====================================================

class UserManager(BaseManager):
    """Manages user operations and authentication"""
    
    def authenticate(self, username, password):
        """Authenticate user with password hashing"""
        try:
            query = """
                SELECT user_id, username, password_hash, role, account_status 
                FROM users 
                WHERE username = %s
            """
            user = self._execute_query(query, (username,), fetch_one=True)
            
            if user and user['account_status'] == 'Active':
                if check_password_hash(user['password_hash'], password):
                    # Update last login
                    self._execute_query(
                        "UPDATE users SET last_login = NOW() WHERE user_id = %s",
                        (user['user_id'],)
                    )
                    return user
            return None
        except Exception as e:
            print(f"Authentication error: {e}")
            return None
    
    def get_user_by_id(self, user_id):
        """Get user by ID"""
        try:
            query = "SELECT user_id, username, role FROM users WHERE user_id = %s"
            return self._execute_query(query, (user_id,), fetch_one=True)
        except Exception as e:
            print(f"Get user error: {e}")
            return None
    
    def create_user(self, username, password, role='User'):
        """Create new user with hashed password"""
        try:
            password_hash = generate_password_hash(password)
            query = """
                INSERT INTO users (username, password_hash, role) 
                VALUES (%s, %s, %s)
            """
            return self._execute_query(query, (username, password_hash, role))
        except Exception as e:
            print(f"Create user error: {e}")
            return None

# =====================================================
# ACTIVITY LOGGER CLASS
# =====================================================

class ActivityLogger(BaseManager):
    """Logs and manages database activities"""
    
    def log_activity(self, user_id, operation_type, table_name, 
                    operation_status, details='', ip_address=None, username=None):
        """Log database activity with India timestamp"""
        try:
            india_tz = pytz.timezone('Asia/Kolkata')
            india_time = datetime.now(india_tz)
            
            # If username not provided, fetch it
            if not username and user_id:
                user_manager = UserManager()
                user = user_manager.get_user_by_id(user_id)
                username = user['username'] if user else 'Unknown'
            
            query = """
                INSERT INTO activity_logs 
                (user_id, username, operation_type, table_name, operation_status, 
                 operation_details, ip_address, access_timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            return self._execute_query(
                query, 
                (user_id, username, operation_type, table_name, 
                 operation_status, details, ip_address, india_time)
            )
        except Exception as e:
            print(f"Log activity error: {e}")
            return None
    
    def get_all_activities(self, limit=50):
        """Get all activities"""
        try:
            query = """
                SELECT al.*, u.role as user_role 
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.user_id
                ORDER BY al.access_timestamp DESC
                LIMIT %s
            """
            return self._execute_query(query, (limit,), fetch_all=True)
        except Exception as e:
            print(f"Get activities error: {e}")
            return []
    
    def get_suspicious_activities(self):
        """Get suspicious activities"""
        try:
            query = """
                SELECT al.*, u.role as user_role 
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.user_id
                WHERE al.is_suspicious = TRUE
                ORDER BY al.access_timestamp DESC
            """
            return self._execute_query(query, fetch_all=True)
        except Exception as e:
            print(f"Get suspicious activities error: {e}")
            return []
    
    def get_failed_attempts_count(self, username, minutes=5):
        """Count failed attempts in last N minutes"""
        try:
            query = """
                SELECT COUNT(*) as count 
                FROM activity_logs 
                WHERE username = %s 
                  AND operation_status = 'Failed'
                  AND operation_type = 'LOGIN'
                  AND access_timestamp >= DATE_SUB(NOW(), INTERVAL %s MINUTE)
            """
            result = self._execute_query(query, (username, minutes), fetch_one=True)
            return result['count'] if result else 0
        except Exception as e:
            print(f"Get failed attempts error: {e}")
            return 0

# =====================================================
# SECURITY DETECTOR CLASS (Implements Security Rules)
# =====================================================

class SecurityDetector(BaseManager):
    """Detects suspicious activities based on security rules"""
    
    def __init__(self):
        super().__init__()
        self.activity_logger = ActivityLogger()
        self.user_manager = UserManager()
    
    def check_activity(self, activity_id):
        """
        Check if an activity is suspicious based on security rules
        
        Rules implemented:
        1. Guest users performing write operations (INSERT/UPDATE/DELETE)
        2. More than 5 failed operations in 5 minutes
        3. Access outside working hours (9 AM - 6 PM)
        """
        try:
            # Get activity details
            query = """
                SELECT al.*, u.role 
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.user_id
                WHERE al.activity_id = %s
            """
            activity = self._execute_query(query, (activity_id,), fetch_one=True)
            
            if not activity:
                return False, []
            
            suspicious = False
            reasons = []
            
            # RULE 1: Guest user performing write operations
            if activity['role'] == 'Guest' and activity['operation_type'] in ['INSERT', 'UPDATE', 'DELETE']:
                suspicious = True
                reasons.append(f"Guest user attempted {activity['operation_type']} operation")
            
            # RULE 2: Failed login attempts (brute force detection)
            if activity['operation_type'] == 'LOGIN' and activity['operation_status'] == 'Failed':
                username = activity['username']
                failed_count = self.activity_logger.get_failed_attempts_count(
                    username, Config.FAILED_WINDOW_MINUTES
                )
                if failed_count > Config.MAX_FAILED_ATTEMPTS:
                    suspicious = True
                    reasons.append(f"{failed_count} failed login attempts in {Config.FAILED_WINDOW_MINUTES} minutes")
            
            # RULE 3: Access outside working hours
            if activity['access_timestamp']:
                hour = activity['access_timestamp'].hour
                if hour < Config.WORKING_HOURS_START or hour >= Config.WORKING_HOURS_END:
                    suspicious = True
                    reasons.append(f"Access outside working hours ({hour}:00)")
            
            # Update activity if suspicious
            if suspicious:
                self._mark_as_suspicious(activity_id, reasons)
                self._create_alert(activity_id, reasons)
            
            return suspicious, reasons
            
        except Exception as e:
            print(f"Check activity error: {e}")
            return False, []
    
    def _mark_as_suspicious(self, activity_id, reasons):
        """Mark activity as suspicious in database"""
        try:
            reason_text = "; ".join(reasons)
            query = """
                UPDATE activity_logs 
                SET is_suspicious = TRUE, suspicious_reasons = %s
                WHERE activity_id = %s
            """
            self._execute_query(query, (reason_text, activity_id))
        except Exception as e:
            print(f"Mark suspicious error: {e}")
    
    def _create_alert(self, activity_id, reasons):
        """Create security alert"""
        try:
            # Determine severity
            severity = 'Medium'
            if 'Guest user attempted' in reasons[0]:
                severity = 'Critical'
            elif 'failed login attempts' in reasons[0]:
                severity = 'High'
            
            reason_text = "; ".join(reasons)
            query = """
                INSERT INTO security_alerts (activity_id, alert_type, severity, alert_message)
                VALUES (%s, 'Suspicious Activity', %s, %s)
            """
            self._execute_query(query, (activity_id, severity, reason_text))
        except Exception as e:
            print(f"Create alert error: {e}")
    
    def get_security_summary(self):
        """Get security summary report"""
        try:
            # Get suspicious activities count
            query_suspicious = "SELECT COUNT(*) as count FROM activity_logs WHERE is_suspicious = TRUE"
            suspicious = self._execute_query(query_suspicious, fetch_one=True)
            
            # Get failed operations count
            query_failed = "SELECT COUNT(*) as count FROM activity_logs WHERE operation_status = 'Failed'"
            failed = self._execute_query(query_failed, fetch_one=True)
            
            # Get total activities
            query_total = "SELECT COUNT(*) as count FROM activity_logs"
            total = self._execute_query(query_total, fetch_one=True)
            
            # Get alerts by severity
            query_alerts = """
                SELECT severity, COUNT(*) as count 
                FROM security_alerts 
                WHERE is_resolved = FALSE
                GROUP BY severity
            """
            alerts = self._execute_query(query_alerts, fetch_all=True)
            
            return {
                'total_activities': total['count'] if total else 0,
                'suspicious_activities': suspicious['count'] if suspicious else 0,
                'failed_operations': failed['count'] if failed else 0,
                'alerts_by_severity': alerts
            }
        except Exception as e:
            print(f"Get security summary error: {e}")
            return {}

# =====================================================
# PRODUCT MANAGER CLASS (Sample Data Operations)
# =====================================================

class ProductManager(BaseManager):
    """Manages product CRUD operations with activity logging"""
    
    def __init__(self):
        super().__init__()
        self.activity_logger = ActivityLogger()
        self.security_detector = SecurityDetector()
    
    def get_all_products(self):
        """Get all products with activity logging"""
        try:
            query = "SELECT * FROM products ORDER BY product_id"
            products = self._execute_query(query, fetch_all=True)
            return products
        except Exception as e:
            print(f"Get products error: {e}")
            return []
    
    def add_product(self, name, category, price, stock, user_id, ip_address):
        """Add new product with security checks"""
        try:
            # Log the activity before operation
            activity_id = self.activity_logger.log_activity(
                user_id, 'INSERT', 'products', 'Success',
                f"Adding product: {name}", ip_address
            )
            
            # Perform the operation
            query = """
                INSERT INTO products (product_name, category, price, stock_quantity)
                VALUES (%s, %s, %s, %s)
            """
            product_id = self._execute_query(query, (name, category, price, stock))
            
            # Check if suspicious
            if activity_id:
                self.security_detector.check_activity(activity_id)
            
            return product_id
            
        except Exception as e:
            # Log failed operation
            self.activity_logger.log_activity(
                user_id, 'INSERT', 'products', 'Failed',
                f"Failed to add product: {str(e)}", ip_address
            )
            print(f"Add product error: {e}")
            return None
    
    def delete_product(self, product_id, user_id, ip_address):
        """Delete product with security checks"""
        try:
            # Get product name before deletion
            query_select = "SELECT product_name FROM products WHERE product_id = %s"
            product = self._execute_query(query_select, (product_id,), fetch_one=True)
            
            if not product:
                return False
            
            # Log the activity
            activity_id = self.activity_logger.log_activity(
                user_id, 'DELETE', 'products', 'Success',
                f"Deleting product: {product['product_name']}", ip_address
            )
            
            # Perform deletion
            query_delete = "DELETE FROM products WHERE product_id = %s"
            result = self._execute_query(query_delete, (product_id,))
            
            # Check if suspicious
            if activity_id:
                self.security_detector.check_activity(activity_id)
            
            return result > 0
            
        except Exception as e:
            # Log failed operation
            self.activity_logger.log_activity(
                user_id, 'DELETE', 'products', 'Failed',
                f"Failed to delete product: {str(e)}", ip_address
            )
            print(f"Delete product error: {e}")
            return False

# =====================================================
# FLASK WEB APPLICATION
# =====================================================

app = Flask(__name__, template_folder='templates')
app.secret_key = Config.SECRET_KEY
CORS(app)

# Initialize managers
user_manager = UserManager()
activity_logger = ActivityLogger()
security_detector = SecurityDetector()
product_manager = ProductManager()

# =====================================================
# DECORATORS
# =====================================================

def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# =====================================================
# WEB ROUTES
# =====================================================

@app.route('/')
def login_page():
    """Serve login page"""
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Serve dashboard page"""
    user_id = session.get('user_id')
    user = user_manager.get_user_by_id(user_id)
    
    if not user:
        return redirect(url_for('login_page'))
    
    # Get data based on user role
    products = product_manager.get_all_products()
    activities = []
    suspicious = []
    summary = {}
    
    if user['role'] == 'Admin':
        activities = activity_logger.get_all_activities()
        suspicious = activity_logger.get_suspicious_activities()
        summary = security_detector.get_security_summary()
    
    return render_template(
        'dashboard.html',
        username=user['username'],
        role=user['role'],
        products=products,
        activities=activities,
        suspicious=suspicious,
        summary=summary
    )

@app.route('/login', methods=['POST'])
def login():
    """Handle login form submission"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    user = user_manager.authenticate(username, password)
    
    if user:
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        session['role'] = user['role']
        
        # Log successful login
        activity_logger.log_activity(
            user['user_id'], 'LOGIN', 'users', 'Success',
            'User logged in successfully', request.remote_addr
        )
        
        return redirect(url_for('dashboard'))
    else:
        # Log failed login
        activity_logger.log_activity(
            None, 'LOGIN', 'users', 'Failed',
            'Invalid credentials', request.remote_addr, username
        )
        
        # Check for suspicious activity
        recent_activities = activity_logger.get_all_activities(limit=10)
        if recent_activities:
            security_detector.check_activity(recent_activities[0]['activity_id'])
        
        flash('Invalid username or password', 'error')
        return redirect(url_for('login_page'))

@app.route('/logout')
def logout():
    """Handle logout"""
    user_id = session.get('user_id')
    username = session.get('username')
    
    if user_id:
        activity_logger.log_activity(
            user_id, 'LOGOUT', 'users', 'Success',
            'User logged out', request.remote_addr
        )
    
    session.clear()
    return redirect(url_for('login_page'))

# =====================================================
# API ROUTES
# =====================================================

@app.route('/api/login', methods=['POST'])
def api_login():
    """API login endpoint"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    is_guest = data.get('is_guest', False)
    
    if is_guest:
        username = 'guest_user'
        password = 'password123'
    
    user = user_manager.authenticate(username, password)
    
    if user:
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        session['role'] = user['role']
        
        # Log activity
        activity_id = activity_logger.log_activity(
            user['user_id'], 'LOGIN', 'users', 'Success',
            'API login successful', request.remote_addr
        )
        
        if activity_id:
            security_detector.check_activity(activity_id)
        
        return jsonify({
            'success': True,
            'user': {
                'user_id': user['user_id'],
                'username': user['username'],
                'role': user['role']
            }
        })
    else:
        # Log failed attempt
        activity_id = activity_logger.log_activity(
            None, 'LOGIN', 'users', 'Failed',
            'API login failed', request.remote_addr, username
        )
        
        if activity_id:
            security_detector.check_activity(activity_id)
        
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/dashboard', methods=['GET'])
@login_required
def api_dashboard():
    """API endpoint for dashboard data"""
    user_id = session.get('user_id')
    user = user_manager.get_user_by_id(user_id)
    
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    data = {
        'success': True,
        'user': {
            'user_id': user['user_id'],
            'username': user['username'],
            'role': user['role']
        },
        'products': product_manager.get_all_products()
    }
    
    if user['role'] == 'Admin':
        data['activities'] = activity_logger.get_all_activities()
        data['suspicious'] = activity_logger.get_suspicious_activities()
        data['summary'] = security_detector.get_security_summary()
    
    return jsonify(data)

@app.route('/api/products', methods=['GET'])
@login_required
def get_products_api():
    """Get all products API"""
    try:
        products = product_manager.get_all_products()
        return jsonify({'success': True, 'products': products})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/products', methods=['POST'])
@login_required
def create_product_api():
    """Create new product API"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        data = request.json
        
        # RBAC check
        if user_role == 'Guest':
            return jsonify({
                'success': False, 
                'error': 'Access denied. Guest users cannot add products.'
            }), 403
        
        # Validate input
        required_fields = ['name', 'category', 'price', 'stock']
        for field in required_fields:
            if field not in data or not str(data[field]).strip():
                return jsonify({
                    'success': False, 
                    'error': f'{field.capitalize()} is required'
                }), 400
        
        # Add product
        product_id = product_manager.add_product(
            data['name'],
            data['category'],
            float(data['price']),
            int(data['stock']),
            user_id,
            request.remote_addr
        )
        
        if product_id:
            return jsonify({
                'success': True,
                'product_id': product_id,
                'message': 'Product added successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to add product'
            }), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product_api(product_id):
    """Delete product API"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # RBAC check
        if user_role == 'Guest':
            return jsonify({
                'success': False, 
                'error': 'Access denied. Guest users cannot delete products.'
            }), 403
        
        success = product_manager.delete_product(
            product_id, user_id, request.remote_addr
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Product deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Product not found or could not be deleted'
            }), 404
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/activities', methods=['GET'])
@login_required
def get_activities_api():
    """Get activities API (Admin only)"""
    try:
        user_id = session.get('user_id')
        user = user_manager.get_user_by_id(user_id)
        
        if user['role'] != 'Admin':
            return jsonify({
                'success': False, 
                'error': 'Admin access required'
            }), 403
        
        activities = activity_logger.get_all_activities()
        return jsonify({'success': True, 'activities': activities})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts/summary', methods=['GET'])
@login_required
def get_alerts_summary_api():
    """Get security alerts summary API (Admin only)"""
    try:
        user_id = session.get('user_id')
        user = user_manager.get_user_by_id(user_id)
        
        if user['role'] != 'Admin':
            return jsonify({
                'success': False, 
                'error': 'Admin access required'
            }), 403
        
        summary = security_detector.get_security_summary()
        return jsonify({'success': True, 'summary': summary})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# =====================================================
# REPORTING ENDPOINTS
# =====================================================

@app.route('/reports/activities')
@login_required
def activities_report():
    """Generate activities report"""
    try:
        user_id = session.get('user_id')
        user = user_manager.get_user_by_id(user_id)
        
        if user['role'] != 'Admin':
            return "Access denied", 403
        
        activities = activity_logger.get_all_activities(limit=100)
        
        report = "DATABASE ACTIVITY MONITORING REPORT\n"
        report += "=" * 50 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"User: {user['username']}\n"
        report += "=" * 50 + "\n\n"
        
        for activity in activities:
            report += f"ID: {activity['activity_id']}\n"
            report += f"User: {activity['username']} ({activity.get('user_role', 'N/A')})\n"
            report += f"Operation: {activity['operation_type']} on {activity['table_name']}\n"
            report += f"Status: {activity['operation_status']}\n"
            report += f"Time: {activity['access_timestamp']}\n"
            report += f"Suspicious: {'Yes' if activity['is_suspicious'] else 'No'}\n"
            if activity['is_suspicious']:
                report += f"Reason: {activity['suspicious_reasons']}\n"
            report += "-" * 30 + "\n"
        
        return report, 200, {'Content-Type': 'text/plain'}
        
    except Exception as e:
        return str(e), 500

@app.route('/reports/suspicious')
@login_required
def suspicious_report():
    """Generate suspicious activities report"""
    try:
        user_id = session.get('user_id')
        user = user_manager.get_user_by_id(user_id)
        
        if user['role'] != 'Admin':
            return "Access denied", 403
        
        activities = activity_logger.get_suspicious_activities()
        
        report = "SUSPICIOUS ACTIVITIES REPORT\n"
        report += "=" * 50 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Total Suspicious Activities: {len(activities)}\n"
        report += "=" * 50 + "\n\n"
        
        for activity in activities:
            report += f"ID: {activity['activity_id']}\n"
            report += f"User: {activity['username']} ({activity.get('user_role', 'N/A')})\n"
            report += f"Operation: {activity['operation_type']} on {activity['table_name']}\n"
            report += f"Time: {activity['access_timestamp']}\n"
            report += f"Details: {activity['operation_details']}\n"
            report += f"Reasons: {activity['suspicious_reasons']}\n"
            report += "-" * 40 + "\n"
        
        return report, 200, {'Content-Type': 'text/plain'}
        
    except Exception as e:
        return str(e), 500

# =====================================================
# MAIN APPLICATION
# =====================================================

if __name__ == '__main__':
    print("=" * 60)
    print("DATABASE ACTIVITY MONITORING (DAM) SYSTEM")
    print("=" * 60)
    print("Security Features Implemented:")
    print("1. Role-Based Access Control (RBAC)")
    print("2. Brute Force Detection (>5 failed attempts in 5 mins)")
    print("3. Anomalous Timing Detection (9 AM - 6 PM)")
    print("4. Guest User Restriction (Read-Only)")
    print("5. SQL Injection Prevention (Parameterized Queries)")
    print("6. Password Hashing (bcrypt)")
    print("=" * 60)
    print(f"Database: {Config.DB_NAME}")
    print(f"User: {Config.DB_USER}")
    print(f"Server: http://localhost:5000")
    print("=" * 60)
    
    # Initialize database connection
    db = DatabaseConnection()
    
    app.run(debug=True, host='0.0.0.0', port=5000)