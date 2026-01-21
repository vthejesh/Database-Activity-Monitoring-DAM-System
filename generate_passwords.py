"""
Password Hash Generator for DAM System
Generates secure bcrypt password hashes using Werkzeug

Usage:
    python generate_passwords.py
"""

from werkzeug.security import generate_password_hash, check_password_hash

def generate_hash(password):
    """Generate a secure password hash"""
    return generate_password_hash(password)

def verify_hash(password, hash_value):
    """Verify a password against its hash"""
    return check_password_hash(hash_value, password)

if __name__ == "__main__":
    print("=" * 60)
    print("DAM System - Password Hash Generator")
    print("=" * 60)
    print()
    
    # Generate hashes for default users
    passwords = {
        'admin': 'admin123',
        'john_doe': 'user123',
        'jane_smith': 'user456',
        'guest_user': 'guest123'
    }
    
    print("Default User Password Hashes:")
    print("-" * 60)
    
    for username, password in passwords.items():
        hash_value = generate_hash(password)
        
        # Verify the hash works
        is_valid = verify_hash(password, hash_value)
        
        print(f"\nUsername: {username}")
        print(f"Password: {password}")
        print(f"Hash: {hash_value}")
        print(f"Verified: {'✓' if is_valid else '✗'}")
    
    print("\n" + "=" * 60)
    print("\nSQL INSERT Statement (Copy this to seed_data.sql):")
    print("-" * 60)
    print()
    
    for username, password in passwords.items():
        hash_value = generate_hash(password)
        role = 'Admin' if username == 'admin' else 'Guest' if username == 'guest_user' else 'User'
        
        print(f"INSERT INTO users (username, password_hash, role, account_status) VALUES")
        print(f"('{username}', '{hash_value}', '{role}', 'Active');")
        print()
    
    print("=" * 60)
    print("\nCustom Password Hash Generator:")
    print("-" * 60)
    
    while True:
        choice = input("\nGenerate a custom hash? (y/n): ").lower()
        
        if choice != 'y':
            break
        
        custom_password = input("Enter password: ")
        custom_hash = generate_hash(custom_password)
        
        print(f"\nPassword: {custom_password}")
        print(f"Hash: {custom_hash}")
        
        # Verify
        verify = verify_hash(custom_password, custom_hash)
        print(f"Verification: {'✓ Success' if verify else '✗ Failed'}")
        
        # Test with wrong password
        wrong_verify = verify_hash("wrong_password", custom_hash)
        print(f"Wrong password test: {'✗ Correctly rejected' if not wrong_verify else '⚠ WARNING: Accepted wrong password!'}")
    
    print("\nDone! You can now use these hashes in your seed_data.sql file.")
    print("=" * 60)