"""
Simple script to create a test user directly in database
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine, text
from app.core.config import settings
from app.core.auth import get_password_hash

def create_test_user():
    """Create a test user directly in database"""
    try:
        # Connect to database
        engine = create_engine(settings.DATABASE_URL)
        
        # Hash the password
        password = "Test123!@#"
        hashed_password = get_password_hash(password)
        
        # Create user query
        query = text("""
        INSERT INTO users (email, username, hashed_password, first_name, last_name, full_name, role, is_active, is_verified) 
        VALUES (:email, :username, :hashed_password, :first_name, :last_name, :full_name, :role, :is_active, :is_verified)
        ON DUPLICATE KEY UPDATE 
        hashed_password = VALUES(hashed_password),
        first_name = VALUES(first_name),
        last_name = VALUES(last_name),
        full_name = VALUES(full_name)
        """)
        
        with engine.connect() as conn:
            conn.execute(query, {
                "email": "demo@secureshield.com",
                "username": "demo",
                "hashed_password": hashed_password,
                "first_name": "Demo",
                "last_name": "User",
                "full_name": "Demo User",
                "role": "viewer",
                "is_active": 1,
                "is_verified": 1
            })
            conn.commit()
        
        print("✅ Test user created successfully!")
        print(f"   Email: demo@secureshield.com")
        print(f"   Password: {password}")
        print(f"   Username: demo")
        
    except Exception as e:
        print(f"❌ Error creating user: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    create_test_user()