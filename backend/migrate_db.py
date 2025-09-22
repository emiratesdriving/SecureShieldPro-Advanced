"""
Database migration script to update user table schema
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from app.core.config import settings

def run_migration():
    """Run database migration"""
    engine = create_engine(settings.DATABASE_URL)
    
    # SQL commands to add missing columns
    migration_commands = [
        # Add OAuth columns if they don't exist
        """
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS google_id VARCHAR(255) NULL UNIQUE,
        ADD COLUMN IF NOT EXISTS github_id VARCHAR(255) NULL UNIQUE,
        ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500) NULL
        """,
        
        # Add role column if it doesn't exist
        """
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS role ENUM('admin', 'analyst', 'viewer') NOT NULL DEFAULT 'viewer'
        """,
        
        # Add first_name and last_name columns
        """
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS first_name VARCHAR(255) NULL,
        ADD COLUMN IF NOT EXISTS last_name VARCHAR(255) NULL
        """,
        
        # Add timestamps if they don't exist
        """
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        ADD COLUMN IF NOT EXISTS last_login TIMESTAMP NULL
        """,
        
        # Add other user fields
        """
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS two_factor_secret VARCHAR(32) NULL
        """,
        
        # Update existing users to split full_name into first_name and last_name
        """
        UPDATE users 
        SET 
            first_name = SUBSTRING_INDEX(full_name, ' ', 1),
            last_name = CASE 
                WHEN LOCATE(' ', full_name) > 0 
                THEN SUBSTRING(full_name, LOCATE(' ', full_name) + 1)
                ELSE ''
            END
        WHERE first_name IS NULL OR last_name IS NULL
        """
    ]
    
    with engine.connect() as conn:
        for cmd in migration_commands:
            try:
                print(f"Executing: {cmd.strip()[:50]}...")
                conn.execute(text(cmd))
                conn.commit()
                print("✓ Success")
            except Exception as e:
                print(f"✗ Error: {e}")
                if "already exists" not in str(e).lower():
                    print(f"  Command: {cmd}")
    
    print("\nMigration completed!")

if __name__ == "__main__":
    run_migration()