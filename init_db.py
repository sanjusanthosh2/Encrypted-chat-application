#!/usr/bin/env python3
"""
Database initialization script for the encrypted chat application
"""

from app import create_app
from models import db, User, Message, ChatRoom, UserSession
from auth import AuthManager
import os

def init_database():
    """Initialize the database with tables"""
    app = create_app('development')
    
    with app.app_context():
        # Create instance directory if it doesn't exist
        instance_dir = os.path.join(app.root_path, 'instance')
        if not os.path.exists(instance_dir):
            os.makedirs(instance_dir)
            print(f"Created instance directory: {instance_dir}")
        
        # Drop all tables (be careful with this in production!)
        print("Dropping existing tables...")
        db.drop_all()
        
        # Create all tables
        print("Creating database tables...")
        db.create_all()
        
        # Verify tables were created
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"Created tables: {tables}")
        
        print("Database initialized successfully!")
        
        # Optionally create a test user
        create_test_user = input("Create a test user? (y/n): ").strip().lower()
        if create_test_user == 'y':
            create_test_users()

def create_test_users():
    """Create test users for development"""
    app = create_app('development')
    
    with app.app_context():
        try:
            # Test user 1
            user1, private_key1 = AuthManager.create_user(
                username="alice",
                email="alice@example.com",
                password="password123"
            )
            
            if user1:
                print(f"Created test user: {user1.username}")
                print(f"Alice's private key saved to alice_private_key.pem")
                
                # Save private key to file for testing
                with open('alice_private_key.pem', 'w') as f:
                    f.write(private_key1)
            
            # Test user 2
            user2, private_key2 = AuthManager.create_user(
                username="bob",
                email="bob@example.com",
                password="password123"
            )
            
            if user2:
                print(f"Created test user: {user2.username}")
                print(f"Bob's private key saved to bob_private_key.pem")
                
                # Save private key to file for testing
                with open('bob_private_key.pem', 'w') as f:
                    f.write(private_key2)
            
            print("\nTest users created successfully!")
            print("You can now login with:")
            print("Username: alice, Password: password123")
            print("Username: bob, Password: password123")
            
        except Exception as e:
            print(f"Error creating test users: {str(e)}")

def reset_database():
    """Reset the database completely"""
    app = create_app('development')
    
    with app.app_context():
        print("Resetting database...")
        db.drop_all()
        db.create_all()
        print("Database reset successfully!")

def check_database():
    """Check database status"""
    app = create_app('development')
    
    with app.app_context():
        try:
            # Check if tables exist
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"Existing tables: {tables}")
            
            # Count records in each table
            if 'users' in tables:
                user_count = User.query.count()
                print(f"Users: {user_count}")
                
                # List all users
                users = User.query.all()
                for user in users:
                    print(f"  - {user.username} ({user.email}) - Created: {user.created_at}")
            
            if 'messages' in tables:
                message_count = Message.query.count()
                print(f"Messages: {message_count}")
            
            if 'user_sessions' in tables:
                session_count = UserSession.query.count()
                print(f"Active sessions: {session_count}")
                
        except Exception as e:
            print(f"Error checking database: {str(e)}")

def clean_sessions():
    """Clean expired sessions"""
    app = create_app('development')
    
    with app.app_context():
        try:
            from datetime import datetime
            
            # Remove expired sessions
            expired_sessions = UserSession.query.filter(
                UserSession.expires_at < datetime.utcnow()
            ).all()
            
            for session in expired_sessions:
                db.session.delete(session)
            
            db.session.commit()
            print(f"Cleaned {len(expired_sessions)} expired sessions")
            
        except Exception as e:
            print(f"Error cleaning sessions: {str(e)}")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'init':
            init_database()
        elif command == 'reset':
            reset_database()
        elif command == 'check':
            check_database()
        elif command == 'test-users':
            create_test_users()
        elif command == 'clean-sessions':
            clean_sessions()
        else:
            print("Usage: python init_db.py [init|reset|check|test-users|clean-sessions]")
    else:
        print("Available commands:")
        print("  init         - Initialize database tables")
        print("  reset        - Reset database (drop and recreate all tables)")
        print("  check        - Check database status")
        print("  test-users   - Create test users")
        print("  clean-sessions - Clean expired sessions")
        print("\nUsage: python init_db.py <command>")