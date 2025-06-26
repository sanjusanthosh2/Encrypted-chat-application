#!/usr/bin/env python3
"""
Simple start script for the chat application
"""

import os
from app import app
from models import db

def setup_and_start():
    """Setup database and start the application"""
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        print("✅ Database tables ready!")
    
    print("🚀 Starting Simple Encrypted Chat...")
    print("📱 Access your app at:")
    print("   https://upgraded-carnival-vwr6vx745jwhxp5w-5000.app.github.dev/")
    print("")
    print("👥 To test:")
    print("1. Register as 'client1' in normal browser")
    print("2. Register as 'server1' in incognito browser")
    print("3. Start chatting!")
    print("")
    print("🛑 Press Ctrl+C to stop the server")
    print("=" * 50)
    
    # Start the Flask application
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == "__main__":
    setup_and_start()