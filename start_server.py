#!/usr/bin/env python3
"""
Start script for Server1 - Port 5001
"""

import os
from app import app
from models import db

def setup_and_start_server():
    """Setup database and start the server application"""
    with app.app_context():
        # Create tables if they don't exist (shared database)
        db.create_all()
        print("Database tables ready!")
    
    print("Starting Server1 Interface...")
    print("📱 Server1 Access URL:")
    print("   https://upgraded-carnival-vwr6vx745jwhxp5w-5001.app.github.dev/")
    print("")
    print("For Server1:")
    print("1. Click the URL above")
    print("2. Register as 'server1'")  
    print("3. Start chatting with client1!")
    print("")
    print("Press Ctrl+C to stop Server1 server")
    print("=" * 60)
    
    # Start the Flask application on port 5001
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)

if __name__ == "__main__":
    setup_and_start_server()