#!/usr/bin/env python3
"""
Start script for Client1 - Port 5000
"""

import os
from app import app
from models import db

def setup_and_start_client():
    """Setup database and start the client application"""
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        print(" Database tables ready!")
    
    print("🔵 Starting Client1 Interface...")
    print("📱 Client1 Access URL:")
    print("   https://upgraded-carnival-vwr6vx745jwhxp5w-5000.app.github.dev/")
    print("")
    print("For Client1:")
    print("1. Click the URL above")
    print("2. Register as 'client1'")
    print("3. Start chatting with server1!")
    print("")
    print("Press Ctrl+C to stop Client1 server")
    print("=" * 60)
    
    # Start the Flask application on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

if __name__ == "__main__":
    setup_and_start_client()