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
        print(" Database tables ready!")
    
    print("🚀 Starting Simple Encrypted Chat...")
    print("📱 Access your app at:")
    print("   https://upgraded-carnival-vwr6vx745jwhxp5w-5000.app.github.dev/")
    print("")
    print("TESTING OPTIONS:")
    print("")
    print("Option 1 - Dual Interface (Same Browser):")
    print("  • Go to /dual for split-screen testing")
    print("  • Test both users in one window")
    print("")
    print("Option 2 - Dual Ports (Separate Browsers):")
    print("  • Stop this server (Ctrl+C)")
    print("  • Run: python start_both.py")
    print("  • Follow instructions for two-port setup")
    print("")
    print("Option 3 - Incognito Mode:")
    print("  • Register 'client1' in normal browser")
    print("  • Register 'server1' in incognito browser")
    print("  • Start chatting!")
    print("")
    print(" Press Ctrl+C to stop the server")
    print("=" * 50)
    
    # Start the Flask application
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == "__main__":
    setup_and_start()