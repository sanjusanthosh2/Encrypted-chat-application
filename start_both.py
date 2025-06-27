#!/usr/bin/env python3
"""
Instructions to start both Client1 and Server1 on different ports
"""

import os
import sys

def show_instructions():
    """Show instructions for running both applications"""
    
    print(" DUAL PORT CHAT SETUP")
    print("=" * 60)
    print("")
    print("To test with two users on different ports, you need to:")
    print("")
    print("OPTION 1: Manual Start (Recommended)")
    print("1️⃣  Open Terminal 1:")
    print("   cd /workspaces/dev/encrypted-chat")
    print("   python start_client.py")
    print("")
    print(" Open Terminal 2:")
    print("   cd /workspaces/dev/encrypted-chat") 
    print("   python start_server.py")
    print("")
    print("Access URLs:")
    print("   Client1: https://upgraded-carnival-vwr6vx745jwhxp5w-5000.app.github.dev/")
    print("   Server1: https://upgraded-carnival-vwr6vx745jwhxp5w-5001.app.github.dev/")
    print("")
    print("OPTION 2: GitHub Codespaces Ports Panel")
    print("1. Run: python start_client.py")
    print("2. In VS Code, open 'PORTS' tab (next to TERMINAL)")
    print("3. You'll see port 5000 running")
    print("4. Click 'Add Port' and add port 5001")
    print("5. Run: python start_server.py in new terminal")
    print("6. Both ports will be accessible via the Ports panel")
    print("")
    print("TESTING:")
    print("• Register 'client1' on port 5000")
    print("• Register 'server1' on port 5001") 
    print("• Search for each other and start chatting!")
    print("")
    print("=" * 60)

def start_single_port():
    """Start on a specific port"""
    if len(sys.argv) > 1:
        port = sys.argv[1]
        if port == "5000" or port == "client":
            os.system("python start_client.py")
        elif port == "5001" or port == "server":
            os.system("python start_server.py")
        else:
            print(f"❌ Unknown port: {port}")
            print("Use: python start_both.py [5000|client|5001|server]")
    else:
        show_instructions()

if __name__ == "__main__":
    start_single_port()