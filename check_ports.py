#!/usr/bin/env python3
"""
Check which ports are running and show access URLs
"""

import socket
import requests
from datetime import datetime

def check_port(port):
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0
    except:
        return False

def check_app_health(port):
    """Check if the Flask app is responding on a port"""
    try:
        response = requests.get(f'http://127.0.0.1:{port}/', timeout=2)
        return response.status_code == 200
    except:
        return False

def show_port_status():
    """Show the status of both ports"""
    print(" CHECKING PORT STATUS")
    print("=" * 50)
    print(f"Checked at: {datetime.now().strftime('%H:%M:%S')}")
    print("")
    
    # Check Port 5000 (Client1)
    port_5000_open = check_port(5000)
    port_5000_healthy = check_app_health(5000) if port_5000_open else False
    
    print(" PORT 5000 (Client1):")
    if port_5000_healthy:
        print("    RUNNING & HEALTHY")
        print("    https://upgraded-carnival-vwr6vx745jwhxp5w-5000.app.github.dev/")
    elif port_5000_open:
        print("     OPEN BUT NOT RESPONDING")
    else:
        print("    NOT RUNNING")
        print("   Start with: python start_client.py")
    print("")
    
    # Check Port 5001 (Server1)
    port_5001_open = check_port(5001)
    port_5001_healthy = check_app_health(5001) if port_5001_open else False
    
    print(" PORT 5001 (Server1):")
    if port_5001_healthy:
        print("    RUNNING & HEALTHY")
        print("    https://upgraded-carnival-vwr6vx745jwhxp5w-5001.app.github.dev/")
    elif port_5001_open:
        print("    OPEN BUT NOT RESPONDING") 
    else:
        print("   NOT RUNNING")
        print("    Start with: python start_server.py")
    print("")
    
    # Summary
    if port_5000_healthy and port_5001_healthy:
        print(" BOTH PORTS READY FOR TESTING!")
        print(" Register 'client1' on port 5000")
        print(" Register 'server1' on port 5001")
        print(" Start chatting between them!")
    elif port_5000_healthy or port_5001_healthy:
        print("  Only one port is running")
        print("   Start the other port to begin testing")
    else:
        print(" No ports are running")
        print("   Run: python start_both.py for instructions")
    
    print("=" * 50)

if __name__ == "__main__":
    show_port_status()