📁 Encrypted Chat Application - Project Structure
🏗️ Complete Directory Structure
encrypted-chat/
├── 📁 static/                          # Static assets
│   ├── 📁 css/
│   │   └── 📄 style.css                # Custom styles with background image support
│   ├── 📁 images/
│   │   └── 🖼️ image.jpg                # Background image for all screens
│   └── 📁 js/
│       └── 📄 app.js                   # Frontend JavaScript (session-based auth)
│
├── 📁 templates/                       # HTML templates
│   ├── 📄 base.html                    # Base template with navigation
│   ├── 📄 index.html                   # Landing page
│   ├── 📄 login.html                   # User login page
│   ├── 📄 register.html                # User registration page
│   ├── 📄 chat.html                    # Main chat interface
│   ├── 📄 profile.html                 # User profile page
│   └── 📄 dual.html                    # Dual-user testing interface
│
├── 📁 instance/                        # Database storage
│   └── 📄 database.db                  # SQLite database (auto-created)
│
├── 🐍 Core Application Files
├── 📄 app.py                           # Main Flask application (session-based)
├── 📄 models.py                        # Database models (User, Message, etc.)
├── 📄 auth.py                          # Authentication routes and logic
├── 📄 config.py                        # Application configuration
├── 📄 crypto_utils.py                  # Encryption utilities (XOR + Base64)
│
├── 🚀 Startup Scripts
├── 📄 start.py                         # Single port startup (port 5000)
├── 📄 start_client.py                  # Client1 startup (port 5000)
├── 📄 start_server.py                  # Server1 startup (port 5001)
├── 📄 start_both.py                    # Instructions for dual-port setup
│
├── 🛠️ Utility Scripts
├── 📄 check_ports.py                   # Check port status and URLs
├── 📄 background_helper.py             # Background image setup helper
├── 📄 reset.py                         # Database reset utility
├── 📄 init_db.py                       # Database initialization (legacy)
│
├── 📋 Configuration Files
├── 📄 requirements.txt                 # Python dependencies
├── 📄 README.md                        # Project documentation
├── 📄 DUAL_PORT_SETUP.md              # Dual port testing guide
│
└── 🔧 Development Files
    ├── 📄 .gitignore                   # Git ignore file (if using Git)
    └── 📄 dev.code-workspace           # VS Code workspace (if created)
🎯 Key Features Implemented
🔐 Security & Encryption

Session-based authentication (no JWT complexity)
XOR + Base64 encryption for messages
Secure password hashing with bcrypt
SQL injection protection with SQLAlchemy ORM
CSRF protection with session tokens

💬 Chat Functionality

User registration and login
Real-time messaging between users
User search and discovery
Conversation management
Message encryption/decryption
Auto-refresh conversations

🎨 User Interface

Responsive design with Bootstrap 5
Custom background image on all screens
Modern glass effect with backdrop blur
Mobile-friendly interface
Real-time status updates
Intuitive navigation

🧪 Testing Features

Dual-port setup for multi-user testing
Split-screen interface for single-browser testing
Port status monitoring
Database reset utilities
Background image helpers

📊 Database Schema
👤 Users Table
sql- id (Primary Key)
- username (Unique)
- email (Unique) 
- password_hash
- public_key (encryption key)
- created_at
- last_seen
- is_active
💬 Messages Table
sql- id (Primary Key)
- sender_id (Foreign Key → Users)
- recipient_id (Foreign Key → Users)
- encrypted_content
- encrypted_key
- nonce
- timestamp
- is_read
- message_type
🚀 How to Run
Single Port (Basic)
bashpython start.py
# Access: https://your-codespace-5000.app.github.dev/
Dual Port (Recommended for Testing)
bash# Terminal 1
python start_client.py

# Terminal 2  
python start_server.py

# URLs:
# Client1: https://your-codespace-5000.app.github.dev/
# Server1: https://your-codespace-5001.app.github.dev/
Check Status
bashpython check_ports.py           # Check running ports
python background_helper.py     # Manage background image
python reset.py                 # Reset database



🔵 Option 2: Dual Port Setup ⭐ RECOMMENDED
Perfect for: Realistic testing, GitHub Codespaces, multiple browsers
Step 1: Open Two Terminals
In VS Code:

Terminal 1: Already open
Terminal 2: Click + in terminal panel to open new terminal

Step 2: Start Client1 (Terminal 1)
bashcd /workspaces/dev/encrypted-chat
python start_client.py
You'll see:
🔵 Starting Client1 Interface...
📱 Client1 Access URL:
   https://upgraded-carnival-vwr6vx745jwhxp5w-5000.app.github.dev/
Step 3: Start Server1 (Terminal 2)
bashcd /workspaces/dev/encrypted-chat
python start_server.py
You'll see:
🟢 Starting Server1 Interface...
📱 Server1 Access URL:
   https://upgraded-carnival-vwr6vx745jwhxp5w-5001.app.github.dev/
Step 4: Test Your Chat

Open Client1 URL in one browser tab
Open Server1 URL in another browser tab
Register client1 on port 5000
Register server1 on port 5001
Search for each other and start chatting!

Step 5: Check Status (Optional)
bash# In a third terminal
python check_ports.py
This shows you which ports are running and their URLs.

