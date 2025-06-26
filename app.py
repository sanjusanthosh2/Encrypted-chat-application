from flask import Flask, render_template, request, jsonify, session
from models import db, User, Message
from config import config
import os
from datetime import datetime
import hashlib
import base64
import secrets

def create_app(config_name=None):
    """Application factory"""
    app = Flask(__name__)
    
    # Load configuration
    config_name = config_name or os.getenv('FLASK_ENV', 'development')
    app.config.from_object(config[config_name])
    
    # Create instance directory if it doesn't exist
    instance_dir = os.path.join(app.root_path, 'instance')
    if not os.path.exists(instance_dir):
        os.makedirs(instance_dir)
    
    # Initialize extensions
    db.init_app(app)
    
    return app

# Create Flask app
app = create_app()

# Simple encryption for demo (not for production)
def simple_encrypt(text, key):
    """Simple XOR encryption for demo purposes"""
    result = ""
    for i, char in enumerate(text):
        result += chr(ord(char) ^ ord(key[i % len(key)]))
    return base64.b64encode(result.encode()).decode()

def simple_decrypt(encrypted_text, key):
    """Simple XOR decryption for demo purposes"""
    try:
        decoded = base64.b64decode(encrypted_text.encode()).decode()
        result = ""
        for i, char in enumerate(decoded):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        return result
    except:
        return "[Failed to decrypt]"

# Authentication helper
def require_auth():
    """Check if user is logged in"""
    return 'user_id' in session and session.get('user_id') is not None

def get_current_user():
    """Get current logged-in user"""
    if not require_auth():
        return None
    return User.query.get(session['user_id'])

# Main routes
@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@app.route('/register')
def register_page():
    """Registration page"""
    return render_template('register.html')

@app.route('/login')
def login_page():
    """Login page"""
    return render_template('login.html')

@app.route('/chat')
def chat_page():
    """Main chat interface"""
    if not require_auth():
        return render_template('login.html')
    return render_template('chat.html')

@app.route('/dual')
def dual_chat_page():
    """Dual user chat interface for testing"""
    return render_template('dual.html')

# API routes for authentication
@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not all([username, email, password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Generate simple encryption key for this user
        user_key = hashlib.sha256((username + password).encode()).hexdigest()[:16]
        
        # Create user
        user = User(username=username, email=email, password=password, public_key=user_key)
        db.session.add(user)
        db.session.commit()
        
        # Log in user (set session)
        session['user_id'] = user.id
        session['username'] = user.username
        session['encryption_key'] = user_key
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'encryption_key': user_key
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not all([username, password]):
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Find user
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Generate encryption key
        user_key = hashlib.sha256((username + password).encode()).hexdigest()[:16]
        
        # Log in user (set session)
        session['user_id'] = user.id
        session['username'] = user.username
        session['encryption_key'] = user_key
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'encryption_key': user_key
        }), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    session.clear()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/auth/me', methods=['GET'])
def get_current_user_info():
    """Get current user info"""
    if not require_auth():
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email
        },
        'encryption_key': session.get('encryption_key')
    }), 200

@app.route('/api/users/search', methods=['GET'])
def search_users():
    """Search for users"""
    if not require_auth():
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        query = request.args.get('q', '').strip()
        current_user_id = session['user_id']
        
        if not query or len(query) < 2:
            return jsonify({'error': 'Search query must be at least 2 characters'}), 400
        
        users = User.query.filter(
            User.username.ilike(f'%{query}%'),
            User.id != current_user_id
        ).limit(10).all()
        
        return jsonify({
            'users': [{
                'id': user.id,
                'username': user.username,
                'email': user.email
            } for user in users]
        }), 200
        
    except Exception as e:
        print(f"Search error: {str(e)}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/messages/send', methods=['POST'])
def send_message():
    """Send a message"""
    if not require_auth():
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        current_user_id = session['user_id']
        data = request.get_json()
        
        recipient_username = data.get('recipient_username', '').strip()
        message_content = data.get('message', '').strip()
        sender_key = session.get('encryption_key', '')
        
        if not all([recipient_username, message_content]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Find recipient
        recipient = User.query.filter_by(username=recipient_username).first()
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        # Encrypt message with simple encryption
        encrypted_message = simple_encrypt(message_content, sender_key)
        
        # Save message
        message = Message(
            sender_id=current_user_id,
            recipient_id=recipient.id,
            encrypted_content=encrypted_message,
            encrypted_key=sender_key,  # Store sender's key for decryption
            nonce=""  # Not needed for simple encryption
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({
            'message': 'Message sent successfully',
            'message_id': message.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Send message error: {str(e)}")
        return jsonify({'error': 'Failed to send message'}), 500

@app.route('/api/messages/<username>', methods=['GET'])
def get_messages(username):
    """Get messages with a specific user"""
    if not require_auth():
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        current_user_id = session['user_id']
        
        # Find the other user
        other_user = User.query.filter_by(username=username).first()
        if not other_user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get messages between users
        messages = Message.query.filter(
            ((Message.sender_id == current_user_id) & (Message.recipient_id == other_user.id)) |
            ((Message.sender_id == other_user.id) & (Message.recipient_id == current_user_id))
        ).order_by(Message.timestamp.asc()).all()
        
        # Format messages
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                'id': msg.id,
                'sender_username': msg.sender.username,
                'recipient_username': msg.recipient.username,
                'encrypted_content': msg.encrypted_content,
                'encryption_key': msg.encrypted_key,
                'timestamp': msg.timestamp.isoformat(),
                'is_own_message': msg.sender_id == current_user_id
            })
        
        return jsonify({'messages': formatted_messages}), 200
        
    except Exception as e:
        print(f"Get messages error: {str(e)}")
        return jsonify({'error': 'Failed to get messages'}), 500

@app.route('/api/messages/conversations', methods=['GET'])
def get_conversations():
    """Get list of conversations"""
    if not require_auth():
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        current_user_id = session['user_id']
        
        # Get users who have exchanged messages with current user
        conversations = db.session.query(User).join(
            Message, 
            (Message.sender_id == User.id) | (Message.recipient_id == User.id)
        ).filter(
            ((Message.sender_id == current_user_id) | (Message.recipient_id == current_user_id)),
            User.id != current_user_id
        ).distinct().all()
        
        conversation_list = []
        for user in conversations:
            # Get last message
            last_message = Message.query.filter(
                ((Message.sender_id == current_user_id) & (Message.recipient_id == user.id)) |
                ((Message.sender_id == user.id) & (Message.recipient_id == current_user_id))
            ).order_by(Message.timestamp.desc()).first()
            
            conversation_list.append({
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                },
                'last_message_time': last_message.timestamp.isoformat() if last_message else None
            })
        
        return jsonify({'conversations': conversation_list}), 200
        
    except Exception as e:
        print(f"Get conversations error: {str(e)}")
        return jsonify({'error': 'Failed to get conversations'}), 500

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)