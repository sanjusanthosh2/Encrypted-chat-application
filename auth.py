from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from models import db, User, UserSession
from crypto_utils import CryptoUtils
import re
from datetime import datetime, timedelta
import secrets

auth_bp = Blueprint('auth', __name__)

class AuthManager:
    """Authentication and user management utilities"""
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_username(username):
        """Validate username format"""
        # Username should be 3-20 characters, alphanumeric and underscores only
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return re.match(pattern, username) is not None
    
    @staticmethod
    def validate_password(password):
        """Validate password strength"""
        # At least 8 characters, contains letter and number
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r'[A-Za-z]', password):
            return False, "Password must contain at least one letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        return True, "Password is valid"
    
    @staticmethod
    def create_user(username, email, password):
        """Create a new user with RSA key pair"""
        try:
            print(f"Creating user: {username}")
            
            # Validate input
            if not AuthManager.validate_username(username):
                return None, "Invalid username format"
            
            if not AuthManager.validate_email(email):
                return None, "Invalid email format"
            
            is_valid, message = AuthManager.validate_password(password)
            if not is_valid:
                return None, message
            
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                return None, "Username already exists"
            
            if User.query.filter_by(email=email).first():
                return None, "Email already registered"
            
            print(f"Generating RSA key pair for {username}...")
            
            # Generate RSA key pair
            private_key, public_key = CryptoUtils.generate_rsa_keypair()
            
            print(f"RSA keys generated for {username}")
            
            # Create new user
            user = User(username=username, email=email, password=password, public_key=public_key)
            db.session.add(user)
            db.session.commit()
            
            print(f"User {username} saved to database")
            
            return user, private_key  # Return user and private key
        
        except Exception as e:
            print(f"Error in create_user: {str(e)}")
            db.session.rollback()
            return None, f"Error creating user: {str(e)}"
    
    @staticmethod
    def authenticate_user(username, password):
        """Authenticate user credentials"""
        try:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                user.update_last_seen()
                return user
            return None
        except Exception as e:
            current_app.logger.error(f"Authentication error: {str(e)}")
            return None
    
    @staticmethod
    def create_session(user_id, user_agent=None, ip_address=None):
        """Create a new user session"""
        try:
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(days=30)
            
            session = UserSession(
                user_id=user_id,
                session_token=session_token,
                expires_at=expires_at,
                user_agent=user_agent,
                ip_address=ip_address
            )
            
            db.session.add(session)
            db.session.commit()
            
            return session_token
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Session creation error: {str(e)}")
            return None

# Authentication routes
@auth_bp.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not all([username, email, password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        print(f"Attempting to register user: {username}")
        
        # Create user
        user, private_key_or_error = AuthManager.create_user(username, email, password)
        
        if user is None:
            print(f"User creation failed: {private_key_or_error}")
            return jsonify({'error': private_key_or_error}), 400
        
        print(f"User {username} created successfully")
        
        # Create JWT tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        # Create session
        user_agent = request.headers.get('User-Agent')
        ip_address = request.remote_addr
        session_token = AuthManager.create_session(user.id, user_agent, ip_address)
        
        print(f"Session created for user {username}")
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict(),
            'private_key': private_key_or_error,  # Send private key to client
            'access_token': access_token,
            'refresh_token': refresh_token,
            'session_token': session_token
        }), 201
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not all([username, password]):
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Authenticate user
        user = AuthManager.authenticate_user(username, password)
        
        if not user:
            return jsonify({'error': 'Invalid username or password'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 401
        
        # Create JWT tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        # Create session
        user_agent = request.headers.get('User-Agent')
        ip_address = request.remote_addr
        session_token = AuthManager.create_session(user.id, user_agent, ip_address)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token,
            'session_token': session_token
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 404
        
        # Create new access token
        access_token = create_access_token(identity=current_user_id)
        
        return jsonify({
            'access_token': access_token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout endpoint"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        session_token = data.get('session_token') if data else None
        
        # Revoke session if provided
        if session_token:
            session = UserSession.query.filter_by(
                user_id=current_user_id,
                session_token=session_token
            ).first()
            if session:
                session.revoke()
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get current user profile"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Profile error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/users/search', methods=['GET'])
@jwt_required()
def search_users():
    """Search for users by username"""
    try:
        query = request.args.get('q', '').strip()
        
        if not query:
            return jsonify({'error': 'Search query is required'}), 400
        
        if len(query) < 2:
            return jsonify({'error': 'Search query must be at least 2 characters'}), 400
        
        # Search users (exclude current user)
        current_user_id = get_jwt_identity()
        users = User.query.filter(
            User.username.ilike(f'%{query}%'),
            User.id != current_user_id,
            User.is_active == True
        ).limit(10).all()
        
        return jsonify({
            'users': [user.to_dict() for user in users]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"User search error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/users/<username>/public-key', methods=['GET'])
@jwt_required()
def get_user_public_key(username):
    """Get a user's public key by username"""
    try:
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'username': user.username,
            'public_key': user.public_key,
            'fingerprint': CryptoUtils.get_key_fingerprint(user.public_key)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Public key retrieval error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500