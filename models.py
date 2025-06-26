from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and key management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)  # RSA public key in PEM format
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy='dynamic')
    
    def __init__(self, username, email, password, public_key):
        self.username = username
        self.email = email
        self.set_password(password)
        self.public_key = public_key
    
    def set_password(self, password):
        """Hash and set the user password"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        """Check if provided password matches the hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def update_last_seen(self):
        """Update the last seen timestamp"""
        self.last_seen = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self):
        """Convert user object to dictionary (excluding sensitive data)"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'public_key': self.public_key,
            'created_at': self.created_at.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'is_active': self.is_active
        }
    
    def __repr__(self):
        return f'<User {self.username}>'

class Message(db.Model):
    """Message model for storing encrypted messages"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    encrypted_content = db.Column(db.Text, nullable=False)  # AES encrypted message
    encrypted_key = db.Column(db.Text, nullable=False)      # RSA encrypted AES key
    nonce = db.Column(db.String(32), nullable=False)        # AES nonce/IV
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_read = db.Column(db.Boolean, default=False)
    message_type = db.Column(db.String(20), default='text')  # text, file, image, etc.
    
    def __init__(self, sender_id, recipient_id, encrypted_content, encrypted_key, nonce):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.encrypted_content = encrypted_content
        self.encrypted_key = encrypted_key
        self.nonce = nonce
    
    def mark_as_read(self):
        """Mark message as read"""
        self.is_read = True
        db.session.commit()
    
    def to_dict(self):
        """Convert message object to dictionary"""
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'encrypted_content': self.encrypted_content,
            'encrypted_key': self.encrypted_key,
            'nonce': self.nonce,
            'timestamp': self.timestamp.isoformat(),
            'is_read': self.is_read,
            'message_type': self.message_type,
            'sender_username': self.sender.username,
            'recipient_username': self.recipient.username
        }
    
    def __repr__(self):
        return f'<Message from {self.sender.username} to {self.recipient.username}>'

class ChatRoom(db.Model):
    """Chat room model for organizing conversations"""
    __tablename__ = 'chat_rooms'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_private = db.Column(db.Boolean, default=True)  # Private = 1-on-1 chat
    
    # For future group chat functionality
    participants = db.Column(db.Text)  # JSON string of participant IDs
    
    def __init__(self, name, created_by, is_private=True):
        self.name = name
        self.created_by = created_by
        self.is_private = is_private
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'is_private': self.is_private
        }

class UserSession(db.Model):
    """User session model for tracking active sessions"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    user_agent = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    
    def __init__(self, user_id, session_token, expires_at, user_agent=None, ip_address=None):
        self.user_id = user_id
        self.session_token = session_token
        self.expires_at = expires_at
        self.user_agent = user_agent
        self.ip_address = ip_address
    
    def is_expired(self):
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at
    
    def revoke(self):
        """Revoke the session"""
        self.is_active = False
        db.session.commit()
    
    def __repr__(self):
        return f'<UserSession {self.user_id}>'