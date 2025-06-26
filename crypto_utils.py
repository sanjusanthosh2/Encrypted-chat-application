import base64
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

class CryptoUtils:
    """Utility class for encryption and decryption operations"""
    
    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """
        Generate RSA key pair
        Returns: (private_key_pem, public_key_pem)
        """
        try:
            # Use minimum allowed key size for development to speed up generation
            # RSA requires minimum 1024 bits
            dev_key_size = 1024  # Minimum allowed, much faster than 2048
            print(f"Generating RSA key pair with {dev_key_size}-bit keys for development...")
            
            key = RSA.generate(dev_key_size)
            private_key_pem = key.export_key().decode('utf-8')
            public_key_pem = key.publickey().export_key().decode('utf-8')
            
            print("RSA key pair generated successfully!")
            return private_key_pem, public_key_pem
        except Exception as e:
            print(f"Error generating RSA key pair: {str(e)}")
            raise Exception(f"Error generating RSA key pair: {str(e)}")
    
    @staticmethod
    def encrypt_message(message, recipient_public_key_pem):
        """
        Encrypt a message using hybrid encryption (RSA + AES)
        Args:
            message (str): The message to encrypt
            recipient_public_key_pem (str): Recipient's public key in PEM format
        Returns:
            dict: Contains encrypted_content, encrypted_key, and nonce
        """
        try:
            # Generate random AES key (256-bit)
            aes_key = get_random_bytes(32)
            
            # Generate random nonce for AES-GCM
            nonce = get_random_bytes(16)
            
            # Encrypt message with AES-GCM
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            encrypted_message, auth_tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
            
            # Combine encrypted message and auth tag
            encrypted_content = encrypted_message + auth_tag
            
            # Encrypt AES key with recipient's RSA public key
            recipient_public_key = RSA.import_key(recipient_public_key_pem)
            cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            return {
                'encrypted_content': base64.b64encode(encrypted_content).decode('utf-8'),
                'encrypted_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8')
            }
        except Exception as e:
            raise Exception(f"Error encrypting message: {str(e)}")
    
    @staticmethod
    def decrypt_message(encrypted_content, encrypted_key, nonce, private_key_pem):
        """
        Decrypt a message using hybrid decryption (RSA + AES)
        Args:
            encrypted_content (str): Base64 encoded encrypted message
            encrypted_key (str): Base64 encoded encrypted AES key
            nonce (str): Base64 encoded nonce
            private_key_pem (str): Private key in PEM format
        Returns:
            str: Decrypted message
        """
        try:
            # Decode base64 strings
            encrypted_content_bytes = base64.b64decode(encrypted_content)
            encrypted_key_bytes = base64.b64decode(encrypted_key)
            nonce_bytes = base64.b64decode(nonce)
            
            # Decrypt AES key with private RSA key
            private_key = RSA.import_key(private_key_pem)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_key_bytes)
            
            # Split encrypted content and auth tag (last 16 bytes)
            encrypted_message = encrypted_content_bytes[:-16]
            auth_tag = encrypted_content_bytes[-16:]
            
            # Decrypt message with AES-GCM
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce_bytes)
            decrypted_message = cipher_aes.decrypt_and_verify(encrypted_message, auth_tag)
            
            return decrypted_message.decode('utf-8')
        except Exception as e:
            raise Exception(f"Error decrypting message: {str(e)}")
    
    @staticmethod
    def validate_public_key(public_key_pem):
        """
        Validate if the provided string is a valid RSA public key
        Args:
            public_key_pem (str): Public key in PEM format
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            RSA.import_key(public_key_pem)
            return True
        except:
            return False
    
    @staticmethod
    def validate_private_key(private_key_pem):
        """
        Validate if the provided string is a valid RSA private key
        Args:
            private_key_pem (str): Private key in PEM format
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            key = RSA.import_key(private_key_pem)
            return key.has_private()
        except:
            return False
    
    @staticmethod
    def get_key_fingerprint(public_key_pem):
        """
        Generate a fingerprint for a public key
        Args:
            public_key_pem (str): Public key in PEM format
        Returns:
            str: SHA256 fingerprint of the key
        """
        try:
            key_bytes = public_key_pem.encode('utf-8')
            fingerprint = hashlib.sha256(key_bytes).hexdigest()
            # Format fingerprint with colons for readability
            return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        except Exception as e:
            raise Exception(f"Error generating key fingerprint: {str(e)}")
    
    @staticmethod
    def encrypt_file(file_data, recipient_public_key_pem):
        """
        Encrypt file data using hybrid encryption
        Args:
            file_data (bytes): The file data to encrypt
            recipient_public_key_pem (str): Recipient's public key in PEM format
        Returns:
            dict: Contains encrypted_content, encrypted_key, and nonce
        """
        try:
            # Generate random AES key (256-bit)
            aes_key = get_random_bytes(32)
            
            # Generate random nonce for AES-GCM
            nonce = get_random_bytes(16)
            
            # Encrypt file data with AES-GCM
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            encrypted_data, auth_tag = cipher_aes.encrypt_and_digest(file_data)
            
            # Combine encrypted data and auth tag
            encrypted_content = encrypted_data + auth_tag
            
            # Encrypt AES key with recipient's RSA public key
            recipient_public_key = RSA.import_key(recipient_public_key_pem)
            cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            return {
                'encrypted_content': base64.b64encode(encrypted_content).decode('utf-8'),
                'encrypted_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8')
            }
        except Exception as e:
            raise Exception(f"Error encrypting file: {str(e)}")
    
    @staticmethod
    def decrypt_file(encrypted_content, encrypted_key, nonce, private_key_pem):
        """
        Decrypt file data using hybrid decryption
        Args:
            encrypted_content (str): Base64 encoded encrypted file data
            encrypted_key (str): Base64 encoded encrypted AES key
            nonce (str): Base64 encoded nonce
            private_key_pem (str): Private key in PEM format
        Returns:
            bytes: Decrypted file data
        """
        try:
            # Decode base64 strings
            encrypted_content_bytes = base64.b64decode(encrypted_content)
            encrypted_key_bytes = base64.b64decode(encrypted_key)
            nonce_bytes = base64.b64decode(nonce)
            
            # Decrypt AES key with private RSA key
            private_key = RSA.import_key(private_key_pem)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_key_bytes)
            
            # Split encrypted content and auth tag (last 16 bytes)
            encrypted_data = encrypted_content_bytes[:-16]
            auth_tag = encrypted_content_bytes[-16:]
            
            # Decrypt data with AES-GCM
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce_bytes)
            decrypted_data = cipher_aes.decrypt_and_verify(encrypted_data, auth_tag)
            
            return decrypted_data
        except Exception as e:
            raise Exception(f"Error decrypting file: {str(e)}")

# Utility functions for easy access
def generate_keypair():
    """Generate RSA key pair"""
    return CryptoUtils.generate_rsa_keypair()

def encrypt_message(message, public_key):
    """Encrypt a message"""
    return CryptoUtils.encrypt_message(message, public_key)

def decrypt_message(encrypted_content, encrypted_key, nonce, private_key):
    """Decrypt a message"""
    return CryptoUtils.decrypt_message(encrypted_content, encrypted_key, nonce, private_key)