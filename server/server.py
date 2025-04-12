import socket
import argparse
import json
import signal
import sys
import time
import os
import threading
import binascii
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import low_level
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureChatServer')

class SecureServer:
    clients = {}
    FORMAT = 'utf-8'
    SERVER_ADDR = socket.gethostbyname(socket.gethostname())
    SESSION_TIMEOUT = 3600  # 1 hour session timeout
    # Predefined generator for DH key exchange
    G = ec.SECP384R1()

    def __init__(self, port, users_file=None):
        self.port = port
        self.ADDR = (self.SERVER_ADDR, self.port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(self.ADDR)
        self.running = True
        self.users_file = users_file
        self.server_private = ec.generate_private_key(self.G)
        self.server_public = self.server_private.public_key()
        
        # Start session cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

    def load_users(self):
        """Load user credentials from file or use defaults if file not provided"""
        if self.users_file and os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading users file: {e}")
        
        # Default users if no file provided
        users = [
            {
                "name": "Alice",
                "salt": '11e983519be0566ae1c01b05f5d70d2a',
                "verifier": 'c84ce41a6c5c4e3159f26a19b8c02900cc2c0b815cda15dd9d855beb442dedec'
            },
            {
                "name": "Bob",
                "salt": "5ef85ffbc8b7154eb611a6148b341b13",
                "verifier": "1760564b9de826d341b2457d8a5d32ee47af272a189c7d41875df78464626250"
            }
        ]
        return users

    def start(self):
        logger.info(f"Server Initialized on {self.ADDR}")
        while self.running:
            try:
                data, addr = self.server.recvfrom(65535)
            # First byte check - 123 is ASCII '{' (start of JSON)
                if len(data) > 0 and data[0] == 123:
                    try:
                    # Try to decode as JSON first
                        message = json.loads(data.decode(self.FORMAT))
                        self._process_json_message(message, addr)
                    except json.JSONDecodeError:
                    # If JSON parsing fails, try as encrypted
                        self._process_encrypted_message(data, addr)
                else:
                # Directly process as encrypted message
                    self._process_encrypted_message(data, addr)
            except Exception as e:
                logger.error(f"Error processing message: {e}")

    def _process_json_message(self, message, addr):
        """Process unencrypted JSON messages (authentication, etc.)"""
        msg_type = message.get('type')
        
        if msg_type == "SIGN-IN":
            self.case_sign_in(addr, message)
        elif msg_type == "list":
            self.case_list(addr)
        elif msg_type == "logout":
            self.case_logout(addr, message)
        else:
            logger.warning(f"Unknown message type: {msg_type}")

    def _process_encrypted_message(self, data, addr):
    #"""Process encrypted binary messages"""
    # Find sender by address
        sender = None
        for username, client_info in self.clients.items():
            if (client_info['actual_address'], client_info['actual_port']) == addr:
                sender = username
                break
    
        if not sender:
            logger.warning(f"Encrypted message from unknown client {addr}")
            return
        
        try:
        # Format: IV (12 bytes) + Ciphertext + Auth Tag
            iv = data[:12]
            ciphertext = data[12:]
        
        # Decrypt using stored session key
            session_key = self.clients[sender]['session_key']
            aesgcm = AESGCM(session_key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        
        # Parse decrypted message
            decrypted_msg = json.loads(plaintext.decode(self.FORMAT))
        
        # Log decrypted message content for debugging
            logger.debug(f"Decrypted message from {sender}: {json.dumps(decrypted_msg)}")
        
        # Verify HMAC
            if 'hmac' in decrypted_msg:
                msg_hmac = bytes.fromhex(decrypted_msg.pop('hmac'))
            # Important: Sort keys for consistent ordering
                msg_content = json.dumps(decrypted_msg, sort_keys=True).encode(self.FORMAT)
                h = hmac.HMAC(self.clients[sender]['auth_key'], hashes.SHA256())
                h.update(msg_content)
            try:
                h.verify(msg_hmac)
                logger.debug(f"HMAC verification succeeded for message from {sender}")
            except Exception as e:
                logger.warning(f"HMAC verification failed for message from {sender}: {e}")
                # For debugging, calculate what the HMAC should be
                correct_hmac = h.finalize().hex()
                logger.debug(f"Expected HMAC: {correct_hmac}")
                return
        
        # Rest of the function...
            
            # Check nonce to prevent replay attacks
            if 'nonce' in decrypted_msg:
                nonce = decrypted_msg.get('nonce')
                if nonce <= self.clients[sender].get('last_nonce', 0):
                    logger.warning(f"Possible replay attack detected from {sender}")
                    return
                # Update nonce
                self.clients[sender]['last_nonce'] = nonce
            
            # Update last activity time
            self.clients[sender]['last_activity'] = time.time()
            
            # Process message based on type
            if decrypted_msg.get('type') == "send":
                self.case_send(sender, decrypted_msg)
            elif decrypted_msg.get('type') == "peer_discovery":
                self.case_peer_discovery(sender, decrypted_msg)
            else:
                logger.warning(f"Unknown encrypted message type from {sender}: {decrypted_msg.get('type')}")
                
        except Exception as e:
            logger.error(f"Error processing encrypted message: {e}")

    def case_sign_in(self, addr, message):
        username = message['username']
        users = self.load_users()
        user = next((u for u in users if u['name'] == username), None)
        
        if not user:
            logger.warning(f"Invalid username {username}")
            return

        try:
            logger.info(f"Authentication attempt from user: {username}")
            
            # Generate server ephemeral key for this session
            server_ephemeral_private = ec.generate_private_key(self.G)
            server_ephemeral_public = server_ephemeral_private.public_key()
            server_b = os.urandom(32)  # Random b value as in slide
            
            # Get the verifier from stored user info
            verifier = bytes.fromhex(user['verifier'])
            salt = user['salt']
            
            # Format B = g^b * V as in slide
            # Note: We're using ECC, so we simulate this using point addition
            # B = g^b * V in ECC would be B = g^b + V (point addition)
            # For simplicity, we'll use B = g^b and store V separately
            
            # Send salt and public key B to client
            response = {
                'salt': salt,
                'server_public_key': server_ephemeral_public.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                'b_value': binascii.hexlify(server_b).decode()
            }
            self.server.sendto(json.dumps(response).encode(self.FORMAT), addr)
            logger.info(f"Sent salt and public key B to {username}")

            # Receive client public key A and HMAC
            data, addr = self.server.recvfrom(65535)
            client_data = json.loads(data.decode())
            client_public = serialization.load_pem_public_key(
                client_data['client_public_key'].encode()
            )
            client_hmac = bytes.fromhex(client_data['client_hmac'])
            logger.info(f"Received client public key A and HMAC from {username}")

            # Compute shared secret using ECDH
            shared_secret = server_ephemeral_private.exchange(ec.ECDH(), client_public)
            
            # Compute combined secret as in slide
            shared_secret_truncated = shared_secret[:32]
            combined_secret = bytes(x ^ y for x, y in zip(shared_secret_truncated, verifier))
            
            # Derive two keys: one for authentication and one for encryption
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None, 
                info=b'auth_key'
            )
            auth_key = hkdf.derive(combined_secret)
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None, 
                info=b'encryption_key'
            )
            encryption_key = hkdf.derive(combined_secret)
            
            logger.info(f"Derived keys for {username}")

            # Verify client HMAC
            h = hmac.HMAC(auth_key, hashes.SHA256())
            h.update(b"client_confirmation")
            try:
                h.verify(client_hmac)
                logger.info(f"Client HMAC verification succeeded for {username}")
                
                # Send server confirmation
                h = hmac.HMAC(auth_key, hashes.SHA256())
                h.update(b"server_confirmation")
                server_hmac = h.finalize()
                
                # ACK message with HMAC as shown in slide
                ack_msg = {
                    'status': 'ACK',
                    'hmac': server_hmac.hex()
                }
                self.server.sendto(json.dumps(ack_msg).encode(), addr)
                logger.info(f"Sent server HMAC to {username}")

                # Store client details with session information
                current_time = time.time()
                self.clients[username] = {
                    'actual_address': addr[0],
                    'actual_port': addr[1],
                    'session_key': encryption_key,
                    'auth_key': auth_key,
                    'ephemeral_private': server_ephemeral_private,  # Store for PFS
                    'ephemeral_public': server_ephemeral_public,
                    'session_start': current_time,
                    'last_activity': current_time,
                    'last_nonce': 0  # Initialize nonce counter
                }
                logger.info(f"{username} authenticated successfully from {addr}")
                
            except Exception as e:
                logger.error(f"Client HMAC verification failed for {username}: {e}")
                error_msg = json.dumps({
                    'type': 'error',
                    'message': 'Authentication failed: HMAC verification failed'
                }).encode()
                self.server.sendto(error_msg, addr)

        except Exception as e:
            logger.error(f"Authentication failed for {username}: {e}")
            error_msg = json.dumps({
                'type': 'error',
                'message': f'Authentication failed: {str(e)}'
            }).encode()
            self.server.sendto(error_msg, addr)

    def case_peer_discovery(self, sender, message):
        """Handle peer discovery requests as shown in slide 2"""
        try:
            # Get requested user's IP and port
            request = message.get('request')
            
            if not request or request not in self.clients:
                error_response = {
                    'type': 'error',
                    'message': f"User {request} is not online",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
                
            # Create response with IP, Port and HMAC as in slide
            target_client = self.clients[request]
            response = {
                'type': 'peer_info',
                'ip': target_client['actual_address'],
                'port': target_client['actual_port'],
                'nonce': time.time()
            }
            
            # Add HMAC of IP|Port as shown in slide
            h = hmac.HMAC(self.clients[sender]['auth_key'], hashes.SHA256())
            h.update(f"{target_client['actual_address']}|{target_client['actual_port']}".encode())
            response['hmac'] = h.finalize().hex()
            
            # Send encrypted response
            self._send_encrypted_message(sender, response)
            
        except Exception as e:
            logger.error(f"Error handling peer discovery: {e}")

    def case_list(self, addr):
        try:
            # Find requesting user by address
            username = None
            for user, info in self.clients.items():
                if (info['actual_address'], info['actual_port']) == (addr[0], addr[1]):
                    username = user
                    break
                    
            if not username:
                logger.warning(f"List request from unauthenticated client {addr}")
                error_msg = json.dumps({
                    'type': 'error',
                    'message': 'Authentication required'
                }).encode()
                self.server.sendto(error_msg, addr)
                return
            
            # Generate encrypted response
            user_list = list(self.clients.keys())
            
            response_data = {
                'type': 'list_response',
                'users': user_list,
                'nonce': time.time()
            }
            
            # Encrypt response
            self._send_encrypted_message(username, response_data)
            
        except Exception as e:
            logger.error(f"Error sending user list: {e}")

    def case_send(self, sender, message):
        try:
            to_username = message['to']
            
            if to_username not in self.clients:
                # Send error back to sender
                error_response = {
                    'type': 'error',
                    'message': f"User {to_username} is not online",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
            
            # Create message object as in slide 3 (C, Nonce, HMAC)
            # Here C is the encrypted message
            ciphertext = message['message']
            nonce = time.time()
            
            # Forward the message to recipient
            forward_message = {
                'type': 'message',
                'from': sender,
                'message': ciphertext,
                'nonce': nonce
            }
            
            # Add HMAC as in slide
            h = hmac.HMAC(self.clients[to_username]['auth_key'], hashes.SHA256())
            h.update(f"{ciphertext}|{nonce}".encode())
            forward_message['hmac'] = h.finalize().hex()
            
            # Encrypt the message for recipient
            self._send_encrypted_message(to_username, forward_message)
            
            # Send delivery confirmation to sender
            confirm_message = {
                'type': 'delivery_confirmation',
                'to': to_username,
                'status': 'delivered',
                'nonce': time.time()
            }
            self._send_encrypted_message(sender, confirm_message)
            
        except Exception as e:
            logger.error(f"Error sending message: {e}")

    def _send_encrypted_message(self, username, message_data):
        """Encrypt and send a message to a user"""
        if username not in self.clients:
            logger.warning(f"Attempted to send message to non-existent user {username}")
            return
            
        try:
            client_info = self.clients[username]
            session_key = client_info['session_key']
            
            # Add HMAC to message if not already present
            if 'hmac' not in message_data:
                h = hmac.HMAC(client_info['auth_key'], hashes.SHA256())
                h.update(json.dumps(message_data, sort_keys=True).encode(self.FORMAT))
                message_data['hmac'] = h.finalize().hex()
            
            # Convert message to JSON
            plaintext = json.dumps(message_data).encode(self.FORMAT)
            
            # Generate random IV (must be unique for each message)
            iv = os.urandom(12)
            
            # Encrypt message
            aesgcm = AESGCM(session_key)
            ciphertext = aesgcm.encrypt(iv, plaintext, None)
            
            # Send IV + ciphertext
            encrypted_message = iv + ciphertext
            self.server.sendto(encrypted_message, 
                             (client_info['actual_address'], client_info['actual_port']))
                             
        except Exception as e:
            logger.error(f"Error encrypting message for {username}: {e}")

    def case_logout(self, addr, message):
        try:
            # Find username by address
            username = None
            for user, info in self.clients.items():
                if (info['actual_address'], info['actual_port']) == (addr[0], addr[1]):
                    username = user
                    break
                    
            if not username:
                logger.warning(f"Logout request from unknown client {addr}")
                return
                
            # Verify the HMAC if present
            if 'hmac' in message:
                hmac_value = bytes.fromhex(message['hmac'])
                h = hmac.HMAC(self.clients[username]['auth_key'], hashes.SHA256())
                h.update(b"Logout")
                try:
                    h.verify(hmac_value)
                except Exception:
                    logger.warning(f"Invalid logout HMAC from {username}")
                    return
            
            # Send ACK with HMAC as shown in slide 3
            h = hmac.HMAC(self.clients[username]['auth_key'], hashes.SHA256())
            h.update(b"ACK")
            ack_msg = {
                'type': 'logout_ack',
                'hmac': h.finalize().hex()
            }
            self.server.sendto(json.dumps(ack_msg).encode(), addr)
            
            # For PFS (Perfect Forward Secrecy), remove all session keys
            logger.info(f"{username} logged out, removing session keys for PFS")
            del self.clients[username]
            
        except Exception as e:
            logger.error(f"Error handling logout: {e}")

    def _cleanup_expired_sessions(self):
        """Periodically clean up expired sessions"""
        while self.running:
            time.sleep(60)  # Check every minute
            current_time = time.time()
            expired_users = []
            
            for username, info in self.clients.items():
                # Check if session has been inactive for too long
                if current_time - info['last_activity'] > self.SESSION_TIMEOUT:
                    expired_users.append(username)
            
            # Remove expired sessions
            for username in expired_users:
                logger.info(f"Session expired for {username}")
                del self.clients[username]

    def shutdown(self):
        self.running = False
        for username in list(self.clients.keys()):
            try:
                # Send shutdown notice
                shutdown_msg = {
                    'type': 'SERVER_SHUTDOWN',
                    'nonce': time.time()
                }
                self._send_encrypted_message(username, shutdown_msg)
            except Exception as e:
                logger.error(f"Error notifying {username}: {e}")
        
        self.server.close()
        logger.info("Server shut down successfully")
        sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Secure UDP Chat Server")
    parser.add_argument("-sp", "--server-port", type=int, required=True, help="Port to run the server on")
    parser.add_argument("--users-file", type=str, help="JSON file with user credentials")
    args = parser.parse_args()
    
    server = SecureServer(args.server_port, args.users_file)
    
    def signal_handler(signum, frame):
        print("\nShutting down server...")
        server.shutdown()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTSTP, signal_handler)
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.shutdown()