import socket
import argparse
import json
import threading
import queue
import sys
import time
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import low_level
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureChatClient')
import time

class SecureClient:
    FORMAT = 'utf-8'
    DISCONNECT_MESSAGE = "!disconnect"
    # Predefined generator matching server's
    G = ec.SECP384R1()

    def __init__(self, server_port, server_addr, username, password):
        self.running = True
        self.server_port = server_port
        self.server_addr = server_addr
        self.username = username
        self.password = password
        self.ADDR = (self.server_addr, self.server_port)
        self.message_queue = queue.Queue()
        self.authenticated = False
        self.session_key = None
        self.auth_key = None
        self.message_counter = 0
        self.peer_connections = {}  # For direct peer connections
        self.peer_keys = {}  # Stores session keys per peer
        self.peer_addresses = {}  # Stores actual address/port of peers
        self.ephemeral_private_keys = {}  # Store ephemeral private keys per peer

        
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.client.bind(('', 0))
            logger.info(f"Client bound to {self.client.getsockname()}")
        except Exception as e:
            logger.error(f"Error initializing client socket: {e}")
            self.running = False
            raise

        # Start the receive thread after initialization
        self.receive_thread = threading.Thread(target=self.receive_from)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def run(self):
        if not hasattr(self, 'client') or not self.running:
            logger.error("Client not initialized properly")
            return

        # First authenticate
        if not self.sign_in():
            logger.error("Authentication failed. Exiting.")
            self.running = False
            return

        print(f"Successfully connected as {self.username}")
        print("Available commands: list, discover USERNAME, send USERNAME MESSAGE, !disconnect")

        try:
            while self.running:
                command = input().strip().split(maxsplit=2)
                if not command:
                    continue
                    
                if command[0] == "list":
                    self.list()
                elif command[0] == "discover" and len(command) >= 2:
                    self.discover_peer(command[1])
                elif command[0] == "send" and len(command) == 3:
#                    self.send(command[1], command[2])
                    self.send_encrypted_message(command[1], command[2])
                elif command[0] == self.DISCONNECT_MESSAGE:
                    self.disconnect()
                    break
                else:
                    print("Invalid command. Available commands are: list, discover USERNAME, send USERNAME MESSAGE, !disconnect")

                if not self.running:
                    print("Server has shutdown, exiting")
                    break

        except Exception as e:
            logger.error(f"Exception occurred: {e}")

        finally:
            sys.exit(0)

    def sign_in(self):
        try:
            logger.info(f"Attempting to authenticate as {self.username}...")
            # Step 1: Send username to server
            message = {
                'type': "SIGN-IN",
                'username': self.username
            }
            self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)

            # Step 2: Receive salt, server public key and B value
            self.client.settimeout(10)  # Set timeout for authentication
            data, addr = self.client.recvfrom(65535)
            server_params = json.loads(data.decode())
            logger.info(f"Received server parameters (salt and public key)")

            # Step 3: Generate client's key pair
            client_private_key = ec.generate_private_key(self.G)
            client_public_key = client_private_key.public_key()
            
            # Load server's public key
            server_public_key = serialization.load_pem_public_key(
                server_params['server_public_key'].encode()
            )
            
            # Step 4: Compute the shared secret using ECDH
            shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)

            # Step 5: Compute verifier from password and salt
            salt = bytes.fromhex(server_params['salt'])
            verifier = low_level.hash_secret_raw(
                self.password.encode(self.FORMAT),
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=low_level.Type.ID
            )
            
            # Step 6: Combine shared secret with verifier to create session keys
            shared_secret_truncated = shared_secret[:32]  # Use first 32 bytes
            combined_secret = bytes(x ^ y for x, y in zip(shared_secret_truncated, verifier))
            
            # Step 7: Derive authentication and encryption keys from combined secret
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None, 
                info=b'auth_key'
            )
            self.auth_key = hkdf.derive(combined_secret)
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None, 
                info=b'encryption_key'
            )
            self.session_key = hkdf.derive(combined_secret)
            logger.info(f"Derived session keys")

            # Step 8: Create client confirmation HMAC
            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(b"client_confirmation")
            client_hmac = h.finalize()
            
            # Step 9: Send client public key and HMAC to server
            confirmation_message = {
                'client_public_key': client_public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                'client_hmac': client_hmac.hex()
            }
            self.client.sendto(json.dumps(confirmation_message).encode(self.FORMAT), addr)
            logger.info("Sent client public key and HMAC to server")

            # Step 10: Receive and verify server's HMAC confirmation
            data, addr = self.client.recvfrom(65535)
            server_response = json.loads(data.decode())
            
            if server_response.get('status') != 'ACK' or 'hmac' not in server_response:
                logger.error("Invalid server confirmation")
                return False
                
            server_hmac = bytes.fromhex(server_response['hmac'])
            
            # Verify server HMAC
            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(b"server_confirmation")
            try:
                h.verify(server_hmac)
                logger.info(f"Successfully authenticated as {self.username}")
                self.client.settimeout(None)  # Reset timeout for normal operation
                self.authenticated = True
                return True
            except Exception as e:
                logger.error(f"Server HMAC verification failed: {e}")
                return False

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            self.client.settimeout(None)  # Reset timeout
            return False

    def list(self):
        if not self.authenticated:
            print("Not authenticated. Please sign in first.")
            return
            
        try:
            message = {'type': "list"}
            self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)
            logger.info("Sent list request to server")
        except Exception as e:
            logger.error(f"Exception sending list command: {e}")

    def discover_peer(self, username):
    #Request peer information for direct messaging
        if not self.authenticated:
            print("Not authenticated. Please sign in first.")
            return
        
        try:
        # Create peer discovery request
            message = {
            'type': "peer_discovery",
            'request': username,
            'nonce': time.time()
            }
        
        # Send encrypted request to server
            self._send_encrypted_message(message)
            logger.info(f"Sent peer discovery request for {username}")
        
        except Exception as e:
            logger.error(f"Exception during peer discovery: {e}")

    def send(self, send_to, msg):
        if not self.authenticated:
            print("Not authenticated. Please sign in first.")
            return
            
        try:
            # Increment message counter (serves as an additional nonce)
            self.message_counter += 1
            
            # Generate nonce to prevent replay attacks
            nonce = time.time()
            
            # Create message object as in slide 3
            message = {
                'type': "send",
                'to': send_to,
                'message': msg,
                'nonce': nonce,
                'seq': self.message_counter  # Additional sequence number
            }
            
            # Add HMAC for message authenticity
            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(f"{msg}|{nonce}".encode())
            message['hmac'] = h.finalize().hex()
            
            # Send encrypted message
            self._send_encrypted_message(message)
            logger.info(f"Sent encrypted message to {send_to}")
            
        except Exception as e:
            logger.error(f"Exception sending message: {e}")

    def _send_encrypted_message(self, message_data):
        """Encrypt and send a message to the server"""
        try:
            # Add HMAC if not already present
            if 'hmac' not in message_data:
                h = hmac.HMAC(self.auth_key, hashes.SHA256())
                h.update(json.dumps(message_data, sort_keys=True).encode(self.FORMAT))
                message_data['hmac'] = h.finalize().hex()
            
            # Convert message to JSON
            plaintext = json.dumps(message_data).encode(self.FORMAT)
            
            # Generate random IV (must be unique for each message)
            iv = os.urandom(12)
            
            # Encrypt message
            aesgcm = AESGCM(self.session_key)
            ciphertext = aesgcm.encrypt(iv, plaintext, None)
            
            # Send IV + ciphertext
            encrypted_message = iv + ciphertext
            self.client.sendto(encrypted_message, self.ADDR)
                             
        except Exception as e:
            logger.error(f"Error encrypting message: {e}")

    def receive_from(self):
        while self.running:
            try:
            # Skip reception if not authenticated
                if not self.authenticated and self.running:
                    time.sleep(0.1)
                    continue
                
            # Normal message reception after authentication
                self.client.settimeout(1.0)  # Short timeout to allow checking running flag
                data, addr = self.client.recvfrom(65535)
            
            # Check if it's a raw JSON message or encrypted
                if len(data) > 0 and data[0] == 123:  # 123 is ASCII '{' - start of JSON
                    try:
                    # Try to parse as JSON first (for error messages or initial auth)
                        message = json.loads(data.decode())
                        self._handle_json_message(message)
                    except json.JSONDecodeError:
                    # If not JSON, assume it's encrypted
                        self._handle_encrypted_message(data)
                else:
                # Directly handle as encrypted without trying to decode as UTF-8
                    self._handle_encrypted_message(data)
            
            except socket.timeout:
                pass
            except Exception as e:
                if self.running:
                    logger.error(f"Error in receive thread: {e}")


    def _handle_json_message(self, message):
        """Handle unencrypted JSON messages"""
        # Handle error messages
        if message.get('type') == 'error':
            print(f"Error: {message.get('message')}")
        elif message.get('type') == 'logout_ack':
            logger.info("Received logout acknowledgment")
            self.running = False
            
    def _handle_encrypted_message(self, data):
        """Handle and decrypt encrypted messages"""
        try:
            # Format: IV (12 bytes) + Ciphertext + Auth Tag
            iv = data[:12]
            ciphertext = data[12:]
            
            # Decrypt using session key
            aesgcm = AESGCM(self.session_key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            
            # Parse decrypted message
            message = json.loads(plaintext.decode(self.FORMAT))
            
            # Verify HMAC if present
            if 'hmac' in message:
                msg_hmac = bytes.fromhex(message.pop('hmac'))
                msg_content = json.dumps(message, sort_keys=True).encode(self.FORMAT)
                h = hmac.HMAC(self.auth_key, hashes.SHA256())
                h.update(msg_content)
                try:
                    h.verify(msg_hmac)
                except Exception:
                    logger.warning("HMAC verification failed")
                    return
            
            # Handle based on message type
            if message.get('type') == 'SERVER_SHUTDOWN':
                print("Server has shut down. Exiting...")
                self.running = False
                
            elif message.get('type') == 'list_response' and message.get('users'):
                print("Online users:", ", ".join(message['users']))
                
            elif message.get('type') == 'message' and message.get('from') and message.get('message'):
                print(f"Message from {message['from']}: {message['message']}")
                
            elif message.get('type') == 'delivery_confirmation':
                print(f"Message to {message.get('to')} was {message.get('status')}")
                
            elif message.get('type') == 'peer_info':
                # Store peer connection info
                ip = message.get('ip')
                port = message.get('port')
                if ip and port:
                    print(f"Received peer information: {ip}:{port}")
                    self.peer_connections[message.get('user')] = (ip, port)
                
            elif message.get('type') == 'error':
                print(f"Error: {message.get('message')}")
                
            else:
                logger.warning(f"Received unknown message type: {message.get('type', 'unknown')}")
                
        except Exception as e:
            logger.error(f"Error decrypting message: {e}")

    def handle_key_request(self, message, addr):
        """Handle incoming key exchange request"""
        sender = message['from']
        print(f"Key exchange request from {sender}")
    
        # Generate ephemeral key pair
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
    
        # Store keys and peer address
        self.ephemeral_private_keys[sender] = private_key
        self.peer_addresses[sender] = addr
    
        # Prepare response
        response = {
            'type': 'key_response',
            'from': self.username,
            'public_key': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            'timestamp': int(time.time())
        }
    
        # Send response directly to peer (P2P)
        self.client.sendto(
            json.dumps(response).encode(self.FORMAT),
            addr
        )

    def handle_key_response(self, message, addr):
        """Handle key exchange response and establish session key"""
        sender = message['from']
        print(f"Processing key response from {sender}")
    
        # Load peer's public key
        peer_pubkey = serialization.load_pem_public_key(
            message['public_key'].encode()
        )
    
        # Generate our ephemeral key if we haven't already
        if sender not in self.ephemeral_private_keys:
            self.ephemeral_private_keys[sender] = ec.generate_private_key(ec.SECP384R1())
    
        # Perform ECDH key exchange
        shared_secret = self.ephemeral_private_keys[sender].exchange(
            ec.ECDH(),
            peer_pubkey
        )
    
        # Derive session key using HKDF with timestamp as salt
        timestamp = str(message['timestamp']).encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=timestamp,
            info=b'p2p_session_key',
            backend=default_backend()
        )
        session_key = hkdf.derive(shared_secret)
    
        # Store session key and peer address
        self.peer_keys[sender] = session_key
        self.peer_addresses[sender] = addr
    
        print(f"Session established with {sender}")
        print(f"Session key (first 8 bytes): {session_key[:8].hex()}")

    def handle_encrypted_message(self, message):
        """Decrypt and handle an encrypted message"""
        sender = message['from']
        if sender not in self.peer_keys:
            print(f"No session key for {sender}, initiating key exchange...")
            self.initiate_key_exchange(sender)
            return
    
        try:
            # Decode the base64 encoded message
            encrypted_msg = base64.b64decode(message['message'])
        
            # Decrypt using AES-GCM
            decrypted_msg = self.decrypt_message(encrypted_msg, self.peer_keys[sender])
        
            print(f"\n[Encrypted from {sender}]: {decrypted_msg}")
        except Exception as e:
            print(f"Failed to decrypt message from {sender}: {e}")

    def initiate_key_exchange(self, peer_username):
        """Initiate key exchange with another peer"""
        if peer_username not in self.peer_addresses:
            print(f"No address info for {peer_username}")
       #     return
    
        # Generate ephemeral key pair
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
    
        # Store our private key
        self.ephemeral_private_keys[peer_username] = private_key
    
        # Send key request
        request = {
            'type': 'key_request',
            'from': self.username,
            'timestamp': int(time.time())
        }
    
        self.client.sendto(
            json.dumps(request).encode(self.FORMAT),
            self.peer_addresses[peer_username]
        )
        print(f"Sent key exchange request to {peer_username}")

    def send_encrypted_message(self, recipient, plaintext):
        """Send an encrypted message to another peer"""
        if recipient not in self.peer_keys:
            print(f"No session key for {recipient}, initiating key exchange...")
            self.initiate_key_exchange(recipient)
            return
    
        try:
            # Encrypt the message
            encrypted_msg = self.encrypt_message(plaintext, self.peer_keys[recipient])
        
            # Base64 encode for safe transmission
            encoded_msg = base64.b64encode(encrypted_msg).decode()
        
            # Prepare message
            message = {
                'type': 'encrypted_message',
                'from': self.username,
                'message': encoded_msg
            }
        
            # Send directly to peer
            self.client.sendto(
                json.dumps(message).encode(self.FORMAT),
                self.peer_addresses[recipient]
            )
            print(f"Message encrypted and sent to {recipient}")
        except Exception as e:
            print(f"Failed to send encrypted message: {e}")

    def encrypt_message(self, plaintext, key):
        """Encrypt message using AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext

    def decrypt_message(self, ciphertext, key):
        """Decrypt message using AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = ciphertext[:12]
        ciphertext = ciphertext[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()

    def disconnect(self):
        if not self.authenticated or not self.running:
            self.running = False
            self.client.close()
            return
            
        try:
            # Generate HMAC for logout message
            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(b"Logout")
            logout_hmac = h.finalize().hex()
            
            # Create logout message with HMAC
            logout_msg = {
                'type': "logout",
                'hmac': logout_hmac
            }
            
            # Send logout request
            self.client.sendto(json.dumps(logout_msg).encode(self.FORMAT), self.ADDR)
            logger.info("Sent authenticated logout request to server")
            
            # Wait for server ACK
            try:
                self.client.settimeout(5.0)
                data, addr = self.client.recvfrom(65535)
                ack_msg = json.loads(data.decode())
                
                if ack_msg.get('type') == 'logout_ack' and 'hmac' in ack_msg:
                    # Verify server HMAC
                    server_hmac = bytes.fromhex(ack_msg['hmac'])
                    h = hmac.HMAC(self.auth_key, hashes.SHA256())
                    h.update(b"ACK")
                    h.verify(server_hmac)
                    logger.info("Server logout acknowledged")
                else:
                    logger.warning("Invalid logout acknowledgment from server")
                    
            except Exception as e:
                logger.warning(f"Error receiving logout acknowledgment: {e}")
                
        except Exception as e:
            logger.error(f"Exception during logout: {e}")
        finally:
            # Delete all session keys for PFS as shown in Image 3
            self.session_key = None
            self.auth_key = None
            self.authenticated = False
            self.running = False
            self.client.close()
            print("Disconnected from server")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure UDP Chat Client')
    parser.add_argument("-u", "--username", type=str, help="Client Username", required=True)
    parser.add_argument("-sip", "--server-ip", type=str, help="Server IP address", required=True)
    parser.add_argument("-sp", "--server-port", type=int, help="Server Port", required=True)
    parser.add_argument("-p", "--password", type=str, help="Password", required=True)
    args = parser.parse_args()
    
    client_obj = SecureClient(args.server_port, args.server_ip, args.username, args.password)
    client_obj.run()
