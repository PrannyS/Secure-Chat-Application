import socket
import argparse
import json
import threading
import queue
import sys
import time
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from argon2 import low_level
import logging
from cryptography.hazmat.primitives.asymmetric import padding
import getpass


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureChatClient')


class SecureClient:
    FORMAT = 'utf-8'
    DISCONNECT_MESSAGE = "!disconnect"
    
    G = ec.SECP384R1() # This is the elliptic curve used for ECDH key exchange


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
        self.peer_connections = {}  
        self.peer_keys = {}         # Stores session keys per peer
        self.peer_addresses = {}    # Stores actual address/port of peers
        self.ephemeral_private_keys = {}  # Store ephemeral private keys per peer
        self.key_exchange_nonces = {}  # Store nonces for key exchange verification
        
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.client.bind(('', 0))
            logger.info(f"Client is bound to {self.client.getsockname()}")
        except Exception as e:
            logger.error(f"Error initializing client socket: {e}")
            self.running = False
            raise

        # Receive Thread
        self.receive_thread = threading.Thread(target=self.receive_from)
        self.receive_thread.daemon = True
        self.receive_thread.start()


    def run(self):
        if not hasattr(self, 'client') or not self.running:
            logger.error("Client not initialized properly")
            return

        # Authentication check
        if not self.sign_in():
            logger.error("Authentication failed. Exiting.")
            self.running = False
            return

        print(f"Successfully connected as {self.username}")
        print("Available commands: list, discover <USERNAME>, send <USERNAME> <MESSAGE>, !disconnect")

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

            # Client ephemeral key pair for communication with server
            client_private_key = ec.generate_private_key(self.G)
            client_public_key = client_private_key.public_key()
            
            message = {
                'type': "SIGN-IN",
                'username': self.username,
                'client_public_key': client_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            }
            self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)
            logger.info(f"Sent username and public key to server")


            self.client.settimeout(10) # This is a timeout for the receiving message
            data, addr = self.client.recvfrom(65535)
            server_params = json.loads(data.decode())
            logger.info(f"Received server parameters (salt and public key)")

            try:
                with open('public.pem', 'rb') as key_file:
                    server_long_term_public_key = serialization.load_pem_public_key(
                    key_file.read())

            except Exception as e:
                logger.error(f"Failed to load server's long-term public key: {e}")
                return False
            
            server_ephemeral_public_key = serialization.load_pem_public_key(
                server_params['server_ephemeral_public_key'].encode()
            )
            
            # Verify the signature
            signature = bytes.fromhex(server_params['signature'])
            data_to_verify = (server_params['salt'] + server_params['server_ephemeral_public_key']).encode()
            
            try:
                server_long_term_public_key.verify(
                signature,
                data_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256()
                )
                logger.info("Server signature verified successfully")
            except Exception as e:
                logger.error(f"Server signature verification failed: {e}")
                return False
            
            salt = bytes.fromhex(server_params['salt'])
            shared_secret = client_private_key.exchange(ec.ECDH(), server_ephemeral_public_key)
            
            verifier = low_level.hash_secret_raw(
                self.password.encode(self.FORMAT),
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=low_level.Type.ID
            )
            
            shared_secret_truncated = shared_secret[:32] 
            combined_secret = bytes(x ^ y for x, y in zip(shared_secret_truncated, verifier))
            
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

            confirmation_message = {
                'type': 'CLIENT_CONFIRM',
                'username': self.username,
                'timestamp': int(time.time())
            }
            

            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(json.dumps(confirmation_message, sort_keys=True).encode(self.FORMAT))
            confirmation_message['hmac'] = h.finalize().hex()
            
            self.client.sendto(json.dumps(confirmation_message).encode(self.FORMAT), addr)
            logger.info("Sent client confirmation to server")

            data, addr = self.client.recvfrom(65535)
            
            try:
                iv = data[:12]
                ciphertext = data[12:]
                
                aesgcm = AESGCM(self.session_key)
                plaintext = aesgcm.decrypt(iv, ciphertext, None)
                
                server_response = json.loads(plaintext.decode())
                
                if server_response.get('status') != 'ACK':
                    logger.error("Invalid server confirmation")
                    return False
                    
                logger.info(f"Successfully authenticated as {self.username}")
                self.client.settimeout(None)  # Reset timeout for normal operation
                self.authenticated = True
                return True
                
            except Exception as e:
                logger.error(f"Authentication failed at final step: {e}")
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
        if not self.authenticated:
            print("Not authenticated. Please sign in first.")
            return
        
        try:
            # Peer Discovery Request
            message = {
                'type': "peer_discovery",
                'request': username,
                'nonce': time.time()
            }
        
            self._send_encrypted_message(message)
            logger.info(f"Sent peer discovery request for {username}")
        
        except Exception as e:
            logger.error(f"Exception during peer discovery: {e}")


    def send(self, send_to, msg):
        if not self.authenticated:
            print("Not authenticated. Please sign in first.")
            return
            
        try:
            self.message_counter += 1
            
            nonce = time.time()
            
            message = {
                'type': "send",
                'to': send_to,
                'message': msg,
                'nonce': nonce,
                'seq': self.message_counter  # Additional sequence number
            }
            
            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(f"{msg}|{nonce}".encode())
            message['hmac'] = h.finalize().hex()
            
            self._send_encrypted_message(message)
            logger.info(f"Sent encrypted message to {send_to} via server")
            
        except Exception as e:
            logger.error(f"Exception sending message: {e}")


    def _send_encrypted_message(self, message_data):
        try:
            if 'hmac' not in message_data:
                h = hmac.HMAC(self.auth_key, hashes.SHA256())
                h.update(json.dumps(message_data, sort_keys=True).encode(self.FORMAT))
                message_data['hmac'] = h.finalize().hex()
            
            plaintext = json.dumps(message_data).encode(self.FORMAT)
            
            iv = os.urandom(12)
            
            aesgcm = AESGCM(self.session_key)
            ciphertext = aesgcm.encrypt(iv, plaintext, None)
            
            encrypted_message = iv + ciphertext
            self.client.sendto(encrypted_message, self.ADDR)
                             
        except Exception as e:
            logger.error(f"Error encrypting message: {e}")


    def receive_from(self):
        while self.running:
            try:
                if not self.authenticated and self.running:
                    time.sleep(0.1)
                    continue
                
                self.client.settimeout(1.0)  # I added this to check the running status
                data, addr = self.client.recvfrom(65535)

                if len(data) > 0 and data[0] == 123: # 123 is the ASCII code for '{'
                    try:
                        # Decoding the received message as JSON 
                        message = json.loads(data.decode())
                        self._handle_json_message(message, addr)
                    except json.JSONDecodeError:
                        # Decoding the received as an encrypted message
                        self._handle_encrypted_message(data, addr)
                else:
                    # Default to encrypted message processing
                    self._handle_encrypted_message(data, addr)
            
            except socket.timeout:
                pass
            except Exception as e:
                if self.running:
                    logger.error(f"Error in receive thread: {e}")


    def _handle_json_message(self, message, addr):
        msg_type = message.get('type')
        
        if msg_type == 'error':
            print(f"Error: {message.get('message')}")
        elif msg_type == 'logout_ack':
            logger.info("Received logout acknowledgment")
            self.running = False

        elif msg_type == 'key_request':
            self.handle_key_request(message, addr)
        elif msg_type == 'key_response':
            self.handle_key_response(message, addr)
        elif msg_type == 'encrypted_message':
            self.handle_encrypted_p2p_message(message, addr)
        elif msg_type == 'key_exchange':

            self.handle_key_exchange(message, addr)
        else:
            logger.warning(f"Received unknown message type: {msg_type}")


    def handle_key_exchange(self, message, addr):
        sender = message.get('from')
        if not sender:
            logger.warning("Received key exchange without sender information")
            return
            
        print(f"Received key exchange from {sender}")
        
        try:
            if 'public_key' in message:
                peer_pubkey = serialization.load_pem_public_key(
                    message['public_key'].encode()
                )
                
                if sender not in self.ephemeral_private_keys:
                    private_key = ec.generate_private_key(self.G)
                    self.ephemeral_private_keys[sender] = private_key
                else:
                    private_key = self.ephemeral_private_keys[sender]
                
                public_key = private_key.public_key()
                
                shared_secret = private_key.exchange(
                    ec.ECDH(),
                    peer_pubkey
                )
                
                timestamp = str(message.get('timestamp', int(time.time()))).encode()
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=timestamp,
                    info=b'p2p_session_key',
                    backend=default_backend()
                )
                session_key = hkdf.derive(shared_secret)
                
                self.peer_keys[sender] = session_key
                self.peer_addresses[sender] = addr
                
                response = {
                    'type': 'key_response',
                    'from': self.username,
                    'public_key': public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode(),
                    'timestamp': message.get('timestamp', int(time.time()))
                }
                
                self.client.sendto(
                    json.dumps(response).encode(self.FORMAT),
                    addr
                )
                
                print(f"Session established with {sender}")
                print(f"You can now send encrypted messages to {sender}")
                
            else:
                logger.warning(f"Key exchange from {sender} missing public key")
                
        except Exception as e:
            logger.error(f"Error processing key exchange: {e}")


    def handle_relayed_key_exchange(self, message, addr):
        exchange_data = message.get('data', {})
        
        if exchange_data.get('server_verified') and exchange_data.get('from') and exchange_data.get('public_key'):
            sender = exchange_data.get('from')
            print(f"Received verified key exchange from {sender}")
            
            try:
                peer_pubkey = serialization.load_pem_public_key(
                    exchange_data.get('public_key').encode()
                )
                
                if sender not in self.ephemeral_private_keys:
                    private_key = ec.generate_private_key(self.G)
                    self.ephemeral_private_keys[sender] = private_key
                else:
                    private_key = self.ephemeral_private_keys[sender]
                
                public_key = private_key.public_key()
                
                shared_secret = private_key.exchange(
                    ec.ECDH(),
                    peer_pubkey
                )
                
                nonce = exchange_data.get('nonce', '').encode()
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=nonce,
                    info=b'p2p_session_key',
                    backend=default_backend()
                )
                session_key = hkdf.derive(shared_secret)
                
                self.peer_keys[sender] = session_key
                
                self._send_encrypted_message({
                    'type': 'verify_key_exchange',
                    'exchange_data': exchange_data
                })
                
                print(f"Session established with {sender}")
                print(f"You can now send encrypted messages to {sender}")
                
            except Exception as e:
                logger.error(f"Error processing key exchange: {e}")


    def _handle_encrypted_message(self, data, addr):

        try:
            iv = data[:12]
            ciphertext = data[12:]
            
            aesgcm = AESGCM(self.session_key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            
            message = json.loads(plaintext.decode(self.FORMAT))
            message_for_verification = message.copy()
            
            if 'hmac' in message:
                msg_hmac = bytes.fromhex(message.pop('hmac'))
                
                if message.get('type') == 'peer_info':
                    ip = message.get('ip')
                    port = message.get('port')
                    h = hmac.HMAC(self.auth_key, hashes.SHA256())
                    h.update(f"{ip}|{port}".encode(self.FORMAT))
                else:
                    verification_msg = message_for_verification.copy()
                    verification_msg.pop('hmac')
                    msg_content = json.dumps(verification_msg, sort_keys=True).encode(self.FORMAT)
                    h = hmac.HMAC(self.auth_key, hashes.SHA256())
                    h.update(msg_content)
                    
                try:
                    h.verify(msg_hmac)
                    logger.debug("HMAC verification successful")
                except Exception as e:
                    logger.warning(f"HMAC verification failed: {e}")
                    logger.warning("Continuing despite HMAC failure - FOR DEBUGGING ONLY")
            
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
                # Store peer connection info for P2P communication
                ip = message.get('ip')
                port = message.get('port')
                user = message.get('user')
                if ip and port and user:
                    print(f"Received peer information for {user}: {ip}:{port}")
                    # Store peer address and initiate key exchange
                    self.peer_addresses[user] = (ip, int(port))
                    self.initiate_key_exchange(user)
                
            elif message.get('type') == 'error':
                print(f"Error: {message.get('message')}")
                
            elif message.get('type') == 'key_exchange_verification':
                status = message.get('status')
                exchange_data = message.get('exchange_data', {})
                if status == 'verified':
                    sender = exchange_data.get('from')
                    print(f"Key exchange with {sender} verified by server")
                    # If we are the recipient of the key exchange, initiate the session
                    if self.username == exchange_data.get('to') and sender in self.peer_addresses:
                        self.initiate_key_exchange(sender)
                else:
                    print(f"Key exchange verification failed: {message.get('message')}")
                
            else:
                logger.warning(f"Received unknown message type: {message.get('type', 'unknown')}")
                
        except Exception as e:
            logger.error(f"Error decrypting message: {e}")


    def handle_key_request(self, message, addr):
        sender = message.get('from')
        if not sender:
            logger.warning("Received key request without sender information")
            return
            
        print(f"Key exchange request from {sender}")

        # Generate ephemeral key pair for the peer
        if sender not in self.ephemeral_private_keys:
            private_key = ec.generate_private_key(self.G)
            self.ephemeral_private_keys[sender] = private_key
        else:
            private_key = self.ephemeral_private_keys[sender]
            
        public_key = private_key.public_key()

        self.peer_addresses[sender] = addr

        if 'public_key' in message:
            try:
                peer_pubkey = serialization.load_pem_public_key(
                    message['public_key'].encode()
                )
                
                shared_secret = private_key.exchange(
                    ec.ECDH(),
                    peer_pubkey
                )
                
                timestamp = str(message.get('timestamp', int(time.time()))).encode()
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=timestamp,
                    info=b'p2p_session_key',
                    backend=default_backend()
                )
                session_key = hkdf.derive(shared_secret)

                self.peer_keys[sender] = session_key
                print(f"Session established with {sender}")
            except Exception as e:
                logger.error(f"Error processing peer's public key: {e}")

        response = {
            'type': 'key_response',
            'from': self.username,
            'public_key': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            'timestamp': message.get('timestamp', int(time.time()))  # Use original timestamp if available
        }

        try:
            self.client.sendto(
                json.dumps(response).encode(self.FORMAT),
                addr
            )
            logger.info(f"Sent key exchange response to {sender}")
        except Exception as e:
            logger.error(f"Error sending key response: {e}")


    def handle_key_response(self, message, addr):
        sender = message.get('from')
        if not sender:
            logger.warning("Received key response without sender information")
            return
            
        print(f"Processing key response from {sender}")

        try:
            peer_pubkey = serialization.load_pem_public_key(
                message['public_key'].encode()
            )

            if sender not in self.ephemeral_private_keys:
                self.ephemeral_private_keys[sender] = ec.generate_private_key(self.G)
                self.initiate_key_exchange(sender)
                return 

            shared_secret = self.ephemeral_private_keys[sender].exchange(
                ec.ECDH(),
                peer_pubkey
            )

            our_timestamp = int(time.time())
            peer_timestamp = message.get('timestamp', our_timestamp)
            combined_timestamp = str(min(our_timestamp, peer_timestamp)).encode()
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=combined_timestamp,
                info=b'p2p_session_key',
                backend=default_backend()
            )
            session_key = hkdf.derive(shared_secret)

            self.peer_keys[sender] = session_key
            self.peer_addresses[sender] = addr

            print(f"Session established with {sender}")
            print(f"You can now send encrypted messages directly to {sender}")
        except Exception as e:
            logger.error(f"Error processing key response: {e}")


    def handle_encrypted_p2p_message(self, message, addr):
        sender = message.get('from')
        if not sender:
            logger.warning("Received encrypted message without sender information")
            return
            
        if sender not in self.peer_keys:
            print(f"No session key for {sender}, establishing connection...")
            self.peer_addresses[sender] = addr
            self.initiate_key_exchange(sender)
            return
    
        try:
            encrypted_msg = base64.b64decode(message['message'])
        
            decrypted_msg = self.decrypt_message(encrypted_msg, self.peer_keys[sender])
        
            print(f"\n[P2P from {sender}]: {decrypted_msg}")
        except Exception as e:
            print(f"Failed to decrypt message from {sender}: {e}")


    def initiate_key_exchange(self, peer_username):
        if peer_username not in self.peer_addresses:
            print(f"No address info for {peer_username}. Please use 'discover {peer_username}' first.")
            return

        try:
            if peer_username not in self.ephemeral_private_keys:
                private_key = ec.generate_private_key(self.G)
                self.ephemeral_private_keys[peer_username] = private_key
            else:
                private_key = self.ephemeral_private_keys[peer_username]
            
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            nonce = os.urandom(16).hex()
            self.key_exchange_nonces[peer_username] = nonce
            
            data_to_sign = f"{public_key_pem}|{nonce}|{peer_username}"
            
            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(data_to_sign.encode())
            signature = h.finalize().hex()
            
            exchange_data = {
                'from': self.username,
                'to': peer_username,
                'public_key': public_key_pem,
                'nonce': nonce,
                'timestamp': int(time.time()),
                'signature': signature
            }
            

            if peer_username in self.peer_addresses:

                message = {
                    'type': 'key_request',
                    'from': self.username,
                    'public_key': public_key_pem,
                    'nonce': nonce,
                    'timestamp': exchange_data['timestamp']
                }
                
                # Send directly to peer
                peer_addr = self.peer_addresses[peer_username]
                self.client.sendto(
                    json.dumps(message).encode(self.FORMAT),
                    peer_addr
                )
                logger.info(f"Sent direct key exchange request to {peer_username}")
                print(f"Initiated key exchange with {peer_username}")

            else:
                relay_message = {
                    'type': 'relay_key_exchange',
                    'peer': peer_username,
                    'exchange_data': exchange_data
                }
                
                self._send_encrypted_message(relay_message)
                
                print(f"Initiated authenticated key exchange with {peer_username} via server")
            
        except Exception as e:
            logger.error(f"Error initiating key exchange: {e}")


    def send_encrypted_message(self, recipient, plaintext):
        if recipient not in self.peer_addresses:
            print(f"No address information for {recipient}. Discovering peer...")
            self.discover_peer(recipient)
            print(f"Please try sending message to {recipient} again after peer discovery")
            return
            
        if recipient not in self.peer_keys:
            print(f"No secure session with {recipient}. Initiating key exchange...")
            self.initiate_key_exchange(recipient)
            print(f"Please try sending message to {recipient} again after key exchange")
            return

        try:
            encrypted_msg = self.encrypt_message(plaintext, self.peer_keys[recipient])
        
            encoded_msg = base64.b64encode(encrypted_msg).decode()
        
            message = {
                'type': 'encrypted_message',
                'from': self.username,
                'message': encoded_msg
            }
        
            self.client.sendto(
                json.dumps(message).encode(self.FORMAT),
                self.peer_addresses[recipient]
            )
            print(f"Message encrypted and sent directly to {recipient}")
        except Exception as e:
            print(f"Failed to send encrypted message: {e}")


    def encrypt_message(self, plaintext, key):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext


    def decrypt_message(self, ciphertext, key):
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
            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(b"Logout")
            logout_hmac = h.finalize().hex()
            
            logout_msg = {
                'type': "logout",
                'hmac': logout_hmac
            }
            
            self.client.sendto(json.dumps(logout_msg).encode(self.FORMAT), self.ADDR)
            logger.info("Sent authenticated logout request to server")
            
            try:
                self.client.settimeout(5.0)
                data, addr = self.client.recvfrom(65535)
                ack_msg = json.loads(data.decode())
                
                if ack_msg.get('type') == 'logout_ack' and 'hmac' in ack_msg:
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
            # Ensure PFS
            self.session_key = None
            self.auth_key = None
            self.peer_keys.clear()
            self.ephemeral_private_keys.clear()
            self.authenticated = False
            self.running = False
            self.client.close()
            print("Disconnected from server")


def load_config(config_file='config.json'):
    if not os.path.exists(config_file):
        print(f"Error: Configuration file '{config_file}' not found.")
        print("Creating sample configuration file...")
        default_config = {
            "server_addr": "127.0.0.1",
            "server_port": 10000
        }
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        print(f"Sample configuration created at '{config_file}'. Please edit it with the server details.")
        exit(1)
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # Validate required fields
        if 'server_addr' not in config or 'server_port' not in config:
            print("Error: Configuration file missing required fields (server_addr, server_port)")
            exit(1)
            
        return config
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in configuration file '{config_file}'")
        exit(1)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        exit(1)


def get_user_credentials():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    return username, password



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure UDP Chat Client')
    parser.add_argument("-c", "--config", type=str, default="config.json", 
                        help="Path to configuration file (default: config.json)")
    args = parser.parse_args()
    
    config = load_config(args.config)
    username, password = get_user_credentials()
    
    client_obj = SecureClient(
        server_port=config['server_port'],
        server_addr=config['server_addr'],
        username=username,
        password=password)
    
    try:
        client_obj.run()
    except KeyboardInterrupt:
        print("\nExiting client...")
    except Exception as e:
        print(f"Error: {e}")