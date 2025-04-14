import socket
import argparse
import json
import signal
import sys
import time
import os
import threading
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging
from cryptography.hazmat.primitives.asymmetric import padding


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureChatServer')


class SecureServer:
    clients = {}
    FORMAT = 'utf-8'
    SERVER_ADDR = socket.gethostbyname(socket.gethostname())
    SESSION_TIMEOUT = 3600  # 1 hour session timeout

    
    G = ec.SECP384R1() # This is the elliptic curve used for ECDH key exchange


    def __init__(self, port, users_file=None):
        self.port = port
        self.ADDR = (self.SERVER_ADDR, self.port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(self.ADDR)
        self.running = True
        self.users_file = users_file
        self.server_private = ec.generate_private_key(self.G) # This is the ephemeral private key for the server
        self.server_public = self.server_private.public_key() # This is the ephemeral public key for the server
        
        # Start session cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()


    def load_users(self):

        if self.users_file and os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading users file: {e}")
        
        # Default users if no file provided or file does not exist
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
            },
            {
                "name": "Charlie",
                "salt": "378cb817bf8ebde3d89ad8351af36331",
                "verifier": "88fafecaef7ae2ec21bb3aaf77bb3bf8d5385dd99378ff65e5cf41b612f89a52"
            }
        ]
        return users


    def start(self):
        logger.info(f"Server Initialized on {self.ADDR}")
        while self.running:
            try:
                data, addr = self.server.recvfrom(65535)
                
                if len(data) > 0 and data[0] == 123: # 123 is the ASCII code for '{'
                    try:
                        # Decoding the received message as JSON 
                        message = json.loads(data.decode(self.FORMAT))
                        self._process_json_message(message, addr)
                    except json.JSONDecodeError:
                        # Decoding the received as an encrypted message
                        self._process_encrypted_message(data, addr)
                else:
                    # Default to encrypted message processing
                    self._process_encrypted_message(data, addr)
            except Exception as e:
                logger.error(f"Error processing message: {e}")


    def _process_json_message(self, message, addr):
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
        sender = None
        for username, client_info in self.clients.items():
            if (client_info['actual_address'], client_info['actual_port']) == addr:
                sender = username
                break
    
        if not sender:
            logger.warning(f"Encrypted message from unknown client {addr}")
            return
        
        try:
            iv = data[:12]
            ciphertext = data[12:]
        
            session_key = self.clients[sender]['session_key']
            aesgcm = AESGCM(session_key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        
            decrypted_msg = json.loads(plaintext.decode(self.FORMAT))
        
            if 'hmac' in decrypted_msg:
                msg_hmac = bytes.fromhex(decrypted_msg.pop('hmac'))
                msg_content = json.dumps(decrypted_msg, sort_keys=True).encode(self.FORMAT)
                h = hmac.HMAC(self.clients[sender]['auth_key'], hashes.SHA256())
                h.update(msg_content)
                try:
                    h.verify(msg_hmac)
                except Exception as e:
                    logger.warning(f"HMAC verification failed for message from {sender}: {e}")
                    correct_hmac = h.finalize().hex()
                    return
            
            if 'nonce' in decrypted_msg:
                nonce = decrypted_msg.get('nonce')
                if nonce <= self.clients[sender].get('last_nonce', 0):
                    logger.warning(f"Possible replay attack detected from {sender}")
                    return

                self.clients[sender]['last_nonce'] = nonce

            self.clients[sender]['last_activity'] = time.time()
            
            if decrypted_msg.get('type') == "send":
                self.case_send(sender, decrypted_msg)
            elif decrypted_msg.get('type') == "peer_discovery":
                self.case_peer_discovery(sender, decrypted_msg)
            elif decrypted_msg.get('type') == "relay_key_exchange":
                self.case_relay_key_exchange(sender, decrypted_msg)
            elif decrypted_msg.get('type') == "verify_key_exchange":
                self.case_verify_key_exchange(sender, decrypted_msg)
            else:
                logger.warning(f"Unknown encrypted message type from {sender}: {decrypted_msg.get('type')}")
                
        except Exception as e:
            logger.error(f"Error processing encrypted message: {e}")


    def case_sign_in(self, addr, message):
        username = message['username']
        users = self.load_users()
        user = next((u for u in users if u['name'] == username), None)
        
        if not user:
            logger.warning(f"An invalid user with username [{username}] tried to sign in from IP {addr[0]}:{addr[1]}")
            error_msg = json.dumps({
                'type': 'error',
                'message': 'Authentication failed: User not found'
            }).encode()
            self.server.sendto(error_msg, addr)
            return

        try:
            logger.info(f"Authentication attempt from user: {username}")
            
            client_public = serialization.load_pem_public_key(
                message['client_public_key'].encode()
            )
            
            # Server ephemeral key for communcating with client
            server_ephemeral_private = ec.generate_private_key(self.G)
            server_ephemeral_public = server_ephemeral_private.public_key()
            
            try:
                with open('private.pem', 'rb') as key_file:
                    server_long_term_private = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None
                    )
                    server_long_term_public = server_long_term_private.public_key()
            except Exception as e:
                logger.error(f"Failed to load server's long-term key: {e}")
                error_msg = json.dumps({
                    'type': 'error',
                    'message': 'Server configuration error'
                }).encode()
                self.server.sendto(error_msg, addr)
                return
            
            salt = user['salt']
            
            server_ephemeral_public_pem = server_ephemeral_public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            data_to_sign = (salt + server_ephemeral_public_pem).encode()
            
            # This signs the data using the server's long-term private key
            signature = server_long_term_private.sign(
                data_to_sign,
                padding.PKCS1v15(),
                hashes.SHA256()
                )
            
            response = {
                'salt': salt,
                'server_ephemeral_public_key': server_ephemeral_public_pem,
                'signature': signature.hex()
            }
            self.server.sendto(json.dumps(response).encode(self.FORMAT), addr)
            logger.info(f"Sent salt, public keys and signature to {username}")


            shared_secret = server_ephemeral_private.exchange(ec.ECDH(), client_public)
            
            verifier = bytes.fromhex(user['verifier'])
            
            shared_secret_truncated = shared_secret[:32]
            combined_secret = bytes(x ^ y for x, y in zip(shared_secret_truncated, verifier))
            
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

            data, addr = self.server.recvfrom(65535)
            client_confirmation = json.loads(data.decode())
            
            if client_confirmation.get('type') != 'CLIENT_CONFIRM' or 'hmac' not in client_confirmation:
                logger.error(f"Invalid confirmation message from {username}")
                error_msg = json.dumps({
                    'type': 'error',
                    'message': 'Authentication failed: Invalid confirmation'
                }).encode()
                self.server.sendto(error_msg, addr)
                return
                
            client_hmac = bytes.fromhex(client_confirmation.pop('hmac'))
            
            verification_msg = client_confirmation.copy()
            msg_content = json.dumps(verification_msg, sort_keys=True).encode(self.FORMAT)
            h = hmac.HMAC(auth_key, hashes.SHA256())
            h.update(msg_content)
            
            try:
                h.verify(client_hmac)
                logger.info(f"Client confirmation verification succeeded for {username}")
                
                # Store client details with session information
                current_time = time.time()
                self.clients[username] = {
                    'actual_address': addr[0],
                    'actual_port': addr[1],
                    'session_key': encryption_key,
                    'auth_key': auth_key,
                    'ephemeral_private': server_ephemeral_private,
                    'ephemeral_public': server_ephemeral_public,
                    'session_start': current_time,
                    'last_activity': current_time,
                    'last_nonce': 0
                }
                
                # Send encrypted acknowledgment
                ack_msg = {
                    'status': 'ACK',
                    'timestamp': int(time.time())
                }
                
                # Encrypt using AES-GCM with the session key
                iv = os.urandom(12)
                aesgcm = AESGCM(encryption_key)
                plaintext = json.dumps(ack_msg).encode(self.FORMAT)
                ciphertext = aesgcm.encrypt(iv, plaintext, None)
                
                # Send IV + ciphertext
                encrypted_ack = iv + ciphertext
                self.server.sendto(encrypted_ack, addr)
                
                logger.info(f"{username} authenticated successfully from {addr}")
                
            except Exception as e:
                logger.error(f"Client confirmation verification failed for {username}: {e}")
                error_msg = json.dumps({
                    'type': 'error',
                    'message': 'Authentication failed: Verification failed'
                }).encode()
                self.server.sendto(error_msg, addr)

        except Exception as e:
            logger.error(f"Authentication failed for {username}: {e}")
            error_msg = json.dumps({
                'type': 'error',
                'message': f'Authentication failed: {str(e)}'
            }).encode()
            self.server.sendto(error_msg, addr)


    def case_list(self, addr):
        try:
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
            
            user_list = list(self.clients.keys())
            
            response_data = {
                'type': 'list_response',
                'users': user_list,
                'nonce': time.time()
            }
            
            self._send_encrypted_message(username, response_data)
            
        except Exception as e:
            logger.error(f"Error sending user list: {e}")


    def case_send(self, sender, message):
        try:
            to_username = message['to']
            
            if to_username not in self.clients:
                error_response = {
                    'type': 'error',
                    'message': f"User {to_username} is not online",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
            
            ciphertext = message['message']
            nonce = time.time()
            
            forward_message = {
                'type': 'message',
                'from': sender,
                'message': ciphertext,
                'nonce': nonce
            }
            
            h = hmac.HMAC(self.clients[to_username]['auth_key'], hashes.SHA256())
            h.update(f"{ciphertext}|{nonce}".encode())
            forward_message['hmac'] = h.finalize().hex()
            
            self._send_encrypted_message(to_username, forward_message)
            
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
        if username not in self.clients:
            logger.warning(f"Attempted to send message to non-existent user {username}")
            return
            
        try:
            client_info = self.clients[username]
            session_key = client_info['session_key']
            
            if 'hmac' not in message_data:
                h = hmac.HMAC(client_info['auth_key'], hashes.SHA256())
                h.update(json.dumps(message_data, sort_keys=True).encode(self.FORMAT))
                message_data['hmac'] = h.finalize().hex()
            
            plaintext = json.dumps(message_data).encode(self.FORMAT)
            
            iv = os.urandom(12)
            
            aesgcm = AESGCM(session_key)
            ciphertext = aesgcm.encrypt(iv, plaintext, None)
            
            encrypted_message = iv + ciphertext
            self.server.sendto(encrypted_message, 
                             (client_info['actual_address'], client_info['actual_port']))
                             
        except Exception as e:
            logger.error(f"Error encrypting message for {username}: {e}")


    def case_peer_discovery(self, sender, message):
        try:
            requested_user = message.get('request')
            
            if not requested_user or requested_user not in self.clients:
                error_response = {
                    'type': 'error',
                    'message': f"User {requested_user} is not online",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
                
            target_client = self.clients[requested_user]
            
            peer_info = {
                'type': 'peer_info',
                'user': requested_user,
                'ip': target_client['actual_address'],
                'port': target_client['actual_port'],
                'nonce': time.time()
            }
            

            h = hmac.HMAC(self.clients[sender]['auth_key'], hashes.SHA256())
            h.update(f"{target_client['actual_address']}|{target_client['actual_port']}".encode(self.FORMAT))
            peer_info['hmac'] = h.finalize().hex()
            
            self._send_encrypted_message(sender, peer_info)
            logger.info(f"Sent peer info about {requested_user} to {sender}")
                
        except Exception as e:
            logger.error(f"Error handling peer discovery: {e}")


    def case_logout(self, addr, message):
        try:
            username = None
            for user, info in self.clients.items():
                if (info['actual_address'], info['actual_port']) == (addr[0], addr[1]):
                    username = user
                    break
                    
            if not username:
                logger.warning(f"Logout request from unknown client {addr}")
                return
                
            if 'hmac' in message:
                hmac_value = bytes.fromhex(message['hmac'])
                h = hmac.HMAC(self.clients[username]['auth_key'], hashes.SHA256())
                h.update(b"Logout")
                try:
                    h.verify(hmac_value)
                except Exception:
                    logger.warning(f"Invalid logout HMAC from {username}")
                    return
            
            h = hmac.HMAC(self.clients[username]['auth_key'], hashes.SHA256())
            h.update(b"ACK")
            ack_msg = {
                'type': 'logout_ack',
                'hmac': h.finalize().hex()
            }
            self.server.sendto(json.dumps(ack_msg).encode(), addr)
            
            logger.info(f"{username} logged out, removing session keys for PFS")
            del self.clients[username]
            
        except Exception as e:
            logger.error(f"Error handling logout: {e}")


    def _cleanup_expired_sessions(self):
        # To remove expired sessions after 60 mins
        while self.running:
            time.sleep(60)  
            current_time = time.time()
            expired_users = []
            
            for username, info in self.clients.items():
                if current_time - info['last_activity'] > self.SESSION_TIMEOUT:
                    expired_users.append(username)
            
            for username in expired_users:
                logger.info(f"Session expired for {username}")
                del self.clients[username]


    def case_relay_key_exchange(self, sender, message):
        try:
            peer = message.get('peer')
            exchange_data = message.get('exchange_data')
            
            if not peer or peer not in self.clients or not exchange_data:
                error_response = {
                    'type': 'error',
                    'message': f"User {peer} is not online or invalid exchange data",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
            
            sig = exchange_data.get('signature')
            
            if not sig:
                error_response = {
                    'type': 'error',
                    'message': "Missing signature in key exchange",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
            
            data_to_verify = f"{exchange_data.get('public_key', '')}|{exchange_data.get('nonce', '')}|{exchange_data.get('to', '')}"
            h = hmac.HMAC(self.clients[sender]['auth_key'], hashes.SHA256())
            h.update(data_to_verify.encode())
            
            try:
                h.verify(bytes.fromhex(sig))
                
                exchange_data['server_verified'] = True
                
                forward_msg = {
                    'type': 'key_exchange',
                    'data': exchange_data
                }
                self._send_encrypted_message(peer, forward_msg)
                
                logger.info(f"Relayed verified key exchange from {sender} to {peer}")
                
            except Exception as e:
                logger.error(f"Signature verification failed: {e}")
                error_response = {
                    'type': 'error',
                    'message': "Signature verification failed",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                
        except Exception as e:
            logger.error(f"Error in key exchange relay: {e}")
    

    def case_verify_key_exchange(self, sender, message):
        try:
            exchange_data = message.get('exchange_data')
            if not exchange_data:
                error_response = {
                    'type': 'error',
                    'message': "Missing exchange data in verification request",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
                
            original_sender = exchange_data.get('from')
            if not original_sender or original_sender not in self.clients:
                error_response = {
                    'type': 'error',
                    'message': f"Original sender {original_sender} not found or not online",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
            
            signature = exchange_data.get('signature')
            if not signature:
                error_response = {
                    'type': 'error', 
                    'message': "Missing signature in exchange data",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
                
            public_key = exchange_data.get('public_key')
            nonce = exchange_data.get('nonce')
            recipient = exchange_data.get('to')
            
            if not public_key or not nonce or not recipient:
                error_response = {
                    'type': 'error',
                    'message': "Missing required fields in exchange data",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                return
                
            data_to_verify = f"{public_key}|{nonce}|{recipient}"
            h = hmac.HMAC(self.clients[original_sender]['auth_key'], hashes.SHA256())
            h.update(data_to_verify.encode())
            
            try:
                h.verify(bytes.fromhex(signature))
                
                response = {
                    'type': 'key_exchange_verification',
                    'status': 'verified',
                    'exchange_data': exchange_data,
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, response)
                logger.info(f"Key exchange verification succeeded for {sender}")
                
            except Exception as e:
                logger.error(f"Key exchange verification failed: {e}")
                error_response = {
                    'type': 'key_exchange_verification',
                    'status': 'failed',
                    'message': "Signature verification failed",
                    'nonce': time.time()
                }
                self._send_encrypted_message(sender, error_response)
                
        except Exception as e:
            logger.error(f"Error verifying key exchange: {e}")
            error_response = {
                'type': 'error',
                'message': f"Error verifying key exchange: {str(e)}",
                'nonce': time.time()
            }
            self._send_encrypted_message(sender, error_response)


    def shutdown(self):
        self.running = False
        for username in list(self.clients.keys()):
            try:
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
    
    # Add signal handler for clean shutdown
    def signal_handler(sig, frame):
        print("\nShutting down server...")
        server.shutdown()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        server.start()
    except KeyboardInterrupt:
        server.shutdown()