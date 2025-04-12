import socket
import argparse
import json
import signal
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
from argon2 import low_level

class Server:
    clients = {}
    FORMAT = 'utf-8'
    SERVER_ADDR = socket.gethostbyname(socket.gethostname())

    def __init__(self, port):
        self.port = port
        self.ADDR = (self.SERVER_ADDR, self.port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(self.ADDR)
        self.running = True

    def users(self):
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
        print("[Notification] Server Initialized...")
        print("Server is Listening on", self.ADDR)
        while self.running:
            try:
                data, addr = self.server.recvfrom(65535)
                message = json.loads(data.decode(self.FORMAT))
                
                if message['type'] == "SIGN-IN":
                    self.case_sign_in(addr, message)
                elif message['type'] == "list":
                    self.case_list(addr)
                elif message['type'] == "send":
                    self.case_send(message)
                elif message['type'] == "disconnect":
                    self.case_disconnect(addr, message)
            except Exception as e:
                print(f"Error processing message: {e}")

    def case_sign_in(self, addr, message):
        username = message['username']
        user = next((u for u in self.users() if u['name'] == username), None)
        
        if not user:
            print(f"Invalid username {username}")
            return

        try:
            print(f"Authentication attempt from user: {username}")
            # Generate server key pair
            server_private = ec.generate_private_key(ec.SECP384R1())
            server_public = server_private.public_key()
            
            # Send salt and public key 
            response = {
                'salt': user['salt'],  # Keep as hex string
                'server_public_key': server_public.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            }
            self.server.sendto(json.dumps(response).encode(), addr)
            print(f"Sent salt and public key to {username}")

            # Receive client public key and HMAC
            data, addr = self.server.recvfrom(65535)
            client_data = json.loads(data.decode())
            client_public = serialization.load_pem_public_key(
                client_data['client_public_key'].encode()
            )
            client_hmac = bytes.fromhex(client_data['client_hmac'])
            print(f"Received client public key and HMAC from {username}")

            # Compute shared secret
            shared_secret = server_private.exchange(ec.ECDH(), client_public)
            
            # Compute combined secret and derive key
            shared_secret_truncated = shared_secret[:32]  # Match verifier length
            print(f"Computed shared_secret (first few bytes): {shared_secret[:8].hex()}")
            combined_secret = bytes(x ^ y for x, y in zip(shared_secret_truncated, bytes.fromhex(user['verifier'])))
            print(f"Computed combined secret (first few bytes): {combined_secret[:8].hex()}")
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None, 
                info=b'session_key'
            )
            session_key = hkdf.derive(combined_secret)
            print(f"Computed session key for {username} (first few bytes): {session_key[:8].hex()}")

            # Verify client HMAC
            h = hmac.HMAC(session_key, hashes.SHA256())
            h.update(b"client_confirmation")
            try:
                h.verify(client_hmac)
                print(f"Client HMAC verification succeeded for {username}")
                
                # Send server confirmation
                h = hmac.HMAC(session_key, hashes.SHA256())
                h.update(b"server_confirmation")
                server_hmac = h.finalize()
                self.server.sendto(server_hmac.hex().encode(), addr)
                print(f"Sent server HMAC to {username}")

                # Store client details
                self.clients[username] = {
                    'reported_address': message.get('address'),
                    'reported_port': message.get('port'),
                    'actual_address': addr[0],
                    'actual_port': addr[1]
                }
                print(f"{username} authenticated successfully from {addr}")
                
            except Exception as e:
                print(f"Client HMAC verification failed for {username}: {e}")
                # Send error message
                error_msg = json.dumps({
                    'type': 'error',
                    'message': 'Authentication failed: HMAC verification failed'
                }).encode()
                self.server.sendto(error_msg, addr)

        except Exception as e:
            print(f"Authentication failed for {username}: {e}")
            # Send error message
            error_msg = json.dumps({
                'type': 'error',
                'message': f'Authentication failed: {str(e)}'
            }).encode()
            self.server.sendto(error_msg, addr)

    def case_list(self, addr):
        try:
            response = {
                'type': 'list_response',
                'users': list(self.clients.keys())
            }
            self.server.sendto(json.dumps(response).encode(), addr)
        except Exception as e:
            print(f"Error sending user list: {e}")

    def case_send(self, message):
        try:
            to_username = message['to']
            from_username = message['from']
            
            if to_username not in self.clients:
                error_response = {
                    'type': 'error',
                    'message': f"User {to_username} is not online"
                }
                self.server.sendto(json.dumps(error_response).encode(), 
                                  (self.clients[from_username]['actual_address'],
                                   self.clients[from_username]['actual_port']))
                return
                
            forward_message = {
                'type': 'message',
                'from': from_username,
                'message': message['message']
            }
            
            self.server.sendto(json.dumps(forward_message).encode(),
                              (self.clients[to_username]['actual_address'],
                               self.clients[to_username]['actual_port']))
        except Exception as e:
            print(f"Error sending message: {e}")

    def case_disconnect(self, addr, message):
        try:
            username = message['username']
            if username in self.clients:
                print(f"{username} disconnected")
                del self.clients[username]
        except Exception as e:
            print(f"Error handling disconnect: {e}")

    def shutdown(self):
        self.running = False
        for username in self.clients:
            try:
                self.server.sendto(json.dumps({"type": "SERVER_SHUTDOWN"}).encode(),
                                 (self.clients[username]['actual_address'], 
                                  self.clients[username]['actual_port']))
            except Exception as e:
                print(f"Error notifying {username}: {e}")
        self.server.close()
        print("Server shut down successfully")
        sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="UDP Chat Server")
    parser.add_argument("-sp", "--server-port", type=int, required=True)
    args = parser.parse_args()
    
    server = Server(args.server_port)
    
    def signal_handler(signum, frame):
        print("\nShutting down server...")
        server.shutdown()
    
    signal.signal(signal.SIGINT, signal_handler)
#    signal.signal(signal.SIGTSTP, signal_handler)
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.shutdown()