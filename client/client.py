import argparse
import socket
import threading
import json
import queue
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hmac
from argon2 import low_level

class Client:
    FORMAT = 'utf-8'
    DISCONNECT_MESSAGE = "!disconnect"

    def __init__(self, server_port, server_addr, username, password):
        self.running = True
        self.server_port = server_port
        self.server_addr = server_addr
        self.username = username
        self.password = password
        self.ADDR = (self.server_addr, self.server_port)
        self.message_queue = queue.Queue()
        self.authenticated = False

        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.client.bind(('', 0))
        except Exception as e:
            print("Error initializing client socket:", e)
            self.running = False
            raise

        # Start the receive thread after initialization
        self.receive_thread = threading.Thread(target=self.receive_from)
        self.receive_thread.daemon = True  # Make thread exit when main thread exits
        self.receive_thread.start()

    def run(self):
        if not hasattr(self, 'client') or not self.running:
            print("Client not initialized properly")
            return

        # First authenticate
        if not self.sign_in():
            print("Authentication failed. Exiting.")
            self.running = False
            return

        try:
            while self.running:
                command = input().strip().split(maxsplit=2)
                if command[0] == "list":
                    self.list()
                elif command[0] == "send" and len(command) == 3:
                    self.send(command[1], command[2])
                elif command[0] == self.DISCONNECT_MESSAGE:
                    self.disconnect()
                    break
                else:
                    print("Invalid command. Available commands are: list, send USERNAME MESSAGE")

                if not self.running:
                    print("Server has shutdown, exiting")
                    break

        except Exception as e:
            print("Exception occurred:", e)

        finally:
            sys.exit(0)

    def sign_in(self):
        try:
            print(f"Attempting to authenticate as {self.username}...")
            # Step 1: Send username to server
            message = {
                'type': "SIGN-IN",
                'username': self.username,
                'address': self.client.getsockname()[0],
                'port': self.client.getsockname()[1]
            }
            self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)

            # Step 2: Receive public parameters from server
            self.client.settimeout(10)  # Set timeout for authentication
            data, addr = self.client.recvfrom(65535)
            server_params = json.loads(data.decode())
            print(f"Received server parameters (salt and public key)")

            # Step 3: Generate client's key pair and compute shared secret
            client_private_key = ec.generate_private_key(ec.SECP384R1())
            client_public_key = client_private_key.public_key()
            server_public_key = serialization.load_pem_public_key(
                server_params['server_public_key'].encode()
            )
            shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)

            # Step 4: Compute verifier using Argon2
            salt = bytes.fromhex(server_params['salt'])
            verifier = low_level.hash_secret_raw(
                self.password.encode(self.FORMAT),
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=low_level.Type.ID  # Using ID type
            )
            
            
            # Step 5: Combine secrets and derive session key
            shared_secret_truncated = shared_secret[:32]
            print(f"Computed shared secret (first few bytes): {shared_secret_truncated[:8].hex()}")
            combined_secret = bytes(x ^ y for x, y in zip(shared_secret_truncated, verifier))
            print(f"Computed combined secret (first few bytes): {combined_secret[:8].hex()}")
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None, 
                info=b'session_key'
            )
            session_key = hkdf.derive(combined_secret)
            print(f"Computed session key (first few bytes): {session_key[:8].hex()}")

            # Step 6: Send client public key and HMAC
            hmac_client = hmac.HMAC(session_key, hashes.SHA256())
            hmac_client.update(b"client_confirmation")
            confirmation_message = {
                'client_public_key': client_public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                'client_hmac': hmac_client.finalize().hex()
            }
            self.client.sendto(json.dumps(confirmation_message).encode(self.FORMAT), addr)
            print("Sent client public key and HMAC to server")

            # Step 7: Verify server confirmation
            data, addr = self.client.recvfrom(65535)
            server_hmac = bytes.fromhex(data.decode())
            
            # Verify server HMAC
            h = hmac.HMAC(session_key, hashes.SHA256())
            h.update(b"server_confirmation")
            try:
                h.verify(server_hmac)
                print(f"Successfully authenticated as {self.username}")
                self.client.settimeout(None)  # Reset timeout for normal operation
                self.authenticated = True
                return True
            except Exception as e:
                print(f"Server HMAC verification failed: {e}")
                return False

        except Exception as e:
            print(f"Authentication failed: {e}")
            self.client.settimeout(None)  # Reset timeout
            return False

    def list(self):
        try:
            message = {'type': "list"}
            self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)
        except Exception as e:
            print("Exception occurred:", e)

    def send(self, send_to, msg):
        try:
            message = {
                'type': "send",
                'to': send_to,
                'from': self.username,
                'message': msg
            }
            self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)
        except Exception as e:
            print("Exception occurred:", e)

    def receive_from(self):
        while self.running:
            try:
                if not self.authenticated and self.running:
        
                    import time
                    time.sleep(0.1)
                    continue
                    
                # Normal message reception after authentication
                self.client.settimeout(1.0)  # Short timeout to allow checking running flag
                data, addr = self.client.recvfrom(65535)
                message = json.loads(data.decode())
                
                # Handle server shutdown message
                if message.get('type') == "SERVER_SHUTDOWN":
                    print("Server has shut down. Exiting...")
                    self.running = False
                    break
                
                # Handle list response
                if message.get('type') == 'list_response' and message.get('users'):
                    print("Online users:", ", ".join(message['users']))
                # Handle error messages
                elif message.get('type') == 'error':
                    print(f"Error: {message.get('message')}")
                # Handle normal messages
                elif message.get('type') == 'message' and message.get('from') and message.get('message'):
                    print(f"Message from {message['from']}: {message['message']}")
                else:
                    print(f"Received: {message}")
                
            except json.JSONDecodeError:
                print("Received invalid JSON data")
            except socket.timeout:
                pass  
            except Exception as e:
                if self.running:
                    if self.running:
                        print(f"Error in receive thread: {e}")

    def disconnect(self):
        if self.running:
            try:
                message = {'type': "disconnect", 'username': self.username}
                self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)
            except Exception as e:
                print("Exception occurred:", e)
            finally:
                self.running = False
                self.client.close()
                print("Disconnected from server")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Put the server details')
    parser.add_argument("-u", type=str, help="Client Username", required=True)
    parser.add_argument("-sip", type=str, help="Server IP address", required=True)
    parser.add_argument("-sp", type=int, help="Server Port", required=True)
    parser.add_argument("-p", type=str, help="Password", required=True)
    args = parser.parse_args()
    client_obj = Client(args.sp, args.sip, args.u, args.p)
    client_obj.run()