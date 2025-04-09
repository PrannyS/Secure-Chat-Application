import socket
import argparse
import json
import signal
import sys

class Server:
    clients = {} # This is a dictionary to store the details of all the clients
    FORMAT = 'utf-8' # This is the encoding format for the messages
    SERVER_ADDR = socket.gethostbyname(socket.gethostname()) # This gets the IP address of the server


    def __init__(self, port):
        self.port = port
        self.ADDR = (self.SERVER_ADDR, self.port) 

        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # This creates a UDP socket for the server
        self.server.bind(self.ADDR) 
        self.running = True # This is a flag to control execution of loops


    def start(self):
        print("[Notification] Server Initialized...")
        print("Server is Listening on", self.ADDR)

        while True:
            data, addr = self.server.recvfrom(65535) # 65545 is the maximum theorectical size of a UDP datagram
            message = json.loads(data.decode(self.FORMAT))
            
            if message['type'] == "SIGN-IN":
                self.case_sign_in(addr, message)
            elif message['type'] == "list":
                self.case_list(addr)
            elif message['type'] == "send":
                self.case_send(message)
            elif message['type'] == "disconnect":
                self.case_disconnect(addr, message)


    def case_sign_in(self, addr, message):
        username = message['username']
        client_addr = message['address']
        client_port = message['port']

        self.clients[username] = {
            'reported_address': client_addr,
            'reported_port': client_port,
            'actual_address': addr[0],
            'actual_port': addr[1]
        }
        print(f"{username} signed in from {addr}")


    def case_list(self, addr):
        user_list = list(self.clients.keys())
        self.server.sendto(json.dumps(user_list).encode(self.FORMAT), addr)


    def case_send(self, message):
        target_username = message['to']
        from_username = message['from']

        if target_username in self.clients and target_username != from_username:
            details = self.clients[target_username]
            response = {
                'type': 'recipient_details',
                'reported_address': details['reported_address'],
                'reported_port': details['reported_port']
            }
            self.server.sendto(json.dumps(response).encode(), 
                               (self.clients[from_username]['actual_address'], 
                                self.clients[from_username]['actual_port']))
            
        elif target_username == from_username:
            response = {
                        'type': 'Self_Message',
                        'message':"You cannot send a message to yourself"
                        }
            self.server.sendto(json.dumps(response).encode(), 
                               (self.clients[from_username]['actual_address'], 
                                self.clients[from_username]['actual_port']))
        else:
            response = {
                        'type': 'No_User',
                        'message':"No user with that username"
                        }
            self.server.sendto(json.dumps(response).encode(), 
                               (self.clients[from_username]['actual_address'], 
                                self.clients[from_username]['actual_port']))
            

    def case_disconnect(self, addr, message):
        username = message['username']
        if username in self.clients:
            del self.clients[username]
            print(f"{username} disconnected from {addr}")



    def shutdown(self):
        self.running = False
        for username, client_info in self.clients.items():
            try:
                disconnect_message = json.dumps({"type": "SERVER_SHUTDOWN"}).encode(self.FORMAT)
                self.server.sendto(disconnect_message, (client_info['actual_address'], client_info['actual_port']))
            except Exception as e:
                print(f"Error notifying client {username}: {e}")
        
        self.server.close()
        print("Server shut down successfully.")
        sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="UDP Chat Server") # This creates a parser object
    parser.add_argument("-sp", "--server-port", type=int, required=True, help="Server port") # This adds an argument to the parser object
    args = parser.parse_args() # This parses the arguments passed during execution of the script
    
    server = Server(args.server_port) # This creates an instance of the Server class

    def signal_handler(signum,frame):
        print("\nReceived signal to terminate. Shutting down server...")
        server.shutdown()

    signal.signal(signal.SIGINT, signal_handler) # This sets the signal handler for the SIGINT (ctrl + c) signal
    signal.signal(signal.SIGTSTP, signal_handler) # This sets the signal handler for the SIGTSTP (ctrl + z) signal

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Shutting down server...")