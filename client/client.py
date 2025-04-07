import argparse
import socket
import threading
import json
import queue
import sys

class Client:
    FORMAT = 'utf-8' # This is the encoding format for the messages
    DISCONNECT_MESSAGE = "!disconnect"


    def __init__(self, server_port, server_addr, username):
        self.running = True # This is flag to control execution of loops
        self.server_port = server_port
        self.server_addr = server_addr
        self.username = username
        self.ADDR = (self.server_addr, self.server_port)
        self.message_queue = queue.Queue()
        
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # This creates a UDP socket for the client
            self.client.bind(('', 0))
            '''This binds the socket to the ip address and port number. 
                " '' "means the client can receive messages on any interface 
                and '0' means any available port can be assigned '''
            
        except Exception as e:
            print("Error in initialising client scket: ", e)
            self.running = False
            raise # This will re-raise the exception to the caller

        self.receive_thread = threading.Thread(target=self.receive_from)
        self.receive_thread.start()


    def run(self):
        if not hasattr(self, 'client') or not self.running:
            print("Client not initialised properly")
            return
        
        self.sign_in()

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
                    print ("Server has shutdown, exiting")
                    break

        except Exception as e:
            print("Exception has occurred: ", e)

        finally:
            sys.exit(0)


    def sign_in(self):
        try:
            message = {
                'type': "SIGN-IN",
                'username': self.username,
                'address': self.client.getsockname()[0],
                'port': self.client.getsockname()[1]
            }
            self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)

        except Exception as e:
            print("Exception has occured: ", e)


    def list(self):
        try:
            message = {'type': "list"}
            self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)

        except Exception as e:
            print("Exception has occured: ", e)


    def send(self, send_to, msg):
        try:
            message = {
                'type': "send",
                'to': send_to,
                'from': self.username,
            }
            self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)
            
        except Exception as e:
            print("Exception has occured: ", e)
        
        # Wait for server response with recipient details
        try:
            recipient_details = self.message_queue.get(timeout=5)
            if recipient_details['type'] == 'recipient_details':
                receiver_addr = recipient_details['reported_address']
                receiver_port = recipient_details['reported_port']
                
                direct_message = {
                                    'type': 'direct_message',
                                    'from': self.username,
                                    'message': msg
                                }
                self.client.sendto(json.dumps(direct_message).encode(self.FORMAT), (receiver_addr, receiver_port))
                print(f"Message sent to {send_to}")

            else:
                print(f"{recipient_details['message']}")

        except queue.Empty:
            print("Failed to get recipient details from server")


    def receive_from(self):
        while self.running:
            try:
                data, addr = self.client.recvfrom(65535) # 65535 is the maximum theoretical size of a UDP datagram
                message = json.loads(data.decode())

                if isinstance(message, list):
                    print("Signed In Users: ", ", ".join(message))

                elif message['type'] == 'direct_message':
                    print(f"<From {addr[0]}:{addr[1]}:{message['from']}>: {message['message']}")
                    
                elif message['type'] in ['recipient_details','No_User','Self_Message']:
                    self.message_queue.put(message)

                elif message['type'] == 'SERVER_SHUTDOWN':
                    print("Server has shutdown")
                    self.running = False
                    self.disconnect()
                    break

                else:
                    print(f"Received: {message}")

            except OSError as e:
                if not self.running:
                    break

            except Exception as e:
                print("Exception has occured: ", e)
                

    def disconnect(self):
        if self.running:
            try:
                message = {
                    'type': "disconnect",
                    'username': self.username
                }
                self.client.sendto(json.dumps(message).encode(self.FORMAT), self.ADDR)

            except Exception as e:
                print("Exception has occured: ", e)

            finally:
                self.running = False
                self.client.close()
                self.receive_thread.join(timeout=1)

                if self.receive_thread.is_alive():
                    print("Failed to kill thread")
                else:
                    print("Disconnected from server")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Put the server details') # This creates a parser object
    parser.add_argument("-u", type=str, help="Client Username", required=True) # This adds username argument to the parser object
    parser.add_argument("-sip", type=str, help="Server Ip address", required=True) # This adds server ip address argument to the parser object
    parser.add_argument("-sp", type=int, help="Server Port", required=True) # This adds server port argument to the parser object
    args = parser.parse_args() # This parses the arguments passed to the script
    client_obj = Client(args.sp, args.sip, args.u)
    client_obj.run()
