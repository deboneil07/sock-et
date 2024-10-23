import socket
import threading
import pickle
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

class PeerServer:
    def __init__(self, host='0.0.0.0', port=9999):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(5)
        self.clients = []  # List to store active clients
        self.key = b'Sixteen byte key'  # Use a fixed key for consistent encryption

    def handle_client(self, client_socket):
        self.clients.append(client_socket)

        while True:
            try:
                # Receive the message or file request from the client
                data = client_socket.recv(4096)
                if not data:
                    break

                # Process message or file transfer request
                self.process_data(data, client_socket)
            except Exception as e:
                print(f"Error: {e}")
                break

        client_socket.close()
        self.clients.remove(client_socket)

    def process_data(self, data, sender_socket):
        if data.startswith(b'FILE:'):
            # Handle file transfer
            self.broadcast(data, sender_socket)  # Broadcast file data to all clients
        else:
            # Broadcast the message to all clients
            self.broadcast(data, sender_socket)

    def send_file(self, file_name, sender_socket):
        directory = os.path.expanduser("~/Pictures")  # Change this path as needed
        file_path = os.path.join(directory, file_name.decode('utf-8'))

        if os.path.isfile(file_path):
            with open(file_path, 'rb') as f:
                file_data = f.read()
                # Broadcast file data to all clients except sender
                self.broadcast(b'FILE:' + file_name + b':' + file_data, sender_socket)
        else:
            print(f"File not found: {file_path}")

    def broadcast(self, message, sender_socket):
        for client in self.clients:
            if client != sender_socket:  # Don't send the message back to the sender
                client.send(message)

    def start(self):
        print(f"Server listening on port {self.server.getsockname()[1]}")
        while True:
            client_socket, addr = self.server.accept()
            print(f"Client connected: {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

if __name__ == "__main__":
    server = PeerServer()
    server.start()