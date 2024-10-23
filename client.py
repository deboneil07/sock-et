import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os  # Importing os module to use os.path.basename

class PeerClient:
    def __init__(self, host='127.0.0.1', port=9999):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))
        self.iv = get_random_bytes(16)
        self.key = b'Sixteen byte key'
          # Use a fixed key for consistent encryption

        # Create the GUI
        self.window = tk.Tk()
        self.window.title("Chat Client")

        # Create a text area for chat messages
        self.chat_area = scrolledtext.ScrolledText(self.window, wrap=tk.WORD)
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_area.config(state=tk.DISABLED)

        # Entry for sending messages
        self.message_entry = tk.Entry(self.window)
        self.message_entry.pack(padx=10, pady=10, fill=tk.X, side=tk.LEFT, expand=True)

        # Send button
        self.send_button = tk.Button(self.window, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=10, side=tk.RIGHT)

        # File send button
        self.file_button = tk.Button(self.window, text="Send File", command=self.send_file)
        self.file_button.pack(padx=10, pady=10, side=tk.RIGHT)

        # Frame to hold download buttons
        self.download_frame = tk.Frame(self.window)
        self.download_frame.pack(padx=10, pady=10, fill=tk.X)

        # Scrollable canvas for download buttons
        self.download_canvas = tk.Canvas(self.download_frame)
        self.download_scrollbar = tk.Scrollbar(self.download_frame, orient="vertical", command=self.download_canvas.yview)
        self.download_scrollable_frame = tk.Frame(self.download_canvas)

        self.download_scrollable_frame.bind("<Configure>", lambda e: self.download_canvas.configure(scrollregion=self.download_canvas.bbox("all")))

        self.download_canvas.create_window((0, 0), window=self.download_scrollable_frame, anchor="nw")
        self.download_canvas.configure(yscrollcommand=self.download_scrollbar.set)

        self.download_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.download_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # List to keep track of active download buttons
        self.download_buttons = {}

        # Start a thread to receive messages
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def encrypt(self, message):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return self.iv + encrypted_message  # Attach IV to the message so that the receiver can use it

    def decrypt(self, encrypted_message):
        # Extract the IV from the beginning of the message
        iv = encrypted_message[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(encrypted_message[16:])
        try:
            return unpad(decrypted_message, AES.block_size).decode('utf-8')
        except ValueError:
            print("Error decrypting message: Padding is incorrect.")
            return None

    def send_message(self):
        message = self.message_entry.get()
        if message:
            encrypted_message = self.encrypt(message)
            self.client.send(encrypted_message)

            # Display sent message in chat area
            self.chat_area.config(state=tk.NORMAL)
            self.chat_area.insert(tk.END, f"You: {message}\n")
            self.chat_area.config(state=tk.DISABLED)

            self.message_entry.delete(0, tk.END)

    def send_file(self):
        path = filedialog.askopenfilename()
        if path:
            file_name = os.path.basename(path).encode('utf-8')  # Extract file name
            self.client.send(b'FILE:' + file_name)  # Notify server to send the file
            
            # Send the file data without encryption
            with open(path, 'rb') as f:
                file_data = f.read()
                self.client.send(b'FILE:' + file_name + b':' + file_data)  # Send both name and data

            # Display sent message in chat area
            self.chat_area.config(state=tk.NORMAL)
            self.chat_area.insert(tk.END, f"You sent a file: {file_name.decode('utf-8')}\n")
            self.chat_area.config(state=tk.DISABLED)


    def update_chat_area(self, message):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.config(state=tk.DISABLED)

    def receive_messages(self):
        while True:
            try:
                data = self.client.recv(4096)
                if not data:
                    break
                
                if data.startswith(b'FILE:'):
                    # Handle incoming file information
                    file_info = data[5:].split(b':', 1)
                    
                    if len(file_info) < 2:
                        print(f"Received malformed file data: {data}")
                        continue

                    file_name = file_info[0].decode('utf-8')
                    file_data = file_info[1]

                    # Display download button for the file
                    self.window.after(0, self.display_download_button, file_name, file_data)
                    
                else:
                    # Handle chat messages and decryption
                    try:
                        response = self.decrypt(data)
                        if response:
                            self.window.after(0, self.update_chat_area, f"Someone: {response}")
                    except Exception as e:
                        print(f"Error decrypting message: {e}")
                        continue

            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def display_download_button(self, file_name, file_data):
        try:
            # Create a button for downloading the file
            button = tk.Button(self.window, text=f"Download {file_name}", command=lambda: self.save_file(file_name, file_data))
            button.pack(pady=5)
        except Exception as e:
            print(f"Error displaying download button: {e}")

    def save_file(self, file_name, file_data):
        try:
            # Open a dialog to ask the user where to save the file
            save_path = filedialog.asksaveasfilename(defaultextension=".bin", initialfile=file_name)
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                self.chat_area.config(state=tk.NORMAL)
                self.chat_area.insert(tk.END, f"File saved: {file_name}\n")
                self.chat_area.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Error saving file: {e}")

if __name__ == "__main__":
    client = PeerClient()
    tk.mainloop()