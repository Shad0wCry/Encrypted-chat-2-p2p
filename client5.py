import socket
import threading
import rsa
import hashlib
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import tkinter as tk
from tkinter import filedialog

class ChatClient:
    def __init__(self, root, username, socket, aes_key=None):
        self.root = root
        self.username = username
        self.root.title(f"{username} Chat Client")
        self.transcript_area = tk.Text(self.root, width=60, height=10)
        self.transcript_area.pack()
        self.entry_field = tk.Entry(self.root, width=50)
        self.entry_field.pack()
        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack()
        self.file_button = tk.Button(self.root, text="Send File", command=self.send_file)
        self.file_button.pack()
        self.socket = socket
        self.aes_key = aes_key
        if not self.aes_key:
            self.aes_key = os.urandom(32)  # Generate a 32-byte random key
            self.socket.send(self.aes_key)  # Send the AES key to the other client
        else:
            self.socket.recv(32)  # Receive the AES key from the other client
        self.key_label = tk.Label(self.root, text=f"Exchanged Key: {self.aes_key.hex()}")
        self.key_label.pack()
        self.receive_thread = threading.Thread(target=self.receive_message)
        self.receive_thread.start()
        self.update_key_label()

    def send_message(self):
        message = self.entry_field.get()
        encrypted_message = self.encrypt_message(message.encode())
        self.socket.send(encrypted_message)
        self.transcript_area.insert(tk.END, f"{self.username}: {message}\n")
        self.entry_field.delete(0, tk.END)

    def send_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            with open(filename, 'rb') as file:
                file_data = file.read()
            encrypted_file_data = self.encrypt_message(b'FILE:' + os.path.basename(filename).encode() + b':' + file_data)
            self.socket.send(encrypted_file_data)
            self.transcript_area.insert(tk.END, f"{self.username}: Sent file {os.path.basename(filename)}\n")

    def receive_message(self):
        while True:
            encrypted_message = self.socket.recv(2048)
            if not encrypted_message:
                break
            decrypted_message = self.decrypt_message(encrypted_message)
            if decrypted_message.startswith(b'FILE:'):
                filename, file_data = decrypted_message[5:].split(b':', 1)
                with open(filename.decode(), 'wb') as file:
                    file.write(file_data)
                self.transcript_area.insert(tk.END, f"Received file {filename.decode()}\n")
            else:
                print(f"Received encrypted message: {encrypted_message.hex()}")
                print(f"Received decrypted message: {decrypted_message.decode('utf-8', errors='replace')}")
                self.transcript_area.insert(tk.END, f"Received: {decrypted_message.decode('utf-8', errors='replace')}\n")

    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_message

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:16]
        encrypted_message = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        try:
            decrypted_message = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        except ValueError:
            decrypted_message = decrypted_padded_data
        return decrypted_message

    def update_key_label(self):
        self.key_label.config(text=f"Exchanged Key: {self.aes_key.hex()}")
        self.root.after(120000, self.update_key_label)



if __name__ == "__main__":
    root = tk.Tk()
    root.title("Chat Client")

    alice_socket, bob_socket = socket.socketpair()

    alice_window = tk.Toplevel(root)
    alice_window.title("Alice Chat Client")
    alice_client = ChatClient(alice_window, "Alice", alice_socket)

    bob_window = tk.Toplevel(root)
    bob_window.title("Bob Chat Client")
    bob_client = ChatClient(bob_window, "Bob", bob_socket, alice_client.aes_key)

    root.mainloop()