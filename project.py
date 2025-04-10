import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os
import json

PASSWORD_FILE = "passwords.json"
SESSION_KEY_FILE = "session_key.bin"

# Step 1: Generate Server's RSA Keys
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Simulate TLS Handshake and persist the session key
def tls_handshake():
    if os.path.exists(SESSION_KEY_FILE):
        with open(SESSION_KEY_FILE, 'rb') as f:
            session_key = f.read()
        print("Loaded existing session key.")
    else:
        print("Generating new session key (simulated TLS Handshake)...")
        server_private_key, server_public_key = generate_rsa_key_pair()
        session_key = os.urandom(32)
        with open(SESSION_KEY_FILE, 'wb') as f:
            f.write(session_key)
        print("Session key saved.")
    return session_key

# Step 3: GUI + Password Logic
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")

        self.session_key = tls_handshake()
        self.password_dict = self.load_passwords()

        tk.Label(root, text="Secure Password Manager", font=("Helvetica", 16)).pack(pady=10)

        tk.Button(root, text="Store Password", command=self.store_password).pack(pady=5)
        tk.Button(root, text="Retrieve Password", command=self.retrieve_password).pack(pady=5)
        tk.Button(root, text="View Encrypted Password", command=self.view_encrypted_password).pack(pady=5)
        tk.Button(root, text="Exit", command=self.save_and_exit).pack(pady=5)

    def store_password(self):
        website = simpledialog.askstring("Store Password", "Enter website:")
        password = simpledialog.askstring("Store Password", "Enter password:", show='*')

        if website and password:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()

            self.password_dict[website] = {
                "iv": iv.hex(),
                "encrypted_password": encrypted_password.hex()
            }
            messagebox.showinfo("Success", f"Password for {website} stored securely!")

    def retrieve_password(self):
        website = simpledialog.askstring("Retrieve Password", "Enter website:")
        entry = self.password_dict.get(website)

        if entry:
            try:
                iv = bytes.fromhex(entry["iv"])
                encrypted_password = bytes.fromhex(entry["encrypted_password"])
                cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(iv))
                decryptor = cipher.decryptor()
                decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
                messagebox.showinfo("Decrypted Password", f"{website}: {decrypted_password.decode()}")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        else:
            messagebox.showerror("Error", "No password stored for this website.")

    def view_encrypted_password(self):
        website = simpledialog.askstring("View Encrypted", "Enter website:")
        entry = self.password_dict.get(website)

        if entry:
            msg = (
                f"Website: {website}\n"
                f"IV: {entry['iv']}\n"
                f"Encrypted Password: {entry['encrypted_password']}"
            )
            messagebox.showinfo("Encrypted Password", msg)
        else:
            messagebox.showerror("Error", "No password stored for this website.")

    def load_passwords(self):
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, 'r') as f:
                return json.load(f)
        return {}

    def save_and_exit(self):
        with open(PASSWORD_FILE, 'w') as f:
            json.dump(self.password_dict, f, indent=4)
        self.root.quit()

# Step 4: Run App
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
