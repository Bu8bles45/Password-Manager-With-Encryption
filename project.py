from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os

# Step 1: Generate Server's RSA Keys
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Simulate TLS Handshake
def tls_handshake():
    print("Starting TLS Handshake...")
    
    # Server generates RSA keys
    server_private_key, server_public_key = generate_rsa_key_pair()

    # Client generates a session key 
    session_key = os.urandom(32)  # Random 32-byte AES key

    # Client encrypts session key using server's public key
    encrypted_session_key = server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    # Server decrypts session key using its private key
    decrypted_session_key = server_private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    print("TLS Handshake Complete: Session key established.")
    return session_key

# Step 3: Secure Password Storage
def secure_password_storage(session_key):
    password_dict = {}  # Stores encrypted passwords

    while True:
        print("\n1. Store Password")
        print("2. Retrieve Password")
        print("3. View Encrypted Password")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            website = input("Enter website: ")
            password = input("Enter password: ")

            iv = os.urandom(16)  # Generate a random IV
            cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()

            password_dict[website] = (iv, encrypted_password)
            print(f"Password for {website} stored securely!")

        elif choice == "2":
            website = input("Enter website: ")
            if website in password_dict:
                iv, encrypted_password = password_dict[website]

                cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
                decryptor = cipher.decryptor()
                decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

                print(f"Decrypted Password for {website}: {decrypted_password.decode()}")
            else:
                print("No password stored for this website.")

        elif choice == "3":
            website = input("Enter website to view encrypted password: ")
            view_encrypted_password(password_dict, website)

        elif choice == "4":
            break

        else:
            print("Invalid choice! Try again.")

# Step 4: View Encrypted Password for a Specific Website
def view_encrypted_password(password_dict, website):
    if website in password_dict:
        iv, encrypted_password = password_dict[website]
        print(f"\nWebsite: {website}")
        print(f"IV: {iv.hex()}")  # Display IV in hex
        print(f"Encrypted Password: {encrypted_password.hex()}")  # Display encrypted password in hex
    else:
        print("No password stored for this website.")

# Main Simulation
if __name__ == "__main__":
    # Perform TLS Handshake
    session_key = tls_handshake()

    # Securely store and retrieve passwords
    secure_password_storage(session_key)