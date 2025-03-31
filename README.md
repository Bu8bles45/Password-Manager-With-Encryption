Secure Password Manager with TLS Handshake Simulation

This Python project simulates a TLS handshake using RSA encryption and securely stores passwords using AES encryption. It demonstrates how to establish a secure communication channel and encrypt sensitive data.

Features

TLS Handshake Simulation: Generates RSA key pairs and securely exchanges a session key.

AES Encryption for Passwords: Uses AES with a random IV for strong encryption.

Interactive CLI: Store, retrieve, and view encrypted passwords.

Secure Key Exchange: Encrypts session keys using RSA public-key cryptography.

Installation

Prerequisites

Ensure you have Python installed. You also need the cryptography library:

pip install cryptography

Usage

Run the script to start the password manager:

python password_manager.py

Steps

TLS Handshake: Generates RSA key pairs and securely exchanges an AES session key.

Store Passwords: Encrypts and stores passwords securely.

Retrieve Passwords: Decrypts and displays stored passwords.

View Encrypted Data: Displays encrypted passwords in hexadecimal format.

Code Overview

1. TLS Handshake

The server generates an RSA key pair.

The client generates a random AES session key.

The client encrypts the session key with the server's public key and sends it.

The server decrypts it with its private key.

2. Secure Password Storage

AES encryption is used in CFB mode with a random IV.

Encrypted passwords are stored in a dictionary (password_dict).

3. Interactive CLI

Store a password for a website.

Retrieve a stored password securely.

View encrypted password in hex format.

Example Output

Starting TLS Handshake...
TLS Handshake Complete: Session key established.

1. Store Password
2. Retrieve Password
3. View Encrypted Password
4. Exit
Choose an option:

Security Considerations

Random IVs ensure each encryption operation is unique.

AES encryption keeps passwords secure.

RSA encryption safely exchanges the session key.

Future Improvements

Persist encrypted passwords in a database or file.

Use AES-GCM for authenticated encryption.

Implement password hashing instead of direct encryption.
