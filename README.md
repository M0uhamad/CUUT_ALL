import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# This function generates a key from a password using PBKDF2
def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

# This function encrypts a file
def encrypt_file(file_name: str, password: str):
    # Generate a salt
    salt = os.urandom(16)

    # Generate the key from the password
    key = generate_key(password.encode(), salt)

    # Create a Fernet object using the key
    fernet = Fernet(key)

    # Read the contents of the file
    with open(file_name, "rb") as f:
        file_data = f.read()

    # Encrypt the data
    encrypted_data = fernet.encrypt(file_data)

    # Write the encrypted data to a new file
    with open(file_name + ".encrypted", "wb") as f:
        f.write(salt)
        f.write(encrypted_data)

# This function encrypts all the files in a directory
def encrypt_directory(directory: str, password: str):
    # Walk through the directory tree and encrypt all the files
    for root, dirs, files in os.walk(directory):
        for file in files:
            # Get the full path of the file
            file_path = os.path.join(root, file)

            # Encrypt the file
            encrypt_file(file_path, password)

# Encrypt all the files in the current directory
encrypt_directory(".", "password")
