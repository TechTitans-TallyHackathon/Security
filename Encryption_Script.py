from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Function to generate a symmetric key using Scrypt
def generate_symmetric_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to save the password to a file
def save_password_to_file(password: str, password_file: str):
    with open(password_file, 'w') as f:
        f.write(password)
    print(f"Password has been saved to '{password_file}'")

# Function to encrypt a file using a symmetric key derived from the password
def encrypt_file(input_file: str, output_file: str, password: str, password_file: str):
    save_password_to_file(password, password_file)

    salt = os.urandom(16)  # Generate a random salt
    iv = os.urandom(16)    # Generate a random initialization vector (IV)
    key = generate_symmetric_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_file, 'rb') as f_in:
        file_data = f_in.read()

    padded_data = padder.update(file_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f_out:
        f_out.write(salt + iv + encrypted_data)  # Write salt, IV, and encrypted data to file

    print(f"File '{input_file}' has been encrypted and saved as '{output_file}'")

# Function to encrypt the password using the recipient's public key
def encrypt_password_with_public_key(password: str, public_key_path: str) -> bytes:
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted_password = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_password

# Function to save the encrypted password to a .bin file
def save_encrypted_password_to_file(encrypted_password: bytes, encrypted_password_file: str):
    with open(encrypted_password_file, 'wb') as f:
        f.write(encrypted_password)
    print(f"Encrypted password has been saved to '{encrypted_password_file}'")

# Function to generate RSA key pair and save them to the specified directory
def generate_rsa_key_pair(private_key_path: str, public_key_path: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key = private_key.public_key()

    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def main():
    # Create directories to organize files
    os.makedirs('keys', exist_ok=True)
    os.makedirs('encrypted_files', exist_ok=True)

    # Input and output file paths
    input_file = 'example.txt'
    output_file = 'encrypted_files/received_example_encrypted.bin'
    password_file = 'encrypted_files/encryption_password.txt'
    encrypted_password_file = 'encrypted_files/encrypted_password.bin'

    private_key_path = 'keys/receiver_private_key.pem'
    public_key_path = 'keys/receiver_public_key.pem'

    # Generate RSA key pair and save them in the 'keys' directory
    generate_rsa_key_pair(private_key_path, public_key_path)

    # Password and public key
    password = 'SHARKS'

    # Encrypt the file and save the password
    encrypt_file(input_file, output_file, password, password_file)

    # Encrypt the password with the recipient's public key
    encrypted_password = encrypt_password_with_public_key(password, public_key_path)
    save_encrypted_password_to_file(encrypted_password, encrypted_password_file)

    print("All files have been organized and saved in the appropriate directories.")

if __name__ == '__main__':
    main()
