from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
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

# Function to decrypt the password using the recipient's private key
def decrypt_password_with_private_key(encrypted_password: bytes, private_key_path: str) -> str:
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # Provide the password if the private key is encrypted
        )

    decrypted_password = private_key.decrypt(
        encrypted_password,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_password.decode()

# Function to decrypt the file using a symmetric key derived from the password
def decrypt_file(encrypted_file: str, output_file: str, password: str):
    with open(encrypted_file, 'rb') as f_in:
        salt = f_in.read(16)  # Read the salt
        iv = f_in.read(16)    # Read the initialization vector (IV)
        encrypted_data = f_in.read()  # Read the encrypted data

    key = generate_symmetric_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    data = unpadder.update(padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as f_out:
        f_out.write(data)  # Write the decrypted data to file

    print(f"File '{encrypted_file}' has been decrypted and saved as '{output_file}'")

def main():
    # Create directories to organize decrypted files
    os.makedirs('decrypted_files', exist_ok=True)

    # Paths for encrypted password, private key, encrypted file, and output file
    encrypted_password_file = 'encrypted_files/encrypted_password.bin'
    private_key_path = 'keys/receiver_private_key.pem'
    encrypted_file = 'encrypted_files/received_example_encrypted.bin'
    output_file = 'decrypted_files/received_example_decrypted.txt'

    # Read the encrypted password from the file
    with open(encrypted_password_file, 'rb') as f:
        encrypted_password = f.read()

    # Decrypt the password
    decrypted_password = decrypt_password_with_private_key(encrypted_password, private_key_path)
    print("Decrypted password:", decrypted_password)

    # Decrypt the file using the decrypted password
    decrypt_file(encrypted_file, output_file, decrypted_password)

if __name__ == '__main__':
    main()
