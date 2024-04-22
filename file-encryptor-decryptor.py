import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_symmetric_key(password, salt=b'salt_', length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_symmetric(key, plaintext):
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

def decrypt_symmetric(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext

def generate_asymmetric_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def encrypt_asymmetric(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

def decrypt_asymmetric(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext

def write_to_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)

def read_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def get_file_path():
    filepath = input("Enter the full path to the file: ")
    return filepath

def get_action():
    action = input("Do you want to encrypt (E) or decrypt (D) the file? ").upper()
    return action

def main():
    filepath = get_file_path()
    action = get_action()

    if action == "E":
        password = input("Enter the encryption password: ")
        key = generate_symmetric_key(password)
        plaintext = read_from_file(filepath)
        encrypted_data = encrypt_symmetric(key, plaintext)
        write_to_file("encrypted_symmetric.bin", encrypted_data)
    elif action == "D":
        password = input("Enter the decryption password: ")
        key = generate_symmetric_key(password)
        ciphertext = read_from_file(filepath)
        decrypted_data = decrypt_symmetric(key, ciphertext)
        write_to_file("decrypted_symmetric.txt", decrypted_data)
    else:
        print("Invalid action. Please choose 'E' for encryption or 'D' for decryption.")

if __name__ == "__main__":
    main()
