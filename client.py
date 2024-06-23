import socket
import threading
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()
known_clients = {}


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        local_ip = "127.0.0.1"
        print(e)
    return local_ip


def handle_connection(conn, addr):
    try:
        peer_public_key = serialization.load_pem_public_key(conn.recv(1024))
        conn.send(client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

        encrypted_symmetric_key = conn.recv(256)
        symmetric_key = client_private_key.decrypt(encrypted_symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

        iv = conn.recv(16)
        encrypted_message = conn.recv(1024)
        decryptor = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv)).decryptor()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(decryptor.update(encrypted_message)) + unpadder.finalize()

        print(f"Message from {addr}: {decrypted_message.decode()}")
    finally:
        conn.close()


def listen_for_connections(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("", port))
    listener.listen(5)
    print(f"Listening on port {port}...")
    while True:
        conn, addr = listener.accept()
        threading.Thread(target=handle_connection, args=(conn, addr)).start()


def connect_to_peer(ip, port, message):
    try:
        peer_public_key = known_clients[(ip, port)]
    except KeyError:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
        peer_public_key = serialization.load_pem_public_key(s.recv(1024))
        known_clients[(ip, port)] = peer_public_key

    symmetric_key = os.urandom(32)
    encrypted_symmetric_key = peer_public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    iv = os.urandom(16)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv)).encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    s.send(encrypted_symmetric_key)
    s.send(iv + encrypted_message)
    s.close()


def start_client():
    local_ip = get_local_ip()
    local_port = int(input("Enter port to listen on: "))

    threading.Thread(target=listen_for_connections, args=(local_port,), daemon=True).start()

    while True:
        print("Select an action:")
        print("1. Send a message to another client")
        print("2. Show my IP and port")
        print("3. Exit")

        choice = input("Enter action number: ")

        if choice == '1':
            peer_ip = input("Enter recipient IP: ")
            peer_port = int(input("Enter recipient port: "))
            message = input("Enter message to send: ")
            connect_to_peer(peer_ip, peer_port, message)

        elif choice == '2':
            print(f"My IP: {local_ip}, port: {local_port}")

        elif choice == '3':
            break

        else:
            print("Invalid input. Please try again.")


if __name__ == "__main__":
    start_client()
