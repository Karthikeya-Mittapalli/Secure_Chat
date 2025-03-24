import socket
import threading
import struct
from key_exchange import KeyExchange
from digital_signature import DigitalSignature
from message_encryption import MessageEncryption
from key_management import load_public_key

HOST = '127.0.0.1'
PORT = 12345

server_key_exchange = KeyExchange()
server_signature = DigitalSignature()

def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Connection closed while receiving data.")
        data += packet
    return data

def handle_client(client_socket):
    print("[Server] Handling new client connection.")
    
    # Step 1: Receive Client ID
    # length = struct.unpack(">I", client_socket.recv(4))[0]
    # client_id = recv_exact(client_socket, length).decode()
    # print(f"[Server] Client ID received: {client_id}")
    # Step 1: Receive Client ID
    length_data = client_socket.recv(4)  # Receive 4-byte length
    if not length_data:
        print("[Server] Error: No data received for client ID length.")
        client_socket.close()
        return

    length = struct.unpack(">I", length_data)[0]
    client_id = recv_exact(client_socket, length).decode()
    print(f"[Server] Received Client ID: {client_id} (Length: {length})")



    # Step 2: Retrieve Stored Client ECC Public Key
    try:
        client_public_key = load_public_key(client_id)
    except FileNotFoundError:
        print(f"[Server] No registered public key found for client ID: {client_id}. Rejecting connection.")
        client_socket.close()
        return

    # Step 3: Receive Nonce & Signature from Client
    length = struct.unpack(">I", client_socket.recv(4))[0]
    data = recv_exact(client_socket, length)

    nonce_length = 32  # We know nonce is always 32 bytes
    nonce = data[:nonce_length]
    client_signature = data[nonce_length:]  # Remaining bytes are the signature

    # Step 4: Verify Client's Signature on Nonce
    if not server_signature.verify_signature(nonce, client_signature, client_public_key):
        print("[Server] Client authentication failed. Closing connection.")
        client_socket.close()
        return

    print("[Server] Client successfully authenticated.")

    

    # Step 5: Proceed with Hybrid Key Exchange
    server_ecdh_pub = server_key_exchange.get_ecdh_public_bytes()
    server_kyber_pub, server_kyber_secret = server_key_exchange.kyber.keygen()

    length = struct.unpack(">I", client_socket.recv(4))[0]
    client_ecdh_pub = recv_exact(client_socket, length)
    print(f"[Server] Received Client's ECDH Public Key: {client_ecdh_pub.hex()}")

    client_socket.sendall(struct.pack(">I", len(server_ecdh_pub)) + server_ecdh_pub)
    client_socket.sendall(struct.pack(">I", len(server_kyber_pub)) + server_kyber_pub)
    print("[Server] Sent ECC and Kyber Public Keys.")
    
    length = struct.unpack(">I", client_socket.recv(4))[0]
    kyber_ciphertext = recv_exact(client_socket, length)
    print(f"[Server] Received Kyber Ciphertext (length={len(kyber_ciphertext)}).")

    aes_shared_key = server_key_exchange.hybrid_key_decapsulation(kyber_ciphertext, server_kyber_secret, client_ecdh_pub)
    print(f"[Server] Shared Key Derived: {aes_shared_key.hex()}")

    encryption = MessageEncryption(aes_shared_key)

    # Start Secure Communication Threads
    threading.Thread(target=receive_messages, args=(client_socket, encryption)).start()
    threading.Thread(target=send_messages, args=(client_socket, encryption)).start()

def receive_messages(client_socket, encryption):
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("[Server] Client disconnected.")
                break

            iv, tag, ciphertext = data.split(b'||')
            decrypted_message = encryption.decrypt(iv, tag, ciphertext)
            print(f"[Client] {decrypted_message.decode()}")
        except Exception as e:
            print(f"[Server] Error receiving message: {e}")
            break

def send_messages(client_socket, encryption):
    while True:
        message = input("[Server] Enter message: ").encode()
        iv, tag, ciphertext = encryption.encrypt(message)
        client_socket.sendall(b'||'.join([iv, tag, ciphertext]))

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print("[Server] Listening for connections...")

    while True:
        client_socket, _ = server_socket.accept()
        print("[Server] Client connected.")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()
