import socket
import threading
import struct
import os
import secrets
from key_exchange import KeyExchange
from digital_signature import DigitalSignature
from message_encryption import MessageEncryption
from key_management import load_private_key

HOST = '127.0.0.1'
PORT = 12345

client_key_exchange = KeyExchange()
client_signature = DigitalSignature()
client_id = "Shawn"

def recv_exact(sock, length):
    """Receive exactly 'length' bytes from socket."""
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Connection closed while receiving data.")
        data += packet
    return data

def handle_receive(client_socket, encryption):
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("[Server] Client disconnected.")
                break

            print(f"[Server] Received encrypted message: {data.hex()}")

            try:
                iv, tag, ciphertext = data.split(b'||')  # Ensure correct format
                decrypted_message = encryption.decrypt(iv, tag, ciphertext)
                print(f"[Client] {decrypted_message.decode()}")
            except Exception as e:
                print(f"[Server] Error decrypting message: {e}")
                break  # Prevent infinite error loop

        except Exception as e:
            print(f"[Server] Error receiving message: {e}")
            break

def handle_send(client_socket, encryption):
    """Allows the client to send encrypted messages to the server."""
    while True:
        message = input("[Client] Enter message: ").encode()

        # Encrypt the message
        iv, tag, ciphertext = encryption.encrypt(message)

        # Send Encrypted Message
        client_socket.sendall(b'||'.join([iv, tag, ciphertext]))
        print("[Client] Encrypted message sent.")

def start_client():
    """Connects to the server, performs authentication, and securely sends messages."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print("[Client] Connected to Server.")

    # Step 1: Send Client ID
    # Step 1: Send Client ID with length prefix
    client_id_bytes = client_id.encode()
    client_socket.sendall(struct.pack(">I", len(client_id_bytes)) + client_id_bytes)
    print(f"[Client] Sent Client ID: {client_id} (Length: {len(client_id_bytes)})")

    # Step 2: Retrieve Client Private Key
    private_key_path = os.path.join("private_keys", f"{client_id}_private.pem")
    if not os.path.exists(private_key_path):
        print("[Client] Private key not found! Exiting.")
        return
    client_private_key = load_private_key(client_id)

    # Step 3: Generate and Sign Nonce
    nonce = secrets.token_bytes(32)
    signature = client_signature.sign_message(nonce, client_private_key)

    # Step 4: Send Nonce and Signature to Server
    # client_socket.sendall(struct.pack(">I", len(nonce)) + nonce)
    # client_socket.sendall(struct.pack(">I", len(signature)) + signature)
    client_socket.sendall(struct.pack(">I", len(nonce) + len(signature)) + nonce + signature)
    print("[Client] Sent nonce and signature for authentication.")

    # print("[Server] Client authentication failed. Closing connection.")
    # client_socket.close()
    # return

    # Step 5: Proceed with Key Exchange
    client_ecdh_pub = client_key_exchange.get_ecdh_public_bytes()
    client_socket.sendall(struct.pack(">I", len(client_ecdh_pub)) + client_ecdh_pub)
    print(f"[Client] Sent ECDH Public Key = {client_ecdh_pub.hex()}")

    # length = struct.unpack(">I", client_socket.recv(4))[0]
    # server_ecdh_pub = recv_exact(client_socket, length)
    # print(f"[Client] Received Server's ECDH Public Key = {server_ecdh_pub.hex()}")
    try:
        length_data = client_socket.recv(4)  # Attempt to receive data
        if not length_data:
            print("[Client] Server disconnected.")
            client_socket.close()
            return  # Exit cleanly

        length = struct.unpack(">I", length_data)[0]
        server_ecdh_pub = recv_exact(client_socket, length)
        print(f"[Client] Received Server's ECDH Public Key = {server_ecdh_pub.hex()}")

    except ConnectionResetError:
        print("[Client] Server forcibly closed the connection.")
        client_socket.close()
        return
    except Exception as e:
        print(f"[Client] Error: {e}")
        client_socket.close()
        return

    length = struct.unpack(">I", client_socket.recv(4))[0]
    server_kyber_pub = recv_exact(client_socket, length)
    print(f"[Client] Received Server's Kyber Public Key = {server_kyber_pub.hex()}")

    aes_shared_key, kyber_ciphertext = client_key_exchange.hybrid_key_exchange(server_ecdh_pub, server_kyber_pub)
    client_socket.sendall(struct.pack(">I", len(kyber_ciphertext)) + kyber_ciphertext)
    print(f"[Client] Sent Kyber Ciphertext = {kyber_ciphertext.hex()}")
    print(f"[Client] Shared Key Derived: {aes_shared_key.hex()}")

    encryption = MessageEncryption(aes_shared_key)

    threading.Thread(target=handle_receive, args=(client_socket, encryption)).start()
    threading.Thread(target=handle_send, args=(client_socket, encryption)).start()

if __name__ == "__main__":
    start_client()
