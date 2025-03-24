import socket
import threading
import struct
import os
import secrets
from key_exchange import KeyExchange
from digital_signature import DigitalSignature
from message_encryption import MessageEncryption
from key_management import load_private_key,load_public_key

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
        message = input(f"{client_id} Enter message: ").encode()

        # Encrypt the message
        iv, tag, ciphertext = encryption.encrypt(message)

        # Send Encrypted Message
        client_socket.sendall(b'||'.join([iv, tag, ciphertext]))
        print(f"{client_id} Encrypted message sent.")

def verify_connection(client_socket):
    # Step 1: Send Client ID
    # Step 1: Send Client ID with length prefix
    client_id_bytes = client_id.encode()
    client_socket.sendall(struct.pack(">I", len(client_id_bytes)) + client_id_bytes)
    print(f"{client_id} Sent Client ID: {client_id} (Length: {len(client_id_bytes)})")

    # Step 2: Retrieve Client Private Key
    private_key_path = os.path.join("private_keys", f"{client_id}_private.pem")
    if not os.path.exists(private_key_path):
        print(f"{client_id} Private key not found! Exiting.")
        return
    client_private_key = load_private_key(client_id)

    # Step 3: Generate and Sign Nonce
    nonce = secrets.token_bytes(32)
    signature = client_signature.sign_message(nonce, client_private_key)

    # Step 4: Send Nonce and Signature to Server
    # client_socket.sendall(struct.pack(">I", len(nonce)) + nonce)
    # client_socket.sendall(struct.pack(">I", len(signature)) + signature)
    client_socket.sendall(struct.pack(">I", len(nonce) + len(signature)) + nonce + signature)
    print(f"{client_id} Sent nonce and signature for authentication.")

    # Step 1: Wait for server authentication response
    print("Waiting for Confirmation")
    Confirmation_data = client_socket.recv(4)
    if not Confirmation_data:
        print("Connection Closed before confirmation received")
        client_socket.close()
        return False
    confirmation_length = struct.unpack(">I",Confirmation_data)[0]
    if confirmation_length == 0:
        print("My Authentication Failed.")
        client_socket.close()
        return False
    else:
        print("Server Authenticated Me")
    
    # Now Verify Server Signature
    s_length_data = client_socket.recv(4)
    if not s_length_data:
        print(f"{client_id} Server closed connection before sending its ID.")
        client_socket.close()
        return False
    
    s_length = struct.unpack(">I",s_length_data)[0]
    server_id = recv_exact(client_socket,s_length).decode()
    print(f"{client_id} Received Server ID: {server_id} (Length: {s_length})")

    try:
        server_public_key = load_public_key(server_id)
    except FileNotFoundError:
        print(f"{server_id} No registered public key found for server ID: {server_id}. Rejecting connection.")
        client_socket.close()
        return False
    
    svr_length = struct.unpack(">I",client_socket.recv(4))[0]
    data = recv_exact(client_socket,svr_length)

    svr_nonce_length = 32
    svr_nonce = data[:svr_nonce_length]
    server_signature = data[svr_nonce_length:]
    
    # client_socket.sendall(struct.pack(">I", 0)) 
    # client_socket.close()
    if not client_signature.verify_signature(svr_nonce,server_signature,server_public_key):
        print(f"{client_id} Server Authentication Failed")
        client_socket.close()
        return False
    else:
        client_socket.sendall(struct.pack(">I",5))
        print(f"{client_id} Server Authentication Success")

    return True

def start_client():
    """Connects to the server, performs authentication, and securely sends messages."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"{client_id} Connected to Server.")

    if not verify_connection(client_socket):
        print("[Mutual Authentication Failed]")
        # client_socket.close()
        return
    else:
        print("Authentication Successful")

    # Step 5: Proceed with Key Exchange
    client_ecdh_pub = client_key_exchange.get_ecdh_public_bytes()
    client_socket.sendall(struct.pack(">I", len(client_ecdh_pub)) + client_ecdh_pub)
    print(f"{client_id} Sent ECDH Public Key = {client_ecdh_pub.hex()}")

    # length = struct.unpack(">I", client_socket.recv(4))[0]
    # server_ecdh_pub = recv_exact(client_socket, length)
    # print(f"[Client] Received Server's ECDH Public Key = {server_ecdh_pub.hex()}")
    try:
        length_data = client_socket.recv(4)  # Attempt to receive data
        if not length_data:
            print(f"{client_id} Server disconnected.")
            client_socket.close()
            return  # Exit cleanly

        length = struct.unpack(">I", length_data)[0]
        server_ecdh_pub = recv_exact(client_socket, length)
        print(f"{client_id} Received Server's ECDH Public Key = {server_ecdh_pub.hex()}")

    except ConnectionResetError:
        print(f"{client_id} Server forcibly closed the connection.")
        client_socket.close()
        return
    except Exception as e:
        print(f"{client_id} Error: {e}")
        client_socket.close()
        return

    length = struct.unpack(">I", client_socket.recv(4))[0]
    server_kyber_pub = recv_exact(client_socket, length)
    print(f"{client_id} Received Server's Kyber Public Key = {server_kyber_pub.hex()}")

    aes_shared_key, kyber_ciphertext = client_key_exchange.hybrid_key_exchange(server_ecdh_pub, server_kyber_pub)
    client_socket.sendall(struct.pack(">I", len(kyber_ciphertext)) + kyber_ciphertext)
    print(f"{client_id} Sent Kyber Ciphertext = {kyber_ciphertext.hex()}")
    print(f"{client_id} Shared Key Derived: {aes_shared_key.hex()}")

    encryption = MessageEncryption(aes_shared_key)

    threading.Thread(target=handle_receive, args=(client_socket, encryption)).start()
    threading.Thread(target=handle_send, args=(client_socket, encryption)).start()

if __name__ == "__main__":
    start_client()
