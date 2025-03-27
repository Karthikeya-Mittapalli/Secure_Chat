import socket
import threading
import struct
import secrets
import os
from key_exchange import KeyExchange
from digital_signature import DigitalSignature
from message_encryption import MessageEncryption
from key_management import load_public_key, load_private_key
from hmac_utils import generate_hmac,verify_hmac

HOST = '127.0.0.1'
PORT = 12345
server_id = "Mark"

server_key_exchange = KeyExchange()
server_signature = DigitalSignature()
stop_event = threading.Event()

def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Connection closed while receiving data.")
        data += packet
    return data

def verify_connection(client_socket):
    # Client Authentication
    # Step: Receive Client ID
    length_data = client_socket.recv(4)  # Receive 4-byte length
    if not length_data:
        print(f"{server_id} Error: No data received for client ID length.")
        client_socket.close()
        return

    length = struct.unpack(">I", length_data)[0]
    client_id = recv_exact(client_socket, length).decode()
    print(f"{server_id} Received Client ID: {client_id} (Length: {length})")

    # Step: Retrieve Stored Client ECC Public Key
    try:
        client_public_key = load_public_key(client_id)
    except FileNotFoundError:
        print(f"{server_id}] No registered public key found for client ID: {client_id}. Rejecting connection.")
        client_socket.sendall(struct.pack(">I", 0))  # Send rejection signal
        client_socket.close()
        return

    # Step: Receive Nonce & Signature from Client
    length = struct.unpack(">I", client_socket.recv(4))[0]
    data = recv_exact(client_socket, length)

    nonce_length = 32  # We know nonce is always 32 bytes
    nonce = data[:nonce_length]
    client_signature = data[nonce_length:]  # Remaining bytes are the signature

    # Step: Verify Client's Signature on Nonce
    if not server_signature.verify_signature(nonce, client_signature, client_public_key):
        print(f"{server_id} Client authentication failed.")
        client_socket.sendall(struct.pack(">I",0))
        client_socket.close()
        return False
    else:
        client_socket.sendall(struct.pack(">I",4))
        print(f"{server_id} Client authentication successful.")
    
    # Step: Server Authentication - Generate and Send Nonce & Signature
    server_id_bytes = server_id.encode()
    client_socket.sendall(struct.pack(">I", len(server_id_bytes)) + server_id_bytes)
    print(f"{client_id} Sent Client ID: {server_id} (Length: {len(server_id_bytes)})")

    private_key_path = os.path.join("private_keys",f"{server_id}_private.pem")
    if not os.path.exists(private_key_path):
        client_socket.sendall(struct.pack(">I",0))
        print(f"{server_id} Private Key not found")
        return False
    server_private_key = load_private_key(server_id)

    nonce = secrets.token_bytes(32)
    signature = server_signature.sign_message(nonce,server_private_key)

    # Step: Send Nonce and Signature to Client
    client_socket.sendall(struct.pack(">I", len(nonce) + len(signature)) + nonce + signature)
    print(f"{server_id} Sent nonce and signature for authentication.")
    print(f"Waiting for Confirmation")
    Confirmation_data = client_socket.recv(4)
    if not Confirmation_data:
        print(f"Connection Closed before confirmation received")
        client_socket.close()
        return False
    confirmation_length = struct.unpack(">I",Confirmation_data)[0]
    if confirmation_length == 0:
        print(f"My Authentication Failed.")
        client_socket.close()
        return False
    else:
        print(f"Client Authenticated Me")
    return True

def handle_client(client_socket):
    print(f"{server_id} Handling new client connection.")
    
    # Step: Verification of Connected User
    if not verify_connection(client_socket):
        print("Authentication failed. Closing connection.")
        return
    else:
        print("Authentication Successful.")

    # Step: Secure Hybrid Key Exchange & Shared Key Derivation
    server_ecdh_pub = server_key_exchange.get_ecdh_public_bytes()
    server_kyber_pub, server_kyber_secret = server_key_exchange.kyber.keygen()

    length = struct.unpack(">I", client_socket.recv(4))[0]
    client_ecdh_pub = recv_exact(client_socket, length)
    print(f"{server_id} Received Client's ECDH Public Key: {client_ecdh_pub.hex()}")

    client_socket.sendall(struct.pack(">I", len(server_ecdh_pub)) + server_ecdh_pub)
    client_socket.sendall(struct.pack(">I", len(server_kyber_pub)) + server_kyber_pub)
    print(f"{server_id} Sent ECDH and Kyber Public Keys.")
    print(f"{server_id} Sent ECDH Public Key = ",server_ecdh_pub.hex())
    print(f"{server_id} Sent Kyber Public Key = ",server_kyber_pub.hex())
    
    length = struct.unpack(">I", client_socket.recv(4))[0]
    kyber_ciphertext = recv_exact(client_socket, length)
    # print(f"{server_id} Received Kyber Ciphertext (length={len(kyber_ciphertext)}).")
    print(f"{server_id} Received Kyber Ciphertext {kyber_ciphertext.hex()}.")

    aes_shared_key,hmac_shared_key = server_key_exchange.hybrid_key_decapsulation(kyber_ciphertext, server_kyber_secret, client_ecdh_pub)
    print(f"{server_id} Shared Key Derived: {aes_shared_key.hex()}")

    encryption = MessageEncryption(aes_shared_key)

    # Start Secure Communication Threads
    threading.Thread(target=receive_messages, args=(client_socket, encryption,hmac_shared_key)).start()
    threading.Thread(target=send_messages, args=(client_socket, encryption,hmac_shared_key)).start()

def receive_messages(client_socket, encryption,hmac_key):
    while not stop_event.is_set(): #Checking if EXIT is requested
        client_socket.settimeout(1.0)
        try:
            data = client_socket.recv(4096)
            if not data:
                print(f"{server_id} Client disconnected.")
                break

            iv, tag, ciphertext,received_hmac = data.split(b'||')

            # Verify HMAC before decryption
            if not verify_hmac(hmac_key, ciphertext, received_hmac):
                print("[ERROR] HMAC verification failed! Message tampered.")
                continue  # Ignore tampered messages
            else:
                print("Message is Genuine!")

            decrypted_message = encryption.decrypt(iv, tag, ciphertext)
            print(f"\n[Client] {decrypted_message.decode()}")

            if decrypted_message == "EXIT":  # Client wants to disconnect
                print(f"{server_id} Client requested disconnect.")
                stop_event.set()
                client_socket.close()
                break  # Exit loop to terminate server-side handling
        
        except socket.timeout:
            continue
        except Exception as e:
            print(f"{server_id} Error receiving message: {e}")
            break

def send_messages(client_socket, encryption,hmac_key):
    while not stop_event.is_set():
        client_socket.settimeout(1.0)
        try:
            message = input(f"{server_id} Enter message: ").encode()

            if message == b"EXIT":
                iv, tag, ciphertext = encryption.encrypt(message)
                hmac_value = generate_hmac(hmac_key, ciphertext)
                client_socket.sendall(b'||'.join([iv, tag, ciphertext, hmac_value]))
                print("Server closing connection...")
                stop_event.set()
                client_socket.close()
                break

            iv, tag, ciphertext = encryption.encrypt(message)

            hmac_value = generate_hmac(hmac_key,ciphertext)
            # SEnding Encrypted Message + HMAC
            client_socket.sendall(b'||'.join([iv, tag, ciphertext,hmac_value]))
        except socket.timeout:
            continue
        except Exception as e:
            print(f"{server_id} Error receiving message Connection Maybe Closed = {e}")
            break

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"{server_id} Listening for connections...")

    while True:
        client_socket, _ = server_socket.accept()
        print(f"{server_id} Client connected.")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()
