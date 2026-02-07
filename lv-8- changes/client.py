import argparse
import socket
import threading
import sys
from cryptography.fernet import Fernet
from datetime import datetime
import os
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

stop_event = threading.Event()
current_room = "default"

# Client's RSA key pair
client_private_key = None
client_public_key = None
session_fernet = None # This will hold the dynamically exchanged Fernet key

def generate_rsa_keys_client():
    global client_private_key, client_public_key
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    client_public_key = client_private_key.public_key()

generate_rsa_keys_client() # Generate client keys on startup

# ------------------ Dynamic Logging per Session ------------------
#  gives two files stored for logs
def get_log_path(room_name="default"):
    os.makedirs('chat_logs', exist_ok=True)
    # Session-based log file (timestamped)
    filename = f"ROOM-{room_name}-{datetime.now().strftime('%Y%m%d_%H-%M-%S')}.txt"
    return os.path.join('chat_logs', filename)

# Create log_file only once per session
log_file = None
def init_log_file(room_name):
    global log_file
    log_file = get_log_path(room_name)

def write_log(line):
    if log_file:
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception as e:
            print(f"[WARN] Log write error: {e}")

# ------------------ Receive messages ------------------
import hmac
import hashlib


def recv_loop(sock, initial_fernet, username):
    """Receive and decrypt messages from server with graceful disconnect handling."""
    
    old_keys = []
    local_addr = None
    fileobj = None
    global session_fernet
    

    # Use session_fernet for all communication after key exchange
    # Start with initial_fernet, will switch to session_fernet when we get room key
    current_fernet = initial_fernet

    try:
        try:
            local_addr = sock.getsockname()
        except:
            local_addr = "Unknown"

        fileobj = sock.makefile('rb')
        write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {local_addr} :- joined the room")

        while not stop_event.is_set():
            try:
                try:
                    line = fileobj.readline()
                except (OSError, ValueError) as e:
                    print(f"\n[INFO] Socket or file read error: {e}")
                    stop_event.set()
                    break

                if not line:
                    print("\n[ERROR] Server disconnected (connection closed).")
                    stop_event.set()
                    break
                
                line_bytes = line.rstrip(b'\n')
                
                # Handle server ROOM_FERNET_KEY message (initial key exchange)

                # Handle server NEW_ROOM_KEY message (key rotation)
                # Add this handler after line 92 (before the NEW_ROOM_KEY handler):
                try:
                    decrypted_line = initial_fernet.decrypt(line_bytes).decode('utf-8')
                    if decrypted_line.startswith("ROOM_FERNET_KEY:"):
                        encrypted_room_key_b64 = decrypted_line.split("ROOM_FERNET_KEY:", 1)[1].strip()
                        encrypted_room_key = base64.b64decode(encrypted_room_key_b64)

                        # Decrypt the room key using client's private key
                        room_fernet_key = client_private_key.decrypt(
                            encrypted_room_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        
                        # Set this as the session fernet
                        session_fernet = Fernet(room_fernet_key)
                        current_fernet = session_fernet
                        print("[INFO] Received room encryption key.")
                        write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {local_addr} :- Received room key.")
                        continue
                except:
                    pass

                # If we don't have a session fernet yet, skip regular message processing
                if session_fernet is None:
                    # We're still waiting for the room key
                    print("[ERROR] Session key not established. Cannot send messages. Waiting...")
                    time.sleep(1)  # Wait a bit
                    continue
                
                # Separate message and HMAC signature (for regular encrypted messages)
                if len(parts) != 2:
                    print(f"[WARN] Invalid message format from server: {line_bytes}")
                    continue
                
                encrypted_message_content = parts[0]

                # Verify HMAC before decryption
                if current_fernet is None:
                    print(f"[WARN] Current Fernet not available. Cannot verify HMAC.")
                    continue

                hmac_key = current_fernet._signing_key
                expected_hmac_signature = generate_hmac(hmac_key, encrypted_message_content)

                if not hmac.compare_digest(expected_hmac_signature, received_hmac_signature):
                    print(f"\r[WARN] HMAC verification failed for incoming message. Message tampered or key mismatch.\n> ", end='', flush=True)
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {local_addr} :- HMAC verification failed for incoming message.")
                    continue

                try:
                    # Try to decrypt with current key first
                    msg = current_fernet.decrypt(encrypted_message_content).decode('utf-8')
                except Exception:
                    # If fails, try with old keys
                    decrypted = False
                    for old_fernet in old_keys:
                        try:
                            msg = old_fernet.decrypt(encrypted_message_content).decode('utf-8')
                            decrypted = True
                            print(f"\r[INFO] Decrypted with previous room key\n> ", end='', flush=True)
                            break
                        except:
                            continue
                    
                    if not decrypted:
                        print(f"\n[WARN] Message decrypt error (tried {len(old_keys) + 1} keys)")
                        continue

            except (ConnectionResetError, OSError):
                print("\n[INFO] Server forcibly closed the connection (WinError 10054).")
                stop_event.set()
                break
            except Exception as e:
                print(f"\n[ERROR] Receive error: {e}")
                stop_event.set()
                break
    finally:
        try:
            if fileobj:
                fileobj.close()
        except:
            pass
        try:
            sock.close()
        except:
            pass
        print("[INFO] Client receive loop exited.")
        try:
            write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {local_addr} :- receive loop exited")
        except:
            pass

# ------------------ Command Parser ------------------
def handle_command(msg, sock, username):
    """Parse and execute client commands."""
    global current_room, session_fernet

    if session_fernet is None:
        print("[ERROR] Session key not established. Cannot send commands yet.")
        return True # Treat as handled to prevent sending raw command

    if msg == "/help":
        print("""Available commands:
    /help - show this help
    /quit - exit chat
    /rooms - list available rooms
    /join <room> - switch to another room
    /users - list users in current room
    /msg <user> <message> - private messageciphertext | hmac
    /clear - clear terminal
    """)
        return True

    elif msg == "/quit":
        stop_event.set()
        return True

    elif msg == "/clear":
        os.system('cls' if os.name == 'nt' else 'clear')
        return True

    elif msg.startswith("/join "):
        parts = msg.split(" ", 1)
        if len(parts) > 1:
            new_room = parts[1].strip()
            if new_room:
                try:
                    sock.sendall(session_fernet.encrypt(f"/join {new_room}".encode()) + b'\n')
                    # Server will confirm room change, client updates current_room in recv_loop
                except Exception as e:
                    print(f"[ERROR] Failed to send join command: {e}")
        else:
            print("[INFO] Usage: /join <room_name>")
        return True

    elif msg == "/rooms":
        try:
            sock.sendall(session_fernet.encrypt(b"/rooms") + b'\n')
        except Exception as e:
            print(f"[ERROR] Failed to send rooms command: {e}")
        return True

    elif msg == "/users":
        try:
            sock.sendall(session_fernet.encrypt(b"/users") + b'\n')
        except Exception as e:
            print(f"[ERROR] Failed to send users command: {e}")
        return True

    elif msg.startswith("/msg "):
        try:
            sock.sendall(session_fernet.encrypt(msg.encode()) + b'\n')
        except Exception as e:
            print(f"[ERROR] Failed to send private message: {e}")
        return True

    return False  # Not a command

# ------------------ Messaging loop ------------------  

def messaging_loop(sock, initial_fernet, username):
    local_addr = sock.getsockname()
    try:
        while not stop_event.is_set():
            msg = input("> ").strip()
            if not msg:
                continue

            # Multi-room command support
            if handle_command(msg, sock, username):
                continue

            # Use session_fernet for regular messages after key exchange
            if session_fernet:
                try:
                    # Encrypt message
                    encrypted_msg_content = session_fernet.encrypt(msg.encode())
                    
                    # Generate HMAC
                    hmac_key = session_fernet._signing_key # Accessing internal signing key
                    hmac_signature = generate_hmac(hmac_key, encrypted_msg_content)
                    
                    # Send encrypted message + HMAC
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {local_addr} :- sent: {msg}")
                    
                    if msg == "/quit":
                        stop_event.set()
                        break
                except (ConnectionResetError, BrokenPipeError):
                    print("\n[INFO] Server connection lost.")
                    stop_event.set()
                    break
                except Exception as e:
                    print(f"\n[ERROR] Send error: {e}")
                    stop_event.set()
                    break
            else:
                print("[ERROR] Session key not established. Cannot send messages.")
            time.sleep(0.01)
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
        stop_event.set()
    finally:
        try:
            sock.close()
        except:
            pass
        print("[INFO] Client exited.")
        write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {local_addr} :- client exited")

# ------------------ Main ------------------
def main():
    global current_room

    p = argparse.ArgumentParser()
    p.add_argument('--key', default='shared.key')
    p.add_argument('--host', default='192.168.56.1')
    p.add_argument('--port', type=int, default=65432)
    p.add_argument('--name', default='Client')
    p.add_argument('--room', default='default')
    args = p.parse_args()

    current_room = args.room

    # Load encryption key
    try:
        key = open(args.key, 'rb').read().strip()
    except Exception as e:
        print(f"[ERROR] Failed to read key file: {e}")
        sys.exit(1)

    initial_fernet = Fernet(key) # Used for initial auth messages

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((args.host, args.port))
        print(f"[INFO] Connected to {args.host}:{args.port} in room '{current_room}'")
    except Exception as e:
        print(f"[ERROR] Cannot connect to server: {e}")
        sys.exit(1)

# ------------------ Authentication ------------------
    username = None

    try:
        initial_bytes = sock.recv(1024).strip()
        if not initial_bytes:
            print("[ERROR] Server closed connection.")
            sock.close()
            sys.exit(1)

        initial = initial_fernet.decrypt(initial_bytes).decode()
    except (ConnectionAbortedError, ConnectionResetError):
        print("[ERROR] Server disconnected unexpectedly during authentication.")
        sock.close()
        sys.exit(1)

    if initial == "AUTH_REQUIRED":
        print("Choose option:\n1. Register\n2. Login")
        choice = input("> ").strip()
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        try:
            if choice == "1":
                sock.sendall(initial_fernet.encrypt(f"/register {username} {password}".encode()) + b'\n')
            elif choice == "2":
                sock.sendall(initial_fernet.encrypt(f"/login {username} {password}".encode()) + b'\n')
            else:
                print("[ERROR] Invalid choice.")
                sock.close()
                sys.exit(1)

            resp_bytes = sock.recv(1024).strip()
            if not resp_bytes:
                print("[ERROR] Server closed connection.")
                sock.close()
                sys.exit(1)

            resp = initial_fernet.decrypt(resp_bytes).decode()
            if resp.startswith("TOKEN "):
                # Token is still generated by server but not saved
                print("[INFO] Authentication successful.")
            else:
                print(f"[INFO] {resp}")
                sock.close()
                sys.exit(1)

        except (ConnectionAbortedError, ConnectionResetError):
            print("[ERROR] Server disconnected unexpectedly.")
            sock.close()
            sys.exit(1)

    # ------------------ Key Exchange ------------------
    try:
        # Recv SERVER_PUB_KEY
        server_pub_bytes = sock.recv(1024).strip()
        if not server_pub_bytes:
            print("[ERROR] Server closed connection.")
            sock.close()
            sys.exit(1)

        server_pub_decrypted = initial_fernet.decrypt(server_pub_bytes).decode()
        if not server_pub_decrypted.startswith("SERVER_PUB_KEY:"):
            print("[ERROR] Expected SERVER_PUB_KEY")
            sock.close()
            sys.exit(1)

        server_pub_pem = base64.b64decode(server_pub_decrypted.split("SERVER_PUB_KEY:", 1)[1].strip())
        server_rsa_public_key = serialization.load_pem_public_key(server_pub_pem, backend=default_backend())

        # Send client's public key to the server
        client_public_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sock.sendall(initial_fernet.encrypt(b"CLIENT_PUB_KEY:" + base64.b64encode(client_public_pem)) + b'\n')

         # NEW: Just send a placeholder, server will respond with room key
        sock.sendall(initial_fernet.encrypt(b"CLIENT_SESSION_KEY:placeholder") + b'\n')
        
        # Wait for server to send room key (handled in recv_loop)
        print("[INFO] Waiting for room encryption key...")

    except Exception as e:
        print(f"[ERROR] Key exchange failed: {e}")
        sock.close()
        sys.exit(1)

    if not username:
        username = args.name if args.name != "Client" else "Guest"

    init_log_file(current_room) # Initialize log file for the current room

    # Start receive thread
    threading.Thread(target=recv_loop, args=(sock, initial_fernet, username), daemon=True).start()

    # Keep client alive for messaging
    messaging_loop(sock, initial_fernet, username)

if __name__ == '__main__':
    main()
