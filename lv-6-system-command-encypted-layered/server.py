import argparse
import socket
import threading
import sys
from cryptography.fernet import Fernet
from datetime import datetime
import os
import json
import secrets
import queue
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import hmac
import hashlib
import time

clients = []
clients_lock = threading.Lock()
stop_event = threading.Event()
room_code = "default"
client_meta = {}  # conn -> {"username": str, "room": str, "session_key": Fernet, "rsa_public_key": None}

# Server's RSA key pair
server_private_key = None
server_public_key = None

def generate_rsa_keys():
    global server_private_key, server_public_key
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    server_public_key = server_private_key.public_key()

generate_rsa_keys() # Generate server keys on startup

# ------------------ Dynamic Logging per Room ------------------
def get_server_log_path(room_name="default"):
    os.makedirs('server_logs', exist_ok=True)
    folder = os.path.join('server_logs', room_name)
    os.makedirs(folder, exist_ok=True)
    filename = f"ROOM{{{room_name}}}-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    return os.path.join(folder, filename)

log_file = get_server_log_path(room_code)



# ------------------ User database ------------------
USER_FILE = "users.json"

def load_users():
    if os.path.exists(USER_FILE):
        try:
            with open(USER_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_users(users):  
    try:
        with open(USER_FILE, 'w') as f:
            json.dump(users, f)
    except:
        pass

users = load_users()

# ------------------ Token persistence ------------------
TOKEN_FILE = "tokens.json"

def load_tokens():
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_tokens(tokens):
    try:
        with open(TOKEN_FILE, 'w') as f:
            json.dump(tokens, f)
    except:
        pass

tokens = load_tokens()

# ------------------ Logging ------------------
def write_log(line):
    if log_file:
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception as e:
            print(f"[WARN] Log write error: {e}")

# ------------------ Broadcast ------------------
room_queues = {}
room_threads = {}
ROOM_BROADCAST_LOCK = threading.Lock()

def start_room_broadcast(room):
    q = room_queues[room]
    while not stop_event.is_set():
        try:
            message, sender = q.get(timeout=0.5)
        except queue.Empty:
            continue

        with clients_lock:
            for c in clients[:]:
                meta = client_meta.get(c, {})
                if meta.get("room") != room or c == sender:
                    continue
                try:
                    c.sendall(message + b'\n')
                except Exception as e:
                    print(f"[WARN] Failed to send message to {meta.get('username','unknown')}: {e}")
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Server :- Failed to broadcast: {e}")
                    try:
                        c.sendall(b"Network connectivity lost. You were disconnected.\n")
                    except:
                        pass
                    clients.remove(c)
                    if c in client_meta:
                        del client_meta[c]
                    try:
                        c.close()
                    except:
                        pass

def broadcast(message, sender=None, room=None):
    if room is None:
        room = room_code
    with ROOM_BROADCAST_LOCK:
        if room not in room_queues:
            room_queues[room] = queue.Queue()
            t = threading.Thread(target=start_room_broadcast, args=(room,), daemon=True)
            t.start()
            room_threads[room] = t
    room_queues[room].put((message, sender))

def generate_hmac(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()

def send_private_message(fernet_instance, sender_username, target_username, message):
    with clients_lock:
        target_conn = None
        sender_conn = None
        for conn, meta in client_meta.items():
            if meta.get("username") == target_username:
                target_conn = conn
            if meta.get("username") == sender_username:
                sender_conn = conn

        if target_conn and client_meta[target_conn]["session_fernet"]:
            try:
                # Encrypt message
                encrypted_msg_content = fernet_instance.encrypt(f"SERVER_RESPONSE:PRIVATE_MESSAGE:[Private from {sender_username}] {message}".encode())
                
                # Generate HMAC
                hmac_key = client_meta[target_conn]["session_fernet"]._signing_key # Accessing internal signing key
                hmac_signature = generate_hmac(hmac_key, encrypted_msg_content)
                
                # Send encrypted message + HMAC
                target_conn.sendall(encrypted_msg_content + b'|' + base64.b64encode(hmac_signature) + b'\n')

                if sender_conn and client_meta[sender_conn]["session_fernet"]:
                    encrypted_sender_msg = fernet_instance.encrypt(f"SERVER_RESPONSE:PRIVATE_MESSAGE:[Private to {target_username}] {message}".encode())
                    hmac_key_sender = client_meta[sender_conn]["session_fernet"]._signing_key
                    hmac_signature_sender = generate_hmac(hmac_key_sender, encrypted_sender_msg)
                    sender_conn.sendall(encrypted_sender_msg + b'|' + base64.b64encode(hmac_signature_sender) + b'\n')

                print(f"[INFO] Private message from {sender_username} to {target_username}: {message}")
                write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{sender_username}}} :- private message to {target_username}: {message}")
            except Exception as e:
                print(f"[WARN] Failed to send private message to {target_username}: {e}")
                if sender_conn:
                    sender_conn.sendall(fernet_instance.encrypt(f"SERVER_RESPONSE:Failed to send private message to {target_username}.".encode()) + b'\n')
        else:
            if sender_conn:
                sender_conn.sendall(fernet_instance.encrypt(f"SERVER_RESPONSE:User '{target_username}' not found or offline.".encode()) + b'\n')
            print(f"[INFO] Private message from {sender_username} to {target_username} failed: user not found.")
            write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{sender_username}}} :- private message to {target_username} failed: user not found.")

# ------------------ Client handler ------------------
def recv_loop(conn, initial_fernet, addr):
    username = str(addr)
    client_meta[conn] = {"username": None, "room": room_code, "session_fernet": None, "message_count": 0, "last_key_rotation": datetime.now()}

    current_fernet = initial_fernet # Use initial_fernet for initial communication

    try:
        authed = False
        # AUTHENTICATION LOOP
        conn.sendall(initial_fernet.encrypt(b"AUTH_REQUIRED") + b'\n')
        auth_attempts = 0
        while not authed:
            if auth_attempts >= 5:  # Prevent brute force
                conn.close()
                return

            try:
                conn.settimeout(30.0)
                raw = conn.recv(1024).strip()
                if not raw:
                    return

                # Handle client's public key and session key exchange
                try:
                    msg = initial_fernet.decrypt(raw).decode()
                except Exception as e:
                    print(f"[WARN] Initial decryption failed for {addr}: {e}")
                    conn.close()
                    return

                if msg.startswith("CLIENT_PUB_KEY:"):
                    client_pub_key_pem = base64.b64decode(msg.split("CLIENT_PUB_KEY:", 1)[1].strip())
                    client_meta[conn]["rsa_public_key"] = serialization.load_pem_public_key(client_pub_key_pem, backend=default_backend())
                    print(f"[INFO] Received public key from {addr}.")
                    continue # Continue to wait for session key

                elif msg.startswith("CLIENT_SESSION_KEY:"):
                    encrypted_session_key_b64 = msg.split("CLIENT_SESSION_KEY:", 1)[1].strip()
                    encrypted_session_key = base64.b64decode(encrypted_session_key_b64)

                    # Decrypt the session key using server's private key
                    decrypted_session_key = server_private_key.decrypt(
                        encrypted_session_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    client_meta[conn]["session_fernet"] = Fernet(decrypted_session_key)
                    current_fernet = client_meta[conn]["session_fernet"] # Switch to session fernet
                    print(f"[INFO] Established session key with {addr}.")
                    authed = True # Authentication is complete after key exchange
                    break # Exit auth loop
                
                # Existing authentication logic (using initial_fernet)
                auth_attempts += 1
                global users, tokens

                if msg.startswith("/token "):
                    token = msg.split(" ", 1)[1]
                    if token in tokens:
                        username = tokens[token]
                        client_meta[conn]["username"] = username
                        conn.sendall(initial_fernet.encrypt(b"TOKEN_VALID") + b'\n')
                        # Send server's public key
                        server_public_pem = server_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        conn.sendall(initial_fernet.encrypt(b"SERVER_PUB_KEY:" + base64.b64encode(server_public_pem)) + b'\n')
                        # authed = True # Don't set authed here, wait for session key
                    else:
                        conn.sendall(initial_fernet.encrypt(b"TOKEN_INVALID") + b'\n')
                        # Stay in loop

                elif msg.startswith("/register "):
                    parts = msg.split(" ")
                    if len(parts) >= 3:
                        uname, pwd = parts[1], parts[2]
                        if uname in users:
                            conn.sendall(initial_fernet.encrypt(b"Username already exists.") + b'\n')
                        else:
                            users[uname] = {"password": pwd}
                            save_users(users)
                            username = uname
                            client_meta[conn]["username"] = username
                            token = secrets.token_hex(16)
                            tokens[token] = username
                            save_tokens(tokens)
                            conn.sendall(initial_fernet.encrypt(f"TOKEN {token}".encode()) + b'\n')
                            # Send server's public key
                            server_public_pem = server_public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            conn.sendall(initial_fernet.encrypt(b"SERVER_PUB_KEY:" + base64.b64encode(server_public_pem)) + b'\n')
                            print(f"[INFO] {addr} registered as {username}")
                            # authed = True # Don't set authed here, wait for session key
                    else:
                        conn.sendall(initial_fernet.encrypt(b"Invalid register command.") + b'\n')

                elif msg.startswith("/login "):
                    parts = msg.split(" ")
                    if len(parts) >= 3:
                        uname, pwd = parts[1], parts[2]
                        if uname in users and users[uname]["password"] == pwd:
                            username = uname
                            client_meta[conn]["username"] = username
                            token = secrets.token_hex(16)
                            tokens[token] = username
                            save_tokens(tokens)
                            conn.sendall(initial_fernet.encrypt(f"TOKEN {token}".encode()) + b'\n')
                            # Send server's public key
                            server_public_pem = server_public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            conn.sendall(initial_fernet.encrypt(b"SERVER_PUB_KEY:" + base64.b64encode(server_public_pem)) + b'\n')
                            # authed = True # Don't set authed here, wait for session key
                        else:
                            conn.sendall(initial_fernet.encrypt(b"Login failed. Please try again.") + b'\n')
                    else:
                        conn.sendall(initial_fernet.encrypt(b"Invalid login command.") + b'\n')
            except (socket.timeout, ValueError, IndexError) as e:
                print(f"[WARN] Auth loop error for {addr}: {e}")
                conn.close()
                return
        # END AUTHENTICATION LOOP
        conn.settimeout(None)

    except Exception as e:
        print(f"[WARN] Auth failed for {addr}: {e}")
        write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- AUTH ERROR: {e}")
        conn.close()
        return

    # Ensure session_fernet is established before proceeding
    if client_meta[conn]["session_fernet"] is None:
        print(f"[ERROR] Session key not established for {username}. Disconnecting.")
        conn.close()
        return

    client_meta[conn]["username"] = username
    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- joined the room '{client_meta[conn]['room']}'")
    broadcast(client_meta[conn]["session_fernet"].encrypt(f"{username} joined the room.".encode()), conn, room=client_meta[conn]["room"])

    try:
        fileobj = conn.makefile('rb')
        while not stop_event.is_set():
            try:
                line = fileobj.readline().rstrip(b'\n')
                if not line:
                    print(f"[INFO] {addr} ({username}) disconnected.")
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- disconnected")
                    if client_meta[conn]["session_fernet"]:
                        broadcast(client_meta[conn]["session_fernet"].encrypt(f"{username} disconnected.".encode()), conn, room=client_meta[conn]["room"])
                    break

                # Separate message and HMAC signature
                parts = line.split(b'|', 1)
                if len(parts) != 2:
                    print(f"[WARN] Invalid message format from {username}: {line}")
                    continue
                
                encrypted_message_content = parts[0]
                received_hmac_signature = base64.b64decode(parts[1])

                # Verify HMAC before decryption
                if client_meta[conn]["session_fernet"] is None:
                    print(f"[WARN] Session Fernet not available for {username}. Cannot verify HMAC.")
                    continue

                hmac_key = client_meta[conn]["session_fernet"]._signing_key
                expected_hmac_signature = generate_hmac(hmac_key, encrypted_message_content)

                if not hmac.compare_digest(expected_hmac_signature, received_hmac_signature):
                    print(f"[WARN] HMAC verification failed for message from {username}. Message tampered or key mismatch.")
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- HMAC verification failed.")
                    continue

                try:
                    msg = client_meta[conn]["session_fernet"].decrypt(encrypted_message_content).decode()
                except Exception as e:
                    print(f"[WARN] Decryption failed for message from {username}: {e}")
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- Decryption failed: {e}")
                    continue
                
                # Increment message count for key rotation
                client_meta[conn]["message_count"] += 1
                # Check for key rotation
                if client_meta[conn]["message_count"] >= 5 or (datetime.now() - client_meta[conn]["last_key_rotation"]).total_seconds() >= 60: # 1 minute for testing
                    print(f"[INFO] Initiating key rotation for {username}.")
                    rotate_session_key(conn, initial_fernet, username)

                # Command handling
                if msg.startswith("/"):
                    if msg.strip() == "/quit":
                        print(f"[INFO] {addr} ({username}) left the room with /quit.")
                        write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- left the room")
                        broadcast(client_meta[conn]["session_fernet"].encrypt(f"{username} left the room.".encode()), conn, room=client_meta[conn]["room"])
                        break

                    elif msg.strip() == "/rooms":
                        rooms_list = list(room_queues.keys())
                        conn.sendall(client_meta[conn]["session_fernet"].encrypt(f"SERVER_RESPONSE:ROOMS_LIST:{', '.join(rooms_list)}".encode()) + b'\n')
                        continue

                    elif msg.strip() == "/users":
                        room = client_meta[conn]["room"]
                        users_list = [meta["username"] for c, meta in client_meta.items() if meta.get("room") == room and meta.get("username")]
                        conn.sendall(client_meta[conn]["session_fernet"].encrypt(f"SERVER_RESPONSE:USERS_LIST:{', '.join(users_list)}".encode()) + b'\n')
                        continue

                    elif msg.startswith("/join "):
                        parts = msg.split(" ", 1)
                        if len(parts) > 1:
                            new_room = parts[1].strip()
                            if new_room:
                                old_room = client_meta[conn]["room"]
                                if old_room != new_room:
                                    broadcast(client_meta[conn]["session_fernet"].encrypt(f"{username} left the room.".encode()), conn, room=old_room)
                                    client_meta[conn]["room"] = new_room
                                    broadcast(client_meta[conn]["session_fernet"].encrypt(f"{username} joined the room.".encode()), conn, room=new_room)
                                    conn.sendall(client_meta[conn]["session_fernet"].encrypt(f"SERVER_RESPONSE:ROOM_CHANGE_SUCCESS:{new_room}".encode()) + b'\n')
                                    print(f"[INFO] {username} ({addr}) joined room '{new_room}' from '{old_room}'")
                                    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- joined room '{new_room}' from '{old_room}'")
                                else:
                                    conn.sendall(client_meta[conn]["session_fernet"].encrypt(f"SERVER_RESPONSE:You are already in room '{new_room}'.".encode()) + b'\n')
                            else:
                                conn.sendall(client_meta[conn]["session_fernet"].encrypt(b"SERVER_RESPONSE:Usage: /join <room_name>".encode()) + b'\n')
                        else:
                            conn.sendall(client_meta[conn]["session_fernet"].encrypt(b"SERVER_RESPONSE:Usage: /join <room_name>".encode()) + b'\n')
                        continue

                    elif msg.startswith("/msg "):
                        parts = msg.split(" ", 2)
                        if len(parts) >= 3:
                            target_user = parts[1]
                            private_message = parts[2]
                            send_private_message(client_meta[conn]["session_fernet"], username, target_user, private_message)
                        else:
                            conn.sendall(client_meta[conn]["session_fernet"].encrypt(b"SERVER_RESPONSE:Usage: /msg <user> <message>".encode()) + b'\n')
                        continue
                    else:
                        conn.sendall(client_meta[conn]["session_fernet"].encrypt(b"SERVER_RESPONSE:Unknown command. Type /help for a list of commands.".encode()) + b'\n')
                        continue

                # Regular chat message
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} {addr}: {msg}")
                write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- {msg}")
                
                # Encrypt message for broadcast
                encrypted_broadcast_msg = client_meta[conn]["session_fernet"].encrypt(f"{username}: {msg}".encode())
                
                # Generate HMAC for broadcast message
                hmac_key_broadcast = client_meta[conn]["session_fernet"]._signing_key
                hmac_signature_broadcast = generate_hmac(hmac_key_broadcast, encrypted_broadcast_msg)
                
                # Broadcast encrypted message + HMAC
                broadcast(encrypted_broadcast_msg + b'|' + base64.b64encode(hmac_signature_broadcast), conn, room=client_meta[conn]["room"])

            except (ConnectionResetError, BrokenPipeError):
                print(f"[WARN] {addr} ({username}) disconnected unexpectedly.")
                broadcast(client_meta[conn]["session_fernet"].encrypt(f"{username} disconnected unexpectedly.".encode()), conn, room=client_meta[conn]["room"])
                break

            except Exception as e:
                print(f"[ERROR] {addr} ({username}) unhandled error: {e}")
                break
    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
            if conn in client_meta:
                current_room_of_client = client_meta[conn].get("room")
                if current_room_of_client and client_meta[conn]["session_fernet"]:
                    broadcast(client_meta[conn]["session_fernet"].encrypt(f"{username} left the room.".encode()), conn, room=current_room_of_client)
                del client_meta[conn]
        try:
            conn.close()
        except:
            pass

def rotate_session_key(conn, initial_fernet, username):
    """Initiates a session key rotation for a given client."""
    global server_private_key, server_public_key

    if not client_meta[conn].get("rsa_public_key"):
        print(f"[ERROR] Cannot rotate key for {username}: client RSA public key not available.")
        return

    # Generate a new Fernet key for the session
    new_session_key = Fernet.generate_key()
    new_session_fernet = Fernet(new_session_key)

    # Encrypt the new session key with the client's RSA public key
    try:
        encrypted_new_session_key = client_meta[conn]["rsa_public_key"].encrypt(
            new_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"[ERROR] Failed to encrypt new session key for {username}: {e}")
        return

    try:
        # Send the encrypted new session key to the client
        conn.sendall(initial_fernet.encrypt(b"SERVER_NEW_SESSION_KEY:" + base64.b64encode(encrypted_new_session_key)) + b'\n')
        client_meta[conn]["session_fernet"] = new_session_fernet
        client_meta[conn]["message_count"] = 0
        client_meta[conn]["last_key_rotation"] = datetime.now()
        print(f"[INFO] Rotated session key for {username}.")
        write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {conn.getpeername()} :- Rotated session key.")
    except Exception as e:
        print(f"[ERROR] Failed to send new session key to {username}: {e}")
        write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {conn.getpeername()} :- Key rotation failed: {e}")

# ------------------ Main ------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument('--key', default='shared.key')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=65432)
    p.add_argument('--name', default='server')
    args = p.parse_args()

    # The shared.key is no longer used for session encryption, but might be needed for initial auth if not using RSA for that.
    # For now, we'll keep it for compatibility with existing auth, but the session key will be dynamic.
    try:
        initial_key = open(args.key, 'rb').read().strip()
    except Exception as e:
        print(f"[ERROR] Failed to read initial key file: {e}")
        sys.exit(1)

    initial_fernet = Fernet(initial_key) # Used for initial auth messages

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((args.host, args.port))
        server.listen()
        print(f"[INFO] Server listening on {args.host}:{args.port}")
    except Exception as e:
        print(f"[ERROR] Cannot start server: {e}")
        sys.exit(1)

    while True:
        try:
            conn, addr = server.accept()
            with clients_lock:
                clients.append(conn)
            threading.Thread(target=recv_loop, args=(conn, initial_fernet, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[INFO] Shutting down server...")
            stop_event.set()
            server.close()
            break

if __name__ == '__main__':
    main()
