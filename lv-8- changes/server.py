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
import time

clients = []
clients_lock = threading.Lock()
stop_event = threading.Event()
room_code = "default"
client_meta = {}  # conn -> {"username": str, "room": str, "session_key": Fernet, "rsa_public_key": None}
# After: client_meta = {}  # line 28
room_keys = {}  # room_name -> {"fernet": Fernet, "created": datetime, "key": raw_key}
room_message_counts = {}  # room_name -> message_count

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

# After generate_rsa_keys() function (around line 47)

def get_or_create_room_key(room_name):
    """Get existing room key or create new one."""
    if room_name not in room_keys:
        key = Fernet.generate_key()
        room_keys[room_name] = {
            "fernet": Fernet(key),
            "created": datetime.now(),
            "key": key  # Store raw key for distribution
        }
        print(f"[INFO] Created new encryption key for room '{room_name}'")
    return room_keys[room_name]

def rotate_room_key(room_name, initial_fernet):
    """Rotate key for a specific room and distribute to all clients."""
    if room_name not in room_keys:
        return None
    
    print(f"[INFO] Starting key rotation for room '{room_name}'")
    
    # 1. First, send a warning message to all clients
    old_room_key_data = room_keys[room_name]
    warning_msg = old_room_key_data["fernet"].encrypt(b"SERVER_RESPONSE:Key rotation in progress. Messages may be delayed briefly.")
    
    with clients_lock:
        clients_in_room = [(conn, meta) for conn, meta in client_meta.items() 
                          if meta.get("room") == room_name and meta.get("session_fernet")]
        
        # Send warning with old key
        for conn, meta in clients_in_room:
            try:
                conn.sendall(warning_msg + b'|' + base64.b64encode(hmac_warning) + b'\n')
            except:
                pass
        
        # Small delay to ensure warning is delivered
        time.sleep(0.1)
    
     # 2. Generate new key
        new_key = Fernet.generate_key()
        new_fernet = Fernet(new_key)
        
        # 3. Distribute new key to all clients
        for conn, meta in clients_in_room:
            username = meta.get("username", "unknown")
            try:
                # Encrypt with client's RSA public key
                encrypted_key = meta["rsa_public_key"].encrypt(
                    new_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # Send using initial_fernet
                conn.sendall(initial_fernet.encrypt(
                    b"SERVER_NEW_ROOM_KEY:" + base64.b64encode(encrypted_key)) + b'\n')
                print(f"[INFO] Sent new room key to {username}")
                
                # Update client's session fernet IMMEDIATELY
                client_meta[conn]["session_fernet"] = new_fernet
                
            except Exception as e:
                print(f"[WARN] Failed to send new key to {username}: {e}")
        
        # 4. Update room keys AFTER all clients have received new key
        room_keys[room_name] = {
            "fernet": new_fernet,
            "created": datetime.now(),
            "key": new_key
        }
        
        # 5. Send confirmation with NEW key
        confirmation_msg = new_fernet.encrypt(
            b"SERVER_RESPONSE:Key rotation completed successfully."
        )

        for conn, meta in clients_in_room:
            try:
                conn.sendall(confirmation_msg + b'\n')
            except:
                pass
    
    print(f"[INFO] Completed key rotation for room '{room_name}'")
    return new_key

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
# Add this instead (keeps tokens in memory only):
tokens = {}  # Simple in-memory token storage
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


def send_private_message(sender_username, target_username, message, room):
    """Send private message using room's encryption key."""
    with clients_lock:
        target_conn = None
        sender_conn = None
        
        for conn, meta in client_meta.items():
            if meta.get("username") == target_username:
                target_conn = conn
            if meta.get("username") == sender_username:
                sender_conn = conn

        # Get room's fernet for encryption
        room_key_data = get_or_create_room_key(room)
        
        if target_conn and target_conn in client_meta:
            try:
                # Encrypt message with ROOM fernet
                encrypted_msg_content = room_key_data["fernet"].encrypt(
                    f"SERVER_RESPONSE:PRIVATE_MESSAGE:[Private from {sender_username}] {message}".encode()
                )
                
                
                # Send to target
                target_conn.sendall(encrypted_msg_content +  b'\n')

                # Send confirmation to sender
                if sender_conn:
                    encrypted_sender_msg = room_key_data["fernet"].encrypt(
                        f"SERVER_RESPONSE:PRIVATE_MESSAGE:[Private to {target_username}] {message}".encode()
                    )
                    hmac_signature_sender = generate_hmac(hmac_key, encrypted_sender_msg)
                    sender_conn.sendall(encrypted_sender_msg +  b'\n')

                print(f"[INFO] Private message from {sender_username} to {target_username}: {message}")
                write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{sender_username}}} :- private message to {target_username}: {message}")
            except Exception as e:
                print(f"[WARN] Failed to send private message to {target_username}: {e}")
                if sender_conn:
                    # Send error using room fernet
                    error_msg = room_key_data["fernet"].encrypt(
                        f"SERVER_RESPONSE:Failed to send private message to {target_username}.".encode()
                    )
                    hmac_error = generate_hmac(hmac_key, error_msg)
                    sender_conn.sendall(error_msg +  b'\n')
        else:
            if sender_conn:
                error_msg = room_key_data["fernet"].encrypt(
                    f"SERVER_RESPONSE:User '{target_username}' not found or offline.".encode()
                )
                hmac_error = generate_hmac(hmac_key, error_msg)
                sender_conn.sendall(error_msg + b'|' +  b'\n')
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
                    # NEW APPROACH: Send room's Fernet key to client
                    if not client_meta[conn].get("username"):
                        print(f"[ERROR] Client {addr} not authenticated properly")
                        conn.close()
                        return
                    
                    username = client_meta[conn]["username"]
                    room = client_meta[conn]["room"]
                    
                    # Get or create room key
                    room_key_data = get_or_create_room_key(room)
                    
                    # Encrypt room Fernet key with client's RSA public key
                    if client_meta[conn].get("rsa_public_key"):
                        try:
                            encrypted_room_key = client_meta[conn]["rsa_public_key"].encrypt(
                                room_key_data["key"],  # The raw Fernet key
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            
                            # Send encrypted room key to client
                            conn.sendall(initial_fernet.encrypt(
                                b"ROOM_FERNET_KEY:" + base64.b64encode(encrypted_room_key)) + b'\n')
                            
                            print(f"[INFO] Sent room key to {username} for room '{room}'")
                            
                            # Set up the session fernet with the room key
                            client_meta[conn]["session_fernet"] = room_key_data["fernet"]
                            current_fernet = client_meta[conn]["session_fernet"]
                            authed = True
                            break
                        except Exception as e:
                            print(f"[ERROR] Failed to send room key to {username}: {e}")
                            conn.close()
                            return
                    else:
                        print(f"[ERROR] No RSA public key for {username}")
                        conn.close()
                        return
                
                # Existing authentication logic (using initial_fernet)
                auth_attempts += 1
                global users, tokens

                if msg.startswith("/register "):
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
                            token = secrets.token_hex(16)  # Still generate for response
                            tokens[token] = username  # Keep in memory only
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
                            token = secrets.token_hex(16)  # Still generate for response
                            tokens[token] = username  # Keep in memory only
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

    # After authentication, but DON'T broadcast join yet
    client_meta[conn]["username"] = username
    
    # Instead, send a welcome message using initial_fernet
    try:
        conn.sendall(initial_fernet.encrypt(
            f"SERVER_RESPONSE:Welcome to room '{client_meta[conn]['room']}'".encode()) + b'\n')
    except:
        pass
    
    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- joined the room '{client_meta[conn]['room']}'")
    
    # Broadcast join notification to OTHER clients using room fernet
    room = client_meta[conn]["room"]
    room_key_data = get_or_create_room_key(room)
    
    # Create join message
    join_msg = room_key_data["fernet"].encrypt(f"{username} joined the room.".encode())
    hmac_signature = generate_hmac(hmac_key, join_msg)
    
    # Broadcast to other clients in room
    with clients_lock:
        for other_conn, meta in client_meta.items():
            if other_conn != conn and meta.get("room") == room and meta.get("session_fernet"):
                try:
                    other_conn.sendall(join_msg +  b'\n')
                except:
                    pass

    try:
        fileobj = conn.makefile('rb')
        while not stop_event.is_set():
            try:
                line = fileobj.readline().rstrip(b'\n')
                if not line:
                    print(f"[INFO] {addr} ({username}) disconnected.")
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- disconnected")
                    if client_meta[conn]["session_fernet"]:
                        room = client_meta[conn]["room"]
                        room_key_data = get_or_create_room_key(room)
                        broadcast(room_key_data["fernet"].encrypt(f"{username} disconnected.".encode()), conn, room=room)
                    break

                # Separate message and HMAC signature
                parts = line.split(b'|', 1)
                if len(parts) != 2:
                    print(f"[WARN] Invalid message format from {username}: {line}")
                    continue
                
                encrypted_message_content = parts[0]

                # Verify HMAC before decryption
                if client_meta[conn]["session_fernet"] is None:
                    print(f"[WARN] Session Fernet not available for {username}. Cannot verify HMAC.")
                    continue


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
                
            

                # Command handling
                # In /quit command handling:
                if msg.strip() == "/quit":
                        print(f"[INFO] {addr} ({username}) left the room with /quit.")
                        write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- left the room")  
                        # Use room fernet, not client session fernet
                        room = client_meta[conn]["room"]
                        room_key_data = get_or_create_room_key(room)
                        broadcast(room_key_data["fernet"].encrypt(f"{username} left the room.".encode()), conn, room=room)
                        break  

                elif msg.strip() == "/rooms":
                        room_key_data = get_or_create_room_key(client_meta[conn]["room"])
                        conn.sendall(room_key_data["fernet"].encrypt(f"SERVER_RESPONSE:ROOMS_LIST:{', '.join(rooms_list)}".encode()) + b'\n')
                        continue

                elif msg.strip() == "/users":
                        room = client_meta[conn]["room"]
                        room_key_data = get_or_create_room_key(room)
                        users_list = [meta["username"] for c, meta in client_meta.items() if meta.get("room") == room and meta.get("username")]
                        conn.sendall(room_key_data["fernet"].encrypt(f"SERVER_RESPONSE:USERS_LIST:{', '.join(users_list)}".encode()) + b'\n')
                        continue

                elif msg.startswith("/join "):
                        parts = msg.split(" ", 1)
                        if len(parts) > 1:
                            new_room = parts[1].strip()
                            if new_room:
                                old_room = client_meta[conn]["room"]
                                if old_room != new_room:
                                    room_key_data_old = get_or_create_room_key(old_room)
                                    client_meta[conn]["room"] = new_room
                                    room_key_data_new = get_or_create_room_key(new_room)
                                    broadcast(room_key_data_new["fernet"].encrypt(f"{username} joined the room.".encode()), conn, room=new_room)
                                    broadcast(room_key_data_old["fernet"].encrypt(f"{username} left the room.".encode()), conn, room=old_room) 
                                    # Send response with NEW room's fernet
                                    conn.sendall(room_key_data_new["fernet"].encrypt(f"SERVER_RESPONSE:ROOM_CHANGE_SUCCESS:{new_room}".encode()) + b'\n') 
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
                            send_private_message(username, target_user, private_message, client_meta[conn]["room"])
                        else:
                            conn.sendall(client_meta[conn]["session_fernet"].encrypt(b"SERVER_RESPONSE:Usage: /msg <user> <message>".encode()) + b'\n')
                        continue
                else:
                        conn.sendall(client_meta[conn]["session_fernet"].encrypt(b"SERVER_RESPONSE:Unknown command. Type /help for a list of commands.".encode()) + b'\n')
                        continue
                
                # If not a command, process as a regular message
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} {addr}: {msg}")
                
                write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- {msg}")
                
                # Get room key for encryption
                room = client_meta[conn]["room"]
                room_key_data = get_or_create_room_key(room)
                
                # Increment room message count for rotation
                room_message_counts[room] = room_message_counts.get(room, 0) + 1
                
                # In the message processing section of recv_loop:

                # Check for room key rotation BEFORE encrypting the current message
                if (room_message_counts.get(room, 0) >= 100 or 
                    (datetime.now() - room_key_data["created"]).total_seconds() >= 600):
                    
                    print(f"[INFO] Initiating key rotation for room '{room}'")
                    
                    # Get room key BEFORE rotation (for current message)
                    current_room_key_data = get_or_create_room_key(room)
                    
                    # Encrypt THIS message with OLD key
                    encrypted_broadcast_msg = current_room_key_data["fernet"].encrypt(f"{username}: {msg}".encode())
                    hmac_signature_broadcast = generate_hmac(hmac_key_broadcast, encrypted_broadcast_msg)
                    
                    # Broadcast THIS message
                    broadcast(encrypted_broadcast_msg + b'|' + base64.b64encode(hmac_signature_broadcast), conn, room=room)
                    
                    # THEN rotate keys
                    rotate_room_key(room, initial_fernet)
                    room_message_counts[room] = 0
                    
                else:
                    # Normal message processing
                    encrypted_broadcast_msg = room_key_data["fernet"].encrypt(f"{username}: {msg}".encode())
                    hmac_signature_broadcast = generate_hmac(hmac_key_broadcast, encrypted_broadcast_msg)
                    broadcast(encrypted_broadcast_msg + b'|' + base64.b64encode(hmac_signature_broadcast), conn, room=room)

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
                    room_key_data = get_or_create_room_key(current_room_of_client)
                    broadcast(room_key_data["fernet"].encrypt(f"{username} left the room.".encode()), conn, room=current_room_of_client)
                del client_meta[conn]
        try:
            conn.close()
        except:
            pass

# ------------------ Main ------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument('--key', default='shared.key')
    p.add_argument('--host', default='192.168.56.1')
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
