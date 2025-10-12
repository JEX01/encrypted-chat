
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

clients = []
clients_lock = threading.Lock()
stop_event = threading.Event()
room_code = "default"
client_meta = {}  # conn -> {"username": str, "room": str}

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

def send_private_message(fernet, sender_username, target_username, message):
    with clients_lock:
        target_conn = None
        sender_conn = None
        for conn, meta in client_meta.items():
            if meta.get("username") == target_username:
                target_conn = conn
            if meta.get("username") == sender_username:
                sender_conn = conn

        if target_conn:
            try:
                encrypted_message = fernet.encrypt(f"SERVER_RESPONSE:PRIVATE_MESSAGE:[Private from {sender_username}] {message}".encode())
                target_conn.sendall(encrypted_message + b'\n')
                if sender_conn:
                    sender_conn.sendall(fernet.encrypt(f"SERVER_RESPONSE:PRIVATE_MESSAGE:[Private to {target_username}] {message}".encode()) + b'\n')
                print(f"[INFO] Private message from {sender_username} to {target_username}: {message}")
                write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{sender_username}}} :- private message to {target_username}: {message}")
            except Exception as e:
                print(f"[WARN] Failed to send private message to {target_username}: {e}")
                if sender_conn:
                    sender_conn.sendall(fernet.encrypt(f"SERVER_RESPONSE:Failed to send private message to {target_username}.".encode()) + b'\n')
        else:
            if sender_conn:
                sender_conn.sendall(fernet.encrypt(f"SERVER_RESPONSE:User '{target_username}' not found or offline.".encode()) + b'\n')
            print(f"[INFO] Private message from {sender_username} to {target_username} failed: user not found.")
            write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{sender_username}}} :- private message to {target_username} failed: user not found.")

# ------------------ Client handler ------------------
def recv_loop(conn, fernet, addr):
    username = str(addr)
    client_meta[conn] = {"username": None, "room": room_code}

    try:
        authed = False
        # AUTHENTICATION LOOP
        conn.sendall(fernet.encrypt(b"AUTH_REQUIRED") + b'\n')
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
                msg = fernet.decrypt(raw).decode()
            except (socket.timeout, ValueError, IndexError):
                conn.close()
                return

            auth_attempts += 1
            global users, tokens

            if msg.startswith("/token "):
                token = msg.split(" ", 1)[1]
                if token in tokens:
                    username = tokens[token]
                    client_meta[conn]["username"] = username
                    conn.sendall(fernet.encrypt(b"TOKEN_VALID") + b'\n')
                    authed = True
                else:
                    conn.sendall(fernet.encrypt(b"TOKEN_INVALID") + b'\n')
                    # Stay in loop

            elif msg.startswith("/register "):
                parts = msg.split(" ")
                if len(parts) >= 3:
                    uname, pwd = parts[1], parts[2]
                    if uname in users:
                        conn.sendall(fernet.encrypt(b"Username already exists.") + b'\n')
                    else:
                        users[uname] = {"password": pwd}
                        save_users(users)
                        username = uname
                        client_meta[conn]["username"] = username
                        token = secrets.token_hex(16)
                        tokens[token] = username
                        save_tokens(tokens)
                        conn.sendall(fernet.encrypt(f"TOKEN {token}".encode()) + b'\n')
                        print(f"[INFO] {addr} registered as {username}")
                        authed = True
                else:
                    conn.sendall(fernet.encrypt(b"Invalid register command.") + b'\n')

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
                        conn.sendall(fernet.encrypt(f"TOKEN {token}".encode()) + b'\n')
                        authed = True
                    else:
                        conn.sendall(fernet.encrypt(b"Login failed. Please try again.") + b'\n')
                else:
                    conn.sendall(fernet.encrypt(b"Invalid login command.") + b'\n')
        # END AUTHENTICATION LOOP
        conn.settimeout(None)

    except Exception as e:
        print(f"[WARN] Auth failed for {addr}: {e}")
        write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- AUTH ERROR: {e}")
        conn.close()
        return

    client_meta[conn]["username"] = username
    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- joined the room '{client_meta[conn]['room']}'")
    broadcast(fernet.encrypt(f"{username} joined the room.".encode()), conn, room=client_meta[conn]["room"])

    try:
        fileobj = conn.makefile('rb')
        while not stop_event.is_set():
            try:
                line = fileobj.readline()
                if not line:
                    print(f"[INFO] {addr} ({username}) disconnected.")
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- disconnected")
                    broadcast(fernet.encrypt(f"{username} disconnected.".encode()), conn, room=client_meta[conn]["room"])
                    break

                try:
                    msg = fernet.decrypt(line.rstrip(b'\n')).decode()
                except Exception as e:
                    print(f"[WARN] Decryption failed for message from {username}: {e}")
                    continue

                # Command handling
                if msg.startswith("/"):
                    if msg.strip() == "/quit":
                        print(f"[INFO] {addr} ({username}) left the room with /quit.")
                        write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- left the room")
                        broadcast(fernet.encrypt(f"{username} left the room.".encode()), conn, room=client_meta[conn]["room"])
                        break

                    elif msg.strip() == "/rooms":
                        rooms_list = list(room_queues.keys())
                        conn.sendall(fernet.encrypt(f"SERVER_RESPONSE:ROOMS_LIST:{', '.join(rooms_list)}".encode()) + b'\n')
                        continue

                    elif msg.strip() == "/users":
                        room = client_meta[conn]["room"]
                        users_list = [meta["username"] for c, meta in client_meta.items() if meta.get("room") == room and meta.get("username")]
                        conn.sendall(fernet.encrypt(f"SERVER_RESPONSE:USERS_LIST:{', '.join(users_list)}".encode()) + b'\n')
                        continue

                    elif msg.startswith("/join "):
                        parts = msg.split(" ", 1)
                        if len(parts) > 1:
                            new_room = parts[1].strip()
                            if new_room:
                                old_room = client_meta[conn]["room"]
                                if old_room != new_room:
                                    broadcast(fernet.encrypt(f"{username} left the room.".encode()), conn, room=old_room)
                                    client_meta[conn]["room"] = new_room
                                    broadcast(fernet.encrypt(f"{username} joined the room.".encode()), conn, room=new_room)
                                    conn.sendall(fernet.encrypt(f"SERVER_RESPONSE:ROOM_CHANGE_SUCCESS:{new_room}".encode()) + b'\n')
                                    print(f"[INFO] {username} ({addr}) joined room '{new_room}' from '{old_room}'")
                                    write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- joined room '{new_room}' from '{old_room}'")
                                else:
                                    conn.sendall(fernet.encrypt(f"SERVER_RESPONSE:You are already in room '{new_room}'.".encode()) + b'\n')
                            else:
                                conn.sendall(fernet.encrypt(b"SERVER_RESPONSE:Usage: /join <room_name>".encode()) + b'\n')
                        else:
                            conn.sendall(fernet.encrypt(b"SERVER_RESPONSE:Usage: /join <room_name>".encode()) + b'\n')
                        continue

                    elif msg.startswith("/msg "):
                        parts = msg.split(" ", 2)
                        if len(parts) >= 3:
                            target_user = parts[1]
                            private_message = parts[2]
                            send_private_message(fernet, username, target_user, private_message)
                        else:
                            conn.sendall(fernet.encrypt(b"SERVER_RESPONSE:Usage: /msg <user> <message>".encode()) + b'\n')
                        continue
                    else:
                        conn.sendall(fernet.encrypt(b"SERVER_RESPONSE:Unknown command. Type /help for a list of commands.".encode()) + b'\n')
                        continue

                # Regular chat message
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} {addr}: {msg}")
                write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {{{username}}} {addr} :- {msg}")
                broadcast(fernet.encrypt(f"{username}: {msg}".encode()), conn, room=client_meta[conn]["room"])

            except (ConnectionResetError, BrokenPipeError):
                print(f"[WARN] {addr} ({username}) disconnected unexpectedly.")
                broadcast(fernet.encrypt(f"{username} disconnected unexpectedly.".encode()), conn, room=client_meta[conn]["room"])
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
            if current_room_of_client:
                broadcast(fernet.encrypt(f"{username} left the room.".encode()), conn, room=current_room_of_client)
            del client_meta[conn]
        try:
            conn.close()
        except:
            pass

# ------------------ Main ------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument('--key', default='shared.key')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=65432)
    p.add_argument('--name', default='server')
    args = p.parse_args()

    # Load encryption key
    try:
        key = open(args.key, 'rb').read().strip()
    except Exception as e:
        print(f"[ERROR] Failed to read key file: {e}")
        sys.exit(1)

    fernet = Fernet(key)
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
            threading.Thread(target=recv_loop, args=(conn, fernet, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[INFO] Shutting down server...")
            stop_event.set()
            server.close()
            break

if __name__ == '__main__':
    main()