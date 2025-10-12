import argparse
import socket
import threading
import sys
from cryptography.fernet import Fernet
from datetime import datetime
import os
import ctypes

clients = []
clients_lock = threading.Lock()  # Thread-safe access to clients
stop_event = threading.Event()
room_code = None
log_file = None
room_members = []

# ------------------ Logging ------------------
def write_log(line):
    if log_file:
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception as e:
            print(f"[WARN] Log write error: {e}")

# ------------------ Broadcast ------------------
def broadcast(message, sender=None):
    with clients_lock:
        for c in clients[:]:
            if c != sender:
                try:
                    c.sendall(message + b'\n')
                except Exception as e:
                    print(f"[WARN] Failed to send message to a client: {e}")
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] Server :- Failed to broadcast to a client: {e}")

# ------------------ Client handler ------------------
def recv_loop(conn, fernet, addr):
    """
    Handle messages from a connected client, broadcast to others,
    and log with username in format:
    [DATE | TIME] {user-name} ('IP', PORT) :- message
    """
    global room_members
    username = str(addr)  # Default username

    # Receive username from client
    try:
        conn.settimeout(None)  # No strict timeout; prevents disconnect for slow clients
        raw_name = conn.recv(1024).strip()
        if not raw_name:
            print(f"[WARN] {addr} disconnected before sending username.")
            return
        username = fernet.decrypt(raw_name).decode('utf-8')
    except Exception as e:
        print(f"[WARN] Failed to get username from {addr}: {e}")
        write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {addr} :- ERROR: {e}")

    room_members.append(username)
    write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {addr} :- joined the room")
    broadcast(fernet.encrypt(f"{username} joined the room.".encode()), conn)

    try:
        fileobj = conn.makefile('rb')
        while not stop_event.is_set():
            try:
                line = fileobj.readline()
                if not line:
                    print(f"[INFO] {addr} ({username}) disconnected.")
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {addr} :- disconnected")
                    broadcast(fernet.encrypt(f"{username} disconnected.".encode()), conn)
                    break

                try:
                    msg = fernet.decrypt(line.rstrip(b'\n')).decode('utf-8')
                except Exception as e:
                    print(f"[WARN] Failed to decrypt message from {addr}: {e}")
                    continue

                if msg.strip() == "/quit":
                    print(f"[INFO] {addr} ({username}) left the room with /quit.")
                    write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {addr} :- left the room")
                    broadcast(fernet.encrypt(f"{username} left the room.".encode()), conn)
                    break

                # Log and broadcast messages with username
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} {addr}: {msg}")
                write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {addr} :- {msg}")
                broadcast(fernet.encrypt(f"{username}: {msg}".encode()), conn)

            except ConnectionResetError:
                print(f"[WARN] {addr} ({username}) forcibly closed connection (WinError 10054).")
                write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {addr} :- connection reset")
                broadcast(fernet.encrypt(f"{username} disconnected.".encode()), conn)
                break
            except Exception as e:
                print(f"[ERROR] {addr} ({username}) unhandled error: {e}")
                write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {addr} :- ERROR: {e}")
                break
    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        if username in room_members:
            room_members.remove(username)
        try:
            conn.close()
        except:
            pass

# ------------------ Key loader ------------------
def load_or_create_key(path):
    if os.path.exists(path):
        try:
            key = open(path, 'rb').read().strip()
            Fernet(key)  # Validate key
            return key
        except Exception as e:
            print(f"[ERROR] Existing key invalid: {e}. Please fix the key manually.")
            sys.exit(1)  # Prevent key mismatch
    else:
        print("[INFO] Key file not found, generating new key...")
        key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(key)
        print(f"[INFO] Generated new Fernet key at {path}")
        return key

# ------------------ Make file read-only ------------------
def set_file_readonly(filepath):
    FILE_ATTRIBUTE_READONLY = 0x01
    ctypes.windll.kernel32.SetFileAttributesW(filepath, FILE_ATTRIBUTE_READONLY)

# ------------------ Main ------------------
def main():
    global room_code, log_file
    p = argparse.ArgumentParser()
    p.add_argument('--key', default='shared.key')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=65432)
    p.add_argument('--name', default='Server')
    p.add_argument('--room', default='ROOM')
    args = p.parse_args()

    room_code = args.room
    timestamp = datetime.now().strftime('%Y%m%d-%H-%M-%S')
    os.makedirs('chat_logs', exist_ok=True)
    log_file = os.path.join('chat_logs', f"{room_code}-{timestamp}.txt")
    write_log(f"Room created: {room_code} at {timestamp}")
    write_log(f"Server: {args.name}")

    key = load_or_create_key(args.key)
    fernet = Fernet(key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(30.0)  # Accept loop timeout

    try:
        sock.bind((args.host, args.port))
        sock.listen()
        print(f"[INFO] Server listening on {args.host}:{args.port}")

        while not stop_event.is_set():
            try:
                conn, addr = sock.accept()
                conn.settimeout(60.0)
                with clients_lock:
                    clients.append(conn)
                print(f"[INFO] Connection from {addr}")
                threading.Thread(target=recv_loop, args=(conn, fernet, addr), daemon=True).start()
            except socket.timeout:
                continue  # Keep listening
            except Exception as e:
                print(f"[ERROR] Accept error: {e}")
                continue
    except Exception as e:
        print(f"[ERROR] Server setup failed: {e}")
    finally:
        print("[INFO] Closing all connections...")
        write_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ROOM CLOSED")
        with clients_lock:
            for c in clients[:]:
                try:
                    c.sendall(fernet.encrypt(b"Room closed.") + b'\n')
                    c.close()
                except:
                    pass
                clients.remove(c)
        sock.close()
        print("[INFO] Server exited.")
        if log_file:
            set_file_readonly(log_file)
            print(f"[SECURE] Log file locked: {log_file}")

if __name__ == '__main__':
    main()
