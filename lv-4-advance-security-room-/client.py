import argparse
import socket
import threading
import sys
from cryptography.fernet import Fernet
from datetime import datetime
import os
import json
import time

stop_event = threading.Event()
current_room = "default"

# ------------------ Dynamic Logging per Session ------------------
#  gives two files stored for logs
def get_log_path(room_name="default"):
    pass
    # os.makedirs('chat_logs', exist_ok=True)
    # Optional: keep room folder if needed
    # folder = os.path.join('chat_logs-', room_name)
    # os.makedirs(folder, exist_ok=True)
    # Session-based log file (timestamped)
    # filename = f"ROOM-{datetime.now().strftime('-%Y%m%d_%H-%M-%S')}.txt"
    # return os.path.join(folder, filename)

# Create log_file only once per session
if 'log_file' not in globals() or not log_file:
    # log_file = get_log_path(current_room)
    pass
def write_log(line):
    # try:
    #     with open(log_file, 'a', encoding='utf-8') as f:
    #         f.write(line + '\n')
    # except Exception as e:
    #     print(f"[WARN] Log write error: {e}")
    pass
# ------------------ Token storage ------------------
TOKEN_FILE = "tokens.json"

# Load tokens
def load_token():
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, 'r') as f:
                data = json.load(f)
                return data.get('token')
        except:
            return None
    return None

# Save tokens
def save_tokens():
    try:
        with open(TOKEN_FILE, 'w') as f:
            json.dump(tokens, f)
    except:
        pass

tokens = {}
load_token()

# ------------------ Receive messages ------------------
def recv_loop(sock, fernet, username):
    """Receive and decrypt messages from server with graceful disconnect handling."""
    local_addr = None
    fileobj = None

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


                try:
                    msg = fernet.decrypt(line.rstrip(b'\n')).decode('utf-8')
                    if msg in ("Chat or room disconnected.", "Room closed."):
                        print(f"\n[INFO] {msg}")
                        stop_event.set()
                        break

                    # Print message in format [TIME] sender :- message
                    if ": " in msg:
                        sender, message = msg.split(": ", 1)
                        print(f"\r[{datetime.now().strftime('%H:%M:%S')}] {sender} :- {message}\n> ", end='', flush=True)
                    else:
                        print(f"\r[{datetime.now().strftime('%H:%M:%S')}] {msg}\n> ", end='', flush=True)

                    try:
                        write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {local_addr} :- received: {msg}")
                    except:
                        pass
                except Exception as e:
                    print(f"\n[WARN] Message decrypt error: {e}")
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
def handle_command(msg, sock, fernet, username):
    """Parse and execute client commands."""
    global current_room

    if msg == "/help":
        print("""Available commands:
    /help - show this help
    /quit - exit chat
    /rooms - list available rooms
    /join <room> - switch to another room
    /users - list users in current room
    /msg <user> <message> - private message
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
        new_room = msg.split(" ", 1)[1].strip()
        if new_room:
            current_room = new_room
            print(f"[INFO] Switched to room '{current_room}'")
            try:
                sock.sendall(fernet.encrypt(f"/join {new_room}".encode()) + b'\n')
            except:
                pass
        return True

    elif msg == "/rooms":
        try:
            sock.sendall(fernet.encrypt(b"/rooms") + b'\n')
        except:
            pass
        return True

    elif msg == "/users":
        try:
            sock.sendall(fernet.encrypt(b"/users") + b'\n')
        except:
            pass
        return True

    elif msg.startswith("/msg "):
        try:
            sock.sendall(fernet.encrypt(msg.encode()) + b'\n')
        except:
            pass
        return True

    return False  # Not a command

# ------------------ Messaging loop ------------------
def messaging_loop(sock, fernet, username):
    local_addr = sock.getsockname()
    try:
        while not stop_event.is_set():
            msg = input("> ").strip()
            if not msg:
                continue

            # Multi-room command support
            if handle_command(msg, sock, fernet, username):
                continue

            try:
                sock.sendall(fernet.encrypt(msg.encode()) + b'\n')
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
    p.add_argument('--host', default='127.0.0.1')
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

    fernet = Fernet(key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((args.host, args.port))
        print(f"[INFO] Connected to {args.host}:{args.port} in room '{current_room}'")
    except Exception as e:
        print(f"[ERROR] Cannot connect to server: {e}")
        sys.exit(1)

# ----before

# ------------------ Authentication ------------------
    username = None
    token = load_token()

    try:
        initial_bytes = sock.recv(1024).strip()
        if not initial_bytes:
            print("[ERROR] Server closed connection.")
            sock.close()
            sys.exit(1)

        initial = fernet.decrypt(initial_bytes).decode()
    except (ConnectionAbortedError, ConnectionResetError):
        print("[ERROR] Server disconnected unexpectedly during authentication.")
        sock.close()
        sys.exit(1)

    if initial == "AUTH_REQUIRED":
        if token:
            try:
                sock.sendall(fernet.encrypt(f"/token {token}".encode()) + b'\n')
                resp_bytes = sock.recv(1024).strip()
                if not resp_bytes:
                    print("[ERROR] Server closed connection.")
                    sock.close()
                    sys.exit(1)
                resp = fernet.decrypt(resp_bytes).decode()
                if resp == "TOKEN_VALID":
                    print("[INFO] Auto-login successful.")
                else:
                    print("[INFO] Token invalid. Login manually.")
                    token = None
            except (ConnectionAbortedError, ConnectionResetError):
                print("[ERROR] Server disconnected unexpectedly.")
                sock.close()
                sys.exit(1)

        if not token:
            print("Choose option:\n1. Register\n2. Login")
            choice = input("> ").strip()
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            try:
                if choice == "1":
                    sock.sendall(fernet.encrypt(f"/register {username} {password}".encode()) + b'\n')
                elif choice == "2":
                    sock.sendall(fernet.encrypt(f"/login {username} {password}".encode()) + b'\n')
                else:
                    print("[ERROR] Invalid choice.")
                    sock.close()
                    sys.exit(1)

                resp_bytes = sock.recv(1024).strip()
                if not resp_bytes:
                    print("[ERROR] Server closed connection.")
                    sock.close()
                    sys.exit(1)

                resp = fernet.decrypt(resp_bytes).decode()
                if resp.startswith("TOKEN "):
                    token = resp.split(" ", 1)[1]
                    save_token(token)
                    print("[INFO] Authentication successful. Token saved.")
                else:
                    print(f"[INFO] {resp}")
                    sock.close()
                    sys.exit(1)

            except (ConnectionAbortedError, ConnectionResetError):
                print("[ERROR] Server disconnected unexpectedly.")
                sock.close()
                sys.exit(1)

    if not username:
        username = args.name if args.name != "Client" else "Guest"

    # Start receive thread
    threading.Thread(target=recv_loop, args=(sock, fernet, username), daemon=True).start()

    # Keep client alive for messaging
    messaging_loop(sock, fernet, username)

if __name__ == '__main__':
    main()
