import argparse
import socket
import threading
import sys
from cryptography.fernet import Fernet
from datetime import datetime
import os

stop_event = threading.Event()

# ------------------ Logging ------------------
os.makedirs('chat_logs', exist_ok=True)
log_file = os.path.join('chat_logs', 'client_log.txt')

def write_log(line):
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(line + '\n')

# ------------------ Receive messages ------------------
def recv_loop(sock, fernet, username, conn):
    """Receive and decrypt messages from server."""
    fileobj = sock.makefile('rb')
    write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {sock.getsockname()} :- joined the room")

    while not stop_event.is_set():
        line = fileobj.readline()
        if not line:
            print("\n[INFO] Server disconnected. Chat or room disconnected.")
            stop_event.set()
            break

        try:
            msg = fernet.decrypt(line.rstrip(b'\n')).decode('utf-8')
            if msg in ("Chat or room disconnected.", "Room closed."):
                print(f"\n[INFO] {msg}")
                stop_event.set()
                break

            # Print message and log it
            # Expect server sends messages in format "username: message"
            
            if ": " in msg:
                sender, message = msg.split(": ", 1)
                print(f"\r[{datetime.now().strftime('%H:%M:%S')}] {sender} :- {message}\n> ", end='', flush=True)
            else:
                print(f"\r[{datetime.now().strftime('%H:%M:%S')}] {msg}\n> ", end='', flush=True)

            write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {sock.getsockname()} :- {msg}")
        except Exception as e:
            print(f"\n[WARN] Message decrypt error: {e}")
            break


    """Receive and decrypt messages from server."""
    fileobj = sock.makefile('rb')

    while not stop_event.is_set():
        try:
            line = fileobj.readline()
        except ConnectionResetError:
            print("\n[INFO] Server forcibly closed the connection.")
            stop_event.set()
            break

        if not line:
            print("\n[INFO] Server disconnected.")
            stop_event.set()
            break

        try:
            msg = fernet.decrypt(line.rstrip(b'\n')).decode('utf-8')
        except:
            continue

        if msg in ("Chat or room disconnected.", "Room closed."):
            print(f"\n[INFO] {msg}")
            stop_event.set()
            break

        print(f"\r{msg}\n> ", end='', flush=True)
    
    """Receive and display messages with graceful disconnect handling."""
    try:
        fileobj = sock.makefile('rb')
        while True:
            try:
                line = fileobj.readline()
                if not line:
                    print("[INFO] Server disconnected.")
                    break
                msg = fernet.decrypt(line.rstrip(b'\n')).decode('utf-8')
                print(msg)
            except ConnectionResetError:
                print("[INFO] Server disconnected.")
                break
            except Exception as e:
                if "Connection" in str(e):
                    print("[INFO] Server disconnected.")
                else:
                    print(f"[WARN] Connection closed: {e}")
                break
    finally:
        print("[INFO] Client exited.")
        sock.close()
# ------------------ Main ------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument('--key', default='shared.key')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=65432)
    p.add_argument('--name', default='Client')
    args = p.parse_args()

    try:
        key = open(args.key, 'rb').read().strip()
    except Exception as e:
        print(f"Failed to read key file: {e}")
        sys.exit(1)

    fernet = Fernet(key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.host, args.port))
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    print(f"[INFO] Connected to {args.host}:{args.port}")
    print("[INFO] Your first message will be used as your username.")
    
    # Get username from user and send it to server
    username = input("Enter your username: ").strip()
    if not username:
        username = "Guest"
    sock.sendall(fernet.encrypt(username.encode()) + b'\n')

    # Start receiving messages
    threading.Thread(target=recv_loop, args=(sock, fernet, username, sock), daemon=True).start()

    try:
        while not stop_event.is_set():
            msg = input('> ').strip()
            if not msg:
                continue
            if msg == '/quit':
                sock.sendall(fernet.encrypt(msg.encode()) + b'\n')
                stop_event.set()
                break
            sock.sendall(fernet.encrypt(msg.encode()) + b'\n')
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted.")
        stop_event.set()
    finally:
        sock.close()
        print("[INFO] Client exited.")

if __name__ == '__main__':
    main()
