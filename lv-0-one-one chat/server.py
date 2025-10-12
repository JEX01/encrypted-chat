import argparse
import socket
import threading
import sys
from cryptography.fernet import Fernet
from datetime import datetime
import os

clients = []
stop_event = threading.Event()


def broadcast(message, sender=None):
    """Send message to all connected clients except sender."""
    for c in clients:
        if c != sender:
            try:
                c.sendall(message + b'\n')
            except:
                pass


def recv_loop(conn, fernet, addr):
    """Handle messages from a single client."""
    global clients
    try:
        fileobj = conn.makefile('rb')
        while not stop_event.is_set():
            line = fileobj.readline()
            if not line:
                # Client disconnected unexpectedly
                print(f"[WARN] {addr} disconnected unexpectedly.")
                broadcast(fernet.encrypt(b"Chat or room disconnected."), conn)
                break

            try:
                msg = fernet.decrypt(line.rstrip(b'\n')).decode('utf-8')
            except:
                print(f"[WARN] Failed to decrypt message from {addr}")
                continue

            if msg.strip() == "/quit":
                print(f"[INFO] {addr} left the room.")
                broadcast(fernet.encrypt(b"Room closed."), conn)
                stop_event.set()
                break

            print(f"[{datetime.now().strftime('%H:%M:%S')}] {addr}: {msg}")
            broadcast(line.rstrip(b'\n'), conn)
    except Exception as e:
        print(f"[ERROR] {addr} error: {e}")
        broadcast(fernet.encrypt(b"Chat or room disconnected."), conn)
    finally:
        if conn in clients:
            clients.remove(conn)
        try:
            conn.close()
        except:
            pass


def load_or_create_key(path):
    """Load Fernet key from file or generate a new one if invalid/missing."""
    if os.path.exists(path):
        try:
            key = open(path, 'rb').read().strip()
            Fernet(key)  # validate key
            return key
        except Exception:
            print(f"[WARN] Existing key invalid, generating a new key...")
    else:
        print(f"[INFO] Key file not found. Generating a new key...")

    key = Fernet.generate_key()
    with open(path, 'wb') as f:
        f.write(key)
    print(f"[INFO] Generated new Fernet key at {path}")
    return key


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--key', default='shared.key')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=65432)
    p.add_argument('--name', default='Server')
    args = p.parse_args()

    key = load_or_create_key(args.key)
    fernet = Fernet(key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen()
    print(f"[INFO] Server listening on {args.host}:{args.port}")

    try:
        while not stop_event.is_set():
            conn, addr = sock.accept()
            clients.append(conn)
            print(f"[INFO] Connection from {addr}")
            threading.Thread(target=recv_loop, args=(conn, fernet, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
    finally:
        print("[INFO] Closing all connections...")
        for c in clients:
            try:
                c.sendall(fernet.encrypt(b"Room closed.") + b'\n')
                c.close()
            except:
                pass
        sock.close()
        print("[INFO] Server exited.")


if __name__ == '__main__':
    main()
