import argparse
import socket
import threading
import sys
from cryptography.fernet import Fernet
from datetime import datetime

stop_event = threading.Event()

def recv_loop(sock, fernet):
    """Receive and decrypt messages from server."""
    fileobj = sock.makefile('rb')
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
            print(f"\r[{datetime.now().strftime('%H:%M:%S')}] {msg}\n> ", end='', flush=True)
        except Exception as e:
            print(f"\n[WARN] Message decrypt error: {e}")
            break


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
    threading.Thread(target=recv_loop, args=(sock, fernet), daemon=True).start()

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
