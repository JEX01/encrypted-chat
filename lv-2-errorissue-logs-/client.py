import argparse
import socket
import threading
import sys
from cryptography.fernet import Fernet
from datetime import datetime
import os
import time

stop_event = threading.Event()

# ------------------ Logging ------------------
os.makedirs('chat_logs', exist_ok=True)
log_file = os.path.join('chat_logs', 'client_log.txt')

def write_log(line):
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(line + '\n')

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
                    print("\n[INFO] Server disconnected.")
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
        print(f"[ERROR] Failed to read key file: {e}")
        sys.exit(1)

    fernet = Fernet(key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((args.host, args.port))
        print(f"[INFO] Connected to {args.host}:{args.port}")
    except Exception as e:
        print(f"[ERROR] Cannot connect to server at {args.host}:{args.port}. Make sure the server is running.")
        sys.exit(1)

    if args.name and args.name != 'Client':
        username = args.name.strip()
    else:
        username = input("Enter your username: ").strip()

    if not username:
        username = "Guest"
    
    print(f"[INFO] Using username: {username}")

    try:
        sock.sendall(fernet.encrypt(username.encode()) + b'\n')
    except Exception as e:
        print(f"[ERROR] Failed to send username: {e}")
        sock.close()
        sys.exit(1)

    # Save local address before any closure
    local_addr = sock.getsockname()

    # Start receive thread
    threading.Thread(target=recv_loop, args=(sock, fernet, username), daemon=True).start()

    try:
        while not stop_event.is_set():
            if stop_event.is_set():
                break
            try:
                msg = input('> ').strip()
            except EOFError:
                break
            if not msg:
                continue

            if stop_event.is_set():
                break

            try:
                sock.sendall(fernet.encrypt(msg.encode()) + b'\n')
                write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {local_addr} :- sent: {msg}")

                if msg == '/quit':
                    stop_event.set()
                    break

            except (ConnectionResetError, BrokenPipeError):
                print("\n[INFO] Server connection lost (WinError 10054).")
                stop_event.set()
                break
            except Exception as e:
                print(f"\n[ERROR] Send error: {e}")
                stop_event.set()
                break

            time.sleep(0.01)  # small delay to prevent CPU hog

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
        stop_event.set()

    finally:
        try:
            sock.close()
        except:
            pass

        print("[INFO] Client exited.")
        write_log(f"[{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}] {{{username}}} {local_addr} :- client exited")

if __name__ == '__main__':
    main()
