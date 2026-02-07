# TODO: Stabilize Encrypted Chat Project

## Current Work

The project in lv-5-system-command/ has partial implementations of RSA key exchange, HMAC, key rotation, and logging. The task is to fix client logging (flat structure, init on start and /join), reorder RSA exchange after auth, stabilize rotation (server-initiated, RSA-encrypted new keys, logging), and add error handling, without breaking commands, HMAC, auth, etc. Files: client.py, server.py. No changes to existing JSON or keygen.py.

## Key Technical Concepts

- RSA (cryptography.hazmat.primitives.asymmetric.rsa): Generate keys, encrypt/decrypt session keys post-auth.
- Fernet (cryptography.fernet): Symmetric encryption for messages/commands; initial_fernet from shared.key for auth, session_fernet dynamic per client.
- HMAC (hmac, hashlib): Integrity with session.\_signing_key; verify before decrypt.
- Threading: recv_loop, messaging_loop (client); per-client handlers (server).
- Logging: Timestamped files; client to chat_logs/ROOM-<timestamp>.txt (flat); server to server_logs/<room>/ROOM{room}-<timestamp>.txt.
- Auth: Token-based with users.json/tokens.json; /register, /login.
- Commands: /quit, /rooms, /users, /join, /msg (server-handled); /help, /clear (client-local).
- Rotation: Server checks per-client message_count (100) or time (600s), generates new Fernet key, encrypts with client's RSA public, sends via initial_fernet (secure as shared but static; post-auth only).

## Relevant Files and Code

- lv-5-system-command/client.py:
  - Logging: get_log_path (subfolder; change to flat), init_log_file (call post-auth and on /join success), write_log (used in recv/send).
  - Auth: In main(), recv AUTH_REQUIRED, handle /token/register/login with initial_fernet.
  - Key Exchange: Currently in recv_loop (wrong); move to main() post-auth: recv SERVER_PUB_KEY, generate/send CLIENT_SESSION_KEY.
  - Rotation: In recv_loop, handle SERVER_NEW_SESSION_KEY (decrypt with private_key, update session_fernet, reset count/time).
  - Commands: handle_command sends with session_fernet; /join updates current_room (add log reinitialize).
  - Important Snippet (recv_loop HMAC verify):
    ```
    hmac_key = current_fernet._signing_key
    expected_hmac_signature = generate_hmac(hmac_key, encrypted_message_content)
    if not hmac.compare_digest(expected_hmac_signature, received_hmac_signature):
        # log and continue
    ```
- lv-5-system-command/server.py:
  - Logging: get_server_log_path (subfolders ok), write_log.
  - Auth: In recv_loop, send AUTH_REQUIRED first, loop until /token success, then send SERVER_PUB_KEY, handle CLIENT_SESSION_KEY to set session_fernet.
  - Key Exchange: Send SERVER_PUB_KEY post-auth; handle CLIENT_PUB_KEY (store rsa_public_key), CLIENT_SESSION_KEY (decrypt with private, set session_fernet).
  - Rotation: In recv_loop post-decrypt, check client_meta[conn]["message_count"]/time, call rotate_session_key (generate new key, encrypt with client's rsa_public_key, send SERVER_NEW_SESSION_KEY + encrypted via initial_fernet).
  - Commands: Handled post-session_fernet; /join updates meta["room"], broadcasts.
  - Important Snippet (rotate_session_key):
    ```
    encrypted_new_session_key = client_meta[conn]["rsa_public_key"].encrypt(new_session_key, padding.OAEP(...))
    conn.sendall(initial_fernet.encrypt(b"SERVER_NEW_SESSION_KEY:" + base64.b64encode(encrypted_new_session_key)) + b'\n')
    ```

## Problem Solving

- Sequencing Issue: Current code sends SERVER_PUB_KEY before AUTH_REQUIRED (server), causing client to skip auth. Fix: Server auth loop first, then key exchange.
- Logging: Client uses subfolders; change to flat. Ensure /join reinits log_file (server already logs per room).
- Rotation Sync: Server initiates, client updates on receive; add try/except for decrypt fail (disconnect). Use initial_fernet for rotation send (secure enough post-auth).
- HMAC: Already works; ensure applied to all sends (commands, broadcasts, private, rotation).
- Errors: Add try/except in key ops, logging I/O; log to file, print minimal, disconnect on critical.

## Pending Tasks and Next Steps

1. Edit client.py: Fix get_log_path to flat chat_logs/ROOM-<room>-<timestamp>.txt (remove subfolder creation). In handle_command /join, after send, add callback or flag to reinitialize log_file on ROOM_CHANGE_SUCCESS in recv_loop. Add try/except in write_log, recv_loop decrypt/HMAC, rotation decrypt. Move key exchange to main() post-auth: After token save, recv SERVER_PUB_KEY with initial_fernet, generate session_key, encrypt with server_rsa_public_key, send CLIENT_SESSION_KEY with initial_fernet. Start threads only after session_fernet set. Ensure init_log_file(current_room) post-key exchange.
   - Quote from recent: "Client → complete login/register/token auth. Server → send SERVER_PUB_KEY. Client → send CLIENT_PUB_KEY and encrypted CLIENT_SESSION_KEY."
2. Edit server.py: In recv_loop, remove early SERVER_PUB_KEY send. Send AUTH_REQUIRED, enter auth loop (handle /token/register/login with initial_fernet until TOKEN sent). Post-auth (username set), send SERVER_PUB_KEY with initial_fernet. Continue loop to handle CLIENT_PUB_KEY (store rsa_public_key), then CLIENT_SESSION_KEY (decrypt, set session_fernet, authed=True). In rotate_session_key, add try/except for encrypt/send. In broadcast/private, ensure HMAC. Add try/except in write_log.
   - After edits: "Server → decrypt session key → mark client as authenticated."
3. Test: Use execute_command to run python server.py in background, then python client.py --name User1, auth, send msgs, /join room2, check logs created/switched, tamper msg to test HMAC fail log, simulate 100 msgs or time for rotation (manual adjust time for test), verify no crashes.
   - Quote: "Authentication completes before RSA exchange." "Logs are generated for each room and persist after closing." "Key rotation occurs automatically and resyncs properly."
4. If issues (e.g., decrypt error), read logs via read_file, iterate edits.
5. On completion: attempt_completion with summary, command to run server/client for demo.
