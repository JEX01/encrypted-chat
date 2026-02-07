This repository intentionally excludes certain files such as:

runtime logs
user data files (users.json)
authentication/token files (token.json, tokens.json)
encryption key material (*.key)

These files are generated at runtime and may contain sensitive or personal data.
For security, privacy, they are not tracked in version control and have been removed from the repository history.

As a result, the repository may appear to contain fewer files than a full runtime environment, which is expected and intentional.

If required, placeholder or example files can be created locally based on the application logic.

👍👍

level --0
just one to one

-----1

- encrption
- logfile with all detailed chat logs stored in file
- soved eror in diffrent ways like chlint and server exit error

--- 2

Server Features :-
Multi-client support (threaded)
Encrypted communication (Fernet)
Username handling
Room support
Logging (timestamped)
Broadcast messages
Graceful handling of disconnections
Automatic Fernet key generation
Server resilience (error handling)
Time-stamped console display
Read-only log file locking

Client Features :-
Encrypted communication (Fernet)
Username input (CLI or prompt)
Logging (sent/received messages)
Asynchronous message receiving (threaded)
Display messages with timestamp and sender
Graceful exit (/quit or Ctrl+C)
Error handling (connection, decryption, socket errors)
Low CPU usage (small sleep in loop)

--- 3
Serve :- handles registration, login, and token validation using SQLite.
Client:- can register, login, or auto-login with a token.
Messaging & encryption stay the same.

had many issue with logs, error, and new feature addition, and more a lot more

-----4
features:-
secutiry commands- /help,/quit,/exit, /room, /rooms-list, etc

- clear terminal

-------5

> /help
> Available commands:

    /help - show this help
    /quit - exit chat
    /rooms - list available rooms                       //does not work
    /join <room> - switch to another room               //does not work
    /users - list users in current room
    /msg <user> <message> - private message              //does not work
    /clear
