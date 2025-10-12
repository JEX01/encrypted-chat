# Level 1 — Two-Person Encrypted Chat
# Files included below: keygen.py, server.py, client.py
# Save each section into separate files before running.

# ------------------------------
# keygen.py
# ------------------------------
"""
Generates a Fernet symmetric key and writes to a file (default: shared.key).
Usage:
    python keygen.py --out shared.key
"""
import argparse
from cryptography.fernet import Fernet


def main():
    p = argparse.ArgumentParser(description='Generate a Fernet key file.')
    p.add_argument('--out', '-o', default='shared.key', help='Output key filename')
    args = p.parse_args()

    key = Fernet.generate_key()
    with open(args.out, 'wb') as f:
        f.write(key)
    print(f'Key written to {args.out}')


if __name__ == '__main__':
    main()


