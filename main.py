"""
SecureVault — a command-line Password Manager with Multi-Factor Authentication

Security design:
  - Master password is never stored. Only a PBKDF2-HMAC-SHA256 verification
    hash is kept, and the AES-256 vault key is derived from the master
    password on every unlock (never persisted).
  - All credential fields are encrypted individually with AES-256-GCM
    (authenticated encryption).
  - A second factor (TOTP, RFC 6238) is required after the master
    password to unlock the vault, implemented from scratch in totp.py.

Usage:
    python main.py init
    python main.py add
    python main.py get <name>
    python main.py list
    python main.py delete <name>
    python main.py generate [--passphrase]
"""
import argparse
import getpass
import sys

import vault
from totp import get_totp, verify_totp, provisioning_uri
from generator import generate_password, generate_passphrase


def cmd_init(args):
    master = getpass.getpass("Create a master password: ")
    confirm = getpass.getpass("Confirm master password: ")
    if master != confirm:
        print("Passwords do not match.")
        sys.exit(1)
    if len(master) < 8:
        print("Master password should be at least 8 characters.")
        sys.exit(1)

    totp_secret = vault.init_vault(master)
    print("\nVault created successfully!")
    print("=" * 60)
    print("SET UP MULTI-FACTOR AUTHENTICATION")
    print("Add this secret to an authenticator app (Google Authenticator,")
    print("Authy, etc.) — either by entering it manually or by generating")
    print("a QR code from the URI below with any QR code library/site.")
    print("-" * 60)
    print("Secret:", totp_secret)
    print("URI:   ", provisioning_uri(totp_secret, "vault_user"))
    print("=" * 60)


def _authenticate() -> bytes:
    """Two-factor login: master password, then TOTP code. Returns the AES key."""
    master = getpass.getpass("Master password: ")
    try:
        key = vault.unlock(master)
    except vault.VaultError as e:
        print(f"Error: {e}")
        sys.exit(1)

    totp_secret = vault.get_totp_secret()
    code = input("6-digit authentication code: ").strip()
    if not verify_totp(totp_secret, code):
        print("Invalid authentication code. Access denied.")
        sys.exit(1)

    return key


def cmd_add(args):
    key = _authenticate()
    name = input("Entry name (e.g. 'gmail'): ").strip()
    username = input("Username / email: ").strip()

    choice = input("Generate a random password? [Y/n]: ").strip().lower()
    if choice in ("", "y", "yes"):
        pw = generate_password()
        print(f"Generated password: {pw}")
    else:
        pw = getpass.getpass("Password: ")

    notes = input("Notes (optional): ").strip()
    vault.add_entry(key, name, username, pw, notes)
    print(f"Saved entry '{name}'.")


def cmd_get(args):
    key = _authenticate()
    try:
        entry = vault.get_entry(key, args.name)
    except vault.VaultError as e:
        print(f"Error: {e}")
        sys.exit(1)
    print(f"\nUsername: {entry['username']}")
    print(f"Password: {entry['password']}")
    if entry["notes"]:
        print(f"Notes:    {entry['notes']}")


def cmd_list(args):
    _authenticate()  # still require full login to see even the entry names
    names = vault.list_entries()
    if not names:
        print("Vault is empty.")
    else:
        print("Saved entries:")
        for n in names:
            print(f"  - {n}")


def cmd_delete(args):
    _authenticate()
    try:
        vault.delete_entry(args.name)
        print(f"Deleted entry '{args.name}'.")
    except vault.VaultError as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_generate(args):
    if args.passphrase:
        print(generate_passphrase())
    else:
        print(generate_password(length=args.length))


def main():
    parser = argparse.ArgumentParser(description="SecureVault password manager")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)

    sub.add_parser("add", help="add a new credential entry").set_defaults(func=cmd_add)

    p_get = sub.add_parser("get", help="retrieve a credential entry")
    p_get.add_argument("name")
    p_get.set_defaults(func=cmd_get)

    sub.add_parser("list", help="list all saved entry names").set_defaults(func=cmd_list)

    p_del = sub.add_parser("delete", help="delete a credential entry")
    p_del.add_argument("name")
    p_del.set_defaults(func=cmd_delete)

    p_gen = sub.add_parser("generate", help="generate a strong password/passphrase")
    p_gen.add_argument("--passphrase", action="store_true")
    p_gen.add_argument("--length", type=int, default=16)
    p_gen.set_defaults(func=cmd_generate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
