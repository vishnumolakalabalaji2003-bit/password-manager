"""
Vault storage — a single encrypted JSON file on disk holding:
  - master password verification hash + its salt
  - the MFA (TOTP) secret
  - the encrypted key-derivation salt
  - a dict of encrypted credential entries: { name: {username, password, notes} }

Each credential's fields are individually encrypted with AES-256-GCM
under a key derived from the master password via PBKDF2, so nothing in
the file is readable without the master password.
"""
import json
import os
import base64

from crypto_utils import (
    new_salt, derive_key, encrypt, decrypt, hash_master_password,
)
from totp import generate_secret

VAULT_FILE = "vault.json"


class VaultError(Exception):
    pass


def vault_exists(path: str = VAULT_FILE) -> bool:
    return os.path.exists(path)


def init_vault(master_password: str, path: str = VAULT_FILE) -> str:
    """
    Create a brand-new vault. Returns the TOTP secret so the caller can
    show it to the user once (to add to an authenticator app).
    """
    if vault_exists(path):
        raise VaultError("A vault already exists. Delete it first if you want to start over.")

    salt = new_salt()
    verify_hash = hash_master_password(master_password, salt)
    totp_secret = generate_secret()

    data = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "verify_hash": verify_hash,
        "totp_secret": totp_secret,
        "entries": {},
    }
    _write(data, path)
    return totp_secret


def _write(data: dict, path: str = VAULT_FILE) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _read(path: str = VAULT_FILE) -> dict:
    if not vault_exists(path):
        raise VaultError("No vault found. Run `init` first.")
    with open(path) as f:
        return json.load(f)


def unlock(master_password: str, path: str = VAULT_FILE) -> bytes:
    """
    Verify the master password and return the derived AES key.
    Raises VaultError if it doesn't match.
    """
    data = _read(path)
    salt = base64.b64decode(data["salt"])
    if hash_master_password(master_password, salt) != data["verify_hash"]:
        raise VaultError("Incorrect master password.")
    return derive_key(master_password, salt)


def get_totp_secret(path: str = VAULT_FILE) -> str:
    return _read(path)["totp_secret"]


def add_entry(key: bytes, name: str, username: str, password: str, notes: str = "", path: str = VAULT_FILE) -> None:
    data = _read(path)
    data["entries"][name] = {
        "username": encrypt(username, key),
        "password": encrypt(password, key),
        "notes": encrypt(notes, key),
    }
    _write(data, path)


def get_entry(key: bytes, name: str, path: str = VAULT_FILE) -> dict:
    data = _read(path)
    if name not in data["entries"]:
        raise VaultError(f"No entry named '{name}'.")
    enc = data["entries"][name]
    return {
        "username": decrypt(enc["username"], key),
        "password": decrypt(enc["password"], key),
        "notes": decrypt(enc["notes"], key),
    }


def list_entries(path: str = VAULT_FILE) -> list:
    data = _read(path)
    return sorted(data["entries"].keys())


def delete_entry(name: str, path: str = VAULT_FILE) -> None:
    data = _read(path)
    if name not in data["entries"]:
        raise VaultError(f"No entry named '{name}'.")
    del data["entries"][name]
    _write(data, path)
