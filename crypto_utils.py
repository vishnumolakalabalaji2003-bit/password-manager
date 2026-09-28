"""
Cryptographic core for the password manager.

- PBKDF2-HMAC-SHA256 to derive a 256-bit vault key from the user's master
  password (slow-by-design, resists brute-force / dictionary attacks).
- AES-256 in GCM mode to encrypt/decrypt the vault (authenticated
  encryption — tampering with ciphertext is detected, not just silently
  decrypted into garbage).
"""
import os
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 12  # recommended nonce size for AES-GCM
KEY_SIZE = 32    # 256 bits


def derive_key(master_password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit AES key from the master password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        iterations,
        dklen=KEY_SIZE,
    )


def hash_master_password(master_password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> str:
    """
    A separate PBKDF2 hash (different purpose than the vault key derivation)
    used only to *verify* the master password at login, so the raw vault
    key material is never compared/stored directly.
    """
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt + b"verify",  # domain-separate from the key-derivation salt use
        iterations,
        dklen=32,
    )
    return base64.b64encode(digest).decode("utf-8")


def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def encrypt(plaintext: str, key: bytes) -> str:
    """AES-256-GCM encrypt; returns base64(nonce || ciphertext) as a single string."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt(token: str, key: bytes) -> str:
    """Reverse of encrypt(). Raises InvalidTag if the key is wrong or data was tampered with."""
    raw = base64.b64decode(token)
    nonce, ciphertext = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
