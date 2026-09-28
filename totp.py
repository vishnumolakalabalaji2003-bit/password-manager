"""
Minimal TOTP (Time-based One-Time Password) implementation — RFC 6238.

Implemented from scratch (no external MFA library) to demonstrate the
underlying algorithm used by apps like Google Authenticator / Authy.

Compatible with any standard authenticator app: the Base32 secret this
module generates can be entered manually into Google Authenticator,
Authy, etc.
"""
import base64
import hashlib
import hmac
import os
import struct
import time


def generate_secret(length: int = 20) -> str:
    """Generate a random Base32-encoded secret (suitable for authenticator apps)."""
    random_bytes = os.urandom(length)
    return base64.b32encode(random_bytes).decode("utf-8")


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """HMAC-based OTP (RFC 4226) — the building block for TOTP."""
    key = base64.b32decode(secret_b32.upper())
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    offset = mac[-1] & 0x0F
    truncated = mac[offset:offset + 4]
    code_int = struct.unpack(">I", truncated)[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)


def get_totp(secret_b32: str, digits: int = 6, interval: int = 30, for_time: float = None) -> str:
    """Current TOTP code for the given secret."""
    t = for_time if for_time is not None else time.time()
    counter = int(t // interval)
    return _hotp(secret_b32, counter, digits)


def verify_totp(secret_b32: str, code: str, digits: int = 6, interval: int = 30, window: int = 1) -> bool:
    """
    Verify a submitted TOTP code, allowing +/- `window` time-steps of
    clock drift (standard practice for TOTP verification).
    """
    now = time.time()
    for offset in range(-window, window + 1):
        candidate_time = now + (offset * interval)
        if get_totp(secret_b32, digits, interval, candidate_time) == code:
            return True
    return False


def provisioning_uri(secret_b32: str, account_name: str, issuer: str = "SecureVault") -> str:
    """
    Build a otpauth:// URI that (if you add the optional `qrcode` package)
    can be turned into a QR code for scanning into an authenticator app.
    """
    return (
        f"otpauth://totp/{issuer}:{account_name}"
        f"?secret={secret_b32}&issuer={issuer}&digits=6&period=30"
    )


if __name__ == "__main__":
    secret = generate_secret()
    print("Secret (enter manually into your authenticator app):", secret)
    print("Provisioning URI:", provisioning_uri(secret, "demo_user"))
    print("Current code:", get_totp(secret))
