# SecureVault — Password Manager with Multi-Factor Authentication

A command-line password manager implementing the core security design
from my final-year project: **AES-256 encryption**, **PBKDF2 key
derivation**, and **multi-factor authentication (TOTP)** — all
implemented directly rather than relying on a single high-level "vault"
library, so the underlying cryptography is visible and understandable.

## Why this design
- **Master password is never stored.** Only a PBKDF2-HMAC-SHA256
  verification hash is kept; the actual AES-256 key is re-derived from
  the master password on every unlock and never written to disk.
- **AES-256-GCM (authenticated encryption)** protects every stored
  credential field individually — tampering with the ciphertext is
  detected on decryption, not silently ignored.
- **A second factor is mandatory.** After the master password, a
  6-digit TOTP code (RFC 6238, same standard as Google
  Authenticator/Authy) is required to unlock the vault. The TOTP
  algorithm is implemented from scratch in `totp.py`, not imported from
  a library, to demonstrate understanding of how it actually works.
- **A password/passphrase generator** is included, matching the
  original project's approach of offering both random passwords and
  memorable multi-word passphrases.

## Project structure
```
main.py           CLI entry point (init / add / get / list / delete / generate)
vault.py          Encrypted vault storage (reads/writes vault.json)
crypto_utils.py   PBKDF2 key derivation + AES-256-GCM encrypt/decrypt
totp.py           RFC 6238 TOTP implementation (MFA)
generator.py      Random password / passphrase generator
requirements.txt
```

## How to run
```bash
pip install -r requirements.txt

python main.py init      # create your vault + master password + MFA secret
python main.py add       # add a new credential (prompts for master password + TOTP code)
python main.py get gmail # retrieve a saved credential
python main.py list      # list saved entry names
python main.py delete gmail
python main.py generate --passphrase
```

On `init`, you'll be shown a TOTP secret and an `otpauth://` URI — enter
the secret manually into any authenticator app (Google Authenticator,
Authy, etc.) to receive the 6-digit codes needed to unlock the vault
afterward.

## Security notes (for anyone reviewing this repo)
- This is a learning/portfolio project, not an audited production
  security tool — don't use it to store real high-value credentials.
- `vault.json` is created locally and is git-ignored; never commit a
  real vault file.
- The TOTP implementation is for educational transparency; for a
  production system, a well-audited library would normally be
  preferred over a hand-rolled crypto primitive.

## Skills demonstrated
Applied cryptography (PBKDF2, AES-256-GCM), implementing a standard
protocol (TOTP/RFC 6238) from its specification, secure secret handling
(`getpass`, never persisting the master password), and CLI application
design with `argparse`.
