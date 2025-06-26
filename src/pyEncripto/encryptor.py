"""
Encryption tool for Python projects with asset bundling.

This script takes a source directory (`src`) and encrypts all Python files (`.py`)
and assets (e.g., PNGs, audio files) into a secure output directory.
- Python files are saved with a `.crpt` extension after encryption.
- Asset files are bundled into a JSON file `assets.pak` with encrypted keys and values.
- AES encryption is used in CFB mode with a password-derived SHA256 key.
- Asset names are hashed (deterministically) using SHA256(key + name) for lookup.

This structure allows later secure loading and runtime decryption of both code and resources.
"""
from .dotpac import build_pak

import os, base64, json
from pathlib import Path
from hashlib import sha256
from Crypto.Cipher import AES

CRPT_EXT = ".crpt"

# ====== KEY HANDLING ======

def derive_key(password: str) -> bytes:
    """
    Derives a 256-bit AES key from a UTF-8 password using SHA256.

    Args:
        password: Plaintext password.

    Returns:
        SHA256 digest (32 bytes).
    """
    return sha256(password.encode()).digest()

# ====== ENCRYPTION ======

def encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using AES-CFB with a random IV.

    The output is IV (16 bytes) + ciphertext.

    Args:
        data: Plaintext bytes to encrypt.
        key: 32-byte AES key.

    Returns:
        Encrypted bytes with IV prepended.
    """
    cipher = AES.new(key, AES.MODE_CFB)
    return cipher.iv + cipher.encrypt(data)

# ====== ASSET NAME KEYING ======

def name_key(path: str, key: bytes) -> str:
    """
    Generates a deterministic Base64-encoded hash from key and path.

    This ensures consistent dictionary keys for encrypted assets
    without using non-deterministic encryption (which uses random IVs).

    Args:
        path: Relative asset path (e.g., "hero.png").
        key: 32-byte AES key.

    Returns:
        Base64 string of SHA256(key + path).
    """
    h = sha256(key + path.encode()).digest()
    return base64.b64encode(h).decode()

# ====== PROJECT ENCRYPTION ======

def encrypt_project(src: Path, dst: Path, password: str):
    """
    Encrypts all Python source files and assets in a project folder.

    - `.py` files are encrypted and saved with `.crpt` extension.
    - All files in `assets/` are encrypted and added to `assets.pak`.

    Args:
        src: Source project folder.
        dst: Output folder where encrypted files are saved.
        password: Encryption password (used to derive AES key).
    """
    key = derive_key(password)

    # Clean and recreate destination directory
    if dst.exists():
        os.system(f"rm -rf {dst}")
    dst.mkdir(parents=True)

    # --- Encrypt Python files ---
    for f in src.rglob("*.py"):
        rel = f.relative_to(src).with_suffix(CRPT_EXT)
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(encrypt(f.read_bytes(), key))

    # --- Encrypt assets into JSON database ---
    build_pak(encrypt, key, src / "assets", dst / "assets.pak")
