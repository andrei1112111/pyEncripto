"""
secure_runtime.py

This module provides runtime support for executing encrypted Python projects:
- Decrypts `.crpt` modules dynamically on import
- Loads encrypted assets from `assets.pak`
- Manages encryption key and base path configuration

Used during execution of projects encrypted with PyEncripto.
"""

import sys, base64, json
from pathlib import Path
from hashlib import sha256
from Crypto.Cipher import AES
import importlib.util
import importlib.abc
from types import ModuleType

# ====== KEY HANDLING ======

_key = None

def set_key(pw: str):
    """
    Set the encryption key derived from the given password.
    Must be called before decrypting anything.
    """
    global _key
    _key = sha256(pw.encode()).digest()

def _get_key():
    """
    Returns the current key or raises an error if not set.
    """
    if _key is None:
        raise RuntimeError("Encryption key is not set. Call set_key(password) first.")
    return _key

def name_key(path: str, key: bytes) -> str:
    """
    Generates a consistent hashed base64-encoded name for an asset,
    based on its relative path and the encryption key.
    """
    h = sha256(key + path.encode()).digest()
    return base64.b64encode(h).decode()


# ====== DECRYPTION ======

def decrypt_bytes(data: bytes, key: bytes) -> bytes:
    """
    Decrypts AES-CFB encrypted binary data with prepended IV.
    """
    iv, content = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(content)

def decrypt_file(fpath: Path) -> bytes:
    """
    Reads and decrypts a file from disk using the current key.
    """
    return decrypt_bytes(fpath.read_bytes(), _get_key())


# ====== ENCRYPTED MODULE LOADER ======

class EncryptedModuleLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """
    Custom module loader that allows importing .crpt encrypted Python modules.
    """
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir.resolve()

    def find_spec(self, fullname, path, target=None):
        """
        Finds encrypted modules by looking for a corresponding .crpt file.
        """
        rel_path = Path(*fullname.split("."))  # e.g., utils.crypto → utils/crypto
        crpt_file = self.base_dir / (str(rel_path) + ".crpt")
        if crpt_file.exists():
            return importlib.util.spec_from_loader(fullname, self)
        return None

    def create_module(self, spec):
        """
        Optionally creates the module. Returning None uses the default mechanism.
        """
        return ModuleType(spec.name)

    def exec_module(self, module):
        """
        Decrypts and executes the module's code in its namespace.
        """
        rel_path = Path(*module.__name__.split("."))
        crpt_file = self.base_dir / (str(rel_path) + ".crpt")
        code = decrypt_file(crpt_file)
        exec(code, module.__dict__)

def enable_encrypted_imports(base_dir: str):
    """
    Enables encrypted module loading globally via sys.meta_path.
    Use only once at startup.
    """
    sys.meta_path.insert(0, EncryptedModuleLoader(Path(base_dir)))


# ====== ASSET LOADER ======

RESOURCE_DB = {}  # Cached decoded asset map
_BASE_PATH = None  # Path to encrypted project root

def set_base_path(path):
    """
    Sets the root directory for the encrypted project (used for loading assets).
    """
    global _BASE_PATH
    _BASE_PATH = Path(path).resolve()

def load_asset(path: str) -> bytes:
    """
    Decrypts and returns the contents of an asset from the assets.pak bundle.

    Args:
        path (str): Relative path of the asset inside the original project.

    Returns:
        bytes: Decrypted asset content.
    """
    global RESOURCE_DB, _BASE_PATH
    if not RESOURCE_DB:
        if _BASE_PATH is None:
            raise RuntimeError("Base path for assets not set. Call set_base_path(path) first.")

        # Load encrypted asset bundle
        pak = _BASE_PATH / "assets.pak"
        raw = json.loads(pak.read_text())

        # Decrypt and cache each entry
        for name, enc_b64 in raw.items():
            RESOURCE_DB[name] = decrypt_bytes(base64.b64decode(enc_b64), _get_key())

    # Compute hashed name and return decrypted data
    name = name_key(path, _get_key())
    if name not in RESOURCE_DB:
        raise FileNotFoundError(f"Encrypted asset not found: {path}")
    
    return RESOURCE_DB[name]
