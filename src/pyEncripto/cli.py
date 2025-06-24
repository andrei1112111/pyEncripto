"""
Main CLI entry point for PyEncripto project.

Supports two commands:
1. `encrypt <src> <dst> [--key KEY]` — Encrypts a project folder.
2. `run <encrypted_dir> <key>` — Decrypts and runs `main.crpt` from encrypted folder.

Dependencies:
- encryptor.py: handles encryption of source/asset files.
- secure_runtime.py: decrypts and loads encrypted modules/resources at runtime.
"""

import argparse, sys, runpy, importlib.util, types
from pathlib import Path
from . import encryptor, secure_runtime

# ====== CLI HANDLER ======

def main():
    """
    Entry point for CLI.

    Parses arguments and delegates to either encryption or execution.
    """
    parser = argparse.ArgumentParser(description="PyEncripto CLI")
    parser.add_argument("command", choices=["encrypt", "run"],
                        help="Choose 'encrypt' to compile project or 'run' to execute it.")
    parser.add_argument("source",
                        help="'encrypt': path to source project, 'run': path to encrypted folder")
    parser.add_argument("output_or_key",
                        help="'encrypt': output directory, 'run': decryption key")
    parser.add_argument("--key", help="Encryption password (optional for 'encrypt')", required=False)
    args = parser.parse_args()

    # ====== ENCRYPT COMMAND ======
    if args.command == "encrypt":
        encryptor.encrypt_project(
            Path(args.source),
            Path(args.output_or_key),
            args.key or "default"  # Fallback key if not provided
        )
        print(f"[*] Encripting {args.source}")
        print(f"[✓] Project encrypted to {args.output_or_key}")
    
    # ====== RUN COMMAND ======
    elif args.command == "run":
        path = Path(args.source)
        key = args.output_or_key

        # Set decryption context
        secure_runtime.set_key(key)
        secure_runtime.set_base_path(path)

        # Enable encrypted module importing
        sys.path.insert(0, str(path))
        sys.meta_path.insert(0, secure_runtime.EncryptedModuleLoader(path))

        # Load and execute decrypted main.crpt module
        code = secure_runtime.decrypt_file(path / "main.crpt")
        mod = types.ModuleType("main")
        mod.__file__ = str(path / "main.crpt")
        sys.modules["main"] = mod

        # Inject runtime asset loader into module scope
        mod.PYENCRIPTO_load_asset = secure_runtime.load_asset

        mod.USED_PYENCRIPTO = True

        # Run the decrypted code inside the `main` module's namespace
        exec(code, mod.__dict__)

        # If a `main()` function is defined, call it
        if hasattr(mod, "main"):
            mod.main()
