# 🔐 PyEncripto

**PyEncripto** is a tool for encrypting Python source code and resources (assets) with secure runtime decryption. It is designed to protect intellectual property and create encrypted Python packages.

## 🚀 Features

- 🔒 Encrypt `.py` files into `.crpt` using AES (CFB mode)
- 📦 Package and encrypt resources (from `assets/` folder) into `assets.pak`
- 🧹 Runtime loading of encrypted modules
- 🖼 Runtime loading and decryption of encrypted assets (images, sounds, etc.)
- 🔑 Support for encryption keys
- 🧪 Run encrypted projects with preserved `main.main()` interface

---

## 📦 Installation

```bash
pip install pyencripto
```

---

## 💠 Usage

### 1. Encrypt a project

```bash
pyencripto encrypt <source_folder> <output_folder> --key <key>
```

Example:

```bash
pyencripto encrypt ./my_project ./my_project_crpt --key secret123
```

What happens:

- All `.py` files are encrypted and saved with `.crpt` extension
- The `assets/` folder is encrypted and packed into `assets.pak`

> ⚠️ The `.crpt` extension is mandatory! It is used by the module loader.

---

### 2. Run an encrypted project

```bash
pyencripto run <encrypted_project_folder> <key>
```

Example:

```bash
pyencripto run ./my_project_crpt secret123
```

> The project must contain an encrypted `main.crpt` file with a `main()` function.

---

## 📁 Project structure

Original project:

```
my_project/
├── main.py          # contains main()
├── utils/
│   └── helper.py
└── assets/
    └── image.png
```

After encryption:

```
my_project_crpt/
├── main.crpt
├── utils/
│   └── helper.crpt
└── assets.pak
```

---

## 🔧 Internal modules

- `encryptor.py` — handles project encryption
- `secure_runtime.py` — loads `.crpt` modules and decrypts assets at runtime
- `cli.py` — CLI interface (`pyencripto encrypt|run`)

---

## 🧪 Requirements

- Python 3.10+
- `pycryptodome` (automatically installed)

---

## ⚠️ Security notes

- Encryption makes reverse engineering harder but not impossible. Do not treat this as absolute protection.
- The key is stored only in memory but can be extracted during runtime.

---
