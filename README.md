# EndecTools – v1.1.0  
📦 Streaming offline encryption/decryption with TAR+Zstd, AES-CTR+HMAC, secure vault, and shredding utilities.

[![CI](https://github.com/YourUser/EndecTools/actions/workflows/ci.yaml/badge.svg)](https://github.com/CMGsolutions/EndecTools/actions/workflows/ci.yml)
<!-- [![Coverage](https://codecov.io/gh/YourUser/EndecTools/branch/main/graph/badge.svg)](…) -->
<!-- [![PyPI](https://img.shields.io/pypi/v/endectools)](https://pypi.org/project/endectools) -->
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**EndecTools** lets you securely encrypt files or folders using high-speed compression, strong encryption, and tamper detection. It also includes a local-first secrets **vault** and string **hashing utilities**.

* **Compression:** TAR + Zstandard (multi-threaded, high-speed)
* **Encryption:** AES-CTR streaming + HMAC-SHA256 (authenticated)
* **Progress:** Adaptive chunk sizes with live `tqdm` bars
* **Directory support:** Archives directories before encrypting, auto-extracts on decrypt
* **Safe defaults:** Deletes source by default; use `--keep-source` to preserve

## Table of Contents  
- [EndecTools – v1.1.0](#endectools--v110)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Usage](#usage)
  - [Vault Commands](#vault-commands)
  - [Hash Utilities](#hash-utilities)
  - [Testing](#testing)
  - [License](#license)

## Features

- 🔒 **Streaming encryption:** AES-CTR + HMAC-SHA256 for gigabyte-scale data
- 📦 **Fast compression:** TAR + Zstandard at 400–600 MiB/s
- 🔁 **Directory support:** Archives/extracts full directory trees
- 🧪 **Tamper detection:** Authenticated encryption via HMAC
- 🔐 **Encrypted secrets vault:** Master password + per-entry password
- 🧮 **Hashing utilities:** Choose from SHA-256, BLAKE2, SHA-1, MD5, etc.
- 📊 **Live progress:** `tqdm` bars with ETA, throughput, and size
- 🧨 **Shred support:** Securely erase files or folders with multiple passes
- 🧪 **Tested:** Fully unit-tested core logic

## Installation  
```bash
git clone https://github.com/CMGsolutions/EndecTools.git
cd EndecTools
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```
## Quick Start

```bash
# Encrypt a directory (deletes source by default)
endec encrypt my_folder

# Decrypt it back
endec decrypt my_folder.tar.zst.enc

# Hash a string
endec hash string
```

## Usage

```bash
# Encrypt a file or folder
endec encrypt <path> [--out OUTPUT] [-k|--keep-source] [-n|--no-shred]

# Decrypt an encrypted archive (.enc)
endec decrypt <path>.enc [--out OUTPUT] [-k|--keep-source] [-n|--no-shred]

# Shred a file or folder
endec shred <path> [-p PASSES] [--pattern rand|zero]

# Show version
endec version
```

## Vault Commands

Store and retrieve encrypted strings with per-entry passwords:

```bash
# Initialize new vault
endec vault init

# Add a secret (label + value + entry password)
endec vault add

# Retrieve a secret
endec vault get

# Edit a stored secret
endec vault edit

# Delete a specific secret
endec vault delete

# List encrypted labels (only if label encryption disabled)
endec vault list

# Destroy the entire vault (requires system password)
endec vault destroy
```
Vault security features:
- Master password (3-layer SHA-256 derivation)
- Fully encrypted metadata and labels
- Per-entry password required to decrypt individual secrets
- AES-CTR + HMAC authenticated encryption
- System password required to destroy vault

## Hash Utilities

Store and retrieve encrypted strings with per-entry passwords:

```bash
# Interactively hash a string
endec hash string

# Choose from: SHA-256, BLAKE2, SHA-1, MD5, and others
```

## Testing

All core functionality and CLI commands are covered by pytest:

```bash
# Run unit tests with concise output
pytest --maxfail=1 -q
```

For coverage reporting (optional), install `pytest-cov` and run:

```bash
pytest --maxfail=1 -q --cov=endectools --cov-report=term-missing
```

## License

This project is licensed under the [MIT License](LICENSE).
