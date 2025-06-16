# EndecTools

Local-first encryption/decryption utilities<br/>
by CMG Solutions

<!-- [![PyPI Version](https://img.shields.io/pypi/v/endectools)](https://pypi.org/project/endectools/) -->
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

EndecTools lets you securely encrypt and decrypt files or directories offline, using:

* **Compression:** TAR + Zstandard (multi-threaded, high-speed)
* **Encryption:** AES-CTR streaming + HMAC-SHA256 (authenticated)
* **Progress:** Adaptive chunk sizes with live `tqdm` bars
* **Directory support:** Archives directories before encrypting, auto-extracts on decrypt
* **Safe defaults:** Deletes source by default; use `--keep-source` to preserve

## Features

* **Fast compression:** Achieve 400–600 MiB/s with Zstandard
* **Streaming encryption:** Encrypt gigabytes without high memory usage
* **Authenticated:** Tamper-detection via HMAC
* **One-command CLI:** `endec encrypt` / `endec decrypt`
* **Progress bars:** See ETA, throughput, and total size

## Installation

```bash
git clone https://github.com/<YourUser>/EndecTools.git
cd EndecTools
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

# For local installation
python3 -m pip install -e .

```

## Usage

```bash
# Encrypt a file or folder (deletes source by default)
endec encrypt <path> [--out OUTPUT] [-k|--keep-source]

# Decrypt an encrypted archive (.enc) (deletes .enc by default)
endec decrypt <path>.enc [--out OUTPUT] [-k|--keep-source]

# Show version
endec version

# Install shell completion
endec --install-completion
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

## Roadmap

* Secure wipe of plaintext before deletion
* GitHub Actions CI and PyPI release
* Enhanced directory flags (exclusions, patterns)

## License

This project is licensed under the [MIT License](LICENSE).
