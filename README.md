EndecTools

Local-first encryption/decryption utilities

EndecTools lets you securely encrypt and decrypt files or directories offline, using:
	•	Compression: TAR + Zstandard (multi-threaded, high-speed)
	•	Encryption: AES-CTR streaming + HMAC-SHA256 (authenticated)
	•	Progress: Adaptive chunk sizes with live tqdm bars
	•	Directory support: Archives directories before encrypting, auto-extracts on decrypt
	•	Safe defaults: Deletes source by default; use --keep-source to preserve

⸻

Features
	•	Fast compression: Achieve 400–600 MiB/s with Zstandard
	•	Streaming encryption: Encrypt gigabytes without high memory usage
	•	Authenticated: Tamper-detection via HMAC
	•	One-command CLI: endec encrypt / endec decrypt
	•	Progress bars: See ETA, throughput, and total size

Installation

git clone https://github.com/<YourUser>/EndecTools.git
cd EndecTools
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .

Usage

# Encrypt a file or folder (deletes source by default)
endec encrypt <path> [--out OUTPUT] [-k | --keep-source]

# Decrypt an encrypted archive (.enc) (deletes .enc by default)
endec decrypt <path>.enc [--out OUTPUT] [-k | --keep-source]

# Show version
endec version

# Install shell completion
endec --install-completion

Examples

# Encrypt a directory and remove it
endec encrypt documents -k
# decrypt, keep .enc
endec decrypt documents.tar.zst.enc --keep-source

Development
	1.	Create a virtual environment and install editable package
	2.	Edit code under endectools/
	3.	Run tests: pytest --maxfail=1 -q
	4.	Lint with flake8 or black

Testing

Unit tests cover core logic and CLI:

pytest

Roadmap
	•	Secure wipe of plaintext before deletion
	•	GitHub Actions CI and PyPI release
	•	Enhanced directory flags (exclusions, patterns)

License

This project is licensed under the MIT License. See LICENSE for details.