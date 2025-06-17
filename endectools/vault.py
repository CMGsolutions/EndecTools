import os
import json
import uuid
from pathlib import Path
from base64 import urlsafe_b64decode, urlsafe_b64encode
from getpass import getpass
import subprocess

from endectools.utils.crypto import (
    derive_keys,
    encrypt_entry,
    decrypt_entry,
    encrypt_vault,
    decrypt_vault,
    generate_salt,
)

VAULT_DIR = Path.home() / ".endec_vault"
VAULT_FILE = VAULT_DIR / "vault.json.enc"
HEADER_FILE = VAULT_DIR / "vault_header.json"


def check_vault_exists():
    if not VAULT_FILE.exists() or not HEADER_FILE.exists():
        print("❌ Vault not found. Please run 'endec vault init' first.")
        return False
    return True


def init_vault():
    if VAULT_FILE.exists():
        print("Vault already exists.")
        return

    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    password = getpass("Create a master password: ")
    salt = generate_salt()
    real_pw, user_hash, vault_key = derive_keys(password, salt)

    data = {
        "version": 1,
        "user_hash": user_hash,
        "entries": []
    }

    encrypted = encrypt_vault(data, vault_key)

    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

    with open(HEADER_FILE, "w") as f:
        json.dump({"salt": urlsafe_b64encode(salt).decode(), "version": 1}, f)

    print("Vault initialized successfully.")


def load_vault(password):
    if not check_vault_exists():
        raise FileNotFoundError("Vault or header missing.")

    with open(HEADER_FILE, "r") as f:
        header = json.load(f)
        salt = urlsafe_b64decode(header["salt"])

    _, _, vault_key = derive_keys(password, salt)

    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()

    return decrypt_vault(encrypted, vault_key), vault_key, salt


def save_vault(vault_data, vault_key):
    encrypted = encrypt_vault(vault_data, vault_key)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)


def add_secret():
    if not check_vault_exists():
        return

    password = getpass("Enter master password: ")
    vault, vault_key, salt = load_vault(password)

    label = input("Label for secret: ")
    secret = input("Secret value: ")
    entry_pw = getpass("Password for this entry: ")

    enc_secret, entry_hash = encrypt_entry(secret, entry_pw)
    enc_label, _ = encrypt_entry(label, entry_pw)

    vault["entries"].append({
        "id": str(uuid.uuid4()),
        "label": enc_label,
        "entry_hash": entry_hash,
        "enc_secret": enc_secret
    })

    save_vault(vault, vault_key)
    print(f"Secret added.")


def get_secret():
    if not check_vault_exists():
        return

    password = getpass("Enter master password: ")
    vault, _, _ = load_vault(password)

    entry_pw = getpass("Password for this entry: ")
    entry_hash = encrypt_entry("", entry_pw)[1]  # Get hash only

    for entry in vault["entries"]:
        if entry["entry_hash"] == entry_hash:
            label = decrypt_entry(entry["label"], entry_pw)
            result = decrypt_entry(entry["enc_secret"], entry_pw)
            if result:
                print(f"Label: {label}\nSecret: {result}")
                return
            else:
                print("Incorrect password.")
                return

    print("No matching entry found.")


def list_secrets():
    if not check_vault_exists():
        return

    password = getpass("Enter master password: ")
    vault, _, _ = load_vault(password)
    if not vault["entries"]:
        print("Vault is empty.")
        return

    print("Stored secret entries:")
    for i, _ in enumerate(vault["entries"], start=1):
        print(f"- Entry {i}")


def delete_secret():
    if not check_vault_exists():
        return

    password = getpass("Enter master password: ")
    vault, vault_key, _ = load_vault(password)

    entry_pw = getpass("Password for this entry: ")
    entry_hash = encrypt_entry("", entry_pw)[1]

    for i, entry in enumerate(vault["entries"]):
        if entry["entry_hash"] == entry_hash:
            label = decrypt_entry(entry["label"], entry_pw)
            del vault["entries"][i]
            save_vault(vault, vault_key)
            print(f"Secret '{label}' deleted.")
            return

    print("No matching entry found.")


def edit_secret():
    if not check_vault_exists():
        return

    password = getpass("Enter master password: ")
    vault, vault_key, _ = load_vault(password)

    entry_pw = getpass("Password for this entry: ")
    entry_hash = encrypt_entry("", entry_pw)[1]

    for entry in vault["entries"]:
        if entry["entry_hash"] == entry_hash:
            current_label = decrypt_entry(entry["label"], entry_pw)
            current_secret = decrypt_entry(entry["enc_secret"], entry_pw)

            print(f"Current label: {current_label}")
            print(f"Current secret: {current_secret}")

            new_label = input("New label (leave blank to keep current): ") or current_label
            new_secret = input("New secret (leave blank to keep current): ") or current_secret

            enc_label, _ = encrypt_entry(new_label, entry_pw)
            enc_secret, _ = encrypt_entry(new_secret, entry_pw)

            entry["label"] = enc_label
            entry["enc_secret"] = enc_secret

            save_vault(vault, vault_key)
            print("Secret updated successfully.")
            return

    print("No matching entry found.")


def delete_vault():
    if not check_vault_exists():
        return

    confirm = input("Are you sure you want to permanently delete the entire vault? (y/N): ")
    if confirm.lower() != 'y':
        print("Vault deletion cancelled.")
        return

    print("System password required (sudo)...")
    try:
        subprocess.run(["sudo", "-v"], check=True)
    except subprocess.CalledProcessError:
        print("❌ Authentication failed. Vault deletion aborted.")
        return

    if VAULT_FILE.exists():
        os.remove(VAULT_FILE)
    if HEADER_FILE.exists():
        os.remove(HEADER_FILE)
    if VAULT_DIR.exists() and not any(VAULT_DIR.iterdir()):
        VAULT_DIR.rmdir()

    print("✅ Vault and header deleted successfully.")
