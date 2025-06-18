import os
import json
import uuid
import subprocess
from pathlib import Path
from base64 import urlsafe_b64decode, urlsafe_b64encode
from getpass import getpass

from endectools.utils.crypto import (
    derive_keys,
    encrypt_entry,
    decrypt_entry,
    encrypt_vault,
    decrypt_vault,
    generate_salt,
)

def get_vault_paths():
    """Returns: (vault_dir, vault_file, header_file)"""
    env_path = os.getenv("ENDECTOOLS_VAULT_PATH")
    if env_path:
        vault_file = Path(env_path)
        vault_dir = vault_file.parent
    else:
        vault_dir = Path.home() / ".endec_vault"
        vault_file = vault_dir / ".vault.json.enc"

    header_file = vault_dir / ".vault_header.json"
    return vault_dir, vault_file, header_file

def check_vault_exists():
    _, vault_file, header_file = get_vault_paths()
    if not vault_file.exists() or not header_file.exists():
        print("❌ Vault not found. Please run 'endec vault init' first.")
        return False
    return True

def init_vault():
    vault_dir, vault_file, header_file = get_vault_paths()

    if vault_file.exists() and header_file.exists():
        print("Vault already exists.")
        return

    vault_dir.mkdir(parents=True, exist_ok=True)
    password = getpass("Create a master password: ")
    salt = generate_salt()
    _, user_hash, vault_key = derive_keys(password, salt)

    vault_data = {
        "version": 1,
        "user_hash": user_hash,
        "entries": []
    }

    encrypted = encrypt_vault(vault_data, vault_key)

    with open(vault_file, "wb") as f:
        f.write(encrypted)

    with open(header_file, "w") as f:
        json.dump({"salt": urlsafe_b64encode(salt).decode(), "version": 1}, f)

    print("Vault initialized successfully.")

def load_vault(password):
    vault_dir, vault_file, header_file = get_vault_paths()

    if not vault_file.exists() or not header_file.exists():
        raise FileNotFoundError("Vault or header missing.")

    with open(header_file, "r") as f:
        header = json.load(f)
        salt = urlsafe_b64decode(header["salt"])

    _, _, vault_key = derive_keys(password, salt)

    with open(vault_file, "rb") as f:
        encrypted = f.read()

    return decrypt_vault(encrypted, vault_key), vault_key, salt

def save_vault(vault_data, vault_key):
    _, vault_file, _ = get_vault_paths()
    encrypted = encrypt_vault(vault_data, vault_key)
    with open(vault_file, "wb") as f:
        f.write(encrypted)

def add_secret():
    if not check_vault_exists():
        return

    password = getpass("Enter master password: ")
    try:
        vault, vault_key, _ = load_vault(password)
    except Exception:
        print("❌ Vault decryption failed. Wrong password or corrupted file.")
        return

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
    print("Secret added.")

def get_secret():
    if not check_vault_exists():
        return

    password = getpass("Enter master password: ")
    try:
        vault, _, _ = load_vault(password)
    except Exception:
        print("❌ Vault decryption failed. Wrong password or corrupted file.")
        return

    entry_pw = getpass("Password for this entry: ")
    entry_hash = encrypt_entry("", entry_pw)[1]

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

def get_secret_by_label(label: str, master_pw: str, entry_pw: str) -> str | None:
    if not check_vault_exists():
        return None

    try:
        vault, _, _ = load_vault(master_pw)
    except Exception:
        return None

    entry_hash = encrypt_entry(label, entry_pw)[1]

    for entry in vault["entries"]:
        if entry["entry_hash"] == entry_hash:
            return decrypt_entry(entry["enc_secret"], entry_pw)

    return None

def delete_secret():
    if not check_vault_exists():
        return

    try:
        password = getpass("Enter master password: ")
        vault, vault_key, _ = load_vault(password)
    except (ValueError, FileNotFoundError):
        print("❌ Vault decryption failed. Wrong password or corrupted file.")
        return

    if not vault.get("entries"):
        print("ℹ️ No entries to delete.")
        return

    entry_pw = getpass("Password for this entry: ")
    entry_hash = encrypt_entry("", entry_pw)[1]

    for i, entry in enumerate(vault["entries"]):
        if entry["entry_hash"] == entry_hash:
            label = decrypt_entry(entry["label"], entry_pw)
            del vault["entries"][i]
            save_vault(vault, vault_key)
            print(f"✅ Secret '{label}' deleted.")
            return

    print("No matching entry found.")

def edit_secret():
    if not check_vault_exists():
        return

    password = getpass("Enter master password: ")
    try:
        vault, vault_key, _ = load_vault(password)
    except Exception:
        print("❌ Vault decryption failed. Wrong password or corrupted file.")
        return

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

def delete_vault(force=False):
    vault_dir, vault_file, header_file = get_vault_paths()

    if not vault_file.exists() or not header_file.exists():
        print("❌ Vault not found. Nothing to delete.")
        return

    if not force:
        confirm = input("Are you sure you want to permanently delete the entire vault? (y/N): ")
        if confirm.lower() != 'y':
            print("Vault deletion cancelled.")
            return

        if not os.getenv("PYTEST_CURRENT_TEST"):
            print("System password required (sudo)...")
            try:
                subprocess.run(["sudo", "-v"], check=True)
            except subprocess.CalledProcessError:
                print("❌ Authentication failed. Vault deletion aborted.")
                return
        else:
            print("Skipping sudo in test mode.")

    if vault_file.exists():
        os.remove(vault_file)
    if header_file.exists():
        os.remove(header_file)
    if vault_dir.exists() and not any(vault_dir.iterdir()):
        vault_dir.rmdir()

    print("✅ Vault and header deleted successfully.")

def list_secrets():
    if not check_vault_exists():
        return

    try:
        password = getpass("Enter master password: ")
        vault, _, _ = load_vault(password)
    except (ValueError, FileNotFoundError):
        print("❌ Vault decryption failed. Wrong password or corrupted file.")
        return

    num_entries = len(vault.get("entries", []))
    print(f"🔐 Vault contains {num_entries} secret(s).")