# crypto.py

import os
import json
import hmac
import hashlib
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

BACKEND = default_backend()
HMAC_KEY_LENGTH = 32
AES_KEY_LENGTH = 32
IV_LENGTH = 16


def generate_salt(length=16):
    return os.urandom(length)


def hash_sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def derive_keys(password: str, salt: bytes, iterations=100_000):
    real_password = hash_sha256(password)
    user_hash = hash_sha256(real_password)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=salt,
        iterations=iterations,
        backend=BACKEND
    )
    vault_key = urlsafe_b64encode(kdf.derive(real_password.encode()))
    return real_password, user_hash, vault_key


def _hmac_sha256(key: bytes, data: bytes):
    return hmac.new(key, data, hashlib.sha256).digest()


def encrypt_vault(data: dict, vault_key_b64: bytes) -> bytes:
    vault_key = urlsafe_b64decode(vault_key_b64)
    aes_key = vault_key[:AES_KEY_LENGTH]
    hmac_key = vault_key[:HMAC_KEY_LENGTH]

    iv = os.urandom(IV_LENGTH)
    json_data = json.dumps(data).encode()

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(json_data) + encryptor.finalize()

    tag = _hmac_sha256(hmac_key, iv + ciphertext)
    return iv + ciphertext + tag


def decrypt_vault(encrypted_data: bytes, vault_key_b64: bytes) -> dict:
    vault_key = urlsafe_b64decode(vault_key_b64)
    aes_key = vault_key[:AES_KEY_LENGTH]
    hmac_key = vault_key[:HMAC_KEY_LENGTH]

    iv = encrypted_data[:IV_LENGTH]
    ciphertext = encrypted_data[IV_LENGTH:-32]
    tag = encrypted_data[-32:]

    expected_tag = _hmac_sha256(hmac_key, iv + ciphertext)
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("HMAC verification failed — file may be tampered.")

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    json_data = decryptor.update(ciphertext) + decryptor.finalize()

    return json.loads(json_data.decode())


def encrypt_entry(secret: str, entry_password: str):
    key = hashlib.sha256(entry_password.encode()).digest()
    iv = os.urandom(IV_LENGTH)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(secret.encode()) + encryptor.finalize()
    encrypted = urlsafe_b64encode(iv + ciphertext).decode()
    return encrypted, hash_sha256(entry_password)


def decrypt_entry(encrypted: str, entry_password: str):
    try:
        data = urlsafe_b64decode(encrypted.encode())
        iv = data[:IV_LENGTH]
        ciphertext = data[IV_LENGTH:]
        key = hashlib.sha256(entry_password.encode()).digest()

        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=BACKEND)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode()
    except Exception:
        return None