"""
endectools/core.py

Streaming-only core for EndecTools v6:
  • TAR -> Zstd -> AES-CTR + HMAC-SHA256 -> .enc with byte-level progress
  • Decrypt: .enc -> decrypt/HMAC -> Zstd -> temp .tar + extract
  • Secure-shred with nested tqdm for file and pass progress
"""
from __future__ import annotations
import os
import secrets
import struct
import tarfile
from pathlib import Path
from typing import BinaryIO, Literal

import tqdm
import zstandard as zstd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hmac, hashes

# Constants
MAGIC       = b"ENDEC6\x00\x00"
HEADER_FMT  = "!8s16s16s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
TAG_LEN     = 32


def _derive_keys(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    kdf = Scrypt(salt=salt, length=64, n=2**18, r=8, p=1)
    km = kdf.derive(password)
    return km[:32], km[32:]


def _compute_chunk(total: int) -> int:
    step = max(total // 400, 1 * 1024 * 1024)
    return min(step, 16 * 1024 * 1024)


class _EncryptWriter:
    """Wraps file: plaintext->encrypt->HMAC->write and update pbar"""
    def __init__(self, fout: BinaryIO, encryptor, hctx, pbar: tqdm.tqdm | None = None):
        self.fout = fout
        self.encryptor = encryptor
        self.hctx = hctx
        self.pbar = pbar

    def write(self, data: bytes) -> int:
        ct = self.encryptor.update(data)
        self.hctx.update(ct)
        self.fout.write(ct)
        if self.pbar:
            self.pbar.update(len(data))
        return len(data)


class _DecryptReader:
    def __init__(self, fin: BinaryIO, decryptor, hctx, length: int):
        self.fin = fin; self.decryptor = decryptor; self.hctx = hctx; self.left = length

    def read(self, n: int) -> bytes:
        if self.left <= 0:
            return b""
        to_read = min(n, self.left)
        chunk = self.fin.read(to_read)
        self.left -= len(chunk)
        self.hctx.update(chunk)
        return self.decryptor.update(chunk)


def encrypt_path(src: Path, dst_enc: Path, pwd: bytes) -> None:
    # calculate total plaintext size
    if src.is_dir():
        total = sum(p.stat().st_size for p in src.rglob("*") if p.is_file())
    else:
        total = src.stat().st_size

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    key_enc, key_mac = _derive_keys(pwd, salt)

    cipher = Cipher(algorithms.AES(key_enc), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    hctx = hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())

    with dst_enc.open("wb") as fout:
        fout.write(struct.pack(HEADER_FMT, MAGIC, salt, nonce))
        with tqdm.tqdm(total=total, unit="B", unit_scale=True,
                       unit_divisor=1024, desc="Encrypting", leave=False) as pbar:
            enc_writer = _EncryptWriter(fout, encryptor, hctx, pbar)
            comp = zstd.ZstdCompressor().stream_writer(enc_writer)
            with tarfile.open(fileobj=comp, mode="w|") as tar:
                tar.add(src, arcname=src.name)
            comp.close()
            # finalize encryption
            tail = encryptor.finalize()
            hctx.update(tail)
            fout.write(tail)
            fout.write(hctx.finalize())


def decrypt_path(src_enc: Path, dst_root: Path, pwd: bytes) -> None:
    total_file = src_enc.stat().st_size
    cipher_len = total_file - HEADER_SIZE - TAG_LEN
    tmp_tar = dst_root.with_suffix(".tmp.tar")

    with src_enc.open("rb") as fin:
        # Read & verify header
        hdr = fin.read(HEADER_SIZE)
        if len(hdr) != HEADER_SIZE:
            raise ValueError("Not an EndecTools file")
        try:
            magic, salt, nonce = struct.unpack(HEADER_FMT, hdr)
        except struct.error:
            raise ValueError("Not an EndecTools file")
        if magic != MAGIC:
            raise ValueError("Not an EndecTools file")

        key_enc, key_mac = _derive_keys(pwd, salt)
        cipher = Cipher(algorithms.AES(key_enc), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        hctx = hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())

        dec_reader = _DecryptReader(fin, decryptor, hctx, cipher_len)
        dctx = zstd.ZstdDecompressor().stream_reader(dec_reader)
        with tmp_tar.open("wb") as fout, \
             tqdm.tqdm(total=cipher_len, unit="B", unit_scale=True,
                       unit_divisor=1024, desc="Decompressing", leave=False) as pbar:
            for chunk in iter(lambda: dctx.read(_compute_chunk(cipher_len)), b""):
                fout.write(chunk); pbar.update(len(chunk))
        # finalize and verify
        tail = decryptor.finalize()
        hctx.update(tail)
        tag = fin.read(TAG_LEN); hctx.verify(tag)

    with tarfile.open(tmp_tar, "r:") as tar, \
         tqdm.tqdm(total=len(tar.getmembers()), unit="file",
                   desc="Extracting", leave=False) as pbar:
        for m in tar.getmembers():
            tar.extract(m, path=dst_root.parent); pbar.update(1)
    tmp_tar.unlink()


def shred_path(src: Path, passes: int = 3, pattern: Literal["rand","zero"] = "rand") -> None:
    """Securely erase a file or directory recursively, with byte-level progress per file and pass."""
    # Collect files to shred
    files = [p for p in (src.rglob("*") if src.is_dir() else [src]) if p.is_file()]
    with tqdm.tqdm(total=len(files), unit="file", desc="Secure shredding") as file_bar:
        for file in files:
            size = file.stat().st_size
            total_bytes = size * passes
            chunk_size = _compute_chunk(size)
            # Byte-level progress for this file across all passes
            with tqdm.tqdm(total=total_bytes, unit="B", unit_scale=True,
                           unit_divisor=1024, desc=file.name, leave=False) as pbar:
                for i in range(1, passes + 1):
                    pbar.set_postfix_str(f"pass {i}/{passes}")
                    with file.open("r+b") as f:
                        f.seek(0)
                        rem = size
                        while rem > 0:
                            step = min(chunk_size, rem)
                            buf = (secrets.token_bytes(step)
                                   if pattern == "rand" else b"" * step)
                            f.write(buf)
                            rem -= step
                            pbar.update(step)
                        f.flush(); os.fsync(f.fileno())
                file.unlink()
            file_bar.update(1)
    # Clean up empty directories
    if src.is_dir():
        for d in sorted(src.rglob("*"), reverse=True):
            if d.is_dir():
                try:
                    d.rmdir()
                except OSError:
                    pass
        try:
            src.rmdir()
        except OSError:
            pass
