"""
endectools/core.py

Crypto core for EndecTools –
  • transparent TAR+Zstd wrapping
  • AES-CTR streaming encryption
  • HMAC-SHA256 authentication
  • adaptive chunk sizes & tqdm progress bars
  • streaming decrypt without memory blow-up
"""
from __future__ import annotations
import secrets
import struct
import tempfile
import shutil
import tarfile
from pathlib import Path
from typing import BinaryIO

import tqdm
import zstandard as zstd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hmac, hashes

# Header layout
MAGIC      = b"ENDEC3\x00\x00"        # 8-byte signature (v3)
HEADER_FMT = "!8s16s16sQ"               # magic | salt16 | nonce16 | size(uint64)
TAG_LEN    = 32                            # HMAC-SHA256 tag length (bytes)


def _derive_keys(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derive two 256-bit keys from password via Scrypt:
      - first 32 bytes → AES-CTR key
      - next 32 bytes  → HMAC-SHA256 key
    """
    kdf = Scrypt(salt=salt, length=64, n=2**18, r=8, p=1)
    km = kdf.derive(password)
    return km[:32], km[32:]


def _compute_chunk(total: int) -> int:
    """
    Adaptive chunk size for ~400 progress steps:
      clamp(total/400, 1 MiB … 16 MiB)
    """
    step = max(total // 400, 1 * 1024 * 1024)
    return min(step, 16 * 1024 * 1024)


def _stream(
    reader: BinaryIO,
    writer: BinaryIO,
    transform,
    total: int,
    desc: str
) -> None:
    """
    Stream data in adaptive chunks, apply transform on each chunk,
    and update a tqdm progress bar.
    """
    chunk_size = _compute_chunk(total)
    with tqdm.tqdm(
        total=total,
        unit="B", unit_scale=True, unit_divisor=1024,
        desc=desc, leave=False
    ) as pbar:
        while data := reader.read(chunk_size):
            out = transform(data)
            writer.write(out)
            pbar.update(len(data))


def _compress_path(src: Path, tmp_dir: Path) -> Path:
    """
    Create a .tar.zst archive of src (file or dir) in tmp_dir,
    with progress based on uncompressed size.
    """
    archive = tmp_dir / f"{src.name}.tar.zst"
    # collect members and total size
    if src.is_dir():
        members = [p for p in src.rglob("*") if p.is_file()]
        total = sum(p.stat().st_size for p in members)
    else:
        members = [src]
        total = src.stat().st_size

    comp = zstd.ZstdCompressor()
    with archive.open("wb") as f:
        with comp.stream_writer(f) as compressor:
            with tarfile.open(fileobj=compressor, mode="w|") as tar, \
                 tqdm.tqdm(total=total, unit="B", unit_scale=True,
                           unit_divisor=1024, desc="Compressing", leave=False) as pbar:
                for member in members:
                    arcname = member.relative_to(src.parent)
                    tar.add(member, arcname=arcname)
                    pbar.update(member.stat().st_size)
    return archive


def _encrypt_file(src: Path, dst: Path, pwd: bytes) -> None:
    """
    Encrypt src → dst using AES-CTR + HMAC-SHA256 streaming.
    Header includes salt, nonce, and original size.
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    key_enc, key_mac = _derive_keys(pwd, salt)

    cipher = Cipher(
        algorithms.AES(key_enc), modes.CTR(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    h = hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())
    total = src.stat().st_size

    with src.open("rb") as fin, dst.open("wb") as fout:
        fout.write(struct.pack(HEADER_FMT, MAGIC, salt, nonce, total))

        def process(chunk: bytes) -> bytes:
            ct = encryptor.update(chunk)
            h.update(ct)
            return ct

        _stream(fin, fout, process, total, "Encrypting")
        tail = encryptor.finalize()
        h.update(tail)
        fout.write(tail)
        tag = h.finalize()
        fout.write(tag)


def _decrypt_file(src: Path, tmp_archive: Path, pwd: bytes) -> None:
    """
    Decrypt src → temporary .tar.zst archive, streaming with HMAC verification.
    """
    hdr_size = struct.calcsize(HEADER_FMT)
    total_file = src.stat().st_size
    with src.open("rb") as fin:
        hdr = fin.read(hdr_size)
        magic, salt, nonce, _size = struct.unpack(HEADER_FMT, hdr)
        if magic != MAGIC:
            raise ValueError("Not an EndecTools file")

        cipher_len = total_file - hdr_size - TAG_LEN

        key_enc, key_mac = _derive_keys(pwd, salt)
        cipher = Cipher(
            algorithms.AES(key_enc), modes.CTR(nonce),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        h = hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())

        with tmp_archive.open("wb") as fout:
            with tqdm.tqdm(
                total=cipher_len, unit="B", unit_scale=True,
                unit_divisor=1024, desc="Decrypting", leave=False
            ) as pbar:
                to_read = cipher_len
                chunk = _compute_chunk(cipher_len)
                while to_read > 0:
                    read_sz = min(chunk, to_read)
                    data = fin.read(read_sz)
                    to_read -= len(data)
                    h.update(data)
                    pt = decryptor.update(data)
                    fout.write(pt)
                    pbar.update(len(data))

            tail = decryptor.finalize()
            fout.write(tail)

        tag_read = fin.read(TAG_LEN)
        try:
            h.verify(tag_read)
        except Exception:
            tmp_archive.unlink()
            raise ValueError("Authentication failed or corrupt file")


def encrypt_path(src: Path, dst_enc: Path, pwd: bytes) -> None:
    """Compress+encrypt src to .enc."""
    with tempfile.TemporaryDirectory(dir=src.parent) as d:
        archive = _compress_path(src, Path(d))
        _encrypt_file(archive, dst_enc, pwd)


def decrypt_path(src_enc: Path, dst_root: Path, pwd: bytes) -> None:
    """Decrypt+decompress src_enc to original structure."""
    tmp_zst = dst_root.with_suffix(".tmp.tar.zst")
    tmp_tar = dst_root.with_suffix(".tmp.tar")

    # Phase 1: decrypt to compressed archive
    _decrypt_file(src_enc, tmp_zst, pwd)

    # Phase 2: decompress .tar.zst → .tar
    size_zst = tmp_zst.stat().st_size
    dctx = zstd.ZstdDecompressor()
    with tmp_zst.open("rb") as f_in, tmp_tar.open("wb") as f_out, \
         dctx.stream_reader(f_in) as reader, \
         tqdm.tqdm(total=size_zst, unit="B", unit_scale=True,
                   unit_divisor=1024, desc="Decompressing", leave=False) as pbar:
        for chunk in iter(lambda: reader.read(_compute_chunk(size_zst)), b""):
            f_out.write(chunk)
            pbar.update(len(chunk))
    tmp_zst.unlink()

    # Phase 3: extract .tar
    with tarfile.open(tmp_tar, "r:") as tar, \
         tqdm.tqdm(total=len(tar.getmembers()), unit="file",
                   desc="Extracting", leave=False) as pbar:
        for member in tar:
            tar.extract(member, path=dst_root.parent)
            pbar.update(1)
    tmp_tar.unlink()


class BytesReader:
    """Wrap bytes in a file-like interface for streaming."""
    def __init__(self, data: bytes):
        self._data = data
        self._i = 0
    def read(self, n: int) -> bytes:
        chunk = self._data[self._i:self._i+n]
        self._i += len(chunk)
        return chunk