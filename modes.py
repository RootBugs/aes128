"""CBC mode, PKCS#7 padding, hex APIs and file APIs for aes128.

File format (documented, versioned)::

    offset 0 : MAGIC = b"OSSAES12"      (8 bytes)
    offset 8 : IV                     (16 bytes)
    offset 24: ciphertext             (multiple of 16 bytes, PKCS#7 padded)

Every decryption strictly validates padding and raises
:class:`PaddingError` — corrupted plaintext is never silently returned.
"""

from __future__ import annotations

import os
from pathlib import Path

from aes import AES128, BLOCK_SIZE

__all__ = [
    "PaddingError",
    "pkcs7_pad",
    "pkcs7_unpad",
    "cbc_encrypt_nopad",
    "cbc_decrypt_nopad",
    "cbc_encrypt",
    "cbc_decrypt",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_hex",
    "decrypt_hex",
    "encrypt_file",
    "decrypt_file",
    "MAGIC",
]

MAGIC = b"OSSAES12"
_IV_SIZE = 16


class PaddingError(ValueError):
    """Raised when PKCS#7 padding is missing or malformed."""


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Pad *data* to a multiple of *block_size* (always adds a full block
    when already aligned — PKCS#7 rule)."""
    if block_size < 1 or block_size > 255:
        raise ValueError("block size must be in 1..255")
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Strictly remove PKCS#7 padding; raises :class:`PaddingError`."""
    if not data or len(data) % block_size != 0:
        raise PaddingError("padded data must be a non-empty full-block input")
    n = data[-1]
    if n < 1 or n > block_size:
        raise PaddingError(f"invalid padding length byte 0x{n:02x}")
    if data[-n:] != bytes([n]) * n:
        raise PaddingError("padding bytes do not match declared length")
    return data[:-n]


def cbc_encrypt_nopad(cipher: AES128, iv: bytes, plaintext: bytes) -> bytes:
    """Raw CBC encryption: *plaintext* must already be block-aligned."""
    if len(iv) != _IV_SIZE:
        raise ValueError(f"IV must be {_IV_SIZE} bytes")
    if not plaintext or len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(
            "plaintext must be a non-empty multiple of 16 bytes"
        )
    out = bytearray()
    prev = iv
    for off in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(
            a ^ b for a, b in zip(plaintext[off:off + BLOCK_SIZE], prev)
        )
        prev = cipher.encrypt_block(block)
        out += prev
    return bytes(out)


def cbc_decrypt_nopad(cipher: AES128, iv: bytes, ciphertext: bytes) -> bytes:
    """Raw CBC decryption without padding removal."""
    if len(iv) != _IV_SIZE:
        raise ValueError(f"IV must be {_IV_SIZE} bytes")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            "ciphertext must be a non-empty multiple of 16 bytes"
        )
    out = bytearray()
    prev = iv
    for off in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[off:off + BLOCK_SIZE]
        out += bytes(
            a ^ b for a, b in zip(cipher.decrypt_block(block), prev)
        )
        prev = block
    return bytes(out)


def cbc_encrypt(cipher: AES128, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* under CBC with PKCS#7 padding."""
    padded = pkcs7_pad(plaintext)
    return cbc_encrypt_nopad(cipher, iv, padded)


def cbc_decrypt(cipher: AES128, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt CBC ciphertext and strictly validate the final padding."""
    return pkcs7_unpad(cbc_decrypt_nopad(cipher, iv, ciphertext))


def encrypt_bytes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """One-shot CBC encryption with a fresh :class:`AES128` instance."""
    return cbc_encrypt(AES128(key), iv, plaintext)


def decrypt_bytes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """One-shot CBC decryption with a fresh :class:`AES128` instance."""
    return cbc_decrypt(AES128(key), iv, ciphertext)


def encrypt_hex(key: bytes, iv: bytes, plaintext: bytes) -> str:
    """Encrypt and return the ciphertext as lowercase hex."""
    return encrypt_bytes(key, iv, plaintext).hex()


def decrypt_hex(key: bytes, iv: bytes, ciphertext_hex: str) -> bytes:
    """Decrypt a lowercase/uppercase hex ciphertext string."""
    try:
        ct = bytes.fromhex(ciphertext_hex)
    except ValueError as exc:
        raise ValueError(f"ciphertext is not valid hex: {exc}") from None
    return decrypt_bytes(key, iv, ct)


def encrypt_file(
    key: bytes, src: str | Path, dst: str | Path, iv: bytes | None = None
) -> bytes:
    """Encrypt file *src* into *dst* using the documented container format.

    Returns the IV used (generated with :func:`os.urandom` when not given).
    """
    if iv is None:
        iv = os.urandom(_IV_SIZE)
    data = Path(src).read_bytes()
    ct = encrypt_bytes(key, iv, data)
    Path(dst).write_bytes(MAGIC + iv + ct)
    return iv


def decrypt_file(key: bytes, src: str | Path, dst: str | Path) -> bytes:
    """Decrypt a container produced by :func:`encrypt_file`.

    Returns the plaintext (also written to *dst*).
    """
    blob = Path(src).read_bytes()
    if len(blob) < len(MAGIC) + _IV_SIZE + BLOCK_SIZE or blob[:len(MAGIC)] != MAGIC:
        raise ValueError("not an aes128 container (bad magic or too short)")
    iv = blob[len(MAGIC):len(MAGIC) + _IV_SIZE]
    ct = blob[len(MAGIC) + _IV_SIZE:]
    pt = decrypt_bytes(key, iv, ct)
    Path(dst).write_bytes(pt)
    return pt
