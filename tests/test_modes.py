"""CBC mode, PKCS#7 padding, hex/file APIs and corruption tests."""

from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from aes import AES128
from modes import (
    MAGIC,
    PaddingError,
    cbc_decrypt,
    cbc_decrypt_nopad,
    cbc_encrypt,
    cbc_encrypt_nopad,
    decrypt_bytes,
    decrypt_file,
    decrypt_hex,
    encrypt_bytes,
    encrypt_file,
    encrypt_hex,
    pkcs7_pad,
    pkcs7_unpad,
)

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

# NIST SP 800-38A F.2.1 CBC-AES-128 known answer (4 blocks, no padding).
SP800_38A_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
SP800_38A_CIPHERTEXT = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)


class NistKnownAnswerTests(unittest.TestCase):

    def test_sp800_38a_cbc_vector_exact(self):
        ct = cbc_encrypt_nopad(AES128(KEY), IV, SP800_38A_PLAINTEXT)
        self.assertEqual(ct, SP800_38A_CIPHERTEXT)

    def test_sp800_38a_cbc_decrypt_exact(self):
        pt = cbc_decrypt_nopad(AES128(KEY), IV, SP800_38A_CIPHERTEXT)
        self.assertEqual(pt, SP800_38A_PLAINTEXT)


class Pkcs7Tests(unittest.TestCase):

    def test_pad_lengths_zero_to_forty(self):
        for n in range(0, 41):
            data = bytes(range(n))
            padded = pkcs7_pad(data)
            self.assertEqual(len(padded) % 16, 0, n)
            self.assertEqual(pkcs7_unpad(padded), data, n)

    def test_full_block_gets_another_full_block(self):
        padded = pkcs7_pad(b"A" * 16)
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[16:], bytes([0x10]) * 16)
        self.assertEqual(pkcs7_unpad(padded), b"A" * 16)

    def test_empty_input_pads_to_full_block(self):
        padded = pkcs7_pad(b"")
        self.assertEqual(padded, bytes([0x10]) * 16)
        self.assertEqual(pkcs7_unpad(padded), b"")

    def test_unpad_rejects_empty(self):
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"")

    def test_unpad_rejects_non_multiple(self):
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"12345")

    def test_unpad_rejects_zero_length_byte(self):
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"A" * 15 + b"\x00")

    def test_unpad_rejects_oversize_length_byte(self):
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"A" * 15 + b"\x11")

    def test_unpad_rejects_mismatched_bytes(self):
        # Declares 2-byte padding but the first pad byte is wrong.
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"A" * 14 + b"\x01\x02")


class CbcBehaviorTests(unittest.TestCase):

    def test_roundtrip_various_lengths(self):
        rng = random.Random(31337)
        cipher = AES128(KEY)
        for n in (0, 1, 15, 16, 17, 31, 32, 100, 1000):
            data = bytes(rng.randrange(256) for _ in range(n))
            ct = cbc_encrypt(cipher, IV, data)
            self.assertEqual(len(ct) % 16, 0)
            self.assertEqual(cbc_decrypt(cipher, IV, ct), data, n)

    def test_cbc_depends_on_iv(self):
        cipher = AES128(KEY)
        other_iv = bytes(16)
        a = cbc_encrypt(cipher, IV, b"same plaintext")
        b = cbc_encrypt(cipher, other_iv, b"same plaintext")
        self.assertNotEqual(a, b)

    def test_nopad_requires_alignment(self):
        cipher = AES128(KEY)
        with self.assertRaises(ValueError):
            cbc_encrypt_nopad(cipher, IV, b"15 bytes.......")
        with self.assertRaises(ValueError):
            cbc_decrypt_nopad(cipher, IV, b"15 bytes.......")
        with self.assertRaises(ValueError):
            cbc_encrypt_nopad(cipher, IV, b"")

    def test_wrong_iv_length_rejected(self):
        cipher = AES128(KEY)
        with self.assertRaises(ValueError):
            cbc_encrypt(cipher, b"short", b"data")

    def test_bit_flip_in_c0_propagates_exactly(self):
        """Flipping a bit in ciphertext block 0 flips exactly that bit in
        plaintext block 1 (p1 = D(c1) ^ c0), while block 0 changes
        unpredictably — and padded decrypt detects the corruption."""
        data = b"attack at dawn!!"  # 16 bytes -> 32-byte padded result
        ct = bytearray(cbc_encrypt(AES128(KEY), IV, data))
        ct[0] ^= 0x01  # flip one bit inside the first ciphertext block
        plain = cbc_decrypt_nopad(AES128(KEY), IV, bytes(ct))
        original = pkcs7_pad(data)
        # Block 0: AES permutation guarantee -> must differ somewhere.
        self.assertNotEqual(plain[:16], original[:16])
        # Block 1: difference is exactly the flipped mask.
        expected_tail = bytes(
            a ^ b for a, b in zip(original[16:], bytes([0x01]) + bytes(15))
        )
        self.assertEqual(plain[16:], expected_tail)
        # The padding block now starts 0x11 0x10 ... -> strict unpad fails.
        with self.assertRaises(PaddingError):
            cbc_decrypt(AES128(KEY), IV, bytes(ct))

    def test_tampered_last_block_detected_by_padding(self):
        data = b"payload"
        ct = bytearray(cbc_encrypt(AES128(KEY), IV, data))
        # Flip a bit inside the final ciphertext block: the recovered final
        # block is garbage and strict PKCS#7 validation must reject it.
        ct[-1] ^= 0x80
        with self.assertRaises(PaddingError):
            cbc_decrypt(AES128(KEY), IV, bytes(ct))

    def test_decrypt_rejects_truncated_ciphertext(self):
        with self.assertRaises(ValueError):
            cbc_decrypt(AES128(KEY), IV, b"short")


class HexApiTests(unittest.TestCase):

    def test_encrypt_hex_is_lowercase_multiple_of_32(self):
        hx = encrypt_hex(KEY, IV, b"hello")
        self.assertEqual(len(hx) % 32, 0)
        self.assertEqual(hx, hx.lower())

    def test_hex_roundtrip(self):
        rng = random.Random(5)
        data = bytes(rng.randrange(256) for _ in range(47))
        hx = encrypt_hex(KEY, IV, data)
        self.assertEqual(decrypt_hex(KEY, IV, hx), data)

    def test_decrypt_hex_rejects_non_hex(self):
        with self.assertRaises(ValueError):
            decrypt_hex(KEY, IV, "nothex!!")

    def test_decrypt_hex_wrong_key_detected(self):
        hx = encrypt_hex(KEY, IV, b"a message that is long enough to pad")
        other_key = bytes(16)
        with self.assertRaises(PaddingError):
            decrypt_hex(other_key, IV, hx)


class FileApiTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_file_roundtrip_with_explicit_iv(self):
        src = self.dir / "plain.bin"
        enc = self.dir / "enc.bin"
        dec = self.dir / "dec.bin"
        payload = bytes(range(256)) * 3 + b"tail"
        src.write_bytes(payload)
        used_iv = encrypt_file(KEY, src, enc, IV)
        self.assertEqual(used_iv, IV)
        blob = enc.read_bytes()
        self.assertTrue(blob.startswith(MAGIC))
        self.assertEqual(len(blob), 8 + 16 + len(pkcs7_pad(payload)))
        self.assertEqual(decrypt_file(KEY, enc, dec), payload)
        self.assertEqual(dec.read_bytes(), payload)

    def test_file_roundtrip_with_random_iv(self):
        src = self.dir / "p.bin"
        enc = self.dir / "e.bin"
        dec = self.dir / "d.bin"
        src.write_bytes(b"random iv roundtrip")
        encrypt_file(KEY, src, enc)  # IV generated internally
        self.assertEqual(decrypt_file(KEY, enc, dec), b"random iv roundtrip")

    def test_decrypt_file_rejects_bad_magic(self):
        bad = self.dir / "bad.bin"
        bad.write_bytes(b"NOTAES12" + bytes(16) + bytes(16))
        with self.assertRaises(ValueError):
            decrypt_file(KEY, bad, self.dir / "out.bin")

    def test_decrypt_file_rejects_truncated_container(self):
        bad = self.dir / "tiny.bin"
        bad.write_bytes(MAGIC)
        with self.assertRaises(ValueError):
            decrypt_file(KEY, bad, self.dir / "out.bin")

    def test_decrypt_file_detects_wrong_key(self):
        src = self.dir / "p.bin"
        enc = self.dir / "e.bin"
        src.write_bytes(b"secret contents here")
        encrypt_file(KEY, src, enc, IV)
        with self.assertRaises(PaddingError):
            decrypt_file(bytes(16), enc, self.dir / "out.bin")


if __name__ == "__main__":
    unittest.main()
