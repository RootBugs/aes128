"""FIPS-197 known-answer tests for the AES-128 block cipher."""

from __future__ import annotations

import unittest

from aes import INV_SBOX, RCON, SBOX, AES128, expand_key

# FIPS-197 Appendix C.1 — AES-128 worked example.
C1_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
C1_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
C1_CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

# FIPS-197 Appendix B — a single round, worked example.
B_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
B_PLAINTEXT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
B_CIPHERTEXT = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")


class Fips197VectorTests(unittest.TestCase):
    """Known-answer vectors asserted exactly, bit for bit."""

    def test_c1_encrypt_exact(self):
        cipher = AES128(C1_KEY)
        self.assertEqual(cipher.encrypt_block(C1_PLAINTEXT), C1_CIPHERTEXT)

    def test_c1_decrypt_exact(self):
        cipher = AES128(C1_KEY)
        self.assertEqual(cipher.decrypt_block(C1_CIPHERTEXT), C1_PLAINTEXT)

    def test_appendix_b_encrypt_exact(self):
        cipher = AES128(B_KEY)
        self.assertEqual(cipher.encrypt_block(B_PLAINTEXT), B_CIPHERTEXT)

    def test_all_zero_key_and_block(self):
        cipher = AES128(bytes(16))
        ct = cipher.encrypt_block(bytes(16))
        self.assertEqual(
            ct.hex(),
            "66e94bd4ef8a2c3b884cfa59ca342b2e",
        )
        self.assertEqual(cipher.decrypt_block(ct), bytes(16))


class KeyExpansionTests(unittest.TestCase):

    def test_round_key_count_and_first_round_key(self):
        rks = expand_key(C1_KEY)
        self.assertEqual(len(rks), 11)
        self.assertTrue(all(len(rk) == 16 for rk in rks))
        self.assertEqual(rks[0], C1_KEY)

    def test_expanded_word_matches_fips_reference(self):
        # FIPS-197 / SP 800-38A reference: w[4..7] for the 2b7e... key.
        rks = expand_key(B_KEY)
        self.assertEqual(
            rks[1].hex(), "a0fafe1788542cb123a339392a6c7605"
        )

    def test_rcon_values(self):
        self.assertEqual(RCON[0], 0x01)
        self.assertEqual(RCON[9], 0x36)

    def test_wrong_key_length_rejected(self):
        with self.assertRaises(ValueError):
            expand_key(b"short")
        with self.assertRaises(ValueError):
            AES128(b"0" * 17)
        with self.assertRaises(TypeError):
            AES128("not-bytes")


class SBoxTests(unittest.TestCase):

    def test_generated_sbox_spot_values(self):
        # FIPS-197 section 5.1.1 worked values.
        self.assertEqual(SBOX[0x00], 0x63)
        self.assertEqual(SBOX[0x01], 0x7C)
        self.assertEqual(SBOX[0x53], 0xED)

    def test_sbox_is_bijection(self):
        self.assertEqual(len(SBOX), 256)
        self.assertEqual(sorted(SBOX), list(range(256)))

    def test_inverse_sbox_inverts_sbox(self):
        for i in range(256):
            self.assertEqual(INV_SBOX[SBOX[i]], i)

    def test_gf_multiplication_fips_example(self):
        from aes import _gf_mul

        # FIPS-197 section 4.2: 0x57 * 0x83 = 0xc1 in GF(2^8).
        self.assertEqual(_gf_mul(0x57, 0x83), 0xC1)
        self.assertEqual(_gf_mul(0x57, 0x13), 0xFE)


class BlockBehaviorTests(unittest.TestCase):

    def test_encrypt_decrypt_roundtrip_random_blocks(self):
        import random

        rng = random.Random(20260214)
        cipher = AES128(bytes(rng.randrange(256) for _ in range(16)))
        for _ in range(25):
            block = bytes(rng.randrange(256) for _ in range(16))
            self.assertEqual(
                cipher.decrypt_block(cipher.encrypt_block(block)), block
            )

    def test_wrong_block_size_rejected(self):
        cipher = AES128(C1_KEY)
        with self.assertRaises(ValueError):
            cipher.encrypt_block(b"short")
        with self.assertRaises(ValueError):
            cipher.decrypt_block(bytes(15))
        with self.assertRaises(TypeError):
            cipher.encrypt_block("not-bytes")

    def test_avalanche_single_bit_flip(self):
        """One flipped plaintext bit must flip roughly half of 160 bits."""
        cipher = AES128(C1_KEY)
        base = cipher.encrypt_block(C1_PLAINTEXT)
        flipped = cipher.encrypt_block(
            bytes([C1_PLAINTEXT[0] ^ 0x01]) + C1_PLAINTEXT[1:]
        )
        differing = sum(
            bin(a ^ b).count("1") for a, b in zip(base, flipped)
        )
        self.assertGreaterEqual(differing, 40)
        self.assertLessEqual(differing, 90)

    def test_avalanche_second_bit_position(self):
        cipher = AES128(B_KEY)
        base = cipher.encrypt_block(B_PLAINTEXT)
        flipped_pt = bytearray(B_PLAINTEXT)
        flipped_pt[9] ^= 0x80
        flipped = cipher.encrypt_block(bytes(flipped_pt))
        differing = sum(
            bin(a ^ b).count("1") for a, b in zip(base, flipped)
        )
        self.assertGreaterEqual(differing, 40)
        self.assertLessEqual(differing, 90)

    def test_different_keys_give_different_ciphertext(self):
        a = AES128(C1_KEY)
        b = AES128(bytes(reversed(C1_KEY)))
        self.assertNotEqual(
            a.encrypt_block(C1_PLAINTEXT), b.encrypt_block(C1_PLAINTEXT)
        )


if __name__ == "__main__":
    unittest.main()
