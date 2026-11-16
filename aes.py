"""AES-128 from FIPS-197, in pure Python.

The S-box and inverse S-box are *generated*, not transcribed: multiplicative
inverses in GF(2^8) (reduction polynomial 0x11b) followed by the affine
transform of FIPS-197 section 5.1.1 — which means there is no table to
mis-type.

State convention: the 16-byte block is a flat list where byte index
``4*c + r`` lives in column ``c``, row ``r`` (FIPS-197 figure 3).
"""

from __future__ import annotations

__all__ = [
    "SBOX",
    "INV_SBOX",
    "RCON",
    "expand_key",
    "AES128",
    "BLOCK_SIZE",
    "KEY_SIZE",
]

BLOCK_SIZE = 16
KEY_SIZE = 16
_ROUNDS = 10  # AES-128: 10 rounds, 11 round keys


def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) modulo the AES polynomial 0x11b."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return result


def _gf_pow(a: int, exp: int) -> int:
    """Exponentiate in GF(2^8) by square-and-multiply."""
    result = 1
    while exp:
        if exp & 1:
            result = _gf_mul(result, a)
        a = _gf_mul(a, a)
        exp >>= 1
    return result


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _make_sbox() -> tuple[int, ...]:
    """FIPS-197 section 5.1.1: affine transform of the field inverse."""
    table = []
    for x in range(256):
        inv = 0 if x == 0 else _gf_pow(x, 254)  # x^254 = x^-1 (x^255 = 1)
        s = (
            inv
            ^ _rotl8(inv, 1)
            ^ _rotl8(inv, 2)
            ^ _rotl8(inv, 3)
            ^ _rotl8(inv, 4)
            ^ 0x63
        )
        table.append(s)
    return tuple(table)


SBOX = _make_sbox()
INV_SBOX = tuple(sorted(range(256), key=lambda i: SBOX[i]))

# Round constants: x^(i-1) in GF(2^8) for schedule round i.
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def expand_key(key: bytes) -> list[bytes]:
    """Expand a 16-byte AES-128 key into 11 round keys of 16 bytes.

    Implements FIPS-197 section 5.2 (key expansion) exactly.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-128 key must be {KEY_SIZE} bytes, got {len(key)}")
    # w[i] are 32-bit words stored as 4-byte tuples.
    w = [tuple(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 4 * (_ROUNDS + 1)):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= RCON[i // 4 - 1]
        w.append(tuple(a ^ b for a, b in zip(w[i - 4], temp)))
    return [
        b"".join(bytes(w[4 * r + c]) for c in range(4))
        for r in range(_ROUNDS + 1)
    ]


def _sub_bytes(state: list[int]) -> None:
    for i, b in enumerate(state):
        state[i] = SBOX[b]


def _inv_sub_bytes(state: list[int]) -> None:
    for i, b in enumerate(state):
        state[i] = INV_SBOX[b]


def _shift_rows(state: list[int]) -> None:
    """Row r rotates left by r positions (FIPS-197 section 5.1.3)."""
    original = state[:]
    for r in range(1, 4):
        for c in range(4):
            state[4 * c + r] = original[4 * ((c + r) % 4) + r]


def _inv_shift_rows(state: list[int]) -> None:
    original = state[:]
    for r in range(1, 4):
        for c in range(4):
            state[4 * c + r] = original[4 * ((c - r) % 4) + r]


def _mix_columns(state: list[int]) -> None:
    """Multiply each column by the FIPS-197 mixing matrix (x, x+1, 1, 1)."""
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c:4 * c + 4]
        state[4 * c + 0] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        state[4 * c + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        state[4 * c + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        state[4 * c + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)


def _inv_mix_columns(state: list[int]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c:4 * c + 4]
        state[4 * c + 0] = (
            _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
        )
        state[4 * c + 1] = (
            _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
        )
        state[4 * c + 2] = (
            _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
        )
        state[4 * c + 3] = (
            _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
        )


def _add_round_key(state: list[int], round_key: bytes) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


class AES128:
    """AES-128 block cipher: one key, encrypt/decrypt single 16-byte blocks."""

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        self._round_keys = expand_key(bytes(key))

    @property
    def round_keys(self) -> list[bytes]:
        """The 11 expanded round keys (copies), for inspection and tests."""
        return [bytes(rk) for rk in self._round_keys]

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one 16-byte block (FIPS-197 section 5.1)."""
        state = self._check_block(block)
        _add_round_key(state, self._round_keys[0])
        for rnd in range(1, _ROUNDS):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, self._round_keys[rnd])
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, self._round_keys[_ROUNDS])
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt one 16-byte block (FIPS-197 section 5.3)."""
        state = self._check_block(block)
        _add_round_key(state, self._round_keys[_ROUNDS])
        for rnd in range(_ROUNDS - 1, 0, -1):
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
            _add_round_key(state, self._round_keys[rnd])
            _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, self._round_keys[0])
        return bytes(state)

    @staticmethod
    def _check_block(block: bytes) -> list[int]:
        if not isinstance(block, (bytes, bytearray, memoryview)):
            raise TypeError("block must be bytes-like")
        if len(block) != BLOCK_SIZE:
            raise ValueError(
                f"block must be {BLOCK_SIZE} bytes, got {len(block)}"
            )
        return list(block)
