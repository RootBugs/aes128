# aes128 — AES-128 in Pure Python

The cipher, every byte explained. `aes128` implements **all of FIPS-197
AES-128** — SubBytes, ShiftRows, MixColumns, key expansion, encryption and
decryption rounds — in pure Python, plus **CBC mode with IV and PKCS#7
padding**, hex APIs, and a versioned file container. The S-box is *generated*
from the field math (GF(2⁸) inversion + affine transform), never transcribed,
so there is no table to mis-type.

## Why it's special

- **FIPS-197 known-answer vectors are asserted exactly**, including the
  Appendix C.1 worked example (`69c4e0d86a7b0430d8cdb78070b4c55a`), the
  Appendix B single-round example, and the all-zero vector — one flipped bit
  anywhere fails the suite.
- **NIST SP 800-38A CBC vector** (F.2.1, four blocks) asserted byte-exact via
  the raw `cbc_encrypt_nopad` path.
- **Corruption is deterministic**: flipping one bit in CBC ciphertext block 0
  flips *exactly* that bit in plaintext block 1 (the CBC XOR chain), while
  block 0 changes unpredictably — and strict PKCS#7 validation rejects the
  result instead of returning garbage.
- **Avalanche measured**: a single flipped plaintext bit flips ~64 of 160
  ciphertext bits (asserted within 40–90).

## Architecture

| Module | Responsibility |
|---|---|
| `aes.py` | GF(2⁸) math, generated S-box/inv-S-box, key expansion, the 10-round block cipher |
| `modes.py` | PKCS#7 pad/unpad (strict), raw + padded CBC, hex APIs, `OSSAES12` file container |
| `cli.py` | `enc`, `dec`, `enchex`, `dechex` commands |

File container: `b"OSSAES12"` (8) ‖ IV (16) ‖ ciphertext (multiple of 16).

## Runnable example

```console
$ python -c "
from aes import AES128
from modes import cbc_encrypt_nopad
key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
iv  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
pt = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'
                   'ae2d8a571e03ac9c9eb76fac45af8e51'
                   '30c81c46a35ce411e5fbc1191a0a52ef'
                   'f69f2445df4f9b17ad2b417be66c3710')
print(cbc_encrypt_nopad(AES128(key), iv, pt).hex())
"
7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7
```

CLI session:

```console
$ python cli.py enc --key 2b7e151628aed2a6abf7158809cf4f3c --in note.txt --out note.enc
encrypted -> note.enc (iv=c20e87dc61317789ccd5577cef98e204)
$ python cli.py dec --key 2b7e151628aed2a6abf7158809cf4f3c --in note.enc --out note.out
decrypted 15 bytes -> note.out
$ python cli.py enchex --key 2b7e151628aed2a6abf7158809cf4f3c --iv 000102030405060708090a0b0c0d0e0f --text "hello"
d8666ea8aad65cc08354b4bc43d4ff56
```

## Tests

```console
python -m unittest discover -s tests -v
```

53 tests: FIPS-197 C.1/B/all-zero vectors asserted exactly, key expansion
reference word, generated-S-box bijection + FIPS worked values (`0x57·0x83 =
0xc1`), NIST SP 800-38A CBC known answer, CBC roundtrips over lengths
0–1000, PKCS#7 full-block edge (`len % 16 == 0` still pads) and five strict
rejection cases, exact bit-flip propagation in CBC, hex/file API roundtrips,
wrong-key detection, avalanche bounds, and CLI end-to-end flows.
