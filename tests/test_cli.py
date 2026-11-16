"""CLI tests: file enc/dec and hex commands over real temp files."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import cli
from modes import MAGIC, encrypt_bytes

KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"
IV_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)
IV = bytes.fromhex(IV_HEX)


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_enc_dec_file_roundtrip(self):
        plain = self.dir / "plain.bin"
        plain.write_bytes(b"file contents for the CLI roundtrip")
        enc = self.dir / "enc.bin"
        dec = self.dir / "dec.bin"

        code, out, _ = _run(
            ["enc", "--key", KEY_HEX, "--iv", IV_HEX,
             "--in", str(plain), "--out", str(enc)]
        )
        self.assertEqual(code, 0, out)
        self.assertIn("iv=" + IV_HEX, out)
        self.assertTrue(enc.read_bytes().startswith(MAGIC))
        self.assertNotEqual(enc.read_bytes()[24:], plain.read_bytes())

        code, out, _ = _run(
            ["dec", "--key", KEY_HEX, "--in", str(enc), "--out", str(dec)]
        )
        self.assertEqual(code, 0, out)
        self.assertEqual(dec.read_bytes(), plain.read_bytes())

    def test_enc_generates_iv_when_omitted(self):
        plain = self.dir / "p.bin"
        plain.write_bytes(b"data")
        enc = self.dir / "e.bin"
        dec = self.dir / "d.bin"
        code, out, _ = _run(
            ["enc", "--key", KEY_HEX, "--in", str(plain), "--out", str(enc)]
        )
        self.assertEqual(code, 0, out)
        self.assertIn("iv=", out)
        code, _, _ = _run(
            ["dec", "--key", KEY_HEX, "--in", str(enc), "--out", str(dec)]
        )
        self.assertEqual(code, 0)
        self.assertEqual(dec.read_bytes(), b"data")

    def test_enchex_prints_ciphertext_hex(self):
        code, out, _ = _run(
            ["enchex", "--key", KEY_HEX, "--iv", IV_HEX, "--text", "hello"]
        )
        self.assertEqual(code, 0)
        expected = encrypt_bytes(KEY, IV, b"hello").hex()
        self.assertEqual(out.strip(), expected)

    def test_dechex_prints_plaintext(self):
        hx = encrypt_bytes(KEY, IV, b"round trip").hex()
        code, out, _ = _run(
            ["dechex", "--key", KEY_HEX, "--iv", IV_HEX, "--hex", hx]
        )
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "round trip")

    def test_dechex_to_file(self):
        hx = encrypt_bytes(KEY, IV, b"to file").hex()
        outp = self.dir / "plain.txt"
        code, out, _ = _run(
            ["dechex", "--key", KEY_HEX, "--iv", IV_HEX,
             "--hex", hx, "--out", str(outp)]
        )
        self.assertEqual(code, 0, out)
        self.assertEqual(outp.read_bytes(), b"to file")

    def test_dec_on_garbage_exits_1(self):
        bad = self.dir / "garbage.bin"
        bad.write_bytes(b"definitely not an aes container!!")
        code, _, err = _run(
            ["dec", "--key", KEY_HEX, "--in", str(bad),
             "--out", str(self.dir / "o.bin")]
        )
        self.assertEqual(code, 1)
        self.assertIn("error:", err)

    def test_wrong_key_on_dec_exits_1(self):
        plain = self.dir / "p.bin"
        plain.write_bytes(b"long enough plaintext content")
        enc = self.dir / "e.bin"
        _run(["enc", "--key", KEY_HEX, "--iv", IV_HEX,
              "--in", str(plain), "--out", str(enc)])
        code, _, err = _run(
            ["dec", "--key", "00" * 16, "--in", str(enc),
             "--out", str(self.dir / "o.bin")]
        )
        self.assertEqual(code, 1)
        self.assertIn("error:", err)

    def test_bad_key_length_aborts(self):
        with self.assertRaises(SystemExit):
            cli.main(["enc", "--key", "abcd", "--in", "x", "--out", "y"])

    def test_bad_iv_length_aborts(self):
        with self.assertRaises(SystemExit):
            cli.main(
                ["enchex", "--key", KEY_HEX, "--iv", "00", "--text", "x"]
            )

    def test_missing_input_file_exits_1(self):
        code, _, err = _run(
            ["enc", "--key", KEY_HEX, "--iv", IV_HEX,
             "--in", str(self.dir / "absent.bin"),
             "--out", str(self.dir / "o.bin")]
        )
        self.assertEqual(code, 1)
        self.assertIn("error:", err)


if __name__ == "__main__":
    unittest.main()
