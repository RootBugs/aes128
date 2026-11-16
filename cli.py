"""CLI for aes128: file encryption (IV embedded) and hex roundtrips.

Commands::

    python cli.py enc   --key HEX --in plain.bin --out enc.bin [--iv HEX]
    python cli.py dec   --key HEX --in enc.bin  --out plain.bin
    python cli.py enchex --key HEX --iv HEX --text "hello"
    python cli.py dechex --key HEX --iv HEX --hex AABB... [--out FILE]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from modes import (
    PaddingError,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
)

__all__ = ["main"]


def _parse_key(raw: str) -> bytes:
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise SystemExit(f"error: key must be hex, got {raw!r}")
    if len(key) != 16:
        raise SystemExit(f"error: AES-128 key must be 16 bytes, got {len(key)}")
    return key


def _parse_iv(raw: str) -> bytes:
    try:
        iv = bytes.fromhex(raw)
    except ValueError:
        raise SystemExit(f"error: IV must be hex, got {raw!r}")
    if len(iv) != 16:
        raise SystemExit(f"error: IV must be 16 bytes, got {len(iv)}")
    return iv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aes128",
        description="AES-128 in CBC mode with PKCS#7 padding.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_enc = sub.add_parser("enc", help="encrypt a file (IV stored inline)")
    p_enc.add_argument("--key", required=True, metavar="HEX")
    p_enc.add_argument("--iv", default=None, metavar="HEX")
    p_enc.add_argument("--in", dest="inp", required=True, metavar="FILE")
    p_enc.add_argument("--out", dest="outp", required=True, metavar="FILE")

    p_dec = sub.add_parser("dec", help="decrypt a container file")
    p_dec.add_argument("--key", required=True, metavar="HEX")
    p_dec.add_argument("--in", dest="inp", required=True, metavar="FILE")
    p_dec.add_argument("--out", dest="outp", required=True, metavar="FILE")

    p_eh = sub.add_parser("enchex", help="encrypt text to hex ciphertext")
    p_eh.add_argument("--key", required=True, metavar="HEX")
    p_eh.add_argument("--iv", required=True, metavar="HEX")
    p_eh.add_argument("--text", required=True, metavar="STR")

    p_dh = sub.add_parser("dechex", help="decrypt hex ciphertext")
    p_dh.add_argument("--key", required=True, metavar="HEX")
    p_dh.add_argument("--iv", required=True, metavar="HEX")
    p_dh.add_argument("--hex", dest="hexin", required=True, metavar="HEX")
    p_dh.add_argument("--out", dest="outp", default=None, metavar="FILE")

    args = parser.parse_args(argv)

    try:
        if args.command == "enc":
            key = _parse_key(args.key)
            iv = _parse_iv(args.iv) if args.iv else os.urandom(16)
            used = encrypt_file(key, args.inp, args.outp, iv)
            print(f"encrypted -> {args.outp} (iv={used.hex()})")
            return 0

        if args.command == "dec":
            key = _parse_key(args.key)
            pt = decrypt_file(key, args.inp, args.outp)
            print(f"decrypted {len(pt)} bytes -> {args.outp}")
            return 0

        if args.command == "enchex":
            key, iv = _parse_key(args.key), _parse_iv(args.iv)
            print(encrypt_bytes(key, iv, args.text.encode("utf-8")).hex())
            return 0

        # dechex
        key, iv = _parse_key(args.key), _parse_iv(args.iv)
        pt = decrypt_bytes(key, iv, bytes.fromhex(args.hexin))
        if args.outp:
            Path(args.outp).write_bytes(pt)
            print(f"decrypted {len(pt)} bytes -> {args.outp}")
        else:
            sys.stdout.write(pt.decode("utf-8", errors="replace") + "\n")
        return 0
    except (PaddingError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
