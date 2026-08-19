#!/usr/bin/env python3
"""Research solver for Trithemius' public 'Wealth in Poetry' Bitcoin puzzle.

The script focuses on the steganographic mechanisms described by the article:
* linear windows of BIP-39 words (baseline used by earlier researchers)
* digit/GPS positional encoding where each next digit gains +10
* null-cipher streams (nth letter of each word)

No wallet/network access is used. Candidate mnemonics are validated locally and
compared to the published P2PKH target address.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import itertools
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
HARDENED = 0x80000000
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

WORD_RE = re.compile(r"[a-z]+(?:'[a-z]+)?")
NUMBER_RE = re.compile(r"(?<![A-Za-z])[-+]?\d+(?:[.,]\d+)?")


def tokenize(text: str) -> list[str]:
    """Return lowercase word tokens while keeping contractions as one word."""
    normalized = unicodedata.normalize("NFKD", text).lower().replace("’", "'")
    return WORD_RE.findall(normalized)


def load_wordlist(path: Path) -> list[str]:
    words = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(words) != 2048 or len(set(words)) != 2048:
        raise ValueError(f"expected the 2048-word BIP-39 English list, got {len(words)} entries")
    return words


def mnemonic_checksum_valid(words: Sequence[str], word_index: dict[str, int]) -> bool:
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    try:
        indices = [word_index[word] for word in words]
    except KeyError:
        return False
    bit_string = "".join(f"{idx:011b}" for idx in indices)
    checksum_len = len(words) // 3
    entropy_len = len(bit_string) - checksum_len
    entropy_bits = bit_string[:entropy_len]
    checksum_bits = bit_string[entropy_len:]
    entropy = int(entropy_bits, 2).to_bytes(entropy_len // 8, "big")
    expected = f"{hashlib.sha256(entropy).digest()[0]:08b}"[:checksum_len]
    return checksum_bits == expected


def mnemonic_to_seed(words: Sequence[str], passphrase: str = "") -> bytes:
    sentence = unicodedata.normalize("NFKD", " ".join(words)).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    return hashlib.pbkdf2_hmac("sha512", sentence, salt, 2048, dklen=64)


def _inv(value: int, modulus: int) -> int:
    return pow(value, modulus - 2, modulus)


def _jacobian_double(point: tuple[int, int, int]) -> tuple[int, int, int]:
    x, y, z = point
    if y == 0 or z == 0:
        return 0, 0, 0
    yy = y * y % SECP256K1_P
    s = 4 * x * yy % SECP256K1_P
    m = 3 * x * x % SECP256K1_P
    nx = (m * m - 2 * s) % SECP256K1_P
    ny = (m * (s - nx) - 8 * yy * yy) % SECP256K1_P
    nz = 2 * y * z % SECP256K1_P
    return nx, ny, nz


def _jacobian_add(a: tuple[int, int, int], b: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = a
    x2, y2, z2 = b
    if z1 == 0:
        return b
    if z2 == 0:
        return a
    z1z1 = z1 * z1 % SECP256K1_P
    z2z2 = z2 * z2 % SECP256K1_P
    u1 = x1 * z2z2 % SECP256K1_P
    u2 = x2 * z1z1 % SECP256K1_P
    s1 = y1 * z2 * z2z2 % SECP256K1_P
    s2 = y2 * z1 * z1z1 % SECP256K1_P
    if u1 == u2:
        if s1 != s2:
            return 0, 0, 0
        return _jacobian_double(a)
    h = (u2 - u1) % SECP256K1_P
    r = (s2 - s1) % SECP256K1_P
    hh = h * h % SECP256K1_P
    hhh = h * hh % SECP256K1_P
    u1hh = u1 * hh % SECP256K1_P
    nx = (r * r - hhh - 2 * u1hh) % SECP256K1_P
    ny = (r * (u1hh - nx) - s1 * hhh) % SECP256K1_P
    nz = h * z1 * z2 % SECP256K1_P
    return nx, ny, nz


def _point_mul(scalar: int, point: tuple[int, int] = SECP256K1_G) -> tuple[int, int]:
    if not 1 <= scalar < SECP256K1_N:
        raise ValueError("invalid secp256k1 scalar")
    result = (0, 0, 0)
    addend = (point[0], point[1], 1)
    k = scalar
    while k:
        if k & 1:
            result = _jacobian_add(result, addend)
        addend = _jacobian_double(addend)
        k >>= 1
    x, y, z = result
    if z == 0:
        raise ValueError("point at infinity")
    z_inv = _inv(z, SECP256K1_P)
    z2 = z_inv * z_inv % SECP256K1_P
    return x * z2 % SECP256K1_P, y * z2 * z_inv % SECP256K1_P


def _ser_public(private_key: int, compressed: bool = True) -> bytes:
    x, y = _point_mul(private_key)
    if compressed:
        return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _ckd_priv(private_key: int, chain_code: bytes, index: int) -> tuple[int, bytes]:
    if index >= HARDENED:
        data = b"\x00" + private_key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = _ser_public(private_key, compressed=True) + index.to_bytes(4, "big")
    digest = hmac.new(chain_code, data, hashlib.sha512).digest()
    left = int.from_bytes(digest[:32], "big")
    child = (left + private_key) % SECP256K1_N
    if left >= SECP256K1_N or child == 0:
        raise ValueError("invalid BIP-32 child")
    return child, digest[32:]


def derive_private_key(seed: bytes, path: Sequence[int]) -> int:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    private_key = int.from_bytes(digest[:32], "big")
    chain_code = digest[32:]
    if private_key == 0 or private_key >= SECP256K1_N:
        raise ValueError("invalid BIP-32 master key")
    for index in path:
        private_key, chain_code = _ckd_priv(private_key, chain_code, index)
    return private_key


def _hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new("ripemd160")
    ripe.update(sha)
    return ripe.digest()


def _base58check(payload: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    raw = payload + checksum
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    leading_zeroes = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * leading_zeroes + (encoded or "1")


def p2pkh_address(private_key: int, compressed: bool = True) -> str:
    return _base58check(b"\x00" + _hash160(_ser_public(private_key, compressed=compressed)))


def bip44_addresses(words: Sequence[str], passphrase: str = "") -> tuple[str, str]:
    seed = mnemonic_to_seed(words, passphrase)
    private_key = derive_private_key(seed, [44 + HARDENED, 0 + HARDENED, 0 + HARDENED, 0, 0])
    return p2pkh_address(private_key, True), p2pkh_address(private_key, False)


def gps_indices(digits: str) -> list[int]:
    cleaned = "".join(ch for ch in digits if ch.isdigit())
    return [int(digit) + 10 * offset for offset, digit in enumerate(cleaned)]


def words_at_indices(tokens: Sequence[str], indices: Sequence[int], start: int = 0) -> list[str]:
    """Select one-based positions relative to start (0-based token offset)."""
    result = []
    for index in indices:
        if index <= 0:
            raise ValueError("word positions are one-based and must be positive")
        absolute = start + index - 1
        if absolute >= len(tokens):
            raise IndexError(index)
        result.append(tokens[absolute])
    return result


@dataclass(frozen=True)
class Candidate:
    start: int
    positions: tuple[int, ...]
    words: tuple[str, ...]
    compressed_address: str
    uncompressed_address: str

    @property
    def target(self) -> bool:
        return TARGET_ADDRESS in (self.compressed_address, self.uncompressed_address)


def check_candidate(words: Sequence[str], word_index: dict[str, int]) -> tuple[str, str] | None:
    if not mnemonic_checksum_valid(words, word_index):
        return None
    return bip44_addresses(words)


def scan_linear(tokens: Sequence[str], word_index: dict[str, int]) -> Iterator[Candidate]:
    filtered = [(pos, word) for pos, word in enumerate(tokens) if word in word_index]
    for offset in range(len(filtered) - 11):
        group = filtered[offset : offset + 12]
        words = tuple(word for _, word in group)
        addresses = check_candidate(words, word_index)
        if addresses:
            yield Candidate(group[0][0], tuple(pos + 1 for pos, _ in group), words, *addresses)


def gps_block_options(tokens: Sequence[str], start: int, word_index: dict[str, int]) -> list[list[tuple[int, str]]]:
    """Return BIP-39 words available at positions compatible with twelve GPS digits.

    For digit d at offset i, the article uses position 10*i + d. Position zero
    is not a valid one-based word index, so the first digit has options 1..9;
    subsequent blocks have 10..19, 20..29, ..., 110..119.
    """
    options: list[list[tuple[int, str]]] = []
    for block in range(12):
        low = 1 if block == 0 else block * 10
        high = block * 10 + 9
        block_options = []
        for position in range(low, high + 1):
            absolute = start + position - 1
            if 0 <= absolute < len(tokens):
                word = tokens[absolute]
                if word in word_index:
                    block_options.append((position, word))
        options.append(block_options)
    return options


def scan_gps(tokens: Sequence[str], word_index: dict[str, int], max_combinations: int) -> Iterator[Candidate]:
    max_start = max(0, len(tokens) - 119)
    for start in range(max_start + 1):
        options = gps_block_options(tokens, start, word_index)
        if any(not group for group in options):
            continue
        combinations = 1
        for group in options:
            combinations *= len(group)
        if combinations > max_combinations:
            continue
        for selection in itertools.product(*options):
            positions = tuple(position for position, _ in selection)
            words = tuple(word for _, word in selection)
            addresses = check_candidate(words, word_index)
            if addresses:
                yield Candidate(start, positions, words, *addresses)


def positions_to_digits(positions: Sequence[int]) -> str:
    digits = []
    for offset, position in enumerate(positions):
        digit = position - 10 * offset
        if not 0 <= digit <= 9:
            raise ValueError(f"position {position} is incompatible with offset {offset}")
        digits.append(str(digit))
    return "".join(digits)


def null_cipher(tokens: Sequence[str], letter: int) -> str:
    if letter <= 0:
        raise ValueError("letter must be >= 1")
    return "".join(word[letter - 1] for word in tokens if len(word) >= letter)


def format_candidate(candidate: Candidate) -> str:
    digits = ""
    try:
        digits = positions_to_digits(candidate.positions)
    except ValueError:
        pass
    parts = [
        f"start_token={candidate.start + 1}",
        f"positions={','.join(map(str, candidate.positions))}",
        f"mnemonic={' '.join(candidate.words)}",
        f"compressed={candidate.compressed_address}",
        f"uncompressed={candidate.uncompressed_address}",
    ]
    if digits:
        parts.insert(2, f"digits={digits}")
    if candidate.target:
        parts.insert(0, "TARGET MATCH")
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--article", type=Path, default=Path("data/article.txt"))
    parser.add_argument("--wordlist", type=Path, default=Path("data/english.txt"))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("baseline", help="scan consecutive BIP-39 words in article order")

    gps = sub.add_parser("gps", help="scan windows compatible with the article's +10 GPS scheme")
    gps.add_argument("--max-combinations", type=int, default=10_000)
    gps.add_argument("--all-valid", action="store_true", help="print every checksum-valid mnemonic")

    null = sub.add_parser("null", help="emit an nth-letter null-cipher stream")
    null.add_argument("--letter", type=int, default=3)

    sub.add_parser("numbers", help="extract numeric clues in source order")

    args = parser.parse_args()
    text = args.article.read_text(encoding="utf-8")
    tokens = tokenize(text)
    wordlist = load_wordlist(args.wordlist)
    word_index = {word: idx for idx, word in enumerate(wordlist)}

    if args.command == "numbers":
        print("\n".join(NUMBER_RE.findall(text)))
        return 0
    if args.command == "null":
        print(null_cipher(tokens, args.letter))
        return 0

    if args.command == "baseline":
        bip39_occurrences = sum(token in word_index for token in tokens)
        valid = 0
        for candidate in scan_linear(tokens, word_index):
            valid += 1
            if candidate.target:
                print(format_candidate(candidate))
                return 0
        print(f"tokens={len(tokens)} bip39_occurrences={bip39_occurrences} checksum_valid={valid} target_matches=0")
        return 1

    if args.command == "gps":
        valid = 0
        seen: set[tuple[str, ...]] = set()
        for candidate in scan_gps(tokens, word_index, args.max_combinations):
            if candidate.words in seen:
                continue
            seen.add(candidate.words)
            valid += 1
            if args.all_valid or candidate.target:
                print(format_candidate(candidate), "\n")
            if candidate.target:
                return 0
        print(f"gps_checksum_valid_unique={valid} target_matches=0 max_combinations={args.max_combinations}")
        return 1

    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
