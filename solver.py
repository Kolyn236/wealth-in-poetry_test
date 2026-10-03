#!/usr/bin/env python3
"""Research solver for the public Trithemius “Wealth in Poetry” puzzle.

The code intentionally uses only the Python standard library so the search is
reproducible. It implements enough BIP-39/BIP-32/secp256k1 to validate
mnemonics and derive legacy Bitcoin P2PKH addresses.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import unicodedata
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
ARTICLE_URL = "https://raw.githubusercontent.com/HomelessPhD/Wealth_in_Poetry/main/python_script/text.txt"

TOKEN_RE = re.compile(r"[A-Za-z]+(?:['’][A-Za-z]+)?")
VALID_MNEMONIC_LENGTHS = {12, 15, 18, 21, 24}

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
HARDENED = 0x80000000

AUTHOR_GPS_EXAMPLE = (
    "Such an asset to be represented by an experienced and mature lawyer "
    "particularly when you have a trial in front of the Supreme Court of the USA. "
    "Load your argument with logic and do not provide ways to escape. Symbol of "
    "cultural diversity should be used as often as possible in order to support the "
    "story. Our client clearly did not make that complex and improvised bomb himself. "
    "They were on their way to his friend's picnic by the river when he noticed a "
    "suspicious person pretending to do aerobic exercises. He immediately pointed it "
    "out to his friends. Their whereabouts aren't a mystery, during the attack they "
    "were ordering ginger tea with honey to bring to the picnic."
)
AUTHOR_GPS_DIGITS = "388906770044"
AUTHOR_GPS_WORDS = [
    "asset", "trial", "load", "escape", "symbol", "story",
    "bomb", "picnic", "river", "aerobic", "mystery", "honey",
]


def tokenize(text: str) -> list[str]:
    """Tokenize like the author's worked GPS example: punctuation does not count."""
    return TOKEN_RE.findall(text)


def gps_positions(digits: str) -> list[int]:
    """Convert digits to 1-based positions using author's +10-per-digit rule."""
    if not digits.isdigit():
        raise ValueError("GPS selector must contain digits only")
    return [int(digit) + 10 * i for i, digit in enumerate(digits)]


def select_by_positions(tokens: Sequence[str], positions: Sequence[int], start: int = 0) -> list[str] | None:
    selected: list[str] = []
    for pos in positions:
        if pos <= 0:
            return None
        idx = start + pos - 1
        if idx >= len(tokens):
            return None
        selected.append(tokens[idx].lower())
    return selected


def load_wordlist(path: Path) -> list[str]:
    words = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(words) != 2048:
        raise ValueError(f"expected 2048 BIP-39 words, got {len(words)}")
    return words


def validate_mnemonic(words: Sequence[str], wordlist: Sequence[str]) -> bool:
    if len(words) not in VALID_MNEMONIC_LENGTHS:
        return False
    index = {word: i for i, word in enumerate(wordlist)}
    try:
        numbers = [index[word.lower()] for word in words]
    except KeyError:
        return False

    bitstream = "".join(f"{number:011b}" for number in numbers)
    ent_bits = len(bitstream) * 32 // 33
    cs_bits = len(bitstream) - ent_bits
    entropy_bits = bitstream[:ent_bits]
    checksum_bits = bitstream[ent_bits:]
    entropy = int(entropy_bits, 2).to_bytes(ent_bits // 8, "big")
    expected = f"{hashlib.sha256(entropy).digest()[0]:08b}"[:cs_bits]
    return checksum_bits == expected


def mnemonic_to_seed(words: Sequence[str], passphrase: str = "") -> bytes:
    sentence = unicodedata.normalize("NFKD", " ".join(words))
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", sentence.encode(), salt.encode(), 2048, dklen=64)


def _inv(value: int) -> int:
    return pow(value % P, -1, P)


def point_add(a: tuple[int, int] | None, b: tuple[int, int] | None) -> tuple[int, int] | None:
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        slope = (3 * x1 * x1) * _inv(2 * y1)
    else:
        slope = (y2 - y1) * _inv(x2 - x1)
    slope %= P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def scalar_mult(k: int, point: tuple[int, int] = G) -> tuple[int, int] | None:
    if k % N == 0:
        return None
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def public_key(private_key: int, compressed: bool = True) -> bytes:
    point = scalar_mult(private_key)
    if point is None:
        raise ValueError("invalid private key")
    x, y = point
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new("ripemd160")
    ripe.update(sha)
    return ripe.digest()


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    chars = ""
    while number:
        number, rem = divmod(number, 58)
        chars = B58[rem] + chars
    leading = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading + (chars or "")


def base58check(versioned_payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    return base58_encode(versioned_payload + checksum)


def p2pkh_address(private_key: int, compressed: bool = True) -> str:
    return base58check(b"\x00" + hash160(public_key(private_key, compressed=compressed)))


def master_key(seed: bytes) -> tuple[int, bytes]:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(digest[:32], "big")
    if not 1 <= key < N:
        raise ValueError("invalid BIP-32 master key")
    return key, digest[32:]


def child_private(parent_key: int, chain_code: bytes, index: int) -> tuple[int, bytes]:
    if index >= HARDENED:
        data = b"\x00" + parent_key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = public_key(parent_key, compressed=True) + index.to_bytes(4, "big")
    digest = hmac.new(chain_code, data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    if tweak >= N:
        raise ValueError("invalid BIP-32 child tweak")
    child = (tweak + parent_key) % N
    if child == 0:
        raise ValueError("invalid BIP-32 child key")
    return child, digest[32:]


def parse_path(path: str) -> list[int]:
    if path == "m":
        return []
    if not path.startswith("m/"):
        raise ValueError(f"invalid path: {path}")
    result = []
    for part in path[2:].split("/"):
        hardened = part.endswith(("'", "h", "H"))
        if hardened:
            part = part[:-1]
        index = int(part)
        if index < 0 or index >= HARDENED:
            raise ValueError(f"invalid path component: {part}")
        result.append(index + (HARDENED if hardened else 0))
    return result


def derive_private(seed: bytes, path: str) -> int:
    key, chain = master_key(seed)
    for index in parse_path(path):
        key, chain = child_private(key, chain, index)
    return key


def addresses_for_mnemonic(words: Sequence[str], paths: Sequence[str]) -> Iterator[tuple[str, bool, str]]:
    seed = mnemonic_to_seed(words)
    for path in paths:
        private = derive_private(seed, path)
        yield path, True, p2pkh_address(private, compressed=True)
        yield path, False, p2pkh_address(private, compressed=False)


@dataclass
class Match:
    mode: str
    start_word: int
    words: list[str]
    selector: str | None = None
    path: str | None = None
    compressed: bool | None = None
    address: str | None = None

    def as_dict(self) -> dict:
        return {
            "mode": self.mode,
            "start_word": self.start_word,
            "selector": self.selector,
            "words": self.words,
            "path": self.path,
            "compressed": self.compressed,
            "address": self.address,
        }


def check_target(words: Sequence[str], target: str, paths: Sequence[str]) -> tuple[str, bool, str] | None:
    for path, compressed, address in addresses_for_mnemonic(words, paths):
        if address == target:
            return path, compressed, address
    return None


def scan_contiguous(tokens: Sequence[str], wordlist: Sequence[str], target: str, paths: Sequence[str]) -> Iterator[Match]:
    bip = set(wordlist)
    filtered = [word.lower() for word in tokens if word.lower() in bip]
    for start in range(len(filtered) - 11):
        words = filtered[start:start + 12]
        if not validate_mnemonic(words, wordlist):
            continue
        hit = check_target(words, target, paths)
        if hit:
            path, compressed, address = hit
            yield Match("contiguous-bip39", start + 1, list(words), path=path, compressed=compressed, address=address)


def scan_selector(tokens: Sequence[str], wordlist: Sequence[str], selector: str, target: str, paths: Sequence[str]) -> Iterator[Match]:
    positions = gps_positions(selector)
    if not positions:
        return
    max_pos = max(positions)
    for start in range(0, len(tokens) - max_pos + 1):
        words = select_by_positions(tokens, positions, start)
        if words is None or not validate_mnemonic(words, wordlist):
            continue
        hit = check_target(words, target, paths)
        if hit:
            path, compressed, address = hit
            yield Match("gps-selector", start + 1, words, selector=selector, path=path, compressed=compressed, address=address)


def scan_selectors(tokens: Sequence[str], wordlist: Sequence[str], selectors: Iterable[str], target: str, paths: Sequence[str]) -> Iterator[Match]:
    for selector in selectors:
        selector = re.sub(r"\D", "", selector)
        if len(selector) != 12:
            continue
        yield from scan_selector(tokens, wordlist, selector, target, paths)


def null_cipher_stream(tokens: Sequence[str], char_index: int) -> str:
    chars = []
    for word in tokens:
        letters = re.sub(r"[^A-Za-z]", "", word)
        if len(letters) > char_index:
            chars.append(letters[char_index].lower())
    return "".join(chars)


def fetch_file(url: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "wealth-in-poetry-solver/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read()
    path.write_bytes(data)


def command_fetch(args: argparse.Namespace) -> int:
    fetch_file(WORDLIST_URL, args.wordlist)
    fetch_file(ARTICLE_URL, args.article)
    words = load_wordlist(args.wordlist)
    text = args.article.read_text(encoding="utf-8")
    print(f"wordlist: {len(words)} words")
    print(f"article: {len(tokenize(text))} tokens")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    tokens = tokenize(AUTHOR_GPS_EXAMPLE)
    positions = gps_positions(AUTHOR_GPS_DIGITS)
    words = select_by_positions(tokens, positions)
    ok = words == AUTHOR_GPS_WORDS
    print("positions:", positions)
    print("words:", " ".join(words or []))
    print("author-example:", "PASS" if ok else "FAIL")
    if args.wordlist.exists():
        wordlist = load_wordlist(args.wordlist)
        checksum = validate_mnemonic(words or [], wordlist)
        print("bip39-checksum:", "PASS" if checksum else "FAIL")
        ok = ok and checksum
    return 0 if ok else 1


def _load_selectors(args: argparse.Namespace) -> list[str]:
    selectors = list(args.selector or [])
    if args.hypotheses and args.hypotheses.exists():
        payload = json.loads(args.hypotheses.read_text(encoding="utf-8"))
        for item in payload:
            if isinstance(item, str):
                selectors.append(item)
            elif isinstance(item, dict) and "selector" in item:
                selectors.append(str(item["selector"]))
    return selectors


def command_scan(args: argparse.Namespace) -> int:
    wordlist = load_wordlist(args.wordlist)
    tokens = tokenize(args.article.read_text(encoding="utf-8"))
    paths = args.path or ["m/44'/0'/0'/0/0"]
    print(f"tokens={len(tokens)} target={args.target} paths={paths}")

    matches: list[Match] = []
    if args.mode in {"contiguous", "all"}:
        matches.extend(scan_contiguous(tokens, wordlist, args.target, paths))
    if args.mode in {"gps", "all"}:
        selectors = _load_selectors(args)
        print(f"gps-selectors={len(selectors)}")
        matches.extend(scan_selectors(tokens, wordlist, selectors, args.target, paths))

    for match in matches:
        print(json.dumps(match.as_dict(), ensure_ascii=False))
    if matches:
        print(f"TARGET MATCHES: {len(matches)}")
        return 0
    print("No target match found for tested hypotheses.")
    return 0


def command_null(args: argparse.Namespace) -> int:
    tokens = tokenize(args.article.read_text(encoding="utf-8"))
    for index in range(args.from_char - 1, args.to_char):
        stream = null_cipher_stream(tokens, index)
        print(f"char[{index + 1}] {stream[:args.limit]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    fetch = sub.add_parser("fetch", help="download public puzzle data")
    fetch.add_argument("--article", type=Path, default=Path("data/article.txt"))
    fetch.add_argument("--wordlist", type=Path, default=Path("data/english.txt"))
    fetch.set_defaults(func=command_fetch)

    verify = sub.add_parser("verify", help="reproduce the author's GPS example")
    verify.add_argument("--wordlist", type=Path, default=Path("data/english.txt"))
    verify.set_defaults(func=command_verify)

    scan = sub.add_parser("scan", help="run wallet-search hypotheses")
    scan.add_argument("--article", type=Path, default=Path("data/article.txt"))
    scan.add_argument("--wordlist", type=Path, default=Path("data/english.txt"))
    scan.add_argument("--hypotheses", type=Path, default=Path("hypotheses.json"))
    scan.add_argument("--selector", action="append", help="12 digits from GPS/phone-like selector; repeatable")
    scan.add_argument("--mode", choices=["contiguous", "gps", "all"], default="all")
    scan.add_argument("--target", default=TARGET_ADDRESS)
    scan.add_argument("--path", action="append", help="BIP-32 path; repeatable")
    scan.set_defaults(func=command_scan)

    null = sub.add_parser("null", help="print null-cipher character streams")
    null.add_argument("--article", type=Path, default=Path("data/article.txt"))
    null.add_argument("--from-char", type=int, default=1)
    null.add_argument("--to-char", type=int, default=5)
    null.add_argument("--limit", type=int, default=500)
    null.set_defaults(func=command_null)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
