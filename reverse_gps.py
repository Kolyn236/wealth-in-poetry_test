#!/usr/bin/env python3
"""Reverse the GPS-position hiding method used in the Trithemius puzzle.

The author maps 12 selector digits to positions 1..9, 10..19, ... 110..119.
This module inverts that rule: BIP-39 words already present in those ranges
produce both candidate mnemonics and the selector digits that point to them.

The scanner supports deterministic sharding. A large Cartesian product can be
split across independent GitHub Actions jobs without overlap and without each
job walking the full product. High-volume address derivation can use coincurve
(libsecp256k1) while the baseline solver remains standard-library-only.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import itertools
import json
import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

import attack_surface
import solver

BLOCKS = 12
MAX_POSITION = 119
DEFAULT_PATHS = ("m/44'/0'/0'/0/0",)
EXAMPLE_MARKER_RE = re.compile(r"\bExample:\s*", re.IGNORECASE)


@dataclass(frozen=True)
class Choice:
    block: int
    position: int
    digit: int
    word: str
    word_index: int


@dataclass(frozen=True)
class StartPoint:
    start_word: int
    labels: tuple[str, ...]


@dataclass(frozen=True)
class ReverseCandidate:
    start_word: int
    labels: tuple[str, ...]
    selector: str
    positions: tuple[int, ...]
    words: tuple[str, ...]

    def as_dict(self) -> dict:
        return asdict(self)


def block_bounds(block: int) -> tuple[int, int]:
    if not 0 <= block < BLOCKS:
        raise ValueError(f"block must be in 0..{BLOCKS - 1}")
    return (1, 9) if block == 0 else (block * 10, block * 10 + 9)


def digit_for_position(block: int, position: int) -> int:
    low, high = block_bounds(block)
    if not low <= position <= high:
        raise ValueError(f"position {position} is outside {low}..{high}")
    return position if block == 0 else position - block * 10


def build_word_index(wordlist: Sequence[str]) -> dict[str, int]:
    return {word.lower(): index for index, word in enumerate(wordlist)}


def block_choices(tokens: Sequence[str], word_index: dict[str, int], start: int = 0) -> list[list[Choice]]:
    blocks: list[list[Choice]] = []
    for block in range(BLOCKS):
        low, high = block_bounds(block)
        choices: list[Choice] = []
        for position in range(low, high + 1):
            absolute = start + position - 1
            if absolute >= len(tokens):
                break
            word = tokens[absolute].lower()
            index = word_index.get(word)
            if index is not None:
                choices.append(Choice(block, position, digit_for_position(block, position), word, index))
        blocks.append(choices)
    return blocks


def combination_count(blocks: Sequence[Sequence[Choice]]) -> int:
    if len(blocks) != BLOCKS or any(not block for block in blocks):
        return 0
    return math.prod(len(block) for block in blocks)


def validate_12_indices(indices: Sequence[int]) -> bool:
    """Fast BIP-39 checksum validation for exactly 12 word indices."""
    if len(indices) != 12 or any(index < 0 or index >= 2048 for index in indices):
        return False
    value = 0
    for index in indices:
        value = (value << 11) | index
    entropy = (value >> 4).to_bytes(16, "big")
    return (value & 0x0F) == (hashlib.sha256(entropy).digest()[0] >> 4)


def candidate_from_combo(start: StartPoint, combo: Sequence[Choice]) -> ReverseCandidate:
    return ReverseCandidate(
        start_word=start.start_word + 1,
        labels=start.labels,
        selector="".join(str(choice.digit) for choice in combo),
        positions=tuple(choice.position for choice in combo),
        words=tuple(choice.word for choice in combo),
    )


def _located_offsets(text: str, parts: Iterable[str], label: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    cursor = 0
    for index, part in enumerate(parts, start=1):
        char_offset = text.find(part, cursor)
        if char_offset < 0:
            continue
        result.append((len(solver.tokenize(text[:char_offset])), f"{label}:{index}"))
        cursor = char_offset + len(part)
    return result


def _example_offsets(text: str) -> list[tuple[int, str]]:
    """The article prefixes worked stories with `Example:`; counting begins after it."""
    return [
        (len(solver.tokenize(text[:match.end()])), f"example:{index}")
        for index, match in enumerate(EXAMPLE_MARKER_RE.finditer(text), start=1)
    ]


def structural_starts(text: str) -> list[StartPoint]:
    labels_by_start: dict[int, list[str]] = {0: ["article:1"]}
    located = [
        *_located_offsets(text, attack_surface.split_paragraphs(text), "paragraph"),
        *_located_offsets(text, attack_surface.split_sentences(text), "sentence"),
        *_example_offsets(text),
    ]
    for start, label in located:
        labels_by_start.setdefault(start, []).append(label)
    return [StartPoint(start, tuple(labels)) for start, labels in sorted(labels_by_start.items())]


def coordinate_interpretations(selector: str) -> list[dict]:
    if len(selector) != 12 or not selector.isdigit():
        return []
    result: list[dict] = []
    for split, lat_digits, lon_digits, scheme in (
        (6, 2, 2, "lat2.4_lon2.4"),
        (5, 2, 3, "lat2.3_lon3.4"),
        (7, 2, 2, "lat2.5_lon2.3"),
    ):
        lat_raw, lon_raw = selector[:split], selector[split:]
        if len(lat_raw) <= lat_digits or len(lon_raw) <= lon_digits:
            continue
        latitude = float(lat_raw[:lat_digits] + "." + lat_raw[lat_digits:])
        longitude = float(lon_raw[:lon_digits] + "." + lon_raw[lon_digits:])
        if 0 <= latitude <= 90 and 0 <= longitude <= 180:
            result.append({"scheme": scheme, "latitude": latitude, "longitude": longitude})
    return result


def shard_prefix_depth(blocks: Sequence[Sequence[Choice]], shard_count: int) -> int:
    """Choose a prefix deep enough to distribute work across shards."""
    if shard_count <= 1:
        return 1
    product = 1
    for depth, block in enumerate(blocks, start=1):
        product *= len(block)
        if product >= shard_count:
            return depth
    return len(blocks)


def _assigned_prefix_count(prefix_total: int, shard_index: int, shard_count: int) -> int:
    if shard_index >= prefix_total:
        return 0
    return ((prefix_total - 1 - shard_index) // shard_count) + 1


def assigned_combination_count(
    blocks: Sequence[Sequence[Choice]], shard_index: int = 0, shard_count: int = 1
) -> int:
    total = combination_count(blocks)
    if total == 0:
        return 0
    depth = shard_prefix_depth(blocks, shard_count)
    prefix_total = math.prod(len(block) for block in blocks[:depth])
    suffix_total = math.prod(len(block) for block in blocks[depth:]) if depth < len(blocks) else 1
    return _assigned_prefix_count(prefix_total, shard_index, shard_count) * suffix_total


def iter_sharded_combos(
    blocks: Sequence[Sequence[Choice]], shard_index: int = 0, shard_count: int = 1
) -> Iterator[tuple[Choice, ...]]:
    """Yield one shard of the product without iterating other shards' suffixes."""
    if combination_count(blocks) == 0:
        return
    depth = shard_prefix_depth(blocks, shard_count)
    prefix_blocks = blocks[:depth]
    suffix_blocks = blocks[depth:]
    for prefix_index, prefix in enumerate(itertools.product(*prefix_blocks)):
        if prefix_index % shard_count != shard_index:
            continue
        if suffix_blocks:
            for suffix in itertools.product(*suffix_blocks):
                yield prefix + suffix
        else:
            yield prefix


def _coincurve_private(private_key: int):
    try:
        from coincurve import PrivateKey
    except ImportError as exc:
        raise RuntimeError(
            "coincurve backend requested but package is missing; run `pip install coincurve`"
        ) from exc
    return PrivateKey(private_key.to_bytes(32, "big"))


def _fast_public_key(private_key: int, compressed: bool = True) -> bytes:
    return _coincurve_private(private_key).public_key.format(compressed=compressed)


def _fast_child_private(parent_key: int, chain_code: bytes, index: int) -> tuple[int, bytes]:
    if index >= solver.HARDENED:
        data = b"\x00" + parent_key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = _fast_public_key(parent_key, compressed=True) + index.to_bytes(4, "big")
    digest = hmac.new(chain_code, data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    if tweak >= solver.N:
        raise ValueError("invalid BIP-32 child tweak")
    child = (tweak + parent_key) % solver.N
    if child == 0:
        raise ValueError("invalid BIP-32 child key")
    return child, digest[32:]


def _fast_derive_private(seed: bytes, path: str) -> int:
    key, chain = solver.master_key(seed)
    for index in solver.parse_path(path):
        key, chain = _fast_child_private(key, chain, index)
    return key


def fast_addresses_for_mnemonic(words: Sequence[str], paths: Sequence[str]) -> Iterator[tuple[str, bool, str]]:
    seed = solver.mnemonic_to_seed(words)
    for path in paths:
        private_key = _fast_derive_private(seed, path)
        for compressed in (True, False):
            public_key = _fast_public_key(private_key, compressed=compressed)
            address = solver.base58check(b"\x00" + solver.hash160(public_key))
            yield path, compressed, address


def resolve_backend(requested: str) -> str:
    if requested == "stdlib":
        return "stdlib"
    if requested == "coincurve":
        _coincurve_private(1)
        return "coincurve"
    try:
        _coincurve_private(1)
        return "coincurve"
    except RuntimeError:
        return "stdlib"


def derive_candidate(candidate: ReverseCandidate, paths: Sequence[str], target: str, backend: str) -> dict:
    generator = (
        fast_addresses_for_mnemonic(candidate.words, paths)
        if backend == "coincurve"
        else solver.addresses_for_mnemonic(candidate.words, paths)
    )
    addresses = [
        {"path": path, "compressed": compressed, "address": address, "target": address == target}
        for path, compressed, address in generator
    ]
    return {
        **candidate.as_dict(),
        "coordinate_interpretations": coordinate_interpretations(candidate.selector),
        "addresses": addresses,
        "target_hit": any(item["target"] for item in addresses),
    }


def scan(
    text: str,
    wordlist: Sequence[str],
    paths: Sequence[str],
    target: str,
    max_combinations_per_start: int,
    derive_limit: int,
    sample_limit: int,
    shard_index: int = 0,
    shard_count: int = 1,
    backend: str = "stdlib",
) -> dict:
    tokens = solver.tokenize(text)
    word_index = build_word_index(wordlist)
    starts = [item for item in structural_starts(text) if item.start_word + MAX_POSITION <= len(tokens)]

    theoretical = assigned_theoretical = enumerated = checksum_count = derived_count = author_count = 0
    skipped: list[dict] = []
    start_stats: list[dict] = []
    samples: list[dict] = []
    target_hits: list[dict] = []

    for start in starts:
        blocks = block_choices(tokens, word_index, start.start_word)
        total = combination_count(blocks)
        assigned = assigned_combination_count(blocks, shard_index, shard_count)
        theoretical += total
        assigned_theoretical += assigned
        block_sizes = [len(block) for block in blocks]
        stat = {
            "start_word": start.start_word + 1,
            "labels": start.labels,
            "block_sizes": block_sizes,
            "combinations": total,
            "assigned_combinations": assigned,
        }
        if assigned == 0:
            start_stats.append({**stat, "enumerated": True, "checksum_valid": 0})
            continue
        if assigned > max_combinations_per_start:
            skipped.append(stat)
            start_stats.append({**stat, "enumerated": False, "checksum_valid": None})
            continue

        valid_for_start = 0
        enumerated += assigned
        for combo in iter_sharded_combos(blocks, shard_index, shard_count):
            if not validate_12_indices([choice.word_index for choice in combo]):
                continue
            candidate = candidate_from_combo(start, combo)
            checksum_count += 1
            valid_for_start += 1
            if candidate.words == tuple(solver.AUTHOR_GPS_WORDS) and candidate.selector == solver.AUTHOR_GPS_DIGITS:
                author_count += 1
            if len(samples) < sample_limit:
                samples.append({
                    **candidate.as_dict(),
                    "coordinate_interpretations": coordinate_interpretations(candidate.selector),
                })
            if derived_count < derive_limit:
                derived = derive_candidate(candidate, paths, target, backend)
                derived_count += 1
                if derived["target_hit"]:
                    target_hits.append(derived)
        start_stats.append({**stat, "enumerated": True, "checksum_valid": valid_for_start})

    enumeration_complete = not skipped and enumerated == assigned_theoretical
    return {
        "summary": {
            "tokens": len(tokens),
            "structural_starts": len(starts),
            "theoretical_combinations": theoretical,
            "assigned_combinations": assigned_theoretical,
            "enumerated_combinations": enumerated,
            "skipped_explosive_starts": len(skipped),
            "checksum_valid_candidates": checksum_count,
            "derived_candidates": derived_count,
            "target_hits": len(target_hits),
            "author_example_candidates": author_count,
            "enumeration_complete": enumeration_complete,
            "target_scan_complete": enumeration_complete and derived_count == checksum_count,
            "shard_index": shard_index,
            "shard_count": shard_count,
            "backend": backend,
        },
        "skipped_starts": skipped,
        "start_stats": start_stats,
        "candidate_sample": samples,
        "target_hits": target_hits,
    }


def verify_author_example(wordlist: Sequence[str]) -> dict:
    tokens = solver.tokenize(solver.AUTHOR_GPS_EXAMPLE)
    word_index = build_word_index(wordlist)
    blocks = block_choices(tokens, word_index)
    recovered: list[Choice] = []
    for block, (position, word) in enumerate(
        zip(solver.gps_positions(solver.AUTHOR_GPS_DIGITS), solver.AUTHOR_GPS_WORDS)
    ):
        match = next(
            (item for item in blocks[block] if item.position == position and item.word == word),
            None,
        )
        if match is None:
            return {"pass": False, "reason": f"missing {word}@{position}"}
        recovered.append(match)
    selector = "".join(str(choice.digit) for choice in recovered)
    return {
        "pass": selector == solver.AUTHOR_GPS_DIGITS
        and validate_12_indices([item.word_index for item in recovered]),
        "selector": selector,
        "positions": [item.position for item in recovered],
        "words": [item.word for item in recovered],
        "block_sizes": [len(block) for block in blocks],
        "combination_space": combination_count(blocks),
    }


def load_inputs(article: Path, wordlist: Path) -> tuple[str, list[str]]:
    if not article.exists() or not wordlist.exists():
        raise SystemExit("Puzzle data is missing. Run `python solver.py fetch` first.")
    return article.read_text(encoding="utf-8"), solver.load_wordlist(wordlist)


def command_verify(args: argparse.Namespace) -> int:
    _, wordlist = load_inputs(args.article, args.wordlist)
    result = verify_author_example(wordlist)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("pass") else 1


def command_scan(args: argparse.Namespace) -> int:
    text, wordlist = load_inputs(args.article, args.wordlist)
    backend = resolve_backend(args.backend)
    report = scan(
        text,
        wordlist,
        args.path or list(DEFAULT_PATHS),
        args.target,
        args.max_combinations_per_start,
        args.derive_limit,
        args.sample_limit,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
        backend=backend,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    if report["target_hits"]:
        print("TARGET HIT")
        for item in report["target_hits"]:
            print(json.dumps(item, ensure_ascii=False))
    elif report["summary"]["target_scan_complete"]:
        print("target: not found; this shard's reverse-GPS target scan was exhaustive")
    else:
        print("target: not found in derived subset; this shard is NOT exhaustive yet")
    print(f"report={args.report}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="recover the author's worked example in reverse")
    verify.add_argument("--article", type=Path, default=Path("data/article.txt"))
    verify.add_argument("--wordlist", type=Path, default=Path("data/english.txt"))
    verify.set_defaults(func=command_verify)

    scan_parser = sub.add_parser("scan", help="run reverse-GPS search at structural starts")
    scan_parser.add_argument("--article", type=Path, default=Path("data/article.txt"))
    scan_parser.add_argument("--wordlist", type=Path, default=Path("data/english.txt"))
    scan_parser.add_argument("--path", action="append")
    scan_parser.add_argument("--target", default=solver.TARGET_ADDRESS)
    scan_parser.add_argument("--max-combinations-per-start", type=int, default=2_000_000)
    scan_parser.add_argument("--derive-limit", type=int, default=5_000)
    scan_parser.add_argument("--sample-limit", type=int, default=200)
    scan_parser.add_argument("--shard-index", type=int, default=0)
    scan_parser.add_argument("--shard-count", type=int, default=1)
    scan_parser.add_argument("--backend", choices=("auto", "stdlib", "coincurve"), default="auto")
    scan_parser.add_argument("--report", type=Path, default=Path("data/reverse-gps-report.json"))
    scan_parser.set_defaults(func=command_scan)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "max_combinations_per_start", 1) < 1:
        parser.error("--max-combinations-per-start must be positive")
    if getattr(args, "derive_limit", 0) < 0 or getattr(args, "sample_limit", 0) < 0:
        parser.error("limits must be non-negative")
    shard_count = getattr(args, "shard_count", 1)
    shard_index = getattr(args, "shard_index", 0)
    if shard_count < 1:
        parser.error("--shard-count must be positive")
    if not 0 <= shard_index < shard_count:
        parser.error("--shard-index must be in 0..shard-count-1")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
