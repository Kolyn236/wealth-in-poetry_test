#!/usr/bin/env python3
"""Exhaustive, sharded reverse-GPS scan for the public Wealth in Poetry puzzle.

This module builds on reverse_gps.py, but removes the exploratory per-start and
per-address limits. Work is deterministically balanced across shards by the
number of theoretical combinations, and every checksum-valid mnemonic in the
assigned starts is derived against the requested BIP-32 paths.

The expensive secp256k1 operations use coincurve/libsecp256k1. BIP-39 PBKDF2
still dominates runtime, so checksum filtering is applied before derivation.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import hmac
import itertools
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

from coincurve import PrivateKey

import reverse_gps
import solver

DEFAULT_PATHS = ("m/44'/0'/0'/0/0",)


@dataclass(frozen=True)
class PlannedStart:
    start_word: int
    labels: tuple[str, ...]
    block_sizes: tuple[int, ...]
    combinations: int
    shard: int


@dataclass(frozen=True)
class WorkCandidate:
    start_word: int
    labels: tuple[str, ...]
    selector: str
    positions: tuple[int, ...]
    words: tuple[str, ...]


def _public_key(private_key: int, compressed: bool = True) -> bytes:
    secret = private_key.to_bytes(32, "big")
    return PrivateKey(secret).public_key.format(compressed=compressed)


def _master_key(seed: bytes) -> tuple[int, bytes]:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(digest[:32], "big")
    if not 1 <= key < solver.N:
        raise ValueError("invalid BIP-32 master key")
    return key, digest[32:]


def _child_private(parent_key: int, chain_code: bytes, index: int) -> tuple[int, bytes]:
    if index >= solver.HARDENED:
        data = b"\x00" + parent_key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = _public_key(parent_key, compressed=True) + index.to_bytes(4, "big")
    digest = hmac.new(chain_code, data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    if tweak >= solver.N:
        raise ValueError("invalid BIP-32 child tweak")
    child = (tweak + parent_key) % solver.N
    if child == 0:
        raise ValueError("invalid BIP-32 child key")
    return child, digest[32:]


def _derive_private(seed: bytes, path: str) -> int:
    key, chain = _master_key(seed)
    for index in solver.parse_path(path):
        key, chain = _child_private(key, chain, index)
    return key


def _mnemonic_seed(words: Sequence[str]) -> bytes:
    # BIP-39 English words are ASCII and the passphrase is empty in the puzzle,
    # so this is equivalent to solver.mnemonic_to_seed without repeated NFKD work.
    sentence = " ".join(words).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", sentence, b"mnemonic", 2048, dklen=64)


def _decode_base58check(address: str) -> bytes:
    number = 0
    for char in address:
        try:
            digit = solver.B58.index(char)
        except ValueError as exc:
            raise ValueError(f"invalid base58 character: {char!r}") from exc
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(address) - len(address.lstrip("1"))
    raw = b"\x00" * leading + body
    if len(raw) < 5:
        raise ValueError("invalid Base58Check payload")
    payload, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("invalid Base58Check checksum")
    return payload


def _target_hash160(address: str) -> bytes:
    payload = _decode_base58check(address)
    if len(payload) != 21 or payload[0] != 0:
        raise ValueError("target must be a mainnet P2PKH address")
    return payload[1:]


def _candidate_hit(candidate: WorkCandidate, paths: Sequence[str], target_hash: bytes) -> dict | None:
    seed = _mnemonic_seed(candidate.words)
    for path in paths:
        private = _derive_private(seed, path)
        for compressed in (True, False):
            pub = _public_key(private, compressed=compressed)
            if solver.hash160(pub) != target_hash:
                continue
            address = solver.base58check(b"\x00" + target_hash)
            return {
                "start_word": candidate.start_word,
                "labels": candidate.labels,
                "selector": candidate.selector,
                "positions": candidate.positions,
                "words": candidate.words,
                "coordinate_interpretations": reverse_gps.coordinate_interpretations(candidate.selector),
                "path": path,
                "compressed": compressed,
                "address": address,
            }
    return None


def _raw_start_plan(text: str, wordlist: Sequence[str]) -> list[tuple[reverse_gps.StartPoint, tuple[int, ...], int]]:
    tokens = solver.tokenize(text)
    word_index = reverse_gps.build_word_index(wordlist)
    starts = [
        item for item in reverse_gps.structural_starts(text)
        if item.start_word + reverse_gps.MAX_POSITION <= len(tokens)
    ]
    result: list[tuple[reverse_gps.StartPoint, tuple[int, ...], int]] = []
    for start in starts:
        blocks = reverse_gps.block_choices(tokens, word_index, start.start_word)
        sizes = tuple(len(block) for block in blocks)
        result.append((start, sizes, reverse_gps.combination_count(blocks)))
    return result


def build_plan(text: str, wordlist: Sequence[str], shard_count: int) -> list[PlannedStart]:
    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    raw = _raw_start_plan(text, wordlist)
    loads = [0] * shard_count
    assigned: dict[int, int] = {}
    # Longest-processing-time greedy partitioning gives much better balance than
    # start_index % shard_count for the few very large structural starts.
    for start, _, combinations in sorted(raw, key=lambda item: (-item[2], item[0].start_word)):
        shard = min(range(shard_count), key=lambda index: (loads[index], index))
        assigned[start.start_word] = shard
        loads[shard] += combinations
    return [
        PlannedStart(
            start_word=start.start_word,
            labels=start.labels,
            block_sizes=sizes,
            combinations=combinations,
            shard=assigned[start.start_word],
        )
        for start, sizes, combinations in raw
    ]


def _work_candidate(start: reverse_gps.StartPoint, combo: Sequence[reverse_gps.Choice]) -> WorkCandidate:
    return WorkCandidate(
        start_word=start.start_word + 1,
        labels=start.labels,
        selector="".join(str(choice.digit) for choice in combo),
        positions=tuple(choice.position for choice in combo),
        words=tuple(choice.word for choice in combo),
    )


def _derive_batch(
    executor: concurrent.futures.Executor,
    batch: list[WorkCandidate],
    paths: Sequence[str],
    target_hash: bytes,
) -> list[dict]:
    if not batch:
        return []
    hits: list[dict] = []
    for hit in executor.map(lambda candidate: _candidate_hit(candidate, paths, target_hash), batch):
        if hit is not None:
            hits.append(hit)
    return hits


def scan_shard(
    text: str,
    wordlist: Sequence[str],
    shard_index: int,
    shard_count: int,
    paths: Sequence[str],
    target: str,
    workers: int,
    batch_size: int,
    sample_limit: int,
) -> dict:
    if not 0 <= shard_index < shard_count:
        raise ValueError("shard_index must be in 0..shard_count-1")
    if workers < 1 or batch_size < 1 or sample_limit < 0:
        raise ValueError("workers and batch_size must be positive; sample_limit non-negative")

    started = time.monotonic()
    tokens = solver.tokenize(text)
    word_index = reverse_gps.build_word_index(wordlist)
    target_hash = _target_hash160(target)
    plan = build_plan(text, wordlist, shard_count)
    assigned = [item for item in plan if item.shard == shard_index and item.combinations > 0]

    enumerated = checksum_valid = derived = author_examples = 0
    target_hits: list[dict] = []
    samples: list[dict] = []
    start_stats: list[dict] = []
    batch: list[WorkCandidate] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for planned in assigned:
            start = reverse_gps.StartPoint(planned.start_word, planned.labels)
            blocks = reverse_gps.block_choices(tokens, word_index, planned.start_word)
            valid_for_start = 0
            begin = time.monotonic()
            for combo in itertools.product(*blocks):
                enumerated += 1
                indices = [choice.word_index for choice in combo]
                if not reverse_gps.validate_12_indices(indices):
                    continue
                candidate = _work_candidate(start, combo)
                checksum_valid += 1
                valid_for_start += 1
                if candidate.words == tuple(solver.AUTHOR_GPS_WORDS) and candidate.selector == solver.AUTHOR_GPS_DIGITS:
                    author_examples += 1
                if len(samples) < sample_limit:
                    samples.append({
                        **asdict(candidate),
                        "coordinate_interpretations": reverse_gps.coordinate_interpretations(candidate.selector),
                    })
                batch.append(candidate)
                if len(batch) >= batch_size:
                    target_hits.extend(_derive_batch(executor, batch, paths, target_hash))
                    derived += len(batch)
                    batch.clear()
            start_stats.append({
                **asdict(planned),
                "checksum_valid": valid_for_start,
                "seconds": round(time.monotonic() - begin, 3),
            })
            print(
                f"shard={shard_index}/{shard_count} start_word={planned.start_word + 1} "
                f"combinations={planned.combinations} checksum_valid={valid_for_start} "
                f"derived_so_far={derived} hits={len(target_hits)}",
                flush=True,
            )
        if batch:
            target_hits.extend(_derive_batch(executor, batch, paths, target_hash))
            derived += len(batch)
            batch.clear()

    theoretical = sum(item.combinations for item in assigned)
    complete = enumerated == theoretical and derived == checksum_valid
    return {
        "summary": {
            "shard_index": shard_index,
            "shard_count": shard_count,
            "workers": workers,
            "paths": list(paths),
            "target": target,
            "assigned_starts": len(assigned),
            "theoretical_combinations": theoretical,
            "enumerated_combinations": enumerated,
            "checksum_valid_candidates": checksum_valid,
            "derived_candidates": derived,
            "target_hits": len(target_hits),
            "author_example_candidates": author_examples,
            "complete": complete,
            "seconds": round(time.monotonic() - started, 3),
        },
        "plan_loads": [
            {
                "shard": shard,
                "theoretical_combinations": sum(item.combinations for item in plan if item.shard == shard),
                "starts": sum(1 for item in plan if item.shard == shard and item.combinations > 0),
            }
            for shard in range(shard_count)
        ],
        "start_stats": start_stats,
        "candidate_sample": samples,
        "target_hits": target_hits,
    }


def aggregate_reports(paths: Sequence[Path]) -> dict:
    reports = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    if not reports:
        raise ValueError("no shard reports supplied")
    shard_count = reports[0]["summary"]["shard_count"]
    seen = sorted(report["summary"]["shard_index"] for report in reports)
    expected = list(range(shard_count))
    complete_set = seen == expected
    summaries = [report["summary"] for report in reports]
    return {
        "summary": {
            "shard_count": shard_count,
            "shards_present": seen,
            "all_shards_present": complete_set,
            "theoretical_combinations": sum(item["theoretical_combinations"] for item in summaries),
            "enumerated_combinations": sum(item["enumerated_combinations"] for item in summaries),
            "checksum_valid_candidates": sum(item["checksum_valid_candidates"] for item in summaries),
            "derived_candidates": sum(item["derived_candidates"] for item in summaries),
            "target_hits": sum(item["target_hits"] for item in summaries),
            "author_example_candidates": sum(item["author_example_candidates"] for item in summaries),
            "complete": complete_set and all(item["complete"] for item in summaries),
            "max_shard_seconds": max(item["seconds"] for item in summaries),
            "total_shard_seconds": round(sum(item["seconds"] for item in summaries), 3),
            "paths": reports[0]["summary"]["paths"],
            "target": reports[0]["summary"]["target"],
        },
        "shards": summaries,
        "target_hits": [hit for report in reports for hit in report.get("target_hits", [])],
        "candidate_sample": [sample for report in reports for sample in report.get("candidate_sample", [])][:200],
    }


def _load_inputs(article: Path, wordlist_path: Path) -> tuple[str, list[str]]:
    if not article.exists() or not wordlist_path.exists():
        raise SystemExit("Puzzle data is missing. Run `python solver.py fetch` first.")
    return article.read_text(encoding="utf-8"), solver.load_wordlist(wordlist_path)


def command_verify(args: argparse.Namespace) -> int:
    # Cross-check the fast backend against the existing standard-library solver
    # on the author's known, checksum-valid worked example.
    _, wordlist = _load_inputs(args.article, args.wordlist)
    words = tuple(solver.AUTHOR_GPS_WORDS)
    if not solver.validate_mnemonic(words, wordlist):
        print("author mnemonic checksum failed")
        return 1
    fast_seed = _mnemonic_seed(words)
    slow_seed = solver.mnemonic_to_seed(words)
    ok = fast_seed == slow_seed
    rows = []
    for path in args.path or list(DEFAULT_PATHS):
        fast_private = _derive_private(fast_seed, path)
        slow_private = solver.derive_private(slow_seed, path)
        row = {
            "path": path,
            "private_key_match": fast_private == slow_private,
            "compressed_address": solver.base58check(b"\x00" + solver.hash160(_public_key(fast_private, True))),
            "uncompressed_address": solver.base58check(b"\x00" + solver.hash160(_public_key(fast_private, False))),
        }
        ok = ok and row["private_key_match"]
        rows.append(row)
    print(json.dumps({"pass": ok, "rows": rows}, indent=2))
    return 0 if ok else 1


def command_scan(args: argparse.Namespace) -> int:
    text, wordlist = _load_inputs(args.article, args.wordlist)
    workers = args.workers or max(1, min(4, os.cpu_count() or 1))
    report = scan_shard(
        text=text,
        wordlist=wordlist,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
        paths=args.path or list(DEFAULT_PATHS),
        target=args.target,
        workers=workers,
        batch_size=args.batch_size,
        sample_limit=args.sample_limit,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    if report["target_hits"]:
        print("TARGET HIT")
        print(json.dumps(report["target_hits"], ensure_ascii=False, indent=2))
    print(f"report={args.report}")
    return 0 if report["summary"]["complete"] else 2


def command_aggregate(args: argparse.Namespace) -> int:
    report = aggregate_reports(args.reports)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    if report["target_hits"]:
        print("TARGET HIT")
        print(json.dumps(report["target_hits"], ensure_ascii=False, indent=2))
    elif report["summary"]["complete"]:
        print("target: not found; exhaustive reverse-GPS scan complete for tested paths")
    else:
        print("target: not found, but aggregate is incomplete")
    print(f"report={args.output}")
    return 0 if report["summary"]["complete"] else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="cross-check the fast crypto backend")
    verify.add_argument("--article", type=Path, default=Path("data/article.txt"))
    verify.add_argument("--wordlist", type=Path, default=Path("data/english.txt"))
    verify.add_argument("--path", action="append")
    verify.set_defaults(func=command_verify)

    scan = sub.add_parser("scan", help="scan one deterministic exhaustive shard")
    scan.add_argument("--article", type=Path, default=Path("data/article.txt"))
    scan.add_argument("--wordlist", type=Path, default=Path("data/english.txt"))
    scan.add_argument("--path", action="append")
    scan.add_argument("--target", default=solver.TARGET_ADDRESS)
    scan.add_argument("--shard-index", type=int, required=True)
    scan.add_argument("--shard-count", type=int, default=8)
    scan.add_argument("--workers", type=int)
    scan.add_argument("--batch-size", type=int, default=2048)
    scan.add_argument("--sample-limit", type=int, default=25)
    scan.add_argument("--report", type=Path, required=True)
    scan.set_defaults(func=command_scan)

    aggregate = sub.add_parser("aggregate", help="merge all shard reports")
    aggregate.add_argument("reports", nargs="+", type=Path)
    aggregate.add_argument("--output", type=Path, default=Path("data/reverse-gps-exhaustive-report.json"))
    aggregate.set_defaults(func=command_aggregate)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
