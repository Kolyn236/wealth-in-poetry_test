#!/usr/bin/env python3
"""Structural search helpers for the public Trithemius "Wealth in Poetry" puzzle.

This module deliberately keeps hypothesis generation separate from solver.py.
It extracts number-derived selectors, scans article/paragraph/sentence-local
indexing, and looks for instructions in null-cipher streams.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

import solver

NUMBER_RE = re.compile(r"(?<![A-Za-z0-9])\d+(?:[.,]\d+)*(?![A-Za-z0-9])")
PARAGRAPH_RE = re.compile(r"\n\s*\n+")
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")

DEFAULT_KEYWORDS = (
    "seed", "seeds", "gps", "phone", "third", "three", "twelve",
    "word", "words", "latitude", "longitude", "location", "number",
    "numbers", "position", "positions", "wallet", "bitcoin", "first",
    "second", "letter",
)


@dataclass(frozen=True)
class NumericFragment:
    raw: str
    digits: str
    start: int
    end: int
    context: str


@dataclass(frozen=True)
class SelectorCandidate:
    selector: str
    source: str
    fragments: tuple[str, ...]


@dataclass(frozen=True)
class TextUnit:
    kind: str
    index: int
    text: str
    tokens: tuple[str, ...]


def split_paragraphs(text: str) -> list[str]:
    return [part.strip() for part in PARAGRAPH_RE.split(text) if part.strip()]


def split_sentences(text: str) -> list[str]:
    sentences: list[str] = []
    for paragraph in split_paragraphs(text):
        sentences.extend(part.strip() for part in SENTENCE_RE.split(paragraph) if part.strip())
    return sentences


def iter_units(text: str, kinds: Sequence[str] = ("article", "paragraph", "sentence")) -> Iterator[TextUnit]:
    if "article" in kinds:
        tokens = tuple(solver.tokenize(text))
        yield TextUnit("article", 1, text, tokens)
    if "paragraph" in kinds:
        for index, paragraph in enumerate(split_paragraphs(text), start=1):
            tokens = tuple(solver.tokenize(paragraph))
            if tokens:
                yield TextUnit("paragraph", index, paragraph, tokens)
    if "sentence" in kinds:
        for index, sentence in enumerate(split_sentences(text), start=1):
            tokens = tuple(solver.tokenize(sentence))
            if tokens:
                yield TextUnit("sentence", index, sentence, tokens)


def extract_numeric_fragments(text: str, context_radius: int = 42) -> list[NumericFragment]:
    fragments: list[NumericFragment] = []
    for match in NUMBER_RE.finditer(text):
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if not digits:
            continue
        left = max(0, match.start() - context_radius)
        right = min(len(text), match.end() + context_radius)
        context = re.sub(r"\s+", " ", text[left:right]).strip()
        fragments.append(NumericFragment(raw, digits, match.start(), match.end(), context))
    return fragments


def numeric_selector_candidates(fragments: Sequence[NumericFragment], width: int = 12, max_group: int = 8) -> list[SelectorCandidate]:
    """Build selectors only from literal digits; no padding or arithmetic guessing."""
    candidates: dict[tuple[str, tuple[str, ...]], SelectorCandidate] = {}
    for fragment in fragments:
        if len(fragment.digits) == width:
            item = SelectorCandidate(fragment.digits, "single-number", (fragment.raw,))
            candidates[(item.selector, item.fragments)] = item
        elif len(fragment.digits) > width:
            for offset in range(len(fragment.digits) - width + 1):
                selector = fragment.digits[offset:offset + width]
                item = SelectorCandidate(selector, f"substring@{offset}", (fragment.raw,))
                candidates[(item.selector, item.fragments)] = item
    for start in range(len(fragments)):
        digits = ""
        raws: list[str] = []
        for stop in range(start, min(len(fragments), start + max_group)):
            digits += fragments[stop].digits
            raws.append(fragments[stop].raw)
            if len(digits) == width:
                item = SelectorCandidate(digits, "adjacent-numbers", tuple(raws))
                candidates[(item.selector, item.fragments)] = item
                break
            if len(digits) > width:
                break
    return sorted(candidates.values(), key=lambda item: (item.selector, item.source, item.fragments))


def load_hypothesis_selectors(path: Path | None) -> list[SelectorCandidate]:
    if path is None or not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    result: list[SelectorCandidate] = []
    for item in payload:
        if isinstance(item, str):
            digits, label = re.sub(r"\D", "", item), item
        elif isinstance(item, dict) and "selector" in item:
            digits = re.sub(r"\D", "", str(item["selector"]))
            label = str(item.get("label", item["selector"]))
        else:
            continue
        if len(digits) == 12:
            result.append(SelectorCandidate(digits, "hypothesis", (label,)))
    return result


def dedupe_selectors(items: Iterable[SelectorCandidate]) -> list[SelectorCandidate]:
    by_selector: dict[str, SelectorCandidate] = {}
    for item in items:
        if item.selector not in by_selector or item.source == "hypothesis":
            by_selector[item.selector] = item
    return sorted(by_selector.values(), key=lambda item: item.selector)


def _addresses(words: Sequence[str], paths: Sequence[str], target: str) -> list[dict]:
    result: list[dict] = []
    for path, compressed, address in solver.addresses_for_mnemonic(words, paths):
        result.append({"path": path, "compressed": compressed, "address": address, "target": address == target})
    return result


def scan_selector_candidates(units: Iterable[TextUnit], wordlist: Sequence[str], selectors: Sequence[SelectorCandidate], paths: Sequence[str], target: str = solver.TARGET_ADDRESS) -> list[dict]:
    results: list[dict] = []
    for unit in units:
        for candidate in selectors:
            positions = solver.gps_positions(candidate.selector)
            if not positions or min(positions) <= 0:
                continue
            max_position = max(positions)
            if max_position > len(unit.tokens):
                continue
            for start in range(0, len(unit.tokens) - max_position + 1):
                words = solver.select_by_positions(unit.tokens, positions, start)
                if words is None or not solver.validate_mnemonic(words, wordlist):
                    continue
                addresses = _addresses(words, paths, target)
                results.append({
                    "kind": unit.kind,
                    "unit": unit.index,
                    "start_word": start + 1,
                    "selector": candidate.selector,
                    "selector_source": candidate.source,
                    "selector_fragments": list(candidate.fragments),
                    "positions": positions,
                    "words": words,
                    "known_author_example": words == solver.AUTHOR_GPS_WORDS,
                    "addresses": addresses,
                    "target_hit": any(item["target"] for item in addresses),
                })
    return results


def _find_keyword_hits(stream: str, keywords: Sequence[str]) -> list[dict]:
    hits: list[dict] = []
    lower = stream.lower()
    for keyword in keywords:
        key = keyword.lower()
        offset = 0
        while True:
            position = lower.find(key, offset)
            if position < 0:
                break
            hits.append({"keyword": key, "offset": position})
            offset = position + 1
    return hits


def scan_null_keywords(units: Iterable[TextUnit], keywords: Sequence[str] = DEFAULT_KEYWORDS, char_indices: Sequence[int] = (0, 1, 2, 3, 4)) -> list[dict]:
    results: list[dict] = []
    for unit in units:
        for char_index in char_indices:
            stream = solver.null_cipher_stream(unit.tokens, char_index)
            if not stream:
                continue
            for direction, value in (("forward", stream), ("reverse", stream[::-1])):
                hits = _find_keyword_hits(value, keywords)
                if hits:
                    results.append({"kind": unit.kind, "unit": unit.index, "letter": char_index + 1, "direction": direction, "stream_length": len(value), "hits": hits, "sample": value[:240]})
    return results


def boundary_streams(text: str) -> dict[str, str]:
    paragraphs = [solver.tokenize(item) for item in split_paragraphs(text)]
    sentences = [solver.tokenize(item) for item in split_sentences(text)]
    def first_letters(groups: Sequence[Sequence[str]]) -> str:
        return "".join(group[0][0].lower() for group in groups if group and group[0])
    def last_letters(groups: Sequence[Sequence[str]]) -> str:
        return "".join(group[-1][-1].lower() for group in groups if group and group[-1])
    return {"paragraph_first": first_letters(paragraphs), "paragraph_last": last_letters(paragraphs), "sentence_first": first_letters(sentences), "sentence_last": last_letters(sentences)}


def build_report(article_text: str, wordlist: Sequence[str], hypotheses: Path | None, paths: Sequence[str], keywords: Sequence[str], target: str = solver.TARGET_ADDRESS) -> dict:
    fragments = extract_numeric_fragments(article_text)
    selectors = dedupe_selectors([*numeric_selector_candidates(fragments), *load_hypothesis_selectors(hypotheses)])
    units = list(iter_units(article_text))
    candidates = scan_selector_candidates(units, wordlist, selectors, paths, target=target)
    null_hits = scan_null_keywords(units, keywords=keywords)
    return {
        "summary": {
            "tokens": len(solver.tokenize(article_text)),
            "paragraphs": len(split_paragraphs(article_text)),
            "sentences": len(split_sentences(article_text)),
            "numeric_fragments": len(fragments),
            "selectors": len(selectors),
            "checksum_valid_candidates": len(candidates),
            "target_hits": sum(1 for item in candidates if item["target_hit"]),
            "null_keyword_units": len(null_hits),
        },
        "numeric_fragments": [asdict(item) for item in fragments],
        "selectors": [asdict(item) for item in selectors],
        "candidates": candidates,
        "null_keyword_hits": null_hits,
        "boundary_streams": boundary_streams(article_text),
    }


def load_inputs(article: Path, wordlist_path: Path) -> tuple[str, list[str]]:
    if not article.exists() or not wordlist_path.exists():
        raise SystemExit("Puzzle data is missing. Run `python solver.py fetch` first.")
    return article.read_text(encoding="utf-8"), solver.load_wordlist(wordlist_path)


def command_numbers(args: argparse.Namespace) -> int:
    if not args.article.exists():
        raise SystemExit("Puzzle data is missing. Run `python solver.py fetch` first.")
    text = args.article.read_text(encoding="utf-8")
    fragments = extract_numeric_fragments(text)
    selectors = dedupe_selectors([*numeric_selector_candidates(fragments), *load_hypothesis_selectors(args.hypotheses)])
    print(f"numeric-fragments={len(fragments)} selectors={len(selectors)}")
    for item in selectors:
        print(json.dumps(asdict(item), ensure_ascii=False))
    return 0


def command_null(args: argparse.Namespace) -> int:
    if not args.article.exists():
        raise SystemExit("Puzzle data is missing. Run `python solver.py fetch` first.")
    text = args.article.read_text(encoding="utf-8")
    hits = scan_null_keywords(list(iter_units(text)), keywords=args.keyword or DEFAULT_KEYWORDS, char_indices=tuple(range(args.from_letter - 1, args.to_letter)))
    print(f"null-hit-units={len(hits)}")
    for item in hits:
        print(json.dumps(item, ensure_ascii=False))
    print(json.dumps({"boundary_streams": boundary_streams(text)}, ensure_ascii=False))
    return 0


def command_scan(args: argparse.Namespace) -> int:
    text, wordlist = load_inputs(args.article, args.wordlist)
    fragments = extract_numeric_fragments(text)
    selectors = dedupe_selectors([*numeric_selector_candidates(fragments), *load_hypothesis_selectors(args.hypotheses)])
    candidates = scan_selector_candidates(list(iter_units(text)), wordlist, selectors, args.path or ["m/44'/0'/0'/0/0"], target=args.target)
    print(f"selectors={len(selectors)} checksum-valid-candidates={len(candidates)}")
    for item in candidates:
        print(json.dumps(item, ensure_ascii=False))
    print(f"TARGET-HITS={sum(1 for item in candidates if item['target_hit'])}")
    return 0


def command_all(args: argparse.Namespace) -> int:
    text, wordlist = load_inputs(args.article, args.wordlist)
    report = build_report(text, wordlist, args.hypotheses, args.path or ["m/44'/0'/0'/0/0"], args.keyword or DEFAULT_KEYWORDS, target=args.target)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    known = [item for item in report["candidates"] if item["known_author_example"]]
    if known:
        print(f"known-author-example-candidates={len(known)}")
    hits = [item for item in report["candidates"] if item["target_hit"]]
    if hits:
        print("TARGET HIT")
        for item in hits:
            print(json.dumps(item, ensure_ascii=False))
    else:
        print("target: not found in current structural search")
    print(f"report={args.report}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    numbers = sub.add_parser("numbers", help="extract literal number-derived selectors")
    numbers.add_argument("--article", type=Path, default=Path("data/article.txt"))
    numbers.add_argument("--hypotheses", type=Path, default=Path("hypotheses.json"))
    numbers.set_defaults(func=command_numbers)
    null = sub.add_parser("null", help="search null-cipher streams for instruction words")
    null.add_argument("--article", type=Path, default=Path("data/article.txt"))
    null.add_argument("--keyword", action="append")
    null.add_argument("--from-letter", type=int, default=1)
    null.add_argument("--to-letter", type=int, default=5)
    null.set_defaults(func=command_null)
    for name, help_text in (("scan", "scan article/paragraph/sentence-local selector indexing"), ("all", "run structural scans and save a JSON report")):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--article", type=Path, default=Path("data/article.txt"))
        command.add_argument("--wordlist", type=Path, default=Path("data/english.txt"))
        command.add_argument("--hypotheses", type=Path, default=Path("hypotheses.json"))
        command.add_argument("--path", action="append")
        command.add_argument("--target", default=solver.TARGET_ADDRESS)
        if name == "all":
            command.add_argument("--keyword", action="append")
            command.add_argument("--report", type=Path, default=Path("data/attack-report.json"))
            command.set_defaults(func=command_all)
        else:
            command.set_defaults(func=command_scan)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "from_letter", 1) < 1:
        parser.error("--from-letter must be >= 1")
    if getattr(args, "to_letter", 1) < getattr(args, "from_letter", 1):
        parser.error("--to-letter must be >= --from-letter")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
