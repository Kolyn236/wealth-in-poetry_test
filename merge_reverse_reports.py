#!/usr/bin/env python3
"""Merge reverse-GPS shard reports into one exhaustive-search report."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def merge_reports(paths: list[Path]) -> dict:
    if not paths:
        raise ValueError("no shard reports found")

    reports = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    summaries = [report["summary"] for report in reports]
    shard_counts = {item["shard_count"] for item in summaries}
    if len(shard_counts) != 1:
        raise ValueError(f"inconsistent shard counts: {sorted(shard_counts)}")
    shard_count = shard_counts.pop()
    by_index = {item["shard_index"]: report for item, report in zip(summaries, reports)}
    expected_indices = set(range(shard_count))
    found_indices = set(by_index)

    theoretical_values = {item["theoretical_combinations"] for item in summaries}
    if len(theoretical_values) != 1:
        raise ValueError("shards disagree on theoretical combination space")
    theoretical = theoretical_values.pop()

    target_hits = []
    for report in reports:
        target_hits.extend(report.get("target_hits", []))

    all_shards_present = found_indices == expected_indices
    enumeration_complete = all_shards_present and all(
        item["summary"]["enumeration_complete"] for item in reports
    )
    target_scan_complete = all_shards_present and all(
        item["summary"]["target_scan_complete"] for item in reports
    )

    summary = {
        "shards_expected": shard_count,
        "shards_found": len(found_indices),
        "missing_shards": sorted(expected_indices - found_indices),
        "theoretical_combinations": theoretical,
        "assigned_combinations": sum(item["assigned_combinations"] for item in summaries),
        "enumerated_combinations": sum(item["enumerated_combinations"] for item in summaries),
        "checksum_valid_candidates": sum(item["checksum_valid_candidates"] for item in summaries),
        "derived_candidates": sum(item["derived_candidates"] for item in summaries),
        "author_example_candidates": sum(item["author_example_candidates"] for item in summaries),
        "target_hits": len(target_hits),
        "enumeration_complete": enumeration_complete,
        "target_scan_complete": target_scan_complete,
        "backend": sorted({item["backend"] for item in summaries}),
    }
    return {
        "summary": summary,
        "shards": [by_index[index]["summary"] for index in sorted(by_index)],
        "target_hits": target_hits,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("data/reverse-gps-exhaustive.json"))
    args = parser.parse_args()

    paths = sorted(args.input_dir.rglob("reverse-gps-shard-*.json"))
    report = merge_reports(paths)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    if report["target_hits"]:
        print("TARGET HIT IN EXHAUSTIVE REVERSE-GPS SEARCH")
    elif report["summary"]["target_scan_complete"]:
        print("target: not found; exhaustive reverse-GPS scan completed")
    else:
        print("target: not found; aggregate scan is incomplete")
    print(f"report={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
