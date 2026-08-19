# Wealth in Poetry solver

Research code for the public Trithemius **“Securing Wealth in Poetry”** Bitcoin puzzle.

Target legacy P2PKH address:

```text
1K4ezpLybootYF23TM4a8Y4NyP7auysnRo
```

## What the solver verifies

The article gives a worked GPS-position example. The digits:

```text
388906770044
```

become 1-based positions:

```text
3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114
```

and select:

```text
asset trial load escape symbol story bomb picnic river aerobic mystery honey
```

`python solver.py verify` reproduces that example exactly and validates its BIP-39 checksum.

The project then checks candidate 12-word mnemonics against the prize address using BIP-39, BIP-32, secp256k1 and compressed/uncompressed legacy P2PKH derivation. The baseline crypto path in `solver.py` is implemented with the Python standard library only.

## Structural attacks

`attack_surface.py` generates and tests hypotheses rather than guessing seed phrases manually. It currently:

- extracts every literal number/date/coordinate-like fragment from the article;
- combines adjacent numeric fragments when they naturally form a 12-digit selector;
- automatically recovers the author's `38.8906 + 77.0044 -> 388906770044` worked selector;
- tests selectors with indexing restarted at the whole-article, paragraph, and sentence level;
- records every checksum-valid BIP-39 candidate;
- searches first-through-fifth-letter null-cipher streams, forward and reversed, for instruction words;
- records paragraph/sentence initial and final-letter streams;
- writes a machine-readable JSON report.

`hypotheses.json` remains available for manually supplied geographic selectors.

## Reverse-GPS attack

`reverse_gps.py` inverts the author's GPS method instead of guessing a landmark first.

For each structural starting point, it divides the next 119 word positions into the exact ranges implied by the author's rule:

```text
1..9
10..19
20..29
...
110..119
```

Every BIP-39 word found in a range is a possible selected word. Its position determines one selector digit. Choosing one candidate from each of the 12 ranges therefore produces both:

```text
12 BIP-39 words
+
12 selector digits
```

The scanner applies the BIP-39 checksum before wallet derivation. It includes article, paragraph, sentence, and literal `Example:` starts. `python reverse_gps.py verify` independently reconstructs the author's `388906770044` selector and `asset ... honey` seed.

### Why sharding exists

The first reverse run found **66,694,260** theoretical combinations at the structural starts, concentrated heavily around the author's Trithemian-seed examples. A single bounded CI job deliberately did not claim an exhaustive negative.

`reverse_gps.py` now supports deterministic combination sharding:

```bash
python reverse_gps.py scan --shard-index 0 --shard-count 16
```

The Cartesian product is partitioned by prefixes, so shards do not overlap and a shard does not have to iterate through other shards' suffixes. `assigned_combinations` in every report shows the exact amount of work assigned to that shard.

High-volume wallet derivation can use `coincurve`/libsecp256k1:

```bash
python3 -m pip install coincurve
python reverse_gps.py scan --backend coincurve
```

The ordinary baseline solver remains dependency-free.

## GitHub Actions: normal scan

`.github/workflows/scan.yml` runs on pushes to `main`, pushes to the solver branch, pull requests to `main`, and manual `workflow_dispatch`.

It runs:

```text
unit tests
→ fetch article + official BIP-39 wordlist
→ verify forward GPS example
→ baseline hypotheses
→ structural/null-cipher attack
→ verify reverse GPS
→ bounded reverse GPS attack
```

Artifacts:

```text
attack-report
reverse-gps-report
```

The bounded reverse report explicitly contains `enumeration_complete` and `target_scan_complete`. `false` means the result is exploratory, not a proof that the target is absent.

## GitHub Actions: exhaustive reverse-GPS scan

A separate workflow keeps the expensive search away from every commit:

```text
.github/workflows/reverse-exhaustive.yml
```

Run it manually from **Actions → reverse-gps-exhaustive → Run workflow**.

It launches **16 independent shards**. Each shard:

- gets a disjoint part of every structural start's Cartesian product;
- installs `coincurve` for fast secp256k1 public-key operations;
- enumerates its assigned combinations;
- checks BIP-39 checksum;
- derives surviving candidates against the prize address;
- uploads `reverse-gps-shard-N`.

After all shard jobs finish, an aggregate job downloads the shard JSON files and creates:

```text
reverse-gps-exhaustive
└── reverse-gps-exhaustive.json
```

The aggregate is considered exhaustive only when all 16 shards are present and every shard reports both `enumeration_complete=true` and `target_scan_complete=true`.

This workflow is manual because a full run consumes substantially more GitHub Actions minutes than the normal PR scan.

## Requirements

Local execution is optional; normal research iterations can be run entirely through GitHub Actions.

Baseline/structural requirements:

- **Python 3.11+**; CI uses Python 3.12.
- No third-party packages for `solver.py` and `attack_surface.py`.
- Internet access only for `python solver.py fetch`.
- Python/OpenSSL with RIPEMD-160 (normally present on Ubuntu).

For fast reverse-GPS address derivation:

```bash
python3 -m pip install coincurve
```

Quick RIPEMD-160 check:

```bash
python3 -c "import hashlib; print('ripemd160' in hashlib.algorithms_available)"
```

Expected output: `True`.

## First local run

```bash
git clone https://github.com/Kolyn236/wealth-in-poetry_test.git
cd wealth-in-poetry_test

python3 solver.py fetch
python3 -m unittest discover -s tests -v
python3 solver.py verify
python3 solver.py scan --mode all
python3 attack_surface.py all
python3 reverse_gps.py verify

python3 -m pip install coincurve
python3 reverse_gps.py scan --backend coincurve
```

Generated files:

```text
data/attack-report.json
data/reverse-gps-report.json
```

The `data/` directory is intentionally ignored by Git.

### Useful focused commands

Show number-derived selectors:

```bash
python3 attack_surface.py numbers
```

Search null-cipher streams:

```bash
python3 attack_surface.py null
```

Measure reverse-GPS candidate space without deriving addresses:

```bash
python3 reverse_gps.py scan --derive-limit 0
```

Run one of 16 shards locally:

```bash
python3 reverse_gps.py scan \
  --shard-index 7 \
  --shard-count 16 \
  --backend coincurve \
  --derive-limit 1000000
```

Test additional derivation paths:

```bash
python3 solver.py scan \
  --path "m/44'/0'/0'/0/0" \
  --path "m/44'/0'/0'/0/1"
```

The structural and reverse scanners accept path overrides.

## Data provenance

`python solver.py fetch` downloads:

- the BIP-39 English wordlist from the Bitcoin BIPs repository;
- the article text mirror from `HomelessPhD/Wealth_in_Poetry`.

Downloaded puzzle data and generated reports are not committed.

## Search strategy

The working model is split into independently testable layers:

1. **Forward positional search** — obtain a selector, then select words.
2. **Structural/null-cipher search** — look for an instruction or selector hidden in article structure.
3. **Reverse positional search** — infer selector digits from BIP-39 word positions.

Every candidate follows the same funnel:

```text
positions -> 12 words -> BIP-39 checksum -> BIP-32 -> P2PKH -> target address
```

The reports distinguish exhaustive scans from bounded exploratory scans so a resource limit cannot silently become a false negative.
