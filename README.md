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

The project then checks candidate 12-word mnemonics against the prize address using BIP-39, BIP-32, secp256k1 and compressed/uncompressed legacy P2PKH derivation. The crypto path is implemented with the Python standard library only.

## Structural attacks

`attack_surface.py` generates and tests hypotheses rather than guessing seed phrases manually. It currently:

- extracts every literal number/date/coordinate-like fragment from the article;
- combines adjacent numeric fragments when they naturally form a 12-digit selector;
- automatically recovers the author's `38.8906 + 77.0044 -> 388906770044` worked selector;
- tests selectors with indexing restarted at the whole-article, paragraph, and sentence level;
- records every checksum-valid BIP-39 candidate;
- searches first-through-fifth-letter null-cipher streams, forward and reversed, for instruction words such as `seed`, `gps`, `phone`, `third`, `twelve`, `latitude`, `longitude`, `position`, and `wallet`;
- records paragraph/sentence initial and final-letter streams;
- writes a machine-readable JSON report.

`hypotheses.json` remains available for manually supplied geographic selectors.

## Requirements

For a local run after this PR is merged:

- **Python 3.11+**; CI uses Python 3.12.
- No `pip install` and no `requirements.txt` are required.
- Internet access is needed only for `python solver.py fetch`, which downloads the public article mirror and official BIP-39 English wordlist.
- After `data/article.txt` and `data/english.txt` exist, the analysis can run offline.
- Python/OpenSSL must expose RIPEMD-160. This is normally available on Ubuntu.

Quick RIPEMD-160 check:

```bash
python3 -c "import hashlib; print('ripemd160' in hashlib.algorithms_available)"
```

Expected output: `True`.

## First local run

```bash
git clone https://github.com/Kolyn236/wealth-in-poetry_test.git
cd wealth-in-poetry_test

python3 --version
python3 solver.py fetch
python3 -m unittest discover -s tests -v
python3 solver.py verify
python3 solver.py scan --mode all
python3 attack_surface.py all
```

The last command writes `data/attack-report.json`. The `data/` directory is intentionally ignored by Git.

### Useful focused commands

Show number-derived selectors:

```bash
python3 attack_surface.py numbers
```

Search null-cipher streams:

```bash
python3 attack_surface.py null
```

Run only structural selector scans:

```bash
python3 attack_surface.py scan
```

Test another GPS/number hypothesis directly:

```bash
python3 solver.py scan --mode gps --selector 388906770044
```

Test additional derivation paths:

```bash
python3 solver.py scan \
  --path "m/44'/0'/0'/0/0" \
  --path "m/44'/0'/0'/0/1"
```

The structural scanner accepts the same path override:

```bash
python3 attack_surface.py all \
  --path "m/44'/0'/0'/0/0" \
  --path "m/44'/0'/0'/0/1"
```

## GitHub Actions

`.github/workflows/scan.yml` runs on pushes to the solver branch, pull requests to `main`, and manual `workflow_dispatch`.

It runs tests, fetches puzzle data, verifies the worked GPS example, runs both search layers, and uploads `data/attack-report.json` as the `attack-report` workflow artifact.

If Actions are disabled for the repository, enable them in **Settings → Actions → General** before relying on CI. Local execution does not depend on GitHub Actions.

## Data provenance

`python solver.py fetch` downloads:

- the BIP-39 English wordlist from the Bitcoin BIPs repository;
- the article text mirror from `HomelessPhD/Wealth_in_Poetry`.

We do not commit downloaded puzzle data into this repository.

## Search strategy

The main working hypothesis is that the article may hide either the seed words themselves through positional indexing, or an instruction/selector that tells us how to recover those words.

The code keeps those stages separate. Every hypothesis should be reproducible and falsifiable: produce positions, produce 12 words, pass BIP-39 checksum, derive addresses, then compare with the known prize address.
