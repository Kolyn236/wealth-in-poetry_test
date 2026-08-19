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

The scanner applies the BIP-39 checksum before doing expensive wallet derivation. It starts at article, paragraph, and sentence boundaries and reports the size of any search space skipped because it exceeds the configured per-start combination ceiling.

`python reverse_gps.py verify` independently reconstructs the author's `388906770044` selector and `asset ... honey` seed from the worked example.

The default GitHub Actions pass derives at most 5,000 checksum-valid reverse candidates. The JSON report explicitly says whether enumeration and target-address derivation were exhaustive; a partial run must not be interpreted as “the target is impossible.”

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

Local execution is optional because the same commands run in GitHub Actions.

```bash
git clone https://github.com/Kolyn236/wealth-in-poetry_test.git
cd wealth-in-poetry_test

python3 --version
python3 solver.py fetch
python3 -m unittest discover -s tests -v
python3 solver.py verify
python3 solver.py scan --mode all
python3 attack_surface.py all
python3 reverse_gps.py verify
python3 reverse_gps.py scan
```

The generated files are:

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

Run only structural selector scans:

```bash
python3 attack_surface.py scan
```

Measure the reverse-GPS candidate space without deriving addresses:

```bash
python3 reverse_gps.py scan --derive-limit 0
```

Increase the number of checksum-valid reverse candidates whose Bitcoin addresses are derived:

```bash
python3 reverse_gps.py scan --derive-limit 20000
```

Raise the per-start combination ceiling explicitly:

```bash
python3 reverse_gps.py scan --max-combinations-per-start 10000000
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

The structural and reverse scanners accept the same path override.

## GitHub Actions

`.github/workflows/scan.yml` runs on:

- pushes to `main`;
- pushes to `agent/wealth-poetry-solver` while this PR is open;
- pull requests to `main`;
- manual `workflow_dispatch`.

It runs tests, fetches puzzle data, verifies both forward and reverse versions of the worked GPS example, runs all current search layers, and uploads two artifacts:

```text
attack-report
reverse-gps-report
```

Open a successful workflow run and scroll to **Artifacts** to download the reports. This means a local environment is not required for normal puzzle iterations.

If Actions are disabled for the repository, enable them in **Settings → Actions → General** before relying on CI. Local execution does not depend on GitHub Actions.

## Data provenance

`python solver.py fetch` downloads:

- the BIP-39 English wordlist from the Bitcoin BIPs repository;
- the article text mirror from `HomelessPhD/Wealth_in_Poetry`.

We do not commit downloaded puzzle data into this repository.

## Search strategy

The working model is now split into three independently testable layers:

1. **Forward positional search** — guess or extract a selector, then select words.
2. **Structural/null-cipher search** — look for an instruction or selector hidden in article structure.
3. **Reverse positional search** — infer selector digits from where BIP-39 words already occur.

Every candidate should pass the same funnel:

```text
positions -> 12 words -> BIP-39 checksum -> BIP-32 -> P2PKH -> target address
```

The reports distinguish exhaustive scans from bounded exploratory scans so a resource limit cannot silently become a false negative.
