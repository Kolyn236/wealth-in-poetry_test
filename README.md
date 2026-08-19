# Wealth in Poetry solver

Research code for the public Trithemius **“Securing Wealth in Poetry”** Bitcoin puzzle.

Target P2PKH address:

```text
1K4ezpLybootYF23TM4a8Y4NyP7auysnRo
```

## What this PR tests

The article itself gives us an unusually strong specification for one hiding method. For the worked U.S. Supreme Court example, GPS digits `388906770044` become positions:

```text
3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114
```

Those positions select:

```text
asset trial load escape symbol story bomb picnic river aerobic mystery honey
```

`solver.py verify` reproduces this exactly. That test matters because punctuation/tokenization errors shift every later word position.

The first search pass covers:

- the already-known contiguous BIP-39-word baseline;
- GPS/phone-like 12-digit selectors at every possible start offset in the article;
- several geographic hypotheses mentioned by or adjacent to the article;
- null-cipher streams (first through fifth letters of words);
- BIP-39 checksum validation;
- BIP-39 seed generation, BIP-32 private derivation and compressed/uncompressed legacy P2PKH generation using only Python's standard library.

## Run

```bash
python solver.py fetch
python -m unittest discover -s tests -v
python solver.py verify
python solver.py scan --mode all
python solver.py null
```

To test another GPS/number hypothesis without changing code:

```bash
python solver.py scan --mode gps --selector 388906770044
```

To test additional derivation paths:

```bash
python solver.py scan \
  --path "m/44'/0'/0'/0/0" \
  --path "m/44'/0'/0'/0/1"
```

## Data provenance

`solver.py fetch` downloads data at runtime rather than committing copies:

- BIP-39 English wordlist from the Bitcoin BIPs repository;
- article text mirror from `HomelessPhD/Wealth_in_Poetry`.

The downloaded files live under `data/` and are ignored by Git.

## Next hypotheses

The current solver is deliberately modular. Useful next attacks are:

1. derive selectors from every number/date in the article instead of hand-entering coordinates;
2. search paragraph/sentence-local word indexing rather than only whole-article offsets;
3. interpret null-cipher output as an instruction or number selector rather than as seed words directly;
4. enumerate plausible coordinate formatting/precision variants for geographic entities in the story;
5. extend wallet derivation candidates if the 12 words are found but BIP-44 path `m/44'/0'/0'/0/0` is not the prize address.

The goal is to keep each hypothesis deterministic and testable so we can rule out large classes of ideas instead of guessing seed phrases manually.
