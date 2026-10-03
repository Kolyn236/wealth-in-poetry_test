# Wealth in Poetry solver

Research tooling for the public **Trithemius / “Securing Wealth in Poetry”** Bitcoin puzzle.

Published target address:

```text
1K4ezpLybootYF23TM4a8Y4NyP7auysnRo
```

The goal is not generic wallet brute force. The solver searches the steganographic constructions explicitly described in the article and uses the BIP-39 checksum plus the published address as validation oracles.

## What is implemented

- deterministic article tokenization
- BIP-39 checksum validation
- BIP-39 seed generation
- BIP-32 private derivation
- BIP-44 `m/44'/0'/0'/0/0`
- compressed and uncompressed legacy P2PKH address generation
- baseline scan of consecutive BIP-39 words
- the article's GPS / `+10 per digit` positional scheme
- reverse conversion from positions back to coordinate digits
- nth-letter null-cipher extraction
- numeric-clue extraction

The crypto path is implemented with the Python standard library only, including secp256k1 arithmetic. No private-key or wallet service is contacted.

## Run

```bash
python fetch_sources.py
python -m unittest -v
python solver.py baseline
python solver.py gps --max-combinations 1000
python solver.py null --letter 3
python solver.py numbers
```

`fetch_sources.py` downloads:

- the article text mirror from `HomelessPhD/Wealth_in_Poetry`
- the canonical English BIP-39 word list from `bitcoin/bips`

Downloaded source material stays under `data/` and is intentionally ignored by git.

## Current result

On the mirrored article text used by the earlier public research repo:

```text
tokens=2431
bip39_occurrences=585
linear checksum-valid mnemonics=24
linear target matches=0
```

A positional GPS scan with `--max-combinations 1000` produced **1,934 unique checksum-valid mnemonics** and no target match.

See [FINDINGS.md](FINDINGS.md) for the research notes and next hypotheses.
