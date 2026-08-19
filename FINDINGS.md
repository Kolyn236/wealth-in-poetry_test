# Findings

## Reproduced author examples

The GPS example is internally consistent under normal word tokenization.

Coordinates:

```text
38.8906 N, 77.0044 W
```

Digits become positions by adding ten for each successive digit:

```text
3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114
```

Those positions select:

```text
asset trial load escape symbol story bomb picnic river aerobic mystery honey
```

The resulting 12 words pass the BIP-39 checksum. This makes the GPS mechanism a useful ground-truth test for tokenization and indexing.

## Baseline search

The earlier public solver filtered the article to BIP-39 words and tested consecutive groups of twelve. Reimplementing that search gives:

```text
2431 article tokens
585 BIP-39-word occurrences
24 checksum-valid consecutive 12-word mnemonics
0 matches for 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo
```

So the simple linear-window interpretation remains ruled out for the mirrored text and the standard BIP-44 first address.

## GPS positional search

For an unknown story start, each coordinate digit constrains a seed word to one ten-word region. The solver slides that 119-word shape through the article, retains only positions containing BIP-39 words, rejects windows whose Cartesian product is above a configurable threshold, validates BIP-39 checksums, and finally derives the target address.

Initial run:

```text
python solver.py gps --max-combinations 1000
```

Result:

```text
gps_checksum_valid_unique=1934
target_matches=0
```

This rules out the less-ambiguous GPS-shaped windows first. Larger thresholds expand the same search systematically.

## Null-cipher ambiguity

The article says that taking the third letter of each word in its null-cipher example yields:

```text
sendlawyersgunsandmoney
```

Literal tokenization of the mirrored example yields:

```text
sendlawyersgunsandmoneyy
```

The final `day` contributes the extra `y`. This is worth keeping in mind: boundaries and editorial text may matter, and a future solver should test several defensible tokenization/boundary conventions rather than assuming the prose examples are perfectly exact.

## Next hypotheses

1. Expand the GPS positional scan while ranking windows by semantic landmark clues.
2. Test likely story boundaries (paragraphs/sections) rather than every token as an arbitrary start.
3. Generate null-cipher streams for multiple letter positions and search them for instructions, numbers, place names, and coordinate-like material.
4. Treat article numbers, publication metadata, captions, and bibliography markers as candidate index material.
5. Test alternative derivation assumptions only after a candidate passes BIP-39 checksum; keep the steganographic search separate from wallet-format variation.
