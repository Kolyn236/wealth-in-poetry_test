#!/usr/bin/env python3
"""Fetch the article mirror and the canonical BIP-39 English word list."""
from pathlib import Path
from urllib.request import Request, urlopen

SOURCES = {
    "article.txt": "https://raw.githubusercontent.com/HomelessPhD/Wealth_in_Poetry/main/python_script/text.txt",
    "english.txt": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt",
}


def main() -> None:
    data = Path("data")
    data.mkdir(exist_ok=True)
    for filename, url in SOURCES.items():
        request = Request(url, headers={"User-Agent": "wealth-in-poetry-research/1.0"})
        with urlopen(request, timeout=30) as response:
            content = response.read()
        path = data / filename
        path.write_bytes(content)
        print(f"wrote {path} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
