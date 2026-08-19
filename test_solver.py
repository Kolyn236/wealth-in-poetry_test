import unittest

from solver import (
    bip44_addresses,
    gps_indices,
    mnemonic_checksum_valid,
    null_cipher,
    positions_to_digits,
    tokenize,
    words_at_indices,
)

# Exact indices from the canonical BIP-39 English list for words used in tests.
INDEX = {
    "abandon": 0,
    "about": 3,
    "aerobic": 33,
    "asset": 109,
    "bomb": 201,
    "escape": 616,
    "honey": 873,
    "load": 1047,
    "mystery": 1171,
    "picnic": 1313,
    "river": 1494,
    "story": 1716,
    "symbol": 1763,
    "trial": 1857,
}


class SolverTest(unittest.TestCase):
    def test_known_bip39_vector(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()
        self.assertTrue(mnemonic_checksum_valid(mnemonic, INDEX))
        compressed, _ = bip44_addresses(mnemonic)
        self.assertEqual(compressed, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")

    def test_invalid_checksum(self):
        mnemonic = ("abandon " * 12).split()
        self.assertFalse(mnemonic_checksum_valid(mnemonic, INDEX))

    def test_gps_indices(self):
        self.assertEqual(
            gps_indices("38.8906,77.0044"),
            [3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114],
        )

    def test_positions_roundtrip(self):
        positions = [3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114]
        self.assertEqual(positions_to_digits(positions), "388906770044")

    def test_article_gps_example(self):
        text = """Such an asset to be represented by an experienced and mature lawyer particularly when you have a trial in front of the Supreme Court of the USA. Load your argument with logic and do not provide ways to escape. Symbol of cultural diversity should be used as often as possible in order to support the story. Our client clearly did not make that complex and improvised bomb himself. They were on their way to his friend's picnic by the river when he noticed a suspicious person pretending to do aerobic exercises. He immediately pointed it out to his friends. Their whereabouts aren't a mystery, during the attack they were ordering ginger tea with honey to bring to the picnic."""
        tokens = tokenize(text)
        positions = gps_indices("388906770044")
        selected = words_at_indices(tokens, positions)
        self.assertEqual(
            selected,
            "asset trial load escape symbol story bomb picnic river aerobic mystery honey".split(),
        )
        self.assertTrue(mnemonic_checksum_valid(selected, INDEX))

    def test_null_cipher_example_exposes_trailing_y_ambiguity(self):
        text = "Fishing freshwater bends and saltwater coasts rewards anyone feeling stressed Resourceful anglers usually find masterful leapers fun and admit swordfish rank overwhelming any day"
        stream = null_cipher(tokenize(text), 3)
        self.assertEqual(stream.lower(), "sendlawyersgunsandmoneyy")


if __name__ == "__main__":
    unittest.main()
