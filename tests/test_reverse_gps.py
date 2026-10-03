import unittest

import reverse_gps
import solver


class ReverseGpsTests(unittest.TestCase):
    def test_bip39_checksum_fast_path(self):
        # Standard BIP-39 test vector: abandon x11 + about.
        self.assertTrue(reverse_gps.validate_12_indices([0] * 11 + [3]))
        self.assertFalse(reverse_gps.validate_12_indices([0] * 12))

    def test_author_positions_are_recoverable_from_blocks(self):
        tokens = solver.tokenize(solver.AUTHOR_GPS_EXAMPLE)
        fake_index = {word: index for index, word in enumerate(solver.AUTHOR_GPS_WORDS)}
        blocks = reverse_gps.block_choices(tokens, fake_index)
        positions = solver.gps_positions(solver.AUTHOR_GPS_DIGITS)

        recovered_digits = []
        recovered_words = []
        for block, (position, word) in enumerate(zip(positions, solver.AUTHOR_GPS_WORDS)):
            choice = next(
                item for item in blocks[block]
                if item.position == position and item.word == word
            )
            recovered_digits.append(str(choice.digit))
            recovered_words.append(choice.word)

        self.assertEqual("".join(recovered_digits), solver.AUTHOR_GPS_DIGITS)
        self.assertEqual(recovered_words, solver.AUTHOR_GPS_WORDS)

    def test_digit_ranges_match_author_rule(self):
        self.assertEqual(reverse_gps.block_bounds(0), (1, 9))
        self.assertEqual(reverse_gps.block_bounds(1), (10, 19))
        self.assertEqual(reverse_gps.block_bounds(11), (110, 119))
        self.assertEqual(reverse_gps.digit_for_position(0, 3), 3)
        self.assertEqual(reverse_gps.digit_for_position(4, 40), 0)
        self.assertEqual(reverse_gps.digit_for_position(11, 114), 4)

    def test_coordinate_interpretation_recovers_supreme_court_format(self):
        interpretations = reverse_gps.coordinate_interpretations("388906770044")
        self.assertIn(
            {"scheme": "lat2.4_lon2.4", "latitude": 38.8906, "longitude": 77.0044},
            interpretations,
        )

    def test_example_marker_starts_after_label(self):
        text = "Intro words. Example: Such an asset to remember."
        starts = reverse_gps.structural_starts(text)
        example = next(item for item in starts if "example:1" in item.labels)
        self.assertEqual(example.start_word, 3)
        self.assertEqual(solver.tokenize(text)[example.start_word], "Such")

    def test_shards_partition_product_without_overlap(self):
        blocks = []
        sizes = [2, 3, 2] + [1] * 9
        for block, size in enumerate(sizes):
            blocks.append([
                reverse_gps.Choice(block, max(1, block * 10) + i, i, f"w{block}_{i}", i)
                for i in range(size)
            ])

        full = list(reverse_gps.iter_sharded_combos(blocks, 0, 1))
        shards = [list(reverse_gps.iter_sharded_combos(blocks, i, 4)) for i in range(4)]
        flattened = [combo for shard in shards for combo in shard]

        self.assertEqual(len(full), 12)
        self.assertEqual(sum(len(shard) for shard in shards), len(full))
        self.assertEqual({tuple(item.word for item in combo) for combo in flattened},
                         {tuple(item.word for item in combo) for combo in full})

    def test_assigned_counts_sum_to_full_space(self):
        blocks = []
        sizes = [5, 4, 3] + [1] * 9
        for block, size in enumerate(sizes):
            blocks.append([
                reverse_gps.Choice(block, max(1, block * 10) + i, i, f"w{block}_{i}", i)
                for i in range(size)
            ])
        assigned = [reverse_gps.assigned_combination_count(blocks, i, 16) for i in range(16)]
        self.assertEqual(sum(assigned), reverse_gps.combination_count(blocks))
        self.assertLessEqual(max(assigned) - min(assigned), 12)


if __name__ == "__main__":
    unittest.main()
