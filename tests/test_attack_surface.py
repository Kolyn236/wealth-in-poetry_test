import unittest

import attack_surface


class AttackSurfaceTests(unittest.TestCase):
    def test_extracts_author_gps_selector_from_adjacent_coordinates(self):
        text = "Landmark: 38.8906 N, 77.0044 W."
        fragments = attack_surface.extract_numeric_fragments(text)
        selectors = attack_surface.numeric_selector_candidates(fragments)
        self.assertIn("388906770044", {item.selector for item in selectors})

    def test_paragraph_and_sentence_splitting(self):
        text = "First sentence. Second sentence!\n\nThird paragraph?"
        self.assertEqual(len(attack_surface.split_paragraphs(text)), 2)
        self.assertEqual(len(attack_surface.split_sentences(text)), 3)

    def test_null_cipher_keyword_detection(self):
        text = "xxs xxe xxe xxd"
        units = list(attack_surface.iter_units(text, kinds=("article",)))
        hits = attack_surface.scan_null_keywords(
            units,
            keywords=("seed",),
            char_indices=(2,),
        )
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["letter"], 3)
        self.assertEqual(hits[0]["direction"], "forward")
        self.assertEqual(hits[0]["hits"][0]["keyword"], "seed")

    def test_boundary_streams(self):
        streams = attack_surface.boundary_streams(
            "Alpha beta. Charlie delta.\n\nEcho foxtrot."
        )
        self.assertEqual(streams["paragraph_first"], "ae")
        self.assertEqual(streams["sentence_first"], "ace")


if __name__ == "__main__":
    unittest.main()
