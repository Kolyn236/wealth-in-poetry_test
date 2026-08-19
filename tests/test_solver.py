import unittest

import solver


class SolverTests(unittest.TestCase):
    def test_author_gps_example(self):
        tokens = solver.tokenize(solver.AUTHOR_GPS_EXAMPLE)
        positions = solver.gps_positions(solver.AUTHOR_GPS_DIGITS)
        self.assertEqual(
            positions,
            [3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114],
        )
        self.assertEqual(
            solver.select_by_positions(tokens, positions),
            solver.AUTHOR_GPS_WORDS,
        )

    def test_private_key_one_p2pkh(self):
        self.assertEqual(
            solver.p2pkh_address(1, compressed=True),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        )
        self.assertEqual(
            solver.p2pkh_address(1, compressed=False),
            "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
        )

    def test_parse_bip44_path(self):
        self.assertEqual(
            solver.parse_path("m/44'/0'/0'/0/0"),
            [44 + solver.HARDENED, solver.HARDENED, solver.HARDENED, 0, 0],
        )


if __name__ == "__main__":
    unittest.main()
