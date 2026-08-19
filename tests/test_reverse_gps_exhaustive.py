import unittest

import reverse_gps_exhaustive as exhaustive
import solver


class ReverseGpsExhaustiveTests(unittest.TestCase):
    def test_base58_target_decode(self):
        payload = exhaustive._decode_base58check(solver.TARGET_ADDRESS)
        self.assertEqual(payload[0], 0)
        self.assertEqual(len(payload), 21)

    def test_private_key_one_addresses_with_coincurve(self):
        compressed = solver.base58check(
            b"\x00" + solver.hash160(exhaustive._public_key(1, True))
        )
        uncompressed = solver.base58check(
            b"\x00" + solver.hash160(exhaustive._public_key(1, False))
        )
        self.assertEqual(compressed, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        self.assertEqual(uncompressed, "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")

    def test_plan_balances_every_start_once(self):
        text = solver.AUTHOR_GPS_EXAMPLE + " " + solver.AUTHOR_GPS_EXAMPLE
        known = list(dict.fromkeys(word.lower() for word in solver.tokenize(text)))
        wordlist = known + [f"zz{i}" for i in range(2048 - len(known))]
        plan = exhaustive.build_plan(text, wordlist, shard_count=3)
        starts = [item.start_word for item in plan]
        self.assertEqual(len(starts), len(set(starts)))
        self.assertTrue(all(0 <= item.shard < 3 for item in plan))


if __name__ == "__main__":
    unittest.main()
