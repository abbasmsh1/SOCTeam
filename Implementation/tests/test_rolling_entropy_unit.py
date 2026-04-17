import unittest

from Implementation.src.IDS.IDS import RollingEntropyWindow


class TestRollingEntropyWindow(unittest.TestCase):
    def test_entropy_increases_with_diversity(self):
        w = RollingEntropyWindow(window_seconds=9999)

        r1 = w.observe_and_compute({"Source IP": "1.1.1.1", "Destination IP": "9.9.9.9", "Protocol": "6"})
        self.assertEqual(r1["WINDOW_FLOW_COUNT"], 1.0)
        self.assertEqual(r1["ENT_SRC_IP"], 0.0)

        r2 = w.observe_and_compute({"Source IP": "1.1.1.1", "Destination IP": "9.9.9.9", "Protocol": "6"})
        self.assertEqual(r2["WINDOW_FLOW_COUNT"], 2.0)
        self.assertEqual(r2["ENT_SRC_IP"], 0.0)

        r3 = w.observe_and_compute({"Source IP": "2.2.2.2", "Destination IP": "9.9.9.9", "Protocol": "6"})
        self.assertEqual(r3["WINDOW_FLOW_COUNT"], 3.0)
        self.assertGreater(r3["ENT_SRC_IP"], 0.0)


if __name__ == "__main__":
    unittest.main()

