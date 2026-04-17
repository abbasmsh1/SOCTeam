import unittest

import pandas as pd

from Implementation.src.IDS.preprocess import EntropyWindowFeatures


class TestEntropyWindowFeatures(unittest.TestCase):
    def test_disabled_no_columns_added(self):
        df = pd.DataFrame(
            {
                "Timestamp": [0, 1, 2],
                "IPV4_SRC_ADDR": ["1.1.1.1", "1.1.1.1", "2.2.2.2"],
                "Attack": ["BENIGN", "BENIGN", "BENIGN"],
            }
        )
        t = EntropyWindowFeatures(enable=False, window_seconds=10)
        out = t.transform(df)
        self.assertNotIn("ENT_SRC_IP", out.columns)

    def test_enabled_adds_entropy_columns(self):
        df = pd.DataFrame(
            {
                "Timestamp": [0, 1, 2, 12, 13],
                "IPV4_SRC_ADDR": ["1.1.1.1", "1.1.1.1", "2.2.2.2", "3.3.3.3", "3.3.3.3"],
                "IPV4_DST_ADDR": ["9.9.9.9", "9.9.9.9", "9.9.9.9", "8.8.8.8", "8.8.4.4"],
                "L4_SRC_PORT": [1000, 1000, 1001, 2000, 2000],
                "L4_DST_PORT": [80, 80, 80, 443, 443],
                "PROTOCOL": [6, 6, 6, 6, 6],
                "L7_PROTO": [0, 0, 0, 0, 0],
                "LONGEST_FLOW_PKT": [100, 110, 120, 1300, 1300],
                "Attack": ["BENIGN"] * 5,
            }
        )
        t = EntropyWindowFeatures(enable=True, window_seconds=10)
        out = t.transform(df)
        for c in [
            "ENT_SRC_IP",
            "ENT_DST_IP",
            "ENT_SRC_PORT",
            "ENT_DST_PORT",
            "ENT_PROTOCOL",
            "ENT_L7_PROTO",
            "ENT_PKT_LEN_BIN",
            "WINDOW_FLOW_COUNT",
        ]:
            self.assertIn(c, out.columns)
        # Window 0 should have 3 rows, window 1 should have 2 rows
        self.assertEqual(out.loc[0, "WINDOW_FLOW_COUNT"], 3.0)
        self.assertEqual(out.loc[3, "WINDOW_FLOW_COUNT"], 2.0)


if __name__ == "__main__":
    unittest.main()

