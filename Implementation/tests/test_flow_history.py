"""
test_flow_history.py
====================
Integration test for the FlowHistoryManager.
Verifies that flow history data is correctly persisted to the database
and can be queried back via `get_ip_stats()`.

This test does NOT require a running LLM or backend server – it only
validates the database persistence layer.
"""

import sys
import os
import json

# Ensure the project root is on the import path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Implementation.src.Database.FlowHistoryManager import FlowHistoryManager


def test_flow_history_injection():
    """
    Test that FlowHistoryManager correctly stores repeated flows for
    a given IP and returns accurate statistics.

    Steps:
      1. Initialize the FlowHistoryManager (creates/connects to DB).
      2. Insert 10 simulated BRUTEFORCE flows for a test IP.
      3. Query the stats and verify the count matches.
    """
    print("=== Testing Flow History Injection ===")

    # Step 1: Initialize the database manager
    history = FlowHistoryManager()

    # Step 2: Simulate 10 brute-force flows from a single source IP
    test_ip = "10.0.0.55"
    num_flows = 10
    print(f"Simulating {num_flows} flows for {test_ip}...")

    for _ in range(num_flows):
        history.add_flow(
            {"src_ip": test_ip, "dst_ip": "192.168.1.1", "Protocol": "TCP"},
            "BRUTEFORCE",
            0.9,
        )

    # Step 3: Verify the persisted stats match expectations
    stats = history.get_ip_stats(test_ip)
    print(f"\nVerified Stats in DB: {json.dumps(stats, indent=2)}")

    total = stats.get("total_flows_last_5min", 0)
    if total >= num_flows:
        print("\nSUCCESS: Flow history correctly persisted and queryable.")
    else:
        print(f"\nFAILURE: Expected >= {num_flows} flows, got {total}.")


if __name__ == "__main__":
    test_flow_history_injection()
