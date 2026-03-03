import requests
import json
import time
import os
import unittest

class TestIDSEndpoints(unittest.TestCase):
    BASE_URL = "http://localhost:6050"
    API_KEY = "ids-secret-key"
    HEADERS = {"X-API-Key": API_KEY}

    def test_01_home(self):
        """Test the home endpoint."""
        response = requests.get(f"{self.BASE_URL}/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Intrusion Detection System", response.json()["message"])

    def test_02_predict_unauthorized(self):
        """Test predict endpoint without API key."""
        response = requests.post(f"{self.BASE_URL}/predict/", json={})
        self.assertEqual(response.status_code, 422) # Validation error for missing header usually, but here X-API-Key is required by Depends

    def test_03_predict_valid(self):
        """Test predict endpoint with valid dummy data."""
        # Data based on feature_names.txt
        dummy_data = {
            "PROTOCOL": 6,
            "L7_PROTO": 0,
            "IN_BYTES": 1000,
            "IN_PKTS": 10,
            "OUT_BYTES": 500,
            "OUT_PKTS": 5,
            "TCP_FLAGS": 2,
            "CLIENT_TCP_FLAGS": 2,
            "SERVER_TCP_FLAGS": 2,
            "FLOW_DURATION_MILLISECONDS": 100,
            "DURATION_IN": 50,
            "DURATION_OUT": 50,
            "MIN_TTL": 64,
            "MAX_TTL": 64,
            "LONGEST_FLOW_PKT": 100,
            "SHORTEST_FLOW_PKT": 40,
            "MIN_IP_PKT_LEN": 40,
            "MAX_IP_PKT_LEN": 100,
            "SRC_TO_DST_SECOND_BYTES": 1000,
            "DST_TO_SRC_SECOND_BYTES": 500,
            "RETRANSMITTED_IN_BYTES": 0,
            "RETRANSMITTED_IN_PKTS": 0,
            "RETRANSMITTED_OUT_BYTES": 0,
            "RETRANSMITTED_OUT_PKTS": 0,
            "SRC_TO_DST_AVG_THROUGHPUT": 10000,
            "DST_TO_SRC_AVG_THROUGHPUT": 5000,
            "NUM_PKTS_UP_TO_128_BYTES": 15,
            "NUM_PKTS_128_TO_256_BYTES": 0,
            "NUM_PKTS_256_TO_512_BYTES": 0,
            "NUM_PKTS_512_TO_1024_BYTES": 0,
            "NUM_PKTS_1024_TO_1514_BYTES": 0,
            "TCP_WIN_MAX_IN": 65535,
            "TCP_WIN_MAX_OUT": 65535,
            "ICMP_TYPE": 0,
            "ICMP_IPV4_TYPE": 0,
            "DNS_TTL_ANSWER": 0,
            "FTP_COMMAND_RET_CODE": 0
        }
        
        response = requests.post(f"{self.BASE_URL}/predict/", json=dummy_data, headers=self.HEADERS)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("predicted_label", result)
        self.assertIn("confidence", result)
        print(f"Prediction result: {result['predicted_label']} ({result['confidence']})")

    def test_04_list_reports(self):
        """Test listing reports."""
        response = requests.get(f"{self.BASE_URL}/reports", headers=self.HEADERS)
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)

    def test_05_events(self):
        """Test events monitoring."""
        # Add event
        event_data = {"event": "test_event", "predicted_label": "DDOS"}
        add_response = requests.post(f"{self.BASE_URL}/events/add", json=event_data, headers=self.HEADERS)
        self.assertEqual(add_response.status_code, 200)

        # Get events
        get_response = requests.get(f"{self.BASE_URL}/events", headers=self.HEADERS)
        self.assertEqual(get_response.status_code, 200)
        self.assertTrue(len(get_response.json()) > 0)

        # Get stats
        stats_response = requests.get(f"{self.BASE_URL}/events/stats", headers=self.HEADERS)
        self.assertEqual(stats_response.status_code, 200)
        self.assertIn("confirmed_threats", stats_response.json())

    def test_06_workflow(self):
        """Test the SOC workflow endpoint."""
        alert_data = {
            "Attack": "DDOS",
            "Severity": "CRITICAL",
            "confidence": 0.95
        }
        response = requests.post(f"{self.BASE_URL}/workflow/process", json=alert_data, headers=self.HEADERS)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("tier1_analysis", result)
        self.assertIn("report_path", result)
        print(f"Workflow result: {result.get('final_severity')} | Report: {result.get('report_path')}")


if __name__ == "__main__":
    unittest.main()
