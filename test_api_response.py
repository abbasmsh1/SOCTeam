#!/usr/bin/env python3
"""Test API endpoints to debug the data flow."""

import requests
import json
import time

BASE_URL = "http://localhost:6050"
API_KEY = "ids-secret-key"
HEADERS = {"X-API-Key": API_KEY}

def test_endpoint(endpoint, method="GET"):
    """Test an endpoint with timeout and error handling."""
    url = f"{BASE_URL}{endpoint}"
    print(f"\n{'='*60}")
    print(f"Testing: {method} {endpoint}")
    print(f"URL: {url}")
    print(f"{'='*60}")
    
    try:
        if method == "GET":
            response = requests.get(url, headers=HEADERS, timeout=5)
        else:
            response = requests.post(url, headers=HEADERS, timeout=5)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        try:
            data = response.json()
            print(f"Response JSON:\n{json.dumps(data, indent=2)}")
        except:
            print(f"Response Text:\n{response.text[:500]}")
            
    except requests.exceptions.Timeout:
        print(f"❌ TIMEOUT after 5 seconds")
    except Exception as e:
        print(f"❌ ERROR: {type(e).__name__}: {e}")

def main():
    print("Testing API Endpoints")
    print(f"Base URL: {BASE_URL}")
    print(f"API Key: {API_KEY}")
    
    # Test 1: Health check
    test_endpoint("/")
    time.sleep(0.5)
    
    # Test 2: Get stats
    test_endpoint("/events/stats")
    time.sleep(0.5)
    
    # Test 3: Get events
    test_endpoint("/events")
    time.sleep(0.5)
    
    # Test 4: Get reports
    test_endpoint("/reports")
    time.sleep(0.5)

if __name__ == "__main__":
    main()
