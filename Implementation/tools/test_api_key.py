"""
Test API Key Validity

Validates the Mistral AI API key in .env by making a real API call.
Also tests the local IDS backend API key.
"""

import os
import sys
import requests
from pathlib import Path

# Add project root to path and load .env
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

env_file = PROJECT_ROOT / "Implementation" / ".env"
if env_file.exists():
    from dotenv import load_dotenv
    load_dotenv(env_file)
    print(f"[OK] Loaded .env from: {env_file}")
else:
    print(f"[!] .env not found at: {env_file}")


def print_separator(title: str = ""):
    line = "=" * 60
    if title:
        print(f"\n{line}")
        print(f"  {title}")
        print(line)
    else:
        print(line)


def test_mistral_api_key():
    """Test Mistral AI API key with a minimal API call."""
    print_separator("1. Mistral AI API Key")

    api_key = os.getenv("MISTRAL_API_KEY")
    if not api_key:
        print("[X] MISTRAL_API_KEY not found in environment!")
        return False

    masked = f"{api_key[:6]}...{api_key[-4:]}"
    print(f"[*] Key found: {masked} (length: {len(api_key)})")
    print("[*] Testing against Mistral API (models endpoint)...")

    try:
        response = requests.get(
            "https://api.mistral.ai/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )

        if response.status_code == 200:
            models = response.json().get("data", [])
            model_ids = [m.get("id") for m in models[:5]]
            print(f"[OK] Mistral API key is VALID!")
            print(f"     Available models (first 5): {model_ids}")
            return True
        elif response.status_code == 401:
            print(f"[X] INVALID API Key — 401 Unauthorized")
            print(f"     Response: {response.text[:200]}")
            return False
        elif response.status_code == 429:
            print(f"[!] Rate limited (429) — Key is valid but quota exceeded")
            return True
        else:
            print(f"[!] Unexpected status {response.status_code}")
            print(f"     Response: {response.text[:200]}")
            return False

    except requests.exceptions.ConnectionError:
        print("[X] Cannot reach api.mistral.ai — check internet connection")
        return False
    except requests.exceptions.Timeout:
        print("[X] Request timed out (10s)")
        return False
    except Exception as e:
        print(f"[X] Unexpected error: {e}")
        return False


def test_ids_backend(base_url: str = "http://localhost:6050", api_key: str = "ids-secret-key"):
    """Test the local IDS backend API key and connectivity."""
    print_separator("2. IDS Backend (localhost:6050)")
    print(f"[*] Backend URL: {base_url}")
    print(f"[*] API Key: {api_key}")

    # Health check (no auth needed)
    try:
        r = requests.get(f"{base_url}/", timeout=3)
        if r.status_code == 200:
            print(f"[OK] Backend is UP: {r.json().get('message', '?')}")
        else:
            print(f"[!] Backend responded with: {r.status_code}")
    except Exception as e:
        print(f"[X] Backend not reachable: {e}")
        print("    > Start it with: start_all.ps1 or start_agents.ps1")
        return False

    # Auth check — events endpoint
    try:
        r = requests.get(f"{base_url}/events", headers={"X-API-Key": api_key}, timeout=3)
        if r.status_code == 200:
            print(f"[OK] IDS API Key is VALID — /events returned {r.status_code}")
            return True
        elif r.status_code == 403:
            print(f"[X] IDS API Key REJECTED — 403 Forbidden")
            print(f"    Check IDSConfig.API_KEY or IDS_API_KEY env var")
            return False
        else:
            print(f"[!] Unexpected status: {r.status_code}")
            return False
    except Exception as e:
        print(f"[X] Error testing IDS auth: {e}")
        return False


def test_agent_microservices():
    """Test all 5 agent microservice health endpoints."""
    print_separator("3. Agent Microservices (ports 6051–6055)")

    agents = {
        "tier1": 6051,
        "tier2": 6052,
        "tier3": 6053,
        "warroom": 6054,
        "reporter": 6055,
    }

    all_ok = True
    for name, port in agents.items():
        try:
            r = requests.get(f"http://localhost:{port}/health", timeout=2)
            if r.status_code == 200:
                data = r.json()
                agent_type = data.get("agent_type", "?")
                print(f"  [OK] {name:8s} (:{port}) — {data.get('status', '?')} [{agent_type}]")
            else:
                print(f"  [!] {name:8s} (:{port}) — HTTP {r.status_code}")
                all_ok = False
        except Exception:
            print(f"  [X] {name:8s} (:{port}) — Not running")
            all_ok = False

    return all_ok


def main():
    print_separator()
    print("  SOC System — API Key & Service Health Check")
    print_separator()

    results = {}
    results["mistral"]  = test_mistral_api_key()
    results["ids"]      = test_ids_backend()
    results["agents"]   = test_agent_microservices()

    # Summary
    print_separator("Summary")
    for name, ok in results.items():
        status = "[OK]" if ok else "[X]"
        print(f"  {status} {name}")

    if all(results.values()):
        print("\n[OK] All checks passed — system is ready!")
        sys.exit(0)
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"\n[!] Failed checks: {', '.join(failed)}")
        print("    Run start_all.ps1 to start all services.")
        sys.exit(1)


if __name__ == "__main__":
    main()
