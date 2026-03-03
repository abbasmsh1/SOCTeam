import subprocess
import time
import os
import sys

def main():
    print("Starting agent microservices and IDS server...")
    
    # Set up environment
    env = os.environ.copy()
    env["PYTHONPATH"] = "E:\\IMT\\2nd Sem\\Project"
    env["TIER1_URL"] = "http://localhost:6051"
    env["TIER2_URL"] = "http://localhost:6052"
    env["TIER3_URL"] = "http://localhost:6053"
    env["WARROOM_URL"] = "http://localhost:6054"
    env["REPORTER_URL"] = "http://localhost:6055"
    
    processes = []
    
    try:
        # Start Agents
        processes.append(subprocess.Popen([sys.executable, "-m", "Implementation.src.agent_server", "--agent", "tier1", "--port", "6051"], env=env))
        processes.append(subprocess.Popen([sys.executable, "-m", "Implementation.src.agent_server", "--agent", "tier2", "--port", "6052"], env=env))
        processes.append(subprocess.Popen([sys.executable, "-m", "Implementation.src.agent_server", "--agent", "tier3", "--port", "6053"], env=env))
        processes.append(subprocess.Popen([sys.executable, "-m", "Implementation.src.agent_server", "--agent", "warroom", "--port", "6054"], env=env))
        processes.append(subprocess.Popen([sys.executable, "-m", "Implementation.src.agent_server", "--agent", "reporter", "--port", "6055"], env=env))
        
        # Start IDS
        processes.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "src.IDS.IDS:app", "--port", "6050"], env=env))
        
        print("Waiting 15 seconds for services to start...")
        time.sleep(15)
        
        print("Running tests...")
        result = subprocess.run([sys.executable, "-m", "pytest", "tests/"], env=env, capture_output=True, text=True)
        
        print("--- Pytest Output ---")
        print(result.stdout)
        if result.stderr:
            print("--- Pytest Errors ---")
            print(result.stderr)
            
    finally:
        print("Cleaning up processes...")
        for p in processes:
            p.terminate()
            
if __name__ == "__main__":
    main()
