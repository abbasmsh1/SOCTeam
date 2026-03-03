import os
import argparse
import sys
import json
import logging
from dotenv import load_dotenv

# Add project root to path
# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Implementation.src.Agents.SOCWorkflow import SOCWorkflow
from Implementation.utils.Logger import setup_logger

logger = setup_logger("SOC_Main")

def load_config():
    """Load configuration from config.json."""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Config file not found at {config_path}")
        raise
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in {config_path}")
        raise

def main():
    parser = argparse.ArgumentParser(description="Agentic SOC System CLI")
    parser.add_argument("--alert", type=str, help="Path to JSON file containing alert data")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--monitor", action="store_true", help="Run in live traffic monitoring mode")
    parser.add_argument("--interface", type=str, default="eth0", help="Network interface for monitoring (default: eth0)")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration in seconds (default: 10)")
    args = parser.parse_args()

    # Load environment variables
    load_dotenv()
    
    # Check for API key
    api_key = os.getenv('MISTRAL_API_KEY')
    if not api_key:
        logger.warning("MISTRAL_API_KEY not found in environment variables. Agents may run in fallback mode.")

    if args.monitor:
        logger.info(f"Starting Live Traffic Monitor on {args.interface}...")
        try:
            # Import here to avoid dependency issues if not using monitoring
            from Implementation.tools.live_traffic_monitor import LiveTrafficMonitor
            
            monitor = LiveTrafficMonitor(
                interface=args.interface,
                capture_duration=args.duration
            )
            monitor.run_continuous()
            
        except ImportError:
            logger.error("Could not import LiveTrafficMonitor. Ensure 'tools' package is accessible.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Monitoring failed: {e}")
            sys.exit(1)

    elif args.alert:
        logger.info("Initializing SOC Workflow...")
        workflow = SOCWorkflow(api_key=api_key)
        try:
            with open(args.alert, 'r') as f:
                alert_data = json.load(f)
            
            logger.info(f"Processing alert from {args.alert}")
            
            input_data = {
                "alert_data": alert_data,
                "current_status": "Normal Operation",
                "context_logs": "No anomalies in last hour",
                "current_incidents": "None"
            }
            
            result = workflow.process(input_data)
            logger.info("Processing complete.")
            
        except Exception as e:
            logger.error(f"Failed to process alert: {e}")
            sys.exit(1)
            
    elif args.interactive:
        logger.info("Initializing SOC Workflow...")
        workflow = SOCWorkflow(api_key=api_key)
        print("\n--- Interactive SOC Agent Mode ---\n")
        print("Paste your alert JSON below (Press Ctrl+Z/Ctrl+D and Enter to finish):")
        try:
            alert_str = sys.stdin.read()
            if not alert_str.strip():
                print("No input provided.")
                return

            alert_data = json.loads(alert_str)
            logger.info("Processing interactive input...")
            
            input_data = {
                "alert_data": alert_data,
                "current_status": "Normal Operation",
                "context_logs": "Interactive Session",
                "current_incidents": "None"
            }
            
            result = workflow.process(input_data)
            print("\n>>> Final Result:")
            print(json.dumps(result, indent=2))
            
            if "report_path" in result:
                print(f"\nReport generated: {result['report_path']}")
                
        except json.JSONDecodeError:
            logger.error("Invalid JSON input.")
        except Exception as e:
            logger.error(f"Error: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
