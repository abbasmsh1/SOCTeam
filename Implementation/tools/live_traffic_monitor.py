"""
Live Network Traffic Capture Service
Continuously captures traffic from eth0 and feeds into SOC workflow.
"""

import time
import logging
import argparse
from datetime import datetime
from typing import Dict, Any
import os
import sys
import json
import requests
import random

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from Implementation.src.IDS.FlowExtractor import FlowExtractor, check_cicflowmeter_installation
from Implementation.src.IDS.IDS import IDSPredictor
from Implementation.src.Agents.SOCWorkflow import SOCWorkflow

try:
    from scapy.all import get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class LiveTrafficMonitor:
    """
    Monitor live network traffic and process through Full SOC Workflow.
    """
    
    def __init__(
        self,
        interface: str = 'eth0',
        capture_duration: int = 10,
        threshold_confidence: float = 0.7,
        simulate: bool = False
    ):
        """
        Initialize live traffic monitor.
        
        Args:
            interface: Network interface to monitor
            capture_duration: Seconds to capture per batch
            threshold_confidence: Minimum confidence to trigger alerts
            simulate: Whether to simulate traffic from CSV
        """
        self.interface = interface
        self.capture_duration = capture_duration
        self.threshold_confidence = threshold_confidence
        self.simulate = simulate
        self.api_url = "http://localhost:6050"
        self.api_key = os.getenv("IDS_API_KEY", "ids-secret-key")
        
        # Check dependencies
        if not check_cicflowmeter_installation() and not simulate:
             logger.warning("CICFlowMeter not installed. Run: pip install cicflowmeter")
             self.flow_extractor = None
        elif not simulate:
             # Initialize components
             self.flow_extractor = FlowExtractor()
        else:
             self.flow_extractor = None # Not needed for pure simulation
            
        self.ids_predictor = IDSPredictor()
        
        # Use full SOC Workflow (Tier 1 -> Tier 3 -> War Room)
        api_key = os.getenv("MISTRAL_API_KEY")
        self.workflow = SOCWorkflow(api_key=api_key)
        
        logger.info(f"🚀 Live Traffic Monitor initialized (Simulation: {simulate})")
        logger.info(f"   Interface: {interface}")
        logger.info(f"   Capture Duration: {capture_duration}s")
        logger.info(f"   Alert Threshold: {threshold_confidence:.0%}")
    
    def _report_event(self, event: Dict[str, Any]):
        """Report event to backend API."""
        try:
            requests.post(
                f"{self.api_url}/events/add",
                json=event,
                headers={"x-api-key": self.api_key},
                timeout=2
            )
        except Exception as e:
            logger.error(f"Failed to report event to API: {e}")

    def capture_and_analyze(self) -> Dict[str, Any]:
        """
        Capture traffic batch and analyze for threats.
        
        Returns:
            Analysis results
        """
        if self.simulate:
            logger.info(f"🎮 Simulating {self.capture_duration}s of traffic flows...")
            # Use the existing CSV fallback logic from FlowExtractor for realism
            temp_extractor = FlowExtractor()
            flows_df = temp_extractor._load_from_csv_fallback()
            time.sleep(2) # Simulate processing time
        else:
            logger.info(f"📡 Capturing {self.capture_duration}s of traffic from {self.interface}...")
            try:
                if self.flow_extractor is None:
                    logger.error("🛑 Cannot capture: CICFlowMeter dependency missing.")
                    return {"status": "error", "error": "missing_dependencies"}

                # Capture live traffic
                flows_df = self.flow_extractor.extract_live(
                    interface=self.interface,
                    duration=self.capture_duration
                )
            except Exception as e:
                logger.error(f"❌ Error during capture: {e}")
                return {"status": "error", "error": str(e)}
            
        if flows_df.empty:
            logger.warning("⚠️  No traffic captured")
            return {"status": "no_traffic", "flows": 0}
        
        flow_count = len(flows_df)
        logger.info(f"✅ Received {flow_count} flows")
        
        # Run IDS predictions
        predictions = self.ids_predictor.predict_batch(flows_df)
        
        # DEBUG: Force first flow to be a high-confidence threat for escalation testing
        if len(predictions) > 0:
            predictions[0] = {
                'predicted_label': 'DDOS',
                'confidence': 0.99,
                'anomaly_score': 0.99
            }
            logger.info("🧪 TEST ALERT: Forcing DDOS threat on first flow for escalation verification.")
        
        # Analyze results and report to dashboard
        for i, p in enumerate(predictions):
            event = {
                "SourceIP": flows_df.iloc[i].get('IPV4_SRC_ADDR', flows_df.iloc[i].get('Source IP', 'Unknown')),
                "DestinationIP": flows_df.iloc[i].get('IPV4_DST_ADDR', flows_df.iloc[i].get('Destination IP', 'Unknown')),
                "SourcePort": int(flows_df.iloc[i].get('L4_SRC_PORT', flows_df.iloc[i].get('Source Port', 0))),
                "DestinationPort": int(flows_df.iloc[i].get('L4_DST_PORT', flows_df.iloc[i].get('Destination Port', 0))),
                "Protocol": int(flows_df.iloc[i].get('PROTOCOL', flows_df.iloc[i].get('Protocol', 0))),
                "Attack": p['predicted_label'],
                "confidence": p['confidence'],
                "Severity": self._map_severity(p['predicted_label'])
            }
            self._report_event(event)

        malicious_flows = [p for i, p in enumerate(predictions) if p['predicted_label'] != 'BENIGN']
        
        if not malicious_flows:
            logger.info("✅ All traffic benign")
            return {
                "status": "benign",
                "flows": flow_count,
                "timestamp": datetime.now().isoformat()
            }
        
        logger.warning(f"⚠️  Detected {len(malicious_flows)} potentially malicious flows!")
        
        # Process high-confidence threats
        alerts_triggered = []
        for pred in malicious_flows:
            if pred['confidence'] >= self.threshold_confidence:
                alert = self._create_alert(pred, pred)
                alerts_triggered.append(alert)
                
                # Process through FULL SOC Workflow
                logger.info(f"🚨 Executing Agentic Workflow for: {pred['predicted_label']} ({pred['confidence']:.1%} confidence)")
                self._process_alert(alert)
            else:
                logger.debug(f"ℹ️ Skipping low-confidence threat: {pred['predicted_label']} ({pred['confidence']:.1%} confidence < {self.threshold_confidence:.1%})")
        
        return {
            "status": "threats_detected",
            "flows": flow_count,
            "malicious_flows": len(malicious_flows),
            "alerts_triggered": len(alerts_triggered),
            "timestamp": datetime.now().isoformat(),
            "details": malicious_flows[:5]  # Top 5 threats
        }
    
    def _create_alert(self, flow_data: Dict, prediction: Dict) -> Dict[str, Any]:
        """Create alert from flow data and prediction."""
        return {
            "alert_type": "live_traffic_detection",
            "timestamp": datetime.now().isoformat(),
            "SourceIP": flow_data.get('IPV4_SRC_ADDR', flow_data.get('Source IP', 'Unknown')),
            "DestinationIP": flow_data.get('IPV4_DST_ADDR', flow_data.get('Destination IP', 'Unknown')),
            "SourcePort": flow_data.get('L4_SRC_PORT', flow_data.get('Source Port', 0)),
            "DestinationPort": flow_data.get('L4_DST_PORT', flow_data.get('Destination Port', 0)),
            "Protocol": flow_data.get('PROTOCOL', flow_data.get('Protocol', 0)),
            "Attack": prediction['predicted_label'],
            "Severity": self._map_severity(prediction['predicted_label']),
            "confidence": prediction['confidence'],
            "flow_duration": flow_data.get('Flow Duration', 0),
            "total_packets": flow_data.get('Tot Fwd Pkts', 0) + flow_data.get('Tot Bwd Pkts', 0),
        }
    
    def _map_severity(self, attack_type: str) -> str:
        """Map attack type to severity level."""
        high_severity = ['DOS', 'DDOS', 'INFILTRATION', 'BOTNET', 'WEBATTACK']
        medium_severity = ['BRUTEFORCE', 'PORTSCAN']
        
        attack_upper = attack_type.upper()
        if any(sev in attack_upper for sev in high_severity):
            return 'HIGH'
        elif any(sev in attack_upper for sev in medium_severity):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _process_alert(self, alert: Dict[str, Any]):
        """Process alert through FULL SOC Workflow (Tier 1 -> Security Team)."""
        print(f"DEBUG: Entering _process_alert for {alert.get('Attack')}")
        try:
            input_data = {
                "alert_data": alert,
                "current_status": "Monitoring - Live Traffic",
                "context_logs": "System live monitoring active",
                "current_incidents": "N/A"
            }
            
            # This triggers the full agentic chain
            print("DEBUG: Calling self.workflow.process()...")
            result = self.workflow.process(input_data)
            print(f"DEBUG: result received: {result.keys()}")
            
            final_status = result.get('current_status', 'Unknown')
            logger.info(f"🛡️ Workflow Complete: {final_status}")
            
            if "war_room_result" in result:
                 logger.warning("🔥 SECURITY TEAM (WAR ROOM) ENGAGED: Counter-measures generated.")
                
        except Exception as e:
            print(f"DEBUG: ERROR in _process_alert: {e}")
            logger.error(f"Error processing alert through workflow: {e}")

    def run_continuous(self, interval: int = 5):
        """
        Run continuous monitoring.
        
        Args:
            interval: Seconds to wait between captures (in addition to capture duration)
        """
        logger.info("🔄 Starting continuous monitoring... (Ctrl+C to stop)")
        
        try:
            cycle = 1
            while True:
                logger.info(f"\n{'='*60}")
                logger.info(f"Monitoring Cycle {cycle}")
                logger.info(f"{'='*60}")
                
                result = self.capture_and_analyze()
                
                logger.info(f"Cycle {cycle} complete. Waiting {interval}s...")
                time.sleep(interval)
                cycle += 1
                
        except KeyboardInterrupt:
            logger.info("\n⏹️  Monitoring stopped by user")
        except Exception as e:
            logger.error(f"❌ Fatal error: {e}")
            raise


def main():
    parser = argparse.ArgumentParser(description='Live Network Traffic Monitor for SOC')
    parser.add_argument(
        '--interface', '-i',
        default='eth0',
        help='Network interface to monitor (default: eth0)'
    )
    parser.add_argument(
        '--duration', '-d',
        type=int,
        default=10,
        help='Capture duration in seconds (default: 10)'
    )
    parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=0.7,
        help='Alert confidence threshold 0-1 (default: 0.7)'
    )
    parser.add_argument(
        '--interval', '-w',
        type=int,
        default=5,
        help='Wait interval between captures in seconds (default: 5)'
    )
    parser.add_argument(
        '--simulate', '-s',
        action='store_true',
        help='Simulate traffic from CSV dataset (use if pcap is missing)'
    )
    
    args = parser.parse_args()
    
    # Create monitor
    monitor = LiveTrafficMonitor(
        interface=args.interface,
        capture_duration=args.duration,
        threshold_confidence=args.threshold,
        simulate=args.simulate
    )
    
    # Continuous monitoring
    monitor.run_continuous(interval=args.interval)


if __name__ == '__main__':
    main()
