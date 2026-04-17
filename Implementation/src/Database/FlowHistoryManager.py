import sqlite3
import json
import os
import datetime
from typing import Dict, Any, List, Optional
try:
    from Implementation.utils.Logger import setup_logger
except ImportError:
    import logging
    def setup_logger(name):
        return logging.getLogger(name)

logger = setup_logger(__name__)

class FlowHistoryManager:
    """
    Manages long-term persistence for all network flows processed by the IDS.
    Used to provide historical context to LLM agents.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            # Resolve to Data folder
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            data_dir = os.path.join(base_dir, "Data")
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, "flow_history.db")
            
        self.db_path = db_path
        self._init_db()
        logger.info(f"FlowHistoryManager initialized at {self.db_path}")

    def _init_db(self):
        """Creates the flows table if it doesn't exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS flows (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        label TEXT,
                        confidence REAL,
                        raw_data TEXT
                    )
                """)
                # Create index for faster IP-based lookups
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON flows (src_ip)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flows (timestamp)")
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize Flow DB: {e}")

    def add_flow(self, flow_data: Dict[str, Any], label: str, confidence: float) -> bool:
        """
        Saves a flow and its prediction to the database.
        """
        try:
            timestamp = datetime.datetime.now().isoformat()
            src_ip = flow_data.get("Source IP", flow_data.get("src_ip", "Unknown"))
            dst_ip = flow_data.get("Destination IP", flow_data.get("dst_ip", "Unknown"))
            src_port = flow_data.get("Source Port", flow_data.get("src_port", 0))
            dst_port = flow_data.get("Destination Port", flow_data.get("dst_port", 0))
            protocol = flow_data.get("Protocol", "TCP")
            
            # Serialize full flow for debugging/deep analysis
            raw_data = json.dumps(flow_data)

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO flows (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, label, confidence, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, label, confidence, raw_data))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save flow: {e}")
            return False

    def get_ip_stats(self, ip_address: str, window_minutes: int = 5) -> Dict[str, Any]:
        """
        Retrieves statistics for a specific IP address within a time window.
        """
        try:
            now = datetime.datetime.now()
            since = (now - datetime.timedelta(minutes=window_minutes)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Count total flows
                cursor.execute("SELECT COUNT(*) as total FROM flows WHERE src_ip = ? AND timestamp > ?", (ip_address, since))
                total = cursor.fetchone()['total']
                
                if total == 0:
                    return {
                        "ip": ip_address,
                        "total_flows_last_n_min": 0,
                        "malicious_counts": {},
                        "unique_destinations": 0,
                        "unique_dst_ports": 0,
                        "threat_ratio": 0.0,
                        "window_minutes": window_minutes
                    }

                # Count malicious flows
                cursor.execute("SELECT label, COUNT(*) as count FROM flows WHERE src_ip = ? AND timestamp > ? AND label != 'BENIGN' GROUP BY label", (ip_address, since))
                malicious_labels = {row['label']: row['count'] for row in cursor.fetchall()}
                
                # Get unique destinations
                cursor.execute("SELECT COUNT(DISTINCT dst_ip) as dst_count FROM flows WHERE src_ip = ? AND timestamp > ?", (ip_address, since))
                unique_dst = cursor.fetchone()['dst_count']

                # Get unique destination ports (useful for port scan detection)
                cursor.execute("SELECT COUNT(DISTINCT dst_port) as port_count FROM flows WHERE src_ip = ? AND timestamp > ?", (ip_address, since))
                unique_ports = cursor.fetchone()['port_count']

                return {
                    "ip": ip_address,
                    "total_flows_last_n_min": total,
                    "malicious_counts": malicious_labels,
                    "unique_destinations": unique_dst,
                    "unique_dst_ports": unique_ports,
                    "threat_ratio": sum(malicious_labels.values()) / total if total > 0 else 0,
                    "window_minutes": window_minutes
                }
        except Exception as e:
            logger.error(f"Failed to query IP stats: {e}")
            return {}

    def get_recent_flows(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Returns the most recent flows for UI or quick check.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM flows ORDER BY id DESC LIMIT ?", (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get recent flows: {e}")
            return []

if __name__ == "__main__":
    # Self-test
    mgr = FlowHistoryManager()
    mgr.add_flow({"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "Source Port": 443}, "BENIGN", 0.99)
    print(mgr.get_ip_stats("192.168.1.100"))
