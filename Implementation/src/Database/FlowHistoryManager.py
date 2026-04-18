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
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON flows (dst_ip)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flows (timestamp)")
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize Flow DB: {e}")

    @staticmethod
    def resolve_src_ip(flow_data: Dict[str, Any]) -> str:
        """Match IDS / dashboard field names so persisted rows join workflow lookups."""
        if not isinstance(flow_data, dict):
            return "Unknown"
        v = (
            flow_data.get("SourceIP")
            or flow_data.get("Source IP")
            or flow_data.get("src_ip")
            or flow_data.get("IPV4_SRC_ADDR")
            or flow_data.get("ipv4_src_addr")
        )
        if v is None:
            return "Unknown"
        s = str(v).strip()
        return s if s and s.lower() != "nan" else "Unknown"

    @staticmethod
    def resolve_dst_ip(flow_data: Dict[str, Any]) -> str:
        if not isinstance(flow_data, dict):
            return "Unknown"
        v = (
            flow_data.get("DestinationIP")
            or flow_data.get("Destination IP")
            or flow_data.get("dst_ip")
            or flow_data.get("IPV4_DST_ADDR")
            or flow_data.get("ipv4_dst_addr")
        )
        if v is None:
            return "Unknown"
        s = str(v).strip()
        return s if s and s.lower() != "nan" else "Unknown"

    def add_flow(self, flow_data: Dict[str, Any], label: str, confidence: float) -> bool:
        """
        Saves a flow and its prediction to the database.
        """
        try:
            timestamp = datetime.datetime.now().isoformat()
            src_ip = self.resolve_src_ip(flow_data)
            dst_ip = self.resolve_dst_ip(flow_data)
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

    def get_ip_stats(
        self,
        ip_address: str,
        window_minutes: int = 5,
        role: str = "src",
    ) -> Dict[str, Any]:
        """
        Statistics for an IP within a sliding window.

        ``role``:
          - ``src``: rows where this IP is the source (attacker-centric).
          - ``either``: rows where this IP is source **or** destination (broader footprint).
        """
        try:
            now = datetime.datetime.now()
            since = (now - datetime.timedelta(minutes=window_minutes)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                if role == "either":
                    where_time = "AND timestamp > ?"
                    base_params: List[Any] = [since]
                    ip_filter_src = "(src_ip = ? OR dst_ip = ?)"
                    ip_params = [ip_address, ip_address]
                else:
                    where_time = "AND timestamp > ?"
                    base_params = [since]
                    ip_filter_src = "src_ip = ?"
                    ip_params = [ip_address]

                # Count total flows
                cursor.execute(
                    f"SELECT COUNT(*) as total FROM flows WHERE {ip_filter_src} {where_time}",
                    tuple(ip_params + base_params),
                )
                total = cursor.fetchone()['total']
                
                if total == 0:
                    return {
                        "ip": ip_address,
                        "total_flows_last_n_min": 0,
                        "malicious_counts": {},
                        "unique_destinations": 0,
                        "unique_dst_ports": 0,
                        "threat_ratio": 0.0,
                        "window_minutes": window_minutes,
                        "role": role,
                    }

                cursor.execute(
                    f"SELECT label, COUNT(*) as count FROM flows WHERE {ip_filter_src} {where_time} AND label != 'BENIGN' GROUP BY label",
                    tuple(ip_params + base_params),
                )
                malicious_labels = {row['label']: row['count'] for row in cursor.fetchall()}

                if role == "either":
                    cursor.execute(
                        """
                        SELECT COUNT(DISTINCT CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END) as peer_cnt
                        FROM flows WHERE (src_ip = ? OR dst_ip = ?) AND timestamp > ?
                        """,
                        (ip_address, ip_address, ip_address, since),
                    )
                    unique_dst = int(cursor.fetchone()["peer_cnt"] or 0)
                else:
                    cursor.execute(
                        "SELECT COUNT(DISTINCT dst_ip) as dst_count FROM flows WHERE src_ip = ? AND timestamp > ?",
                        (ip_address, since),
                    )
                    unique_dst = cursor.fetchone()['dst_count']

                if role == "either":
                    cursor.execute(
                        f"SELECT COUNT(DISTINCT dst_port) as port_count FROM flows WHERE {ip_filter_src} {where_time}",
                        tuple(ip_params + base_params),
                    )
                else:
                    cursor.execute(
                        "SELECT COUNT(DISTINCT dst_port) as port_count FROM flows WHERE src_ip = ? AND timestamp > ?",
                        (ip_address, since),
                    )
                unique_ports = cursor.fetchone()['port_count']

                return {
                    "ip": ip_address,
                    "total_flows_last_n_min": total,
                    "malicious_counts": malicious_labels,
                    "unique_destinations": unique_dst,
                    "unique_dst_ports": unique_ports,
                    "threat_ratio": sum(malicious_labels.values()) / total if total > 0 else 0,
                    "window_minutes": window_minutes,
                    "role": role,
                }
        except Exception as e:
            logger.error(f"Failed to query IP stats: {e}")
            return {}

    def get_recent_flows_for_ip(
        self,
        ip_address: str,
        window_minutes: int = 60,
        limit: int = 25,
        role: str = "src",
    ) -> List[Dict[str, Any]]:
        """
        Recent persisted flows involving this IP (for LLM and analysts).

        ``role``: ``src`` | ``dst`` | ``either``
        """
        if ip_address in ("", "Unknown", "unknown"):
            return []
        try:
            now = datetime.datetime.now()
            since = (now - datetime.timedelta(minutes=window_minutes)).isoformat()
            if role == "either":
                clause = "(src_ip = ? OR dst_ip = ?)"
                ip_params = (ip_address, ip_address)
            elif role == "dst":
                clause = "dst_ip = ?"
                ip_params = (ip_address,)
            else:
                clause = "src_ip = ?"
                ip_params = (ip_address,)

            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, label, confidence
                    FROM flows
                    WHERE {clause} AND timestamp > ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    ip_params + (since, limit),
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to list recent flows for IP: {e}")
            return []

    def format_history_for_llm(
        self,
        src_ip: str,
        dst_ip: Optional[str] = None,
        windows: tuple = (5, 60),
    ) -> str:
        """Human-readable database history for SOC LLM prompts."""
        lines: List[str] = [
            "### DATABASE: Flow history (IDS persistence)",
            f"- **Primary source IP (alert):** `{src_ip}`",
        ]
        if dst_ip and dst_ip not in ("Unknown", ""):
            lines.append(f"- **Primary destination IP (alert):** `{dst_ip}`")
        if src_ip in ("", "Unknown"):
            lines.append("- **Note:** Source IP could not be resolved; stats may be empty until flow keys align (`IPV4_SRC_ADDR`, etc.).")
            return "\n".join(lines)

        for w in windows:
            st = self.get_ip_stats(src_ip, window_minutes=int(w), role="src")
            lines.append(
                f"- **Last {w} min (as source):** flows={st.get('total_flows_last_n_min', 0)}, "
                f"non-BENIGN counts={st.get('malicious_counts', {})}, "
                f"unique_dst={st.get('unique_destinations', 0)}, "
                f"threat_ratio~{float(st.get('threat_ratio', 0.0)):.3f}"
            )
        ev = self.get_ip_stats(src_ip, window_minutes=max(windows), role="either")
        lines.append(
            f"- **Last {max(windows)} min (src OR dst involvement):** flows={ev.get('total_flows_last_n_min', 0)}, "
            f"non-BENIGN={ev.get('malicious_counts', {})}"
        )

        recent = self.get_recent_flows_for_ip(src_ip, window_minutes=max(windows), limit=20, role="src")
        if not recent:
            recent = self.get_recent_flows_for_ip(src_ip, window_minutes=max(windows), limit=20, role="either")
        if recent:
            lines.append("- **Recent flow records (newest first, abridged):**")
            for row in recent[:15]:
                lines.append(
                    f"  - {row.get('timestamp')} | {row.get('src_ip')}→{row.get('dst_ip')} | "
                    f"{row.get('protocol')}:{row.get('src_port')}->{row.get('dst_port')} | "
                    f"label={row.get('label')} conf={row.get('confidence')}"
                )
        else:
            lines.append("- **Recent flow records:** none in window (database empty or IP not yet stored under resolved address).")

        return "\n".join(lines)

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
