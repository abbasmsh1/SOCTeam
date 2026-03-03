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

class MetadataManager:
    """
    Manages structured persistence for SOC incidents using SQLite.
    Stores alerts, report paths, and technical remediation actions.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        # Resolve DB path to project root
        if db_path is None:
            # Look for project root by identifying Reports folder
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            reports_dir = os.path.join(base_dir, "Reports")
            if not os.path.exists(reports_dir):
                # Fallback to local Reports if run from root
                reports_dir = os.path.join(os.getcwd(), "Reports")
                os.makedirs(reports_dir, exist_ok=True)
            db_path = os.path.join(reports_dir, "incidents.db")
            
        self.db_path = db_path
        self._init_db()
        logger.info(f"MetadataManager initialized. DB path: {self.db_path}")

    def _init_db(self):
        """Creates the incidents table if it doesn't exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS incidents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_id TEXT UNIQUE,
                        timestamp TEXT,
                        attack_type TEXT,
                        severity TEXT,
                        report_path TEXT,
                        remediation_summary TEXT,
                        raw_data TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize metadata DB: {e}")

    def save_incident(self, final_result: Dict[str, Any]) -> bool:
        """
        Saves a processed incident into the structured database.
        """
        try:
            # Extract core fields
            alert_id = str(final_result.get("alert_data", {}).get("id", "UNK-" + str(datetime.datetime.now().timestamp())))
            timestamp = final_result.get("timestamp", datetime.datetime.utcnow().isoformat())
            attack_type = final_result.get("tier1_analysis", {}).get("raw_alert", {}).get("Attack", "Unknown")
            severity = final_result.get("final_severity", "Unknown")
            report_path = final_result.get("report_path", "N/A")
            
            # Serialize complex objects
            remediation = final_result.get("remediation", {})
            remediation_summary = json.dumps(remediation)
            
            raw_data = json.dumps(final_result.get("alert_data", {}))

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO incidents (alert_id, timestamp, attack_type, severity, report_path, remediation_summary, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (alert_id, timestamp, attack_type, severity, report_path, remediation_summary, raw_data))
                conn.commit()
            
            logger.info(f"Successfully saved incident metadata for: {alert_id}")
            return True
        except sqlite3.IntegrityError:
            logger.warning(f"Incident with ID {alert_id} already exists in Metadata Repository.")
            return False
        except Exception as e:
            logger.error(f"Failed to save incident metadata: {e}")
            return False

    def query_history(self, limit: int = 50, min_severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieves a list of processed incidents.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = "SELECT * FROM incidents"
                params = []
                
                if min_severity:
                    query += " WHERE severity = ?"
                    params.append(min_severity)
                
                query += " ORDER BY id DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, tuple(params))
                rows = cursor.fetchall()
                
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to query incident history: {e}")
            return []

if __name__ == "__main__":
    # Self-test
    mgr = MetadataManager()
    sample = {
        "alert_data": {"id": "test-sql-incident", "Attack": "SQLi"},
        "final_severity": "High",
        "report_path": "Reports/test.md",
        "remediation": {"status": "BLOCKED"}
    }
    mgr.save_incident(sample)
    print(mgr.query_history(limit=5))
