"""
Flow Deduplication and Alert Aggregation

Deduplicates flows and alerts to reduce noise and group related events,
enabling intelligent correlation and escalation throttling.
"""

from __future__ import annotations

import datetime as dt
import logging
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class DuplicateFlowSignature:
    """
    Generates signatures for flow deduplication.
    Used to identify similar flows even if exact 5-tuple differs.
    """
    
    @staticmethod
    def generate_strict_signature(src_ip: str, dst_ip: str, src_port: int,
                                dst_port: int, protocol: str) -> str:
        """
        Generate signature for exact 5-tuple matching.
        
        Args:
            src_ip, dst_ip, src_port, dst_port, protocol: Flow keys
            
        Returns:
            SHA256 hash of 5-tuple
        """
        key = f"{src_ip}:{dst_ip}:{src_port}:{dst_port}:{protocol}"
        return hashlib.sha256(key.encode()).hexdigest()
    
    @staticmethod
    def generate_loose_signature(src_ip: str, dst_ip: str, protocol: str) -> str:
        """
        Generate signature for protocol/address matching (ignores ports).
        Used for detecting similar flows with different ephemeral ports.
        
        Args:
            src_ip, dst_ip, protocol: Flow keys
            
        Returns:
            SHA256 hash
        """
        key = f"{src_ip}:{dst_ip}:{protocol}"
        return hashlib.sha256(key.encode()).hexdigest()
    
    @staticmethod
    def generate_directional_signature(src_ip: str, protocol: str) -> str:
        """
        Generate signature for source IP + protocol.
        Used for detecting traffic patterns from same source.
        
        Args:
            src_ip, protocol: Flow keys
            
        Returns:
            SHA256 hash
        """
        key = f"{src_ip}:{protocol}"
        return hashlib.sha256(key.encode()).hexdigest()


class DeduplicatedAlert:
    """Represents a deduplicated and aggregated alert."""
    
    def __init__(self, alert_id: str, alert_type: str, severity: str,
                 source_ip: str, destination_ip: str, first_seen: dt.datetime,
                 count: int = 1):
        self.alert_id = alert_id
        self.alert_type = alert_type
        self.severity = severity
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.count = count
        self.affected_ports = set()
        self.details = []
    
    def update(self, detail: Dict[str, Any] = None):
        """Update with a related duplicate alert."""
        self.last_seen = dt.datetime.utcnow()
        self.count += 1
        if detail:
            self.details.append(detail)
    
    def add_port(self, port: int):
        """Track affected port."""
        self.affected_ports.add(port)
    
    def get_expiry_seconds(self) -> int:
        """Get time since first alert (for expiry calculation)."""
        return int((dt.datetime.utcnow() - self.first_seen).total_seconds())
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "affected_ports": sorted(list(self.affected_ports)),
            "age_seconds": self.get_expiry_seconds(),
        }


class FlowDeduplicator:
    """
    Deduplicates flows and alerts to reduce noise.
    
    Strategies:
    1. Exact matching: Same 5-tuple within time window
    2. Loose matching: Same src/dst/protocol within time window (different ports)
    3. Pattern matching: Same source with similar behavior
    """
    
    def __init__(self, time_window_seconds: int = 300, max_stored_alerts: int = 10000):
        """
        Initialize deduplicator.
        
        Args:
            time_window_seconds: Window for deduplication grouping
            max_stored_alerts: Maximum deduplicated alerts to keep
        """
        self.time_window = dt.timedelta(seconds=time_window_seconds)
        self.max_stored = max_stored_alerts
        
        # Storage
        self.active_alerts: Dict[str, DeduplicatedAlert] = {}
        self.alert_by_strict_sig: Dict[str, str] = {}
        self.alert_by_loose_sig: Dict[str, str] = {}
        self.deduplicated_count = 0
    
    def _generate_alert_id(self, alert_type: str, src_ip: str, dst_ip: str) -> str:
        """Generate canonical alert ID."""
        key = f"{alert_type}:{src_ip}:{dst_ip}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def add_alert(self, alert_type: str, severity: str, source_ip: str,
                 destination_ip: str, src_port: Optional[int] = None,
                 dst_port: Optional[int] = None, protocol: str = "TCP",
                 detail: Optional[Dict[str, Any]] = None) -> Tuple[str, bool]:
        """
        Add or deduplicate an alert.
        
        Args:
            alert_type: Type of alert (e.g., "PORT_SCAN", "DDOS")
            severity: Alert severity (CRITICAL, HIGH, MEDIUM, LOW)
            source_ip: Source IP
            destination_ip: Destination IP
            src_port: Source port (optional)
            dst_port: Destination port (optional)
            protocol: Protocol (TCP, UDP, etc.)
            detail: Additional details to attach
            
        Returns:
            Tuple of (alert_id, is_new_alert)
                - alert_id: Canonical ID for this alert
                - is_new_alert: True if this is a new alert, False if deduplicated
        """
        alert_id = self._generate_alert_id(alert_type, source_ip, destination_ip)
        now = dt.datetime.utcnow()
        
        # Try to find existing alert
        if alert_id in self.active_alerts:
            existing = self.active_alerts[alert_id]
            
            # Check if still within time window
            if (now - existing.first_seen) <= self.time_window:
                existing.update(detail)
                if dst_port:
                    existing.add_port(dst_port)
                self.deduplicated_count += 1
                logger.debug(f"Deduplicated alert: {alert_id} (count={existing.count})")
                return (alert_id, False)
            else:
                # Expired, remove it
                del self.active_alerts[alert_id]
        
        # Create new alert
        new_alert = DeduplicatedAlert(
            alert_id, alert_type, severity, source_ip, destination_ip, now
        )
        if dst_port:
            new_alert.add_port(dst_port)
        if detail:
            new_alert.details.append(detail)
        
        # Store
        self.active_alerts[alert_id] = new_alert
        
        # Prune if over capacity
        if len(self.active_alerts) > self.max_stored:
            self._prune_expired_alerts()
        
        logger.info(f"New alert created: {alert_id}")
        return (alert_id, True)
    
    def _prune_expired_alerts(self):
        """Remove alerts outside time window."""
        now = dt.datetime.utcnow()
        to_remove = [
            alert_id for alert_id, alert in self.active_alerts.items()
            if (now - alert.first_seen) > self.time_window
        ]
        
        for alert_id in to_remove:
            del self.active_alerts[alert_id]
        
        if to_remove:
            logger.debug(f"Pruned {len(to_remove)} expired alerts")
    
    def get_active_alerts(self) -> List[DeduplicatedAlert]:
        """Get all currently active alerts."""
        self._prune_expired_alerts()
        return list(self.active_alerts.values())
    
    def get_active_alerts_json(self) -> List[Dict[str, Any]]:
        """Export active alerts as JSON."""
        return [alert.to_dict() for alert in self.get_active_alerts()]
    
    def get_alerts_by_severity(self, severity: str) -> List[DeduplicatedAlert]:
        """Get alerts by severity level."""
        return [
            alert for alert in self.get_active_alerts()
            if alert.severity == severity
        ]
    
    def get_alerts_by_source(self, source_ip: str) -> List[DeduplicatedAlert]:
        """Get all alerts originating from a source IP."""
        return [
            alert for alert in self.get_active_alerts()
            if alert.source_ip == source_ip
        ]
    
    def get_alerts_by_type(self, alert_type: str) -> List[DeduplicatedAlert]:
        """Get alerts of a specific type."""
        return [
            alert for alert in self.get_active_alerts()
            if alert.alert_type == alert_type
        ]
    
    def suppress_alert(self, alert_id: str) -> bool:
        """Suppress an alert from further escalation."""
        if alert_id in self.active_alerts:
            del self.active_alerts[alert_id]
            logger.info(f"Suppressed alert: {alert_id}")
            return True
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        alerts = self.get_active_alerts()
        
        # Group by severity
        by_severity = defaultdict(int)
        for alert in alerts:
            by_severity[alert.severity] += 1
        
        # Group by type
        by_type = defaultdict(int)
        for alert in alerts:
            by_type[alert.alert_type] += 1
        
        # Top sources
        top_sources = defaultdict(int)
        for alert in alerts:
            top_sources[alert.source_ip] += 1
        top_sources = sorted(top_sources.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_active": len(alerts),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "total_deduplicated": self.deduplicated_count,
            "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_sources],
            "storage_usage": f"{len(self.active_alerts)}/{self.max_stored}",
        }


class AlertCorrelator:
    """
    Correlates multiple deduplicated alerts to detect coordinated attacks.
    """
    
    def __init__(self):
        self.correlations: Dict[str, List[str]] = {}  # source_ip -> alert_ids
    
    def correlate_alerts(self, deduplicator: FlowDeduplicator) -> List[Dict[str, Any]]:
        """
        Find correlated alerts that might indicate coordinated activity.
        
        Returns:
            List of correlation groups
        """
        alerts = deduplicator.get_active_alerts()
        correlations = []
        
        # Group by source IP
        by_source = defaultdict(list)
        for alert in alerts:
            by_source[alert.source_ip].append(alert)
        
        # Find multi-pattern attacks from same source
        for source_ip, source_alerts in by_source.items():
            if len(source_alerts) > 2:
                # Multiple alert types from same source = coordinated attack
                alert_types = set(a.alert_type for a in source_alerts)
                if len(alert_types) > 1:
                    correlations.append({
                        "type": "MULTI_PATTERN_ATTACK",
                        "source_ip": source_ip,
                        "alert_count": len(source_alerts),
                        "alert_types": list(alert_types),
                        "severity": "CRITICAL",
                        "description": f"Source {source_ip} exhibiting {len(alert_types)} different attack patterns",
                    })
        
        # Group by destination IP (potential target)
        by_dest = defaultdict(list)
        for alert in alerts:
            by_dest[alert.destination_ip].append(alert)
        
        # Many sources targeting one destination = possible DDoS
        for dest_ip, dest_alerts in by_dest.items():
            if len(dest_alerts) > 5:
                sources = set(a.source_ip for a in dest_alerts)
                if len(sources) > 3:
                    correlations.append({
                        "type": "POTENTIAL_DDOS",
                        "destination_ip": dest_ip,
                        "attacking_sources": len(sources),
                        "alert_count": len(dest_alerts),
                        "severity": "CRITICAL",
                        "description": f"{len(sources)} sources attacking {dest_ip}",
                    })
        
        return correlations
