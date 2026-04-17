"""
Live Traffic Monitor - Unified Monitoring Orchestrator

Coordinates real-time packet capture, flow tracking, threat detection,
and alert deduplication across multiple network interfaces.
"""

from __future__ import annotations

import logging
import threading
import time
import queue
from typing import Any, Dict, List, Optional
from collections import defaultdict
import datetime as dt

# Local imports
try:
    from Implementation.src.Database.LiveFlowTracker import LiveFlowTracker
    from Implementation.src.Database.FlowAnalytics import FlowAnalytics
    from Implementation.src.Database.NetworkSegmentMonitor import NetworkSegmentMonitor
    from Implementation.src.Database.FlowDeduplicator import FlowDeduplicator, AlertCorrelator
except ImportError:
    # Fallback for testing
    LiveFlowTracker = None
    FlowAnalytics = None
    NetworkSegmentMonitor = None
    FlowDeduplicator = None

logger = logging.getLogger(__name__)


class LiveTrafficMonitor:
    """
    Unified monitoring orchestrator.
    
    Combines:
    - Real-time flow tracking (LiveFlowTracker)
    - Pattern detection (FlowAnalytics)
    - Multi-interface monitoring (NetworkSegmentMonitor)
    - Alert deduplication (FlowDeduplicator)
    """
    
    def __init__(self, interfaces: Optional[List[str]] = None,
                 segment_mapping: Optional[Dict[str, str]] = None,
                 flow_timeout_seconds: int = 300,
                 capture_timeout_seconds: int = 10,
                 max_flows_per_interface: int = 10000):
        """
        Initialize live traffic monitor.
        
        Args:
            interfaces: List of interface names (e.g., ['eth0', 'eth1'])
            segment_mapping: Dict mapping IP ranges to segment names
            flow_timeout_seconds: Flow timeout for pruning
            capture_timeout_seconds: Time per capture window
            max_flows_per_interface: Max flows per interface
        """
        self.interfaces = interfaces or ["eth0"]
        self.capture_timeout = capture_timeout_seconds
        self.flow_timeout = flow_timeout_seconds
        self.max_flows = max_flows_per_interface
        
        # Core components
        self.flow_tracker = LiveFlowTracker(
            max_flows=max_flows_per_interface,
            timeout_seconds=flow_timeout_seconds
        )
        self.analytics = FlowAnalytics(self.flow_tracker)
        self.network_monitor = NetworkSegmentMonitor(segment_mapping=segment_mapping)
        self.deduplicator = FlowDeduplicator(time_window_seconds=300)
        self.correlator = AlertCorrelator()
        
        # Initialize network interfaces
        for interface in self.interfaces:
            self.network_monitor.add_interface(interface)
        
        # Statistics
        self.stats = {
            "packets_processed": 0,
            "flows_tracked": 0,
            "alerts_created": 0,
            "alerts_deduplicated": 0,
            "patterns_detected": 0,
            "start_time": dt.datetime.utcnow(),
        }
        
        # Control
        self.running = False
        self.monitor_thread = None
        self.lock = threading.RLock()
        
        # Alert queue for external processing
        self.alert_queue = queue.Queue(maxsize=1000)
    
    def start_monitoring(self) -> bool:
        """Start background monitoring thread."""
        with self.lock:
            if self.running:
                logger.warning("Monitor already running")
                return False
            
            self.running = True
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True,
                name="LiveTrafficMonitor"
            )
            self.monitor_thread.start()
            logger.info(f"Started live traffic monitor on {self.interfaces}")
            return True
    
    def stop_monitoring(self) -> bool:
        """Stop background monitoring thread."""
        with self.lock:
            if not self.running:
                logger.warning("Monitor not running")
                return False
            
            self.running = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            
            logger.info("Stopped live traffic monitor")
            return True
    
    def _monitoring_loop(self):
        """Main monitoring loop (runs in background thread)."""
        logger.debug("Monitoring loop started")
        
        while self.running:
            try:
                # Capture and analyze traffic
                self.capture_and_analyze()
                time.sleep(0.1)  # Brief pause to prevent busy-waiting
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
    
    def capture_and_analyze(self):
        """
        Capture traffic, extract flows, run IDS predictions,
        detect patterns, and deduplicate alerts.
        """
        try:
            # Step 1: Capture flows from each interface
            captured_flows = self._capture_flows()
            if not captured_flows:
                return
            
            # Step 2: Update flow trackers
            self._update_flow_trackers(captured_flows)
            
            # Step 3: Run pattern detection
            patterns = self._detect_patterns()
            
            # Step 4: Create and deduplicate alerts
            self._process_alerts(captured_flows, patterns)
            
            # Step 5: Check for coordinated attacks
            correlations = self.correlator.correlate_alerts(self.deduplicator)
            self._process_correlations(correlations)
            
        except Exception as e:
            logger.error(f"Error in capture_and_analyze: {e}", exc_info=True)
    
    def _capture_flows(self) -> List[Dict[str, Any]]:
        """
        Capture flows from network interfaces.
        
        Returns:
            List of flow records
        """
        # This is a placeholder - in production, integrate with:
        # - scapy for live capture
        # - CICFlowMeter for flow extraction
        # - pcap file replay for testing
        
        # For now, return empty list (no actual packet capture)
        # In real implementation, this would:
        # 1. Call tcpdump or scapy to capture packets
        # 2. Extract flows using CICFlowMeter
        # 3. Return flow records
        return []
    
    def add_flow(self, interface: str, src_ip: str, dst_ip: str, src_port: int,
                dst_port: int, protocol: str, packet_info: Dict[str, Any]) -> Optional[str]:
        """
        Add a flow from external packet capture.
        
        Args:
            interface: Interface name
            src_ip, dst_ip: IP addresses
            src_port, dst_port: Ports
            protocol: Protocol (TCP, UDP, etc.)
            packet_info: Packet details (size, timestamp, etc.)
            
        Returns:
            Flow ID or None
        """
        with self.lock:
            # Track in live tracker
            flow_id = self.flow_tracker.add_or_update_flow(
                src_ip, dst_ip, src_port, dst_port, protocol, packet_info
            )
            
            # Track in network segment monitor
            self.network_monitor.add_flow_update(
                interface, src_ip, dst_ip, src_port, dst_port, protocol, packet_info
            )
            
            # Update statistics
            self.stats["packets_processed"] += 1
            self.stats["flows_tracked"] = len(self.flow_tracker.get_active_flows())
            
            return flow_id
    
    def add_flow_prediction(self, src_ip: str, dst_ip: str, src_port: int,
                           dst_port: int, protocol: str, label: str,
                           confidence: float):
        """
        Add IDS prediction for a flow.
        
        Args:
            src_ip, dst_ip, src_port, dst_port, protocol: Flow keys
            label: Predicted label (e.g., "DDoS", "PortScan")
            confidence: Prediction confidence (0-1)
        """
        with self.lock:
            # Update flow tracking
            self.flow_tracker.update_flow_prediction(
                src_ip, dst_ip, src_port, dst_port, protocol, label, confidence
            )
            
            # Create alert if confidence high enough
            if confidence >= 0.7:
                severity = self._map_confidence_to_severity(confidence)
                alert_id, is_new = self.deduplicator.add_alert(
                    alert_type=label,
                    severity=severity,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    detail={
                        "confidence": confidence,
                        "label": label,
                    }
                )
                
                if is_new:
                    self.stats["alerts_created"] += 1
                    self._queue_alert(alert_id, label, severity, src_ip, dst_ip)
                else:
                    self.stats["alerts_deduplicated"] += 1
    
    def _update_flow_trackers(self, flows: List[Dict[str, Any]]):
        """Update flow tracking from captured flows."""
        for flow in flows:
            self.add_flow(
                interface=flow.get("interface", self.interfaces[0]),
                src_ip=flow["src_ip"],
                dst_ip=flow["dst_ip"],
                src_port=flow["src_port"],
                dst_port=flow["dst_port"],
                protocol=flow.get("protocol", "TCP"),
                packet_info={"size": flow.get("size", 0)}
            )
    
    def _detect_patterns(self) -> List[Dict[str, Any]]:
        """Run pattern detection on active flows."""
        with self.lock:
            patterns = self.analytics.analyze_flows()
            self.stats["patterns_detected"] = len(patterns)
            return patterns
    
    def _process_alerts(self, flows: List[Dict[str, Any]], patterns: List[Any]):
        """Create and deduplicate alerts from flows and patterns."""
        with self.lock:
            # Process pattern-based alerts
            for pattern in patterns:
                severity = "CRITICAL" if pattern.severity == "CRITICAL" else pattern.severity
                
                for affected_ip in pattern.affected_ips:
                    alert_id, is_new = self.deduplicator.add_alert(
                        alert_type=pattern.pattern_type,
                        severity=severity,
                        source_ip=affected_ip,
                        destination_ip="0.0.0.0",
                        detail={
                            "description": pattern.description,
                            "confidence": pattern.confidence,
                        }
                    )
                    
                    if is_new:
                        self.stats["alerts_created"] += 1
                        self._queue_alert(
                            alert_id,
                            pattern.pattern_type,
                            severity,
                            affected_ip,
                            "0.0.0.0"
                        )
    
    def _process_correlations(self, correlations: List[Dict[str, Any]]):
        """Process correlated attacks."""
        with self.lock:
            for corr in correlations:
                severity = corr.get("severity", "HIGH")
                alert_type = corr.get("type", "CORRELATED_ATTACK")
                
                # Get representative source IPs
                sources = corr.get("affected_sources", [corr.get("source_ip", "0.0.0.0")])
                dest = corr.get("destination_ip", "0.0.0.0")
                
                for src_ip in sources[:3]:  # Limit to 3 sources per correlation
                    alert_id, is_new = self.deduplicator.add_alert(
                        alert_type=alert_type,
                        severity=severity,
                        source_ip=src_ip,
                        destination_ip=dest,
                        detail={"correlation": corr}
                    )
                    
                    if is_new:
                        self._queue_alert(alert_id, alert_type, severity, src_ip, dest)
    
    def _queue_alert(self, alert_id: str, alert_type: str, severity: str,
                    src_ip: str, dst_ip: str):
        """Queue alert for external processing."""
        try:
            alert = {
                "alert_id": alert_id,
                "type": alert_type,
                "severity": severity,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "timestamp": dt.datetime.utcnow().isoformat(),
            }
            self.alert_queue.put_nowait(alert)
            logger.info(f"Queued alert: {alert_id} ({alert_type})")
        except queue.Full:
            logger.warning("Alert queue full, dropping alert")
    
    def get_next_alert(self, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """
        Get next alert from queue.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Alert dict or None if queue empty
        """
        try:
            return self.alert_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def _map_confidence_to_severity(self, confidence: float) -> str:
        """Map IDS confidence to alert severity."""
        if confidence >= 0.95:
            return "CRITICAL"
        elif confidence >= 0.8:
            return "HIGH"
        elif confidence >= 0.65:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_active_flows(self) -> Dict[str, Any]:
        """Get active flows and statistics."""
        with self.lock:
            return {
                "flows": self.flow_tracker.export_flows_json(),
                "statistics": self.flow_tracker.get_summary_statistics(),
            }
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active deduplicated alerts."""
        with self.lock:
            return self.deduplicator.get_active_alerts_json()
    
    def get_analytics_report(self) -> Dict[str, Any]:
        """Get comprehensive analytics report."""
        with self.lock:
            return self.analytics.get_analysis_report()
    
    def get_segment_report(self) -> Dict[str, Any]:
        """Get network segment monitoring report."""
        with self.lock:
            return self.network_monitor.get_segment_report()
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        with self.lock:
            uptime = (dt.datetime.utcnow() - self.stats["start_time"]).total_seconds()
            return {
                "uptime_seconds": uptime,
                "packets_processed": self.stats["packets_processed"],
                "flows_tracked": self.stats["flows_tracked"],
                "alerts_created": self.stats["alerts_created"],
                "alerts_deduplicated": self.stats["alerts_deduplicated"],
                "patterns_detected": self.stats["patterns_detected"],
                "dedup_statistics": self.deduplicator.get_statistics(),
                "active_alerts": len(self.deduplicator.get_active_alerts()),
                "alert_queue_size": self.alert_queue.qsize(),
            }
    
    def export_full_report(self) -> Dict[str, Any]:
        """Export comprehensive monitoring report."""
        with self.lock:
            return {
                "timestamp": dt.datetime.utcnow().isoformat(),
                "monitor": "LiveTrafficMonitor",
                "running": self.running,
                "interfaces": self.interfaces,
                "statistics": self.get_monitoring_statistics(),
                "flows": self.get_active_flows(),
                "alerts": self.get_active_alerts(),
                "analytics": self.get_analytics_report(),
                "segments": self.get_segment_report(),
            }
