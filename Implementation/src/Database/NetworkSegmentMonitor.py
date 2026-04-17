"""
Multi-Interface Network Monitoring

Tracks flows across multiple network interfaces simultaneously,
enabling detection of lateral movement and cross-segment attacks.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict

from Implementation.src.Database.LiveFlowTracker import LiveFlowTracker, FlowKey

logger = logging.getLogger(__name__)


class InterfaceTracker:
    """Tracks flows for a single network interface."""
    
    def __init__(self, interface_name: str, max_flows: int = 10000, timeout_seconds: int = 300):
        """
        Initialize interface tracker.
        
        Args:
            interface_name: Interface name (e.g., 'eth0', 'eth1')
            max_flows: Maximum concurrent flows to track
            timeout_seconds: Time before inactive flows are pruned
        """
        self.interface_name = interface_name
        self.tracker = LiveFlowTracker(max_flows=max_flows, timeout_seconds=timeout_seconds)
        self.created_at = dt.datetime.utcnow()
        self.packets_captured = 0
        self.bytes_captured = 0
        self.lock = threading.RLock()
    
    def add_flow_update(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                       protocol: str, packet_info: Dict[str, Any]) -> Optional[str]:
        """Add or update a flow."""
        with self.lock:
            self.packets_captured += 1
            self.bytes_captured += packet_info.get("size", 0)
            return self.tracker.add_or_update_flow(
                src_ip, dst_ip, src_port, dst_port, protocol, packet_info
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get interface statistics."""
        with self.lock:
            base_stats = self.tracker.get_summary_statistics()
            return {
                "interface": self.interface_name,
                "created_at": self.created_at.isoformat(),
                "packets_captured": self.packets_captured,
                "bytes_captured": self.bytes_captured,
                **base_stats
            }
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as dictionary."""
        with self.lock:
            return {
                "interface": self.interface_name,
                "flows": self.tracker.export_flows_json(),
                "statistics": self.get_statistics(),
            }


class LateralMovementDetector:
    """Detects lateral movement across network segments."""
    
    def __init__(self, segment_mapping: Optional[Dict[str, str]] = None):
        """
        Initialize detector.
        
        Args:
            segment_mapping: Dict mapping IP ranges to segment names
                           e.g., {"10.0.1.0/24": "internal_segment"}
        """
        self.segment_mapping = segment_mapping or {}
        self.detected_movements: List[Dict[str, Any]] = []
    
    def _get_segment(self, ip: str) -> Optional[str]:
        """Get segment for an IP."""
        for ip_range, segment in self.segment_mapping.items():
            # Simple subnet check (in production, use ipaddress library)
            if ip.startswith(ip_range.split("/")[0].rsplit(".", 1)[0]):
                return segment
        return None
    
    def detect_lateral_movement(self, interfaces: Dict[str, InterfaceTracker]) -> List[Dict[str, Any]]:
        """
        Detect lateral movement across interfaces.
        
        Returns:
            List of suspicious lateral movement patterns
        """
        movements = []
        cross_interface_flows = defaultdict(set)
        
        # Map flows across interfaces
        for interface_name, tracker in interfaces.items():
            flows = tracker.tracker.get_active_flows()
            for flow in flows:
                pair = (flow.key.src_ip, flow.key.dst_ip)
                cross_interface_flows[pair].add(interface_name)
        
        # Detect cross-interface communication
        for (src_ip, dst_ip), interfaces_set in cross_interface_flows.items():
            if len(interfaces_set) > 1:
                src_segment = self._get_segment(src_ip)
                dst_segment = self._get_segment(dst_ip)
                
                # Different segments = lateral movement
                if src_segment and dst_segment and src_segment != dst_segment:
                    movements.append({
                        "type": "CROSS_SEGMENT_MOVEMENT",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "source_segment": src_segment,
                        "destination_segment": dst_segment,
                        "interfaces": list(interfaces_set),
                        "severity": "HIGH",
                        "timestamp": dt.datetime.utcnow().isoformat(),
                    })
        
        self.detected_movements = movements
        return movements


class NetworkSegmentMonitor:
    """
    Monitors multiple network interfaces simultaneously,
    tracking flows across segments and detecting lateral movement.
    """
    
    def __init__(self, segment_mapping: Optional[Dict[str, str]] = None):
        """
        Initialize network segment monitor.
        
        Args:
            segment_mapping: Dict mapping IP ranges to segment names
        """
        self.interfaces: Dict[str, InterfaceTracker] = {}
        self.lateral_detector = LateralMovementDetector(segment_mapping)
        self.lock = threading.RLock()
        self.created_at = dt.datetime.utcnow()
    
    def add_interface(self, interface_name: str, max_flows: int = 10000,
                     timeout_seconds: int = 300) -> InterfaceTracker:
        """
        Register a network interface for monitoring.
        
        Args:
            interface_name: Interface name (e.g., 'eth0', 'eth1')
            max_flows: Maximum concurrent flows per interface
            timeout_seconds: Flow timeout
            
        Returns:
            InterfaceTracker instance
        """
        with self.lock:
            if interface_name not in self.interfaces:
                tracker = InterfaceTracker(interface_name, max_flows, timeout_seconds)
                self.interfaces[interface_name] = tracker
                logger.info(f"Added interface monitor for {interface_name}")
            return self.interfaces[interface_name]
    
    def remove_interface(self, interface_name: str) -> bool:
        """Remove interface from monitoring."""
        with self.lock:
            if interface_name in self.interfaces:
                del self.interfaces[interface_name]
                logger.info(f"Removed interface monitor for {interface_name}")
                return True
            return False
    
    def add_flow_update(self, interface_name: str, src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int, protocol: str,
                       packet_info: Dict[str, Any]) -> Optional[str]:
        """Add or update a flow from a specific interface."""
        with self.lock:
            if interface_name not in self.interfaces:
                self.add_interface(interface_name)
            
            return self.interfaces[interface_name].add_flow_update(
                src_ip, dst_ip, src_port, dst_port, protocol, packet_info
            )
    
    def get_interface_tracker(self, interface_name: str) -> Optional[InterfaceTracker]:
        """Get tracker for a specific interface."""
        with self.lock:
            return self.interfaces.get(interface_name)
    
    def get_aggregate_flows(self) -> Dict[str, Any]:
        """
        Get aggregate flows across all interfaces (deduplicated by 5-tuple).
        """
        with self.lock:
            aggregate_tracker = LiveFlowTracker()
            
            for interface_name, tracker in self.interfaces.items():
                flows = tracker.tracker.get_active_flows()
                for flow in flows:
                    # Merge into aggregate tracker
                    aggregate_tracker.add_or_update_flow(
                        flow.key.src_ip,
                        flow.key.dst_ip,
                        flow.key.src_port,
                        flow.key.dst_port,
                        flow.key.protocol,
                        {
                            "size": flow.byte_count,
                            "direction": "fwd",
                            "_interface": interface_name,
                        }
                    )
            
            return {
                "flows": aggregate_tracker.export_flows_json(),
                "statistics": aggregate_tracker.get_summary_statistics(),
            }
    
    def get_flows_by_interface(self, interface_name: str) -> Dict[str, Any]:
        """Get flows for a specific interface."""
        with self.lock:
            tracker = self.interfaces.get(interface_name)
            if not tracker:
                return {"error": f"Interface {interface_name} not found"}
            
            return tracker.to_dict()
    
    def get_flows_crossing_interfaces(self) -> Dict[str, Any]:
        """Get flows that traverse multiple interfaces."""
        with self.lock:
            cross_interface = defaultdict(set)
            
            for interface_name, tracker in self.interfaces.items():
                flows = tracker.tracker.get_active_flows()
                for flow in flows:
                    key = (flow.key.src_ip, flow.key.dst_ip, flow.key.protocol)
                    cross_interface[key].add(interface_name)
            
            # Filter to only flows crossing interfaces
            crossing = {
                str(key): list(interfaces)
                for key, interfaces in cross_interface.items()
                if len(interfaces) > 1
            }
            
            return {
                "count": len(crossing),
                "flows": crossing,
            }
    
    def detect_lateral_movement(self) -> List[Dict[str, Any]]:
        """Detect lateral movement across network segments."""
        with self.lock:
            return self.lateral_detector.detect_lateral_movement(self.interfaces)
    
    def get_interface_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for each interface."""
        with self.lock:
            stats = {}
            for interface_name, tracker in self.interfaces.items():
                stats[interface_name] = tracker.get_statistics()
            return stats
    
    def get_aggregate_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics across all interfaces."""
        with self.lock:
            total_packets = 0
            total_bytes = 0
            total_flows = 0
            
            for tracker in self.interfaces.values():
                stats = tracker.get_statistics()
                total_packets += stats.get("packets_captured", 0)
                total_bytes += stats.get("bytes_captured", 0)
                total_flows += stats.get("total_flows", 0)
            
            return {
                "timestamp": dt.datetime.utcnow().isoformat(),
                "interfaces_monitored": len(self.interfaces),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "total_flows": total_flows,
                "bytes_mb": total_bytes / (1024 * 1024),
                "interface_breakdown": self.get_interface_statistics(),
                "cross_interface_flows": self.get_flows_crossing_interfaces(),
            }
    
    def get_segment_report(self) -> Dict[str, Any]:
        """Get comprehensive segment monitoring report."""
        with self.lock:
            return {
                "timestamp": dt.datetime.utcnow().isoformat(),
                "created_at": self.created_at.isoformat(),
                "aggregate_statistics": self.get_aggregate_statistics(),
                "lateral_movements": self.detect_lateral_movement(),
                "interface_count": len(self.interfaces),
                "interfaces": list(self.interfaces.keys()),
            }
    
    def export_all_to_json(self) -> Dict[str, Any]:
        """Export all flows and statistics as JSON."""
        with self.lock:
            return {
                "timestamp": dt.datetime.utcnow().isoformat(),
                "monitor": {
                    "created_at": self.created_at.isoformat(),
                    "interfaces": list(self.interfaces.keys()),
                },
                "interfaces": {
                    name: tracker.to_dict()
                    for name, tracker in self.interfaces.items()
                },
                "aggregate": self.get_aggregate_flows(),
                "segment_report": self.get_segment_report(),
            }
