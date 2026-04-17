"""
Real-Time Flow Tracking and Statistics

Tracks active flows in real-time, maintains flow state, and provides
statistics for live traffic monitoring and pattern detection.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class FlowKey:
    """Unique 5-tuple key for a network flow."""
    
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.upper()
        
    def __hash__(self) -> int:
        """Hash based on 5-tuple."""
        tuple_str = f"{self.src_ip}:{self.dst_ip}:{self.src_port}:{self.dst_port}:{self.protocol}"
        return hash(tuple_str)
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, FlowKey):
            return False
        return (self.src_ip == other.src_ip and 
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)
    
    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} ({self.protocol})"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol
        }


class LiveFlow:
    """Represents an active network flow with real-time statistics."""
    
    def __init__(self, key: FlowKey):
        self.key = key
        self.first_seen = dt.datetime.utcnow()
        self.last_seen = self.first_seen
        self.packet_count = 0
        self.byte_count = 0
        self.fwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_packets = 0
        self.bwd_bytes = 0
        self.predicted_label: Optional[str] = None
        self.confidence: float = 0.0
        self.severity: Optional[str] = None
        self.flags: Set[str] = set()  # e.g., {'SYN_FLOOD', 'PORT_SCAN'}
        self.duplicate_count = 0  # Number of duplicate packets
        self.inter_arrival_times: deque = deque(maxlen=100)  # Last 100 inter-arrival times
        self.packet_sizes: deque = deque(maxlen=100)  # Last 100 packet sizes
        
    def update(self, packet_info: Dict[str, Any]) -> None:
        """Update flow with new packet information."""
        self.last_seen = dt.datetime.utcnow()
        
        packet_size = packet_info.get('size', 0)
        direction = packet_info.get('direction', 'fwd')  # 'fwd' or 'bwd'
        
        self.packet_count += 1
        self.byte_count += packet_size
        
        if direction == 'fwd':
            self.fwd_packets += 1
            self.fwd_bytes += packet_size
        else:
            self.bwd_packets += 1
            self.bwd_bytes += packet_size
        
        # Track packet size distribution
        self.packet_sizes.append(packet_size)
        
        # Track inter-arrival times if we have a previous time
        if hasattr(self, '_last_packet_time'):
            inter_arrival = (self.last_seen - self._last_packet_time).total_seconds() * 1000  # ms
            self.inter_arrival_times.append(inter_arrival)
        
        self._last_packet_time = self.last_seen
    
    def get_duration_seconds(self) -> float:
        """Get flow duration in seconds."""
        return (self.last_seen - self.first_seen).total_seconds()
    
    def get_packet_rate(self) -> float:
        """Get packets per second."""
        duration = self.get_duration_seconds()
        return self.packet_count / duration if duration > 0 else 0
    
    def get_byte_rate(self) -> float:
        """Get bytes per second."""
        duration = self.get_duration_seconds()
        return self.byte_count / duration if duration > 0 else 0
    
    def get_avg_packet_size(self) -> float:
        """Get average packet size."""
        return self.byte_count / self.packet_count if self.packet_count > 0 else 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert flow to dictionary for JSON serialization."""
        return {
            "flow": self.key.to_dict(),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.get_duration_seconds(),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "fwd_packets": self.fwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_packets": self.bwd_packets,
            "bwd_bytes": self.bwd_bytes,
            "packet_rate_pps": round(self.get_packet_rate(), 2),
            "byte_rate_bps": round(self.get_byte_rate(), 2),
            "avg_packet_size": round(self.get_avg_packet_size(), 2),
            "predicted_label": self.predicted_label,
            "confidence": self.confidence,
            "severity": self.severity,
            "flags": list(self.flags),
            "duplicate_count": self.duplicate_count,
        }


class LiveFlowTracker:
    """
    Tracks active network flows in real-time with statistics and pattern detection.
    """
    
    def __init__(self, max_flows: int = 10000, timeout_seconds: int = 300):
        """
        Initialize flow tracker.
        
        Args:
            max_flows: Maximum flows to track before pruning
            timeout_seconds: Flow timeout (remove inactive flows)
        """
        self.max_flows = max_flows
        self.timeout_seconds = timeout_seconds
        self.flows: Dict[FlowKey, LiveFlow] = {}
        self._lock = threading.Lock()
        
        # Statistics
        self.total_flows_seen = 0
        self.total_packets = 0
        self.total_bytes = 0
        self.malicious_flows = 0
        
        # Per-IP tracking
        self.ip_flow_count: Dict[str, int] = defaultdict(int)
        self.ip_packet_rate: Dict[str, float] = defaultdict(float)
        self.ip_byte_rate: Dict[str, float] = defaultdict(float)
    
    def add_or_update_flow(self, src_ip: str, dst_ip: str, src_port: int, 
                          dst_port: int, protocol: str, 
                          packet_info: Dict[str, Any]) -> LiveFlow:
        """
        Add or update a flow in the tracker.
        
        Returns:
            The LiveFlow object
        """
        key = FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
        
        with self._lock:
            if key not in self.flows:
                self.flows[key] = LiveFlow(key)
                self.total_flows_seen += 1
                self.ip_flow_count[src_ip] += 1
            
            flow = self.flows[key]
            flow.update(packet_info)
            
            self.total_packets += 1
            self.total_bytes += packet_info.get('size', 0)
            
            # Prune if too many flows
            if len(self.flows) > self.max_flows:
                self._prune_flows()
        
        return flow
    
    def update_flow_prediction(self, src_ip: str, dst_ip: str, src_port: int,
                              dst_port: int, protocol: str,
                              label: str, confidence: float, 
                              severity: Optional[str] = None) -> bool:
        """Update a flow with IDS prediction results."""
        key = FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
        
        with self._lock:
            if key in self.flows:
                flow = self.flows[key]
                flow.predicted_label = label
                flow.confidence = confidence
                flow.severity = severity
                
                if label != "BENIGN":
                    self.malicious_flows += 1
                
                return True
        
        return False
    
    def get_flow(self, src_ip: str, dst_ip: str, src_port: int, 
                 dst_port: int, protocol: str) -> Optional[LiveFlow]:
        """Get a specific flow."""
        key = FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
        
        with self._lock:
            return self.flows.get(key)
    
    def get_active_flows(self) -> List[LiveFlow]:
        """Get all active flows."""
        with self._lock:
            return list(self.flows.values())
    
    def get_malicious_flows(self) -> List[LiveFlow]:
        """Get flows predicted as malicious."""
        with self._lock:
            return [f for f in self.flows.values() if f.predicted_label and f.predicted_label != "BENIGN"]
    
    def get_flows_by_src_ip(self, src_ip: str) -> List[LiveFlow]:
        """Get all flows from a source IP."""
        with self._lock:
            return [f for f in self.flows.values() if f.key.src_ip == src_ip]
    
    def get_flows_by_dst_ip(self, dst_ip: str) -> List[LiveFlow]:
        """Get all flows to a destination IP."""
        with self._lock:
            return [f for f in self.flows.values() if f.key.dst_ip == dst_ip]
    
    def get_high_rate_flows(self, threshold_pps: float = 1000) -> List[LiveFlow]:
        """Get flows exceeding packet rate threshold."""
        with self._lock:
            return [f for f in self.flows.values() if f.get_packet_rate() > threshold_pps]
    
    def detect_port_scan(self, src_ip: str, threshold: int = 20) -> List[str]:
        """
        Detect potential port scan from a source IP.
        Returns list of unique destination ports if scan detected.
        """
        flows = self.get_flows_by_src_ip(src_ip)
        
        # Count unique destination ports
        dst_ports = set()
        for flow in flows:
            if flow.key.protocol in ["TCP", "UDP"]:
                dst_ports.add(flow.key.dst_port)
        
        if len(dst_ports) > threshold:
            return sorted(list(dst_ports))
        
        return []
    
    def detect_ddos_pattern(self, src_ip: str) -> bool:
        """
        Detect DDoS-like pattern from source IP:
        - High packet rate
        - Low packet size variance
        - Multiple flows to single destination
        """
        flows = self.get_flows_by_src_ip(src_ip)
        
        if not flows:
            return False
        
        avg_rate = sum(f.get_packet_rate() for f in flows) / len(flows)
        
        # Check criteria
        high_rate = avg_rate > 1000  # pps
        multiple_flows = len(flows) > 10
        
        return high_rate and multiple_flows
    
    def _prune_flows(self) -> None:
        """Remove inactive/timed-out flows (must hold lock)."""
        now = dt.datetime.utcnow()
        to_remove = []
        
        for key, flow in self.flows.items():
            age = (now - flow.last_seen).total_seconds()
            if age > self.timeout_seconds:
                to_remove.append(key)
        
        for key in to_remove:
            del self.flows[key]
        
        logger.debug(f"Pruned {len(to_remove)} inactive flows")
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics of all flows."""
        with self._lock:
            active_flows = len(self.flows)
            malicious = len([f for f in self.flows.values() 
                           if f.predicted_label and f.predicted_label != "BENIGN"])
            
            if active_flows == 0:
                return {
                    "active_flows": 0,
                    "malicious_flows": 0,
                    "total_flows_seen": self.total_flows_seen,
                    "total_packets": self.total_packets,
                    "total_bytes": self.total_bytes,
                }
            
            rates = [f.get_packet_rate() for f in self.flows.values()]
            byte_rates = [f.get_byte_rate() for f in self.flows.values()]
            
            return {
                "active_flows": active_flows,
                "malicious_flows": malicious,
                "total_flows_seen": self.total_flows_seen,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "avg_packet_rate_pps": round(sum(rates) / len(rates), 2) if rates else 0,
                "max_packet_rate_pps": round(max(rates), 2) if rates else 0,
                "avg_byte_rate_bps": round(sum(byte_rates) / len(byte_rates), 2) if byte_rates else 0,
                "max_byte_rate_bps": round(max(byte_rates), 2) if byte_rates else 0,
            }
    
    def clear_flows(self) -> int:
        """Clear all flows and return count."""
        with self._lock:
            count = len(self.flows)
            self.flows.clear()
            return count
    
    def export_flows_json(self, limit: int = 100) -> str:
        """Export active flows as JSON."""
        with self._lock:
            flows = list(self.flows.values())[:limit]
            data = {
                "timestamp": dt.datetime.utcnow().isoformat(),
                "flow_count": len(flows),
                "flows": [f.to_dict() for f in flows]
            }
            return json.dumps(data, indent=2)
    
    def get_unique_ips(self) -> Tuple[Set[str], Set[str]]:
        """Get unique source and destination IPs."""
        with self._lock:
            src_ips = {f.key.src_ip for f in self.flows.values()}
            dst_ips = {f.key.dst_ip for f in self.flows.values()}
            return src_ips, dst_ips
