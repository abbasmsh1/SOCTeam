"""
Flow-Based Pattern Detection and Analytics

Analyzes patterns in network flows to detect sophisticated attacks,
anomalies, and behavioral changes.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict
from statistics import mean, stdev

from Implementation.src.Database.LiveFlowTracker import LiveFlow, LiveFlowTracker

logger = logging.getLogger(__name__)


class FlowPattern:
    """Detected pattern or anomaly."""
    
    def __init__(self, pattern_type: str, severity: str, description: str,
                 affected_ips: Set[str], confidence: float = 1.0):
        self.pattern_type = pattern_type
        self.severity = severity
        self.description = description
        self.affected_ips = affected_ips
        self.confidence = confidence
        self.detected_at = dt.datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_type": self.pattern_type,
            "severity": self.severity,
            "description": self.description,
            "affected_ips": list(self.affected_ips),
            "confidence": self.confidence,
            "detected_at": self.detected_at.isoformat(),
        }


class FlowAnalytics:
    """
    Analyzes flow statistics and patterns to detect attacks and anomalies.
    """
    
    def __init__(self, flow_tracker: LiveFlowTracker):
        """
        Initialize analytics engine.
        
        Args:
            flow_tracker: LiveFlowTracker instance
        """
        self.tracker = flow_tracker
        self.baseline_stats: Dict[str, Any] = {}
        self.detected_patterns: List[FlowPattern] = []
        
        # Thresholds
        self.port_scan_threshold = 20  # unique ports
        self.ddos_packet_rate_threshold = 1000  # pps
        self.bandwidth_anomaly_threshold = 10  # MB/s
        self.flow_count_anomaly_threshold = 100  # concurrent flows
        self.tcp_reset_threshold = 50  # RST packets
    
    def analyze_flows(self) -> List[Dict[str, Any]]:
        """
        Analyze all active flows and detect patterns.
        
        Returns:
            List of detected patterns as dictionaries
        """
        patterns = []
        
        # Analyze for each pattern type
        patterns.extend(self._detect_port_scans())
        patterns.extend(self._detect_ddos_patterns())
        patterns.extend(self._detect_bandwidth_anomalies())
        patterns.extend(self._detect_flow_concentration())
        patterns.extend(self._detect_slow_networks())
        patterns.extend(self._detect_beaconing())
        
        self.detected_patterns = patterns
        return [p.to_dict() for p in patterns]
    
    def _detect_port_scans(self) -> List[FlowPattern]:
        """Detect port scanning activities."""
        patterns = []
        src_ips_with_many_ports = defaultdict(set)
        
        flows = self.tracker.get_active_flows()
        for flow in flows:
            if flow.key.protocol in ["TCP", "UDP"]:
                src_ips_with_many_ports[flow.key.src_ip].add(flow.key.dst_port)
        
        for src_ip, ports in src_ips_with_many_ports.items():
            if len(ports) > self.port_scan_threshold:
                patterns.append(FlowPattern(
                    pattern_type="PORT_SCAN",
                    severity="HIGH",
                    description=f"Source IP {src_ip} scanning {len(ports)} unique ports",
                    affected_ips={src_ip},
                    confidence=min(len(ports) / 1000, 1.0)
                ))
        
        return patterns
    
    def _detect_ddos_patterns(self) -> List[FlowPattern]:
        """Detect DDoS-like patterns."""
        patterns = []
        
        flows = self.tracker.get_active_flows()
        src_ip_stats = defaultdict(lambda: {"packet_count": 0, "byte_count": 0, "flows": 0})
        
        for flow in flows:
            stats = src_ip_stats[flow.key.src_ip]
            stats["packet_count"] += flow.packet_count
            stats["byte_count"] += flow.byte_count
            stats["flows"] += 1
        
        for src_ip, stats in src_ip_stats.items():
            # Check for high packet rate
            packet_rate = stats["packet_count"]
            if packet_rate > self.ddos_packet_rate_threshold and stats["flows"] > 5:
                patterns.append(FlowPattern(
                    pattern_type="POTENTIAL_DDOS",
                    severity="CRITICAL",
                    description=f"High-rate flooding from {src_ip}: {packet_rate} packets",
                    affected_ips={src_ip},
                    confidence=min(packet_rate / 10000, 1.0)
                ))
        
        return patterns
    
    def _detect_bandwidth_anomalies(self) -> List[FlowPattern]:
        """Detect abnormal bandwidth usage."""
        patterns = []
        
        src_ip_bytes = defaultdict(int)
        flows = self.tracker.get_active_flows()
        
        for flow in flows:
            src_ip_bytes[flow.key.src_ip] += flow.byte_count
        
        # Simple anomaly: bytes > threshold
        for src_ip, byte_count in src_ip_bytes.items():
            bytes_mb = byte_count / (1024 * 1024)
            if bytes_mb > self.bandwidth_anomaly_threshold:
                patterns.append(FlowPattern(
                    pattern_type="BANDWIDTH_ANOMALY",
                    severity="MEDIUM",
                    description=f"High bandwidth usage from {src_ip}: {bytes_mb:.2f} MB",
                    affected_ips={src_ip},
                    confidence=min(bytes_mb / 100, 1.0)
                ))
        
        return patterns
    
    def _detect_flow_concentration(self) -> List[FlowPattern]:
        """Detect unusual flow concentration to a single destination."""
        patterns = []
        
        dst_ip_flows = defaultdict(set)
        flows = self.tracker.get_active_flows()
        
        for flow in flows:
            dst_ip_flows[flow.key.dst_ip].add(flow.key.src_ip)
        
        for dst_ip, src_ips in dst_ip_flows.items():
            # Many IPs targeting one destination = possible DDoS
            if len(src_ips) > self.flow_count_anomaly_threshold:
                patterns.append(FlowPattern(
                    pattern_type="FLOW_CONCENTRATION",
                    severity="HIGH",
                    description=f"{len(src_ips)} sources targeting {dst_ip}",
                    affected_ips=src_ips,
                    confidence=min(len(src_ips) / 1000, 1.0)
                ))
        
        return patterns
    
    def _detect_slow_networks(self) -> List[FlowPattern]:
        """Detect unusually slow flows (possible data exfiltration)."""
        patterns = []
        
        flows = self.tracker.get_active_flows()
        src_ip_slow_flows = defaultdict(list)
        
        for flow in flows:
            # Slow = low byte rate but long duration
            byte_rate = flow.get_byte_rate()
            duration = flow.get_duration_seconds()
            
            if duration > 60 and byte_rate < 10 and flow.byte_count > 1000:
                src_ip_slow_flows[flow.key.src_ip].append(flow)
        
        for src_ip, slow_flows in src_ip_slow_flows.items():
            if len(slow_flows) > 3:
                patterns.append(FlowPattern(
                    pattern_type="SLOW_EXFILTRATION",
                    severity="MEDIUM",
                    description=f"Potential slow data exfiltration from {src_ip}: {len(slow_flows)} slow flows",
                    affected_ips={src_ip},
                    confidence=0.6
                ))
        
        return patterns
    
    def _detect_beaconing(self) -> List[FlowPattern]:
        """Detect periodic beaconing (C2 communication)."""
        patterns = []
        
        flows = self.tracker.get_active_flows()
        src_to_dst = defaultdict(lambda: defaultdict(list))
        
        # Group flows by src->dst pair and collect inter-arrival times
        for flow in flows:
            pair = (flow.key.src_ip, flow.key.dst_ip)
            src_to_dst[flow.key.src_ip][pair].append(flow)
        
        for src_ip, destinations in src_to_dst.items():
            for (s, d), flow_list in destinations.items():
                if len(flow_list) > 5:
                    # Collect intervals
                    intervals = []
                    sorted_flows = sorted(flow_list, key=lambda f: f.first_seen)
                    
                    for i in range(1, len(sorted_flows)):
                        interval = (sorted_flows[i].first_seen - sorted_flows[i-1].first_seen).total_seconds()
                        intervals.append(interval)
                    
                    # Check for periodic pattern
                    if intervals and len(intervals) > 2:
                        try:
                            interval_mean = mean(intervals)
                            interval_stdev = stdev(intervals) if len(intervals) > 1 else 0
                            
                            # Regular spacing = potential beacon
                            if interval_stdev < interval_mean * 0.2 and interval_mean > 0:
                                patterns.append(FlowPattern(
                                    pattern_type="BEACONING",
                                    severity="HIGH",
                                    description=f"Periodic communication from {src_ip} to {d}: {interval_mean:.1f}s interval (±{interval_stdev:.1f}s)",
                                    affected_ips={src_ip},
                                    confidence=0.7
                                ))
                        except:
                            pass
        
        return patterns
    
    def get_top_talkers(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get top source IPs by packet count."""
        flows = self.tracker.get_active_flows()
        src_ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "flows": 0})
        
        for flow in flows:
            stats = src_ip_stats[flow.key.src_ip]
            stats["packets"] += flow.packet_count
            stats["bytes"] += flow.byte_count
            stats["flows"] += 1
        
        top = sorted(src_ip_stats.items(), 
                    key=lambda x: x[1]["packets"], 
                    reverse=True)[:count]
        
        return [{"ip": ip, **stats} for ip, stats in top]
    
    def get_top_destinations(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get top destination IPs by packet count."""
        flows = self.tracker.get_active_flows()
        dst_ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "flows": 0})
        
        for flow in flows:
            stats = dst_ip_stats[flow.key.dst_ip]
            stats["packets"] += flow.packet_count
            stats["bytes"] += flow.byte_count
            stats["flows"] += 1
        
        top = sorted(dst_ip_stats.items(), 
                    key=lambda x: x[1]["packets"], 
                    reverse=True)[:count]
        
        return [{"ip": ip, **stats} for ip, stats in top]
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """Get distribution of protocols in current flows."""
        flows = self.tracker.get_active_flows()
        distribution = defaultdict(int)
        
        for flow in flows:
            distribution[flow.key.protocol] += 1
        
        return dict(distribution)
    
    def get_port_distribution(self) -> Dict[int, Dict[str, int]]:
        """Get distribution of ports by protocol."""
        flows = self.tracker.get_active_flows()
        distribution = defaultdict(lambda: {"src": 0, "dst": 0})
        
        for flow in flows:
            dst_dist = distribution[flow.key.dst_port]
            dst_dist["dst"] += 1
            
            src_dist = distribution[flow.key.src_port]
            src_dist["src"] += 1
        
        return dict(distribution)
    
    def get_analysis_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        patterns = self.analyze_flows()
        
        return {
            "timestamp": dt.datetime.utcnow().isoformat(),
            "total_patterns": len(patterns),
            "patterns_by_severity": {
                "CRITICAL": len([p for p in patterns if p.severity == "CRITICAL"]),
                "HIGH": len([p for p in patterns if p.severity == "HIGH"]),
                "MEDIUM": len([p for p in patterns if p.severity == "MEDIUM"]),
                "LOW": len([p for p in patterns if p.severity == "LOW"]),
            },
            "patterns": patterns,
            "top_talkers": self.get_top_talkers(5),
            "top_destinations": self.get_top_destinations(5),
            "protocol_distribution": self.get_protocol_distribution(),
            "summary": self.tracker.get_summary_statistics(),
        }
