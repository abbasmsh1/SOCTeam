"""
IP Blocking and Malicious IP Management System.

Provides centralized IP reputation checking, blocking decision logic, and
integration with external threat intelligence services (AbuseIPDB, etc).
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from .ReputationSource import ReputationSource, build_reputation_source
except (ImportError, ValueError):
    from ReputationSource import ReputationSource, build_reputation_source  # type: ignore

logger = logging.getLogger(__name__)


class IPReputation:
    """Encapsulates reputation data for a single IP address."""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.abuse_score: float = 0.0  # 0-100 from AbuseIPDB
        self.is_vpn: bool = False
        self.is_proxy: bool = False
        self.is_tor: bool = False
        self.country: Optional[str] = None
        self.isp: Optional[str] = None
        self.threat_types: Set[str] = set()  # e.g., {'DDoS', 'SSH_Brute', 'Spam'}
        self.total_reports: int = 0
        self.last_updated: str = dt.datetime.utcnow().isoformat()
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "abuse_score": self.abuse_score,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "is_tor": self.is_tor,
            "country": self.country,
            "isp": self.isp,
            "threat_types": list(self.threat_types),
            "total_reports": self.total_reports,
            "last_updated": self.last_updated
        }


class IPBlockingManager:
    """
    Manages IP reputation, blocking decisions, and enforcement across the SOC.
    """
    
    ABUSE_SCORE_CRITICAL = 75  # Critical: Block immediately
    ABUSE_SCORE_HIGH = 50      # High: Investigate before blocking
    ABUSE_SCORE_MEDIUM = 25    # Medium: Monitor/rate limit
    
    # Canonical critical-attack set. Aliases at the bottom handle ANN label
    # spellings that don't match the "ideal" form — the ANN emits CIC-IDS
    # labels verbatim, including "Infilteration" (dataset typo), "Bot"
    # (shorter than BOTNET), "Exploits" (plural), etc. Without these, ~30% of
    # non-benign predictions scored too low to enter the RATE_LIMIT band and
    # never reached PENDING_HUMAN.
    CRITICAL_ATTACK_TYPES = {
        "DDOS", "BOTNET", "CRYPTOMINING", "RANSOMWARE",
        "EXPLOIT", "INFILTRATION", "C2", "APT",
        # aliases — ANN / CIC-IDS spellings
        "INFILTERATION",   # CIC-IDS dataset typo (one 't')
        "BOT",             # short form emitted by the model
        "EXPLOITS",        # plural
        "DOS",             # sometimes emitted instead of DDOS
        "BRUTE FORCE",     # with space
        "BRUTEFORCE",      # without space
        "BACKDOOR",        # backdoor traffic
    }
    
    def __init__(
        self,
        data_dir: Optional[str] = None,
        reputation_source: Optional[ReputationSource] = None,
    ):
        """
        Initialize the IP Blocking Manager.

        Args:
            data_dir: Directory for persistent IP reputation cache
            reputation_source: Pluggable reputation lookup. Defaults to the
                env-configured source (REPUTATION_SOURCE).
        """
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))))
        self.data_dir = data_dir or os.path.join(base_dir, "Reports", "ip_blocking")
        os.makedirs(self.data_dir, exist_ok=True)

        self.reputation_cache_path = os.path.join(self.data_dir, "ip_reputation.json")
        self.blocked_ips_path = os.path.join(self.data_dir, "blocked_ips.json")
        self.whitelist_path = os.path.join(self.data_dir, "ip_whitelist.json")

        self.reputation_cache: Dict[str, IPReputation] = self._load_reputation_cache()
        self.blocked_ips: Dict[str, Dict[str, Any]] = self._load_blocked_ips()
        self.whitelist: Set[str] = self._load_whitelist()
        self.reputation_source: ReputationSource = reputation_source or build_reputation_source()
        
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked (lazy expiry check)."""
        record = self.blocked_ips.get(ip)
        if record is None:
            return False
        if self._is_expired(record):
            self.remove_blocked_ip(ip)
            return False
        return True

    @staticmethod
    def _is_expired(record: Dict[str, Any]) -> bool:
        """Return True if the block record's expires_at is in the past."""
        expires_at = record.get("expires_at")
        if not expires_at:
            return False
        try:
            return dt.datetime.fromisoformat(expires_at) <= dt.datetime.utcnow()
        except (TypeError, ValueError):
            return False

    def sweep_expired(self) -> List[str]:
        """Remove all expired block records; return the list of evicted IPs."""
        expired = [ip for ip, rec in self.blocked_ips.items() if self._is_expired(rec)]
        for ip in expired:
            self.blocked_ips.pop(ip, None)
        if expired:
            self._save_blocked_ips()
            logger.info("Swept %d expired block(s): %s", len(expired), expired)
        return expired
        
    def is_ip_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted (exempt from blocking)."""
        return ip in self.whitelist
        
    def should_block_ip(self, ip: str, threat_info: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Determine if an IP should be blocked based on threat intelligence.
        
        Args:
            ip: IP address to evaluate
            threat_info: Dict containing threat context (attack_type, confidence, etc)
            
        Returns:
            Tuple of (should_block, reasoning_dict)
        """
        reasoning: Dict[str, Any] = {
            "ip": ip,
            "decision": "ALLOW",
            "factors": [],
            "score": 0.0,
            "timestamp": dt.datetime.utcnow().isoformat()
        }
        
        # Check whitelist first
        if self.is_ip_whitelisted(ip):
            reasoning["factors"].append("IP is whitelisted")
            return False, reasoning
            
        # Check if already blocked
        if self.is_ip_blocked(ip):
            reasoning["decision"] = "BLOCK"
            reasoning["factors"].append("IP is already in active block list")
            return True, reasoning
        
        # Get reputation
        reputation = self.get_or_fetch_reputation(ip)
        
        # Calculate blocking score (0-1)
        score = 0.0
        
        # Factor 1: AbuseIPDB score
        if reputation.abuse_score >= self.ABUSE_SCORE_CRITICAL:
            score += 0.4
            reasoning["factors"].append(
                f"AbuseIPDB score={reputation.abuse_score} (CRITICAL)"
            )
        elif reputation.abuse_score >= self.ABUSE_SCORE_HIGH:
            score += 0.25
            reasoning["factors"].append(
                f"AbuseIPDB score={reputation.abuse_score} (HIGH)"
            )
        elif reputation.abuse_score >= self.ABUSE_SCORE_MEDIUM:
            score += 0.1
            reasoning["factors"].append(
                f"AbuseIPDB score={reputation.abuse_score} (MEDIUM)"
            )
            
        # Factor 2: Attack type severity
        attack_type = str(threat_info.get("Attack", "")).upper()
        if attack_type in self.CRITICAL_ATTACK_TYPES:
            score += 0.3
            reasoning["factors"].append(f"Critical attack type: {attack_type}")
        elif attack_type in {"PORTSCAN", "SCAN", "EXPLOIT"}:
            score += 0.15
            reasoning["factors"].append(f"High-risk attack type: {attack_type}")
        else:
            score += 0.05
            reasoning["factors"].append(f"Attack type: {attack_type}")
            
        # Factor 3: Confidence score
        confidence = float(threat_info.get("confidence", threat_info.get("ids_confidence", 0.0)))
        if confidence >= 0.9:
            score += 0.2
            reasoning["factors"].append(f"Very high confidence: {confidence:.2f}")
        elif confidence >= 0.7:
            score += 0.1
            reasoning["factors"].append(f"High confidence: {confidence:.2f}")
            
        # Factor 4: VPN/Tor/Proxy status (increased risk)
        if reputation.is_tor:
            score += 0.15
            reasoning["factors"].append("IP is Tor exit node")
        elif reputation.is_vpn:
            score += 0.08
            reasoning["factors"].append("IP is VPN provider")
        elif reputation.is_proxy:
            score += 0.05
            reasoning["factors"].append("IP is proxy provider")
            
        reasoning["score"] = min(score, 1.0)
        
        # Decision threshold
        if reasoning["score"] >= 0.6:
            reasoning["decision"] = "BLOCK"
            return True, reasoning
        elif reasoning["score"] >= 0.4:
            reasoning["decision"] = "RATE_LIMIT"
            return False, reasoning  # Return False, but agent can decide to rate limit
        else:
            reasoning["decision"] = "ALLOW"
            return False, reasoning
    
    def get_or_fetch_reputation(self, ip: str) -> IPReputation:
        """Get IP reputation from cache or create a new entry."""
        if ip in self.reputation_cache:
            cached = self.reputation_cache[ip]
            # Refresh if older than 24 hours
            last_updated = dt.datetime.fromisoformat(cached.last_updated)
            if (dt.datetime.utcnow() - last_updated).total_seconds() < 86400:
                return cached
                
        reputation = IPReputation(ip)
        reputation = self.reputation_source.fetch(ip, reputation)
        reputation.last_updated = dt.datetime.utcnow().isoformat()

        self.reputation_cache[ip] = reputation
        self._save_reputation_cache()

        return reputation
    
    def add_blocked_ip(self, ip: str, reason: str, duration: str = "permanent",
                       threat_severity: str = "high") -> Dict[str, Any]:
        """
        Add an IP to the block list.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration: Block duration (permanent/1h/24h/etc)
            threat_severity: Threat severity level
            
        Returns:
            Block record
        """
        block_record = {
            "ip": ip,
            "reason": reason,
            "duration": duration,
            "severity": threat_severity,
            "blocked_at": dt.datetime.utcnow().isoformat(),
            "expires_at": self._calculate_expiry(duration)
        }
        
        self.blocked_ips[ip] = block_record
        self._save_blocked_ips()
        
        logger.info(f"Blocked IP {ip}: {reason} (duration: {duration})")
        
        return block_record
    
    def remove_blocked_ip(self, ip: str) -> bool:
        """Remove an IP from the block list."""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self._save_blocked_ips()
            logger.info(f"Unblocked IP {ip}")
            return True
        return False
    
    def add_to_whitelist(self, ip: str, reason: str = "") -> bool:
        """Add an IP to whitelist (exempt from blocking)."""
        self.whitelist.add(ip)
        self._save_whitelist()
        logger.info(f"Whitelisted IP {ip}: {reason}")
        return True
    
    def get_block_list(self) -> Dict[str, Any]:
        """Get current block list statistics and entries."""
        return {
            "total_blocked": len(self.blocked_ips),
            "blocked_ips": self.blocked_ips,
            "whitelisted_count": len(self.whitelist),
            "reputation_cache_size": len(self.reputation_cache),
            "timestamp": dt.datetime.utcnow().isoformat()
        }
    
    def _calculate_expiry(self, duration: str) -> Optional[str]:
        """Calculate expiry time based on duration string."""
        now = dt.datetime.utcnow()
        
        if duration == "permanent":
            return None
        elif duration.endswith("h"):
            hours = int(duration[:-1])
            expiry = now + dt.timedelta(hours=hours)
            return expiry.isoformat()
        elif duration.endswith("d"):
            days = int(duration[:-1])
            expiry = now + dt.timedelta(days=days)
            return expiry.isoformat()
        else:
            return None
    
    def _load_reputation_cache(self) -> Dict[str, IPReputation]:
        """Load reputation cache from disk."""
        if not os.path.exists(self.reputation_cache_path):
            return {}
        try:
            with open(self.reputation_cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                cache = {}
                for ip, rep_data in data.items():
                    rep = IPReputation(ip)
                    rep.abuse_score = rep_data.get("abuse_score", 0)
                    rep.is_vpn = rep_data.get("is_vpn", False)
                    rep.is_proxy = rep_data.get("is_proxy", False)
                    rep.is_tor = rep_data.get("is_tor", False)
                    rep.country = rep_data.get("country")
                    rep.isp = rep_data.get("isp")
                    rep.threat_types = set(rep_data.get("threat_types", []))
                    rep.total_reports = rep_data.get("total_reports", 0)
                    rep.last_updated = rep_data.get("last_updated", dt.datetime.utcnow().isoformat())
                    cache[ip] = rep
                return cache
        except Exception as e:
            logger.warning(f"Could not load reputation cache: {e}")
            return {}
    
    def _save_reputation_cache(self) -> None:
        """Save reputation cache to disk."""
        try:
            data = {ip: rep.to_dict() for ip, rep in self.reputation_cache.items()}
            with open(self.reputation_cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save reputation cache: {e}")
    
    def _load_blocked_ips(self) -> Dict[str, Dict[str, Any]]:
        """Load blocked IPs from disk."""
        if not os.path.exists(self.blocked_ips_path):
            return {}
        try:
            with open(self.blocked_ips_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load blocked IPs: {e}")
            return {}
    
    def _save_blocked_ips(self) -> None:
        """Save blocked IPs to disk."""
        try:
            with open(self.blocked_ips_path, "w", encoding="utf-8") as f:
                json.dump(self.blocked_ips, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save blocked IPs: {e}")
    
    def _load_whitelist(self) -> Set[str]:
        """Load whitelisted IPs from disk."""
        if not os.path.exists(self.whitelist_path):
            return set()
        try:
            with open(self.whitelist_path, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception as e:
            logger.warning(f"Could not load whitelist: {e}")
            return set()
    
    def _save_whitelist(self) -> None:
        """Save whitelisted IPs to disk."""
        try:
            with open(self.whitelist_path, "w", encoding="utf-8") as f:
                json.dump(list(self.whitelist), f, indent=2)
        except Exception as e:
            logger.error(f"Could not save whitelist: {e}")
