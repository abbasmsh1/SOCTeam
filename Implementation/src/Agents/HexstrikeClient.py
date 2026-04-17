"""
Hexstrike-AI MCP Client
Provides integration with the Hexstrike-AI MCP server for advanced cybersecurity tools.

Enhancements:
- Response caching for repeated scans
- Retry logic with exponential backoff
- Request validation
- Comprehensive error handling
- Tool execution statistics
"""

try:
    import requests
except ImportError:  # pragma: no cover - optional in unit tests
    requests = None
import json
import logging
import hashlib
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from functools import wraps

logger = logging.getLogger(__name__)


class HexstrikeClient:
    """
    Client for communicating with Hexstrike-AI MCP server.
    Provides access to 150+ security tools and AI agents.
    """

    def __init__(self, base_url: str = "http://localhost:8888", timeout: int = 300):
        """
        Initialize Hexstrike client.
        
        Args:
            base_url: Base URL of the Hexstrike MCP server
            timeout: Request timeout in seconds (default 300 for long-running scans)
            cache_ttl: Cache time-to-live in seconds (default 300)
            max_retries: Maximum retry attempts for failed requests (default 3)
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.cache_ttl = 300  # Cache TTL in seconds
        self.max_retries = 3
        self.session = requests.Session() if requests is not None else None
        if self.session is not None:
            self.session.headers.update({
                'Content-Type': 'application/json',
                'User-Agent': 'SOCTeam-Integration/1.0'
            })

        # Thread-safe cache for response caching
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()

        # Execution statistics
        self._stats = {
            "total_requests": 0,
            "cache_hits": 0,
            "successes": 0,
            "failures": 0,
            "retries": 0,
        }
        self._stats_lock = threading.Lock()

    def health_check(self) -> Dict[str, Any]:
        """
        Check if the Hexstrike MCP server is running.

        Returns:
            Server health status
        """
        try:
            if self.session is None:
                raise RuntimeError("requests dependency is not installed")
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            response.raise_for_status()
            self._log_stats(success=True)
            return {
                "status": "healthy",
                "server": "hexstrike-ai",
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.debug(f"Hexstrike health check failed (expected if server is off): {e}")
            self._log_stats(success=False)
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def _generate_cache_key(self, endpoint: str, payload: Dict[str, Any]) -> str:
        """Generate a cache key from endpoint and payload."""
        key_data = f"{endpoint}:{json.dumps(payload, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _get_cached(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached response if valid."""
        with self._cache_lock:
            if cache_key in self._cache:
                cached = self._cache[cache_key]
                cached_at = datetime.fromisoformat(cached["cached_at"])
                if datetime.utcnow() - cached_at < timedelta(seconds=self.cache_ttl):
                    with self._stats_lock:
                        self._stats["cache_hits"] += 1
                    logger.debug(f"Cache hit for {cache_key}")
                    return cached["response"]
                else:
                    del self._cache[cache_key]
        return None

    def _set_cached(self, cache_key: str, response: Dict[str, Any]) -> None:
        """Cache a response."""
        with self._cache_lock:
            self._cache[cache_key] = {
                "response": response,
                "cached_at": datetime.utcnow().isoformat()
            }

    def _execute_command(
        self,
        endpoint: str,
        payload: Dict[str, Any],
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a command on the MCP server with caching and retry logic.

        Args:
            endpoint: API endpoint
            payload: Command payload
            use_cache: Whether to use response caching (default True)

        Returns:
            Command execution result
        """
        with self._stats_lock:
            self._stats["total_requests"] += 1

        # Cache lookup
        cache_key = self._generate_cache_key(endpoint, payload)
        if use_cache:
            cached_response = self._get_cached(cache_key)
            if cached_response is not None:
                return cached_response

        # Execute with retry logic
        attempt = 0
        backoff = 1.0  # Initial backoff in seconds

        while attempt < self.max_retries:
            try:
                url = f"{self.base_url}{endpoint}"
                response = self.session.post(url, json=payload, timeout=self.timeout)
                response.raise_for_status()
                result = response.json()

                # Cache successful response
                if use_cache:
                    self._set_cached(cache_key, result)

                self._log_stats(success=True)
                return result

            except requests.exceptions.Timeout:
                attempt += 1
                self._log_stats(success=False, retry=True)
                logger.warning(
                    f"Request to {endpoint} timed out (attempt {attempt}/{self.max_retries}). "
                    f"Retrying in {backoff}s..."
                )
                if attempt < self.max_retries:
                    threading.Event().wait(backoff)
                    backoff = min(backoff * 2, 30)  # Exponential backoff, max 30s
                else:
                    logger.error(f"Request to {endpoint} timed out after {self.max_retries} attempts")
                    return {
                        "error": "timeout",
                        "message": f"Request timed out after {self.max_retries} attempts",
                        "retries": attempt,
                    }

            except requests.exceptions.RequestException as e:
                self._log_stats(success=False)
                logger.error(f"Request failed: {e}")
                return {"error": "request_failed", "message": str(e)}

            except json.JSONDecodeError as e:
                self._log_stats(success=False)
                logger.error(f"Failed to parse response: {e}")
                return {"error": "parse_error", "message": "Invalid JSON response"}

        return {"error": "max_retries_exceeded", "message": f"Failed after {self.max_retries} attempts"}

    def _log_stats(self, success: bool, retry: bool = False) -> None:
        """Log execution statistics."""
        with self._stats_lock:
            if success:
                self._stats["successes"] += 1
            else:
                self._stats["failures"] += 1
            if retry:
                self._stats["retries"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        with self._stats_lock:
            return self._stats.copy()

    def clear_cache(self) -> None:
        """Clear the response cache."""
        with self._cache_lock:
            self._cache.clear()
        logger.info("Hexstrike cache cleared")

    # ==================== Network Reconnaissance ====================

    def nmap_scan(self, target: str, scan_type: str = "default", ports: str = None) -> Dict[str, Any]:
        """
        Execute Nmap scan.
        
        Args:
            target: Target IP or hostname
            scan_type: Scan type (default, aggressive, stealth, full)
            ports: Port specification (e.g., "1-1000", "80,443,8080")
            
        Returns:
            Nmap scan results
        """
        payload = {
            "tool": "nmap",
            "target": target,
            "scan_type": scan_type,
            "ports": ports
        }
        return self._execute_command("/api/command", payload)

    def rustscan_scan(self, target: str, ports: str = "1-65535") -> Dict[str, Any]:
        """
        Execute RustScan for fast port scanning.
        
        Args:
            target: Target IP or hostname
            ports: Port range
            
        Returns:
            RustScan results
        """
        payload = {
            "tool": "rustscan",
            "target": target,
            "ports": ports
        }
        return self._execute_command("/api/command", payload)

    def masscan_scan(self, target: str, ports: str = "1-65535", rate: int = 1000) -> Dict[str, Any]:
        """
        Execute Masscan for high-speed scanning.
        
        Args:
            target: Target IP or CIDR range
            ports: Port specification
            rate: Packets per second
            
        Returns:
            Masscan results
        """
        payload = {
            "tool": "masscan",
            "target": target,
            "ports": ports,
            "rate": rate
        }
        return self._execute_command("/api/command", payload)

    def amass_enum(self, domain: str, passive: bool = True) -> Dict[str, Any]:
        """
        Execute Amass for subdomain enumeration.
        
        Args:
            domain: Target domain
            passive: Use passive enumeration only
            
        Returns:
            Amass enumeration results
        """
        payload = {
            "tool": "amass",
            "domain": domain,
            "mode": "passive" if passive else "active"
        }
        return self._execute_command("/api/command", payload)

    def subfinder_enum(self, domain: str) -> Dict[str, Any]:
        """
        Execute Subfinder for fast subdomain discovery.
        
        Args:
            domain: Target domain
            
        Returns:
            Subfinder results
        """
        payload = {
            "tool": "subfinder",
            "domain": domain
        }
        return self._execute_command("/api/command", payload)

    # ==================== Web Application Security ====================

    def nuclei_scan(self, target: str, templates: List[str] = None, severity: str = None) -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner.
        
        Args:
            target: Target URL
            templates: Specific templates to use
            severity: Filter by severity (critical, high, medium, low)
            
        Returns:
            Nuclei scan results
        """
        payload = {
            "tool": "nuclei",
            "target": target,
            "templates": templates or [],
            "severity": severity
        }
        return self._execute_command("/api/command", payload)

    def sqlmap_scan(self, target: str, data: str = None, risk: int = 1, level: int = 1) -> Dict[str, Any]:
        """
        Execute SQLMap for SQL injection testing.
        
        Args:
            target: Target URL
            data: POST data
            risk: Risk level (1-3)
            level: Detection level (1-5)
            
        Returns:
            SQLMap results
        """
        payload = {
            "tool": "sqlmap",
            "target": target,
            "data": data,
            "risk": risk,
            "level": level
        }
        return self._execute_command("/api/command", payload)

    def nikto_scan(self, target: str, ssl: bool = False) -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: Target URL or IP
            ssl: Use SSL/TLS
            
        Returns:
            Nikto scan results
        """
        payload = {
            "tool": "nikto",
            "target": target,
            "ssl": ssl
        }
        return self._execute_command("/api/command", payload)

    def gobuster_scan(self, target: str, wordlist: str = None, extensions: List[str] = None) -> Dict[str, Any]:
        """
        Execute Gobuster directory/file enumeration.
        
        Args:
            target: Target URL
            wordlist: Path to wordlist
            extensions: File extensions to search for
            
        Returns:
            Gobuster results
        """
        payload = {
            "tool": "gobuster",
            "target": target,
            "wordlist": wordlist,
            "extensions": extensions or []
        }
        return self._execute_command("/api/command", payload)

    def feroxbuster_scan(self, target: str, wordlist: str = None, depth: int = 4) -> Dict[str, Any]:
        """
        Execute Feroxbuster recursive content discovery.
        
        Args:
            target: Target URL
            wordlist: Path to wordlist
            depth: Recursion depth
            
        Returns:
            Feroxbuster results
        """
        payload = {
            "tool": "feroxbuster",
            "target": target,
            "wordlist": wordlist,
            "depth": depth
        }
        return self._execute_command("/api/command", payload)

    def ffuf_scan(self, target: str, wordlist: str = None, keyword: str = "FUZZ") -> Dict[str, Any]:
        """
        Execute FFuf web fuzzer.
        
        Args:
            target: Target URL with FUZZ keyword
            wordlist: Path to wordlist
            keyword: Fuzzing keyword (default: FUZZ)
            
        Returns:
            FFuf results
        """
        payload = {
            "tool": "ffuf",
            "target": target,
            "wordlist": wordlist,
            "keyword": keyword
        }
        return self._execute_command("/api/command", payload)

    def wpscan_scan(self, target: str, enumerate: str = "vp,vt,u") -> Dict[str, Any]:
        """
        Execute WPScan WordPress security scanner.
        
        Args:
            target: Target WordPress URL
            enumerate: What to enumerate (vp=vulnerable plugins, vt=vulnerable themes, u=users)
            
        Returns:
            WPScan results
        """
        payload = {
            "tool": "wpscan",
            "target": target,
            "enumerate": enumerate
        }
        return self._execute_command("/api/command", payload)

    # ==================== Password & Authentication ====================

    def hydra_brute(self, target: str, service: str, username: str = None, 
                    password_list: str = None) -> Dict[str, Any]:
        """
        Execute Hydra password brute force.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-get, etc.)
            username: Username (or path to username list)
            password_list: Path to password list
            
        Returns:
            Hydra results
        """
        payload = {
            "tool": "hydra",
            "target": target,
            "service": service,
            "username": username,
            "password_list": password_list
        }
        return self._execute_command("/api/command", payload)

    # ==================== Cloud Security ====================

    def trivy_scan(self, target: str, scan_type: str = "image") -> Dict[str, Any]:
        """
        Execute Trivy container vulnerability scanner.
        
        Args:
            target: Target image, filesystem, or repository
            scan_type: Scan type (image, fs, repo)
            
        Returns:
            Trivy scan results
        """
        payload = {
            "tool": "trivy",
            "target": target,
            "scan_type": scan_type
        }
        return self._execute_command("/api/command", payload)

    def kube_hunter_scan(self, remote: str = None) -> Dict[str, Any]:
        """
        Execute Kube-hunter Kubernetes penetration testing.
        
        Args:
            remote: Remote Kubernetes cluster to scan
            
        Returns:
            Kube-hunter results
        """
        payload = {
            "tool": "kube-hunter",
            "remote": remote
        }
        return self._execute_command("/api/command", payload)

    # ==================== AI Intelligence ====================

    def analyze_target(self, target: str, analysis_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Use AI intelligence engine to analyze target.
        
        Args:
            target: Target domain, IP, or URL
            analysis_type: Type of analysis (comprehensive, quick, targeted)
            
        Returns:
            AI analysis results with recommended tools
        """
        payload = {
            "target": target,
            "analysis_type": analysis_type
        }
        return self._execute_command("/api/intelligence/analyze-target", payload)

    def select_tools(self, target_info: Dict[str, Any], objective: str) -> Dict[str, Any]:
        """
        Use AI to select optimal tools for the objective.
        
        Args:
            target_info: Information about the target
            objective: Security objective (reconnaissance, vulnerability_assessment, exploitation, etc.)
            
        Returns:
            Recommended tools and parameters
        """
        payload = {
            "target_info": target_info,
            "objective": objective
        }
        return self._execute_command("/api/intelligence/select-tools", payload)

    # ==================== IP Blocking & Threat Response ====================

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation via threat intelligence services.
        
        Args:
            ip: IP address to check
            
        Returns:
            IP reputation data (abuse score, threat types, location, etc.)
        """
        payload = {
            "tool": "ip_reputation",
            "ip": ip,
            "services": ["abuseipdb", "ip2location", "maxmind"]
        }
        return self._execute_command("/api/intelligence/ip-reputation", payload, use_cache=True)

    def block_ip_firewall(self, ip: str, rule_name: str = None, duration: str = "permanent") -> Dict[str, Any]:
        """
        Block an IP address at the firewall level (if integration available).
        
        Args:
            ip: IP to block
            rule_name: Name for the block rule
            duration: Duration (permanent, 1h, 24h, etc.)
            
        Returns:
            Firewall block result
        """
        payload = {
            "action": "block_ip",
            "ip": ip,
            "rule_name": rule_name or f"block_{ip}",
            "duration": duration,
            "timestamp": datetime.utcnow().isoformat()
        }
        return self._execute_command("/api/defense/block-ip", payload, use_cache=False)

    def whitelist_ip(self, ip: str, reason: str = "") -> Dict[str, Any]:
        """
        Whitelist an IP address to exempt from blocking.
        
        Args:
            ip: IP to whitelist
            reason: Reason for whitelisting
            
        Returns:
            Whitelist operation result
        """
        payload = {
            "action": "whitelist_ip",
            "ip": ip,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        return self._execute_command("/api/defense/whitelist-ip", payload, use_cache=False)

    def get_blocked_ips(self) -> Dict[str, Any]:
        """Get list of currently blocked IPs."""
        payload = {"action": "list_blocked"}
        return self._execute_command("/api/defense/blocked-ips", payload, use_cache=False)

    def remove_ip_block(self, ip: str) -> Dict[str, Any]:
        """Remove an IP from block list."""
        payload = {
            "action": "unblock_ip",
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat()
        }
        return self._execute_command("/api/defense/unblock-ip", payload, use_cache=False)

    def block_subnet(self, cidr_range: str, threat_type: str = "DDoS") -> Dict[str, Any]:
        """
        Block an entire subnet/CIDR range.
        
        Args:
            cidr_range: CIDR range (e.g., "192.168.1.0/24")
            threat_type: Type of threat detected
            
        Returns:
            Subnet block result
        """
        payload = {
            "action": "block_subnet",
            "cidr": cidr_range,
            "threat_type": threat_type,
            "timestamp": datetime.utcnow().isoformat()
        }
        return self._execute_command("/api/defense/block-subnet", payload, use_cache=False)

    def isolate_network_segment(self, network: str, reason: str = "") -> Dict[str, Any]:
        """
        Isolate a network segment to contain an attack.
        
        Args:
            network: Network identifier to isolate
            reason: Reason for isolation
            
        Returns:
            Network isolation result
        """
        payload = {
            "action": "isolate_network",
            "network": network,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        return self._execute_command("/api/defense/isolate-network", payload, use_cache=False)

    # ==================== Process Management ====================

    def get_process_status(self, pid: str) -> Dict[str, Any]:
        """
        Get status of a running process.
        
        Args:
            pid: Process ID
            
        Returns:
            Process status information
        """
        try:
            response = self.session.get(f"{self.base_url}/api/processes/status/{pid}", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get process status: {e}")
            return {"error": str(e)}

    def terminate_process(self, pid: str) -> Dict[str, Any]:
        """
        Terminate a running process.
        
        Args:
            pid: Process ID
            
        Returns:
            Termination status
        """
        try:
            response = self.session.post(f"{self.base_url}/api/processes/terminate/{pid}", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to terminate process: {e}")
            return {"error": str(e)}

    # ==================== Utility Methods ====================

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics from the server.
        
        Returns:
            Cache statistics
        """
        try:
            response = self.session.get(f"{self.base_url}/api/cache/stats", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {"error": str(e)}
