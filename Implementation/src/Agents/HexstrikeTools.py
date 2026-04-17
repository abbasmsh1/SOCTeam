"""
Hexstrike-AI MCP Tools Integration
===================================
Enhanced LangChain tool wrappers for Hexstrike-AI MCP server.

Improvements:
- Input validation for targets and parameters
- Structured error handling
- Tool execution result parsing
- Security-safe defaults (no dangerous operations by default)
"""

from typing import List, Dict, Any, Optional, Callable
from Implementation.src.Agents.runtime_compat import StructuredTool, ToolException
from Implementation.src.Agents.HexstrikeClient import HexstrikeClient
import re
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Input Validation Helpers
# ---------------------------------------------------------------------------

def _is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def _is_valid_domain(domain: str) -> bool:
    """Validate domain name format."""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def _is_valid_url(url: str) -> bool:
    """Validate URL format."""
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url))


def _validate_target(target: str, target_type: str = "any") -> str:
    """
    Validate target based on expected type.

    Args:
        target: Target string to validate
        target_type: Expected type ("ip", "domain", "url", "any")

    Returns:
        Validated target string

    Raises:
        ToolException: If target validation fails
    """
    if not target:
        raise ToolException("Target cannot be empty")

    if target_type == "ip" and not _is_valid_ip(target):
        raise ToolException(f"Invalid IP address format: {target}")

    if target_type == "domain" and not _is_valid_domain(target):
        # Allow IP addresses for domain-type tools as well
        if not _is_valid_ip(target):
            raise ToolException(f"Invalid domain format: {target}")

    if target_type == "url" and not _is_valid_url(target):
        # Try to construct URL if just domain/IP provided
        if _is_valid_domain(target) or _is_valid_ip(target):
            return f"http://{target}"
        raise ToolException(f"Invalid URL format: {target}")

    return target


def _safe_str_result(result: Dict[str, Any], max_length: int = 5000) -> str:
    """
    Safely convert result to string with length limiting.

    Args:
        result: Result dictionary
        max_length: Maximum string length

    Returns:
        Truncated string representation
    """
    if not result:
        return "No result"

    if result.get("error"):
        return f"Error: {result.get('message', result.get('error'))}"

    result_str = str(result)
    if len(result_str) > max_length:
        return result_str[:max_length] + "... [truncated]"

    return result_str


# ---------------------------------------------------------------------------
# Tool Factory
# ---------------------------------------------------------------------------

def _create_hexstrike_tool(
    client: HexstrikeClient,
    method_name: str,
    name: str,
    description: str,
    target_type: str = "any",
    parse_result: bool = True,
) -> StructuredTool:
    """
    Factory function to create a validated Hexstrike tool.

    Args:
        client: HexstrikeClient instance
        method_name: Name of the client method to wrap
        name: Tool name for LangChain
        description: Tool description
        target_type: Expected target type for validation
        parse_result: Whether to parse and format the result

    Returns:
        Configured StructuredTool
    """

    def make_wrapper(method: Callable, **default_kwargs) -> Callable:
        """Create a wrapper with validation and error handling."""

        def wrapper(*args, **kwargs) -> str:
            try:
                # Merge defaults with provided kwargs
                merged = {**default_kwargs, **kwargs}

                # Validate target if it's the first positional arg
                if args and target_type != "any":
                    args_list = list(args)
                    args_list[0] = _validate_target(args[0], target_type)
                    args = tuple(args_list)

                # Execute the method
                result = method(*args, **merged)

                # Format result
                if parse_result:
                    return _safe_str_result(result)
                return str(result)

            except ToolException:
                raise
            except Exception as e:
                logger.error(f"Tool {name} execution failed: {e}")
                raise ToolException(f"{name} failed: {str(e)}")

        return wrapper

    # Get the client method
    method = getattr(client, method_name, None)
    if not method:
        logger.warning(f"Method {method_name} not found on HexstrikeClient")
        return None

    # Create wrapper with appropriate defaults based on tool type
    default_kwargs = {}

    # Set sensible defaults for scan tools
    if "scan" in method_name:
        default_kwargs["scan_type"] = "default"
        default_kwargs["severity"] = "critical,high"

    if "enum" in method_name:
        default_kwargs["passive"] = True

    return StructuredTool.from_function(
        func=make_wrapper(method, **default_kwargs),
        name=name,
        description=description,
        handle_tool_error=True,
    )


def get_hexstrike_tools(client: HexstrikeClient) -> List[StructuredTool]:
    """
    Return all HexstrikeClient methods as LangChain tools with validation.

    Args:
        client: HexstrikeClient instance

    Returns:
        List of configured StructuredTool instances
    """

    if not client:
        logger.warning("No HexstrikeClient provided, returning empty tools list")
        return []

    tools = []

    # ── Network Reconnaissance ──
    tools.append(_create_hexstrike_tool(
        client, "nmap_scan", "nmap_scan",
        description="Execute Nmap scan on target IP or hostname. scan_type: default, aggressive, stealth, full. ports: e.g., '1-1000' or '80,443'",
        target_type="any",
    ))

    tools.append(_create_hexstrike_tool(
        client, "rustscan_scan", "rustscan_scan",
        description="Execute RustScan for fast port scanning. Returns open ports for target IP or hostname.",
        target_type="any",
    ))

    tools.append(_create_hexstrike_tool(
        client, "masscan_scan", "masscan_scan",
        description="Execute Masscan for high-speed Internet-scale scanning on target IP or CIDR range.",
        target_type="any",
    ))

    tools.append(_create_hexstrike_tool(
        client, "amass_enum", "amass_enum",
        description="Execute Amass for subdomain enumeration. Returns discovered subdomains for a domain.",
        target_type="domain",
    ))

    tools.append(_create_hexstrike_tool(
        client, "subfinder_enum", "subfinder_enum",
        description="Execute Subfinder for fast passive subdomain discovery.",
        target_type="domain",
    ))

    # ── Web Application Security ──
    tools.append(_create_hexstrike_tool(
        client, "nuclei_scan", "nuclei_scan",
        description="Execute Nuclei vulnerability scanner with 4000+ templates. severity: critical, high, medium, low.",
        target_type="url",
    ))

    tools.append(_create_hexstrike_tool(
        client, "sqlmap_scan", "sqlmap_scan",
        description="Execute SQLMap for SQL injection testing. Use responsibly on authorized targets only.",
        target_type="url",
    ))

    tools.append(_create_hexstrike_tool(
        client, "nikto_scan", "nikto_scan",
        description="Execute Nikto web server vulnerability scanner. Detects outdated software, dangerous files.",
        target_type="url",
    ))

    tools.append(_create_hexstrike_tool(
        client, "gobuster_scan", "gobuster_scan",
        description="Execute Gobuster directory/file enumeration. Discovers hidden paths and files.",
        target_type="url",
    ))

    tools.append(_create_hexstrike_tool(
        client, "feroxbuster_scan", "feroxbuster_scan",
        description="Execute Feroxbuster for recursive content discovery. depth: recursion depth (default 4).",
        target_type="url",
    ))

    tools.append(_create_hexstrike_tool(
        client, "ffuf_scan", "ffuf_scan",
        description="Execute FFuf web fuzzer for rapid content discovery. keyword: FUZZ position marker.",
        target_type="url",
    ))

    tools.append(_create_hexstrike_tool(
        client, "wpscan_scan", "wpscan_scan",
        description="Execute WPScan WordPress security scanner. Enumerates vulnerable plugins, themes, users.",
        target_type="url",
    ))

    # ── Password & Authentication ──
    tools.append(_create_hexstrike_tool(
        client, "hydra_brute", "hydra_brute",
        description="Execute Hydra password brute force. service: ssh, ftp, http-get, etc. USE RESPONSIBLY.",
        target_type="any",
    ))

    # ── Cloud Security ──
    tools.append(_create_hexstrike_tool(
        client, "trivy_scan", "trivy_scan",
        description="Execute Trivy container vulnerability scanner. scan_type: image, fs, repo.",
        target_type="any",
    ))

    tools.append(_create_hexstrike_tool(
        client, "kube_hunter_scan", "kube_hunter_scan",
        description="Execute Kube-hunter for Kubernetes penetration testing.",
        target_type="any",
    ))

    # ── AI Intelligence ──
    tools.append(_create_hexstrike_tool(
        client, "analyze_target", "analyze_target",
        description="Use AI intelligence engine to analyze target. analysis_type: comprehensive, quick, targeted.",
        target_type="any",
    ))

    tools.append(_create_hexstrike_tool(
        client, "select_tools", "select_tools",
        description="Use AI to select optimal security tools for an objective. Provide target_info and objective.",
        target_type="any",
    ))

    # ── Utility Tools ──
    tools.append(StructuredTool.from_function(
        func=lambda: str(client.get_stats()),
        name="hexstrike_stats",
        description="Get Hexstrike client execution statistics (requests, cache hits, successes, failures).",
    ))

    tools.append(StructuredTool.from_function(
        func=lambda: str(client.health_check()),
        name="hexstrike_health",
        description="Check Hexstrike MCP server health status.",
    ))

    return tools


# ---------------------------------------------------------------------------
# Tool Categories Helper
# ---------------------------------------------------------------------------

def get_hexstrike_tools_by_category(
    client: HexstrikeClient,
    category: str,
) -> List[StructuredTool]:
    """
    Get tools filtered by category.

    Args:
        client: HexstrikeClient instance
        category: Tool category ("recon", "web", "auth", "cloud", "ai", "all")

    Returns:
        Filtered list of tools
    """
    all_tools = get_hexstrike_tools(client)

    category_map = {
        "recon": ["nmap_scan", "rustscan_scan", "masscan_scan", "amass_enum", "subfinder_enum"],
        "web": ["nuclei_scan", "sqlmap_scan", "nikto_scan", "gobuster_scan",
                "feroxbuster_scan", "ffuf_scan", "wpscan_scan"],
        "auth": ["hydra_brute"],
        "cloud": ["trivy_scan", "kube_hunter_scan"],
        "ai": ["analyze_target", "select_tools"],
        "utility": ["hexstrike_stats", "hexstrike_health"],
    }

    if category == "all":
        return all_tools

    allowed_tools = category_map.get(category, [])
    return [t for t in all_tools if t.name in allowed_tools]
