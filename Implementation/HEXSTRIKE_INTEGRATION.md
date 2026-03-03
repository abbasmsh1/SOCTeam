# Hexstrike-AI Integration Documentation

## Overview

This document describes the integration of [Hexstrike-AI](https://github.com/havij13/Hexstrike-AI) MCP server into the SOC Team project. Hexstrike-AI provides 150+ cybersecurity tools and AI agents accessible via a Model Context Protocol (MCP) server.

## Architecture

```
SOC Team Project
├── Red Team Agent → HexstrikeClient → Hexstrike-AI MCP Server (Offensive Tools)
├── Blue Team Agent → HexstrikeClient → Hexstrike-AI MCP Server (Defensive Tools)
└── HexstrikeClient (MCP Client Wrapper)
```

## Components

### HexstrikeClient.py

A Python client wrapper that communicates with the Hexstrike-AI MCP server via HTTP REST API.

**Key Features:**
- Health checking and connection validation
- Network reconnaissance (nmap, rustscan, masscan)
- Subdomain enumeration (amass, subfinder)
- Web vulnerability scanning (nuclei, sqlmap, nikto, wpscan)
- Directory fuzzing (gobuster, feroxbuster, ffuf)
- Container security (trivy, kube-hunter)
- AI intelligence (analyze_target, select_tools)
- Process management for long-running scans

### Red Team Agent Enhancement

**New Capabilities:**
- **Phase 1 - Reconnaissance:** AI-driven target analysis, port scanning, subdomain enumeration
- **Phase 2 - Vulnerability Scanning:** Nuclei web vulnerability scanning, directory fuzzing
- **Phase 3 - Attack Planning:** AI-powered attack strategy generation based on recon results

**Example Usage:**
```python
from Implementation.src.Agents.RedTeamAgent import RedTeamAgent

red_team = RedTeamAgent()
result = red_team.process({
    "target_info": {
        "target": "example.com",
        "scan_ports": True,
        "vuln_scan": True,
        "web_target": True,
        "fuzz_directories": False,
        "severity_filter": "critical,high"
    }
})

print(result["attack_plan"])
print(result["reconnaissance"])
print(result["vulnerability_scans"])
```

### Blue Team Agent Enhancement

**New Capabilities:**
- **Phase 1 - Security Assessment:** Proactive vulnerability scanning, container security assessment, AI analysis
- **Phase 2 - Threat Response:** Defense planning based on threat intel and assessment results

**Example Usage:**
```python
from Implementation.src.Agents.BlueTeamAgent import BlueTeamAgent

blue_team = BlueTeamAgent()
result = blue_team.process({
    "threat_info": {
        "type": "web_attack",
        "severity": "high"
    },
    "system_state": "Production Environment",
    "system_target": "myapp.example.com",
    "scan_vulnerabilities": True,
    "container_scan": False
})

print(result["defense_plan"])
print(result["security_assessment"])
```

## Setup Instructions

### 1. Install Hexstrike-AI MCP Server

```bash
# Clone the repository
git clone https://github.com/havij13/Hexstrike-AI.git
cd Hexstrike-AI

# Create virtual environment
python -m venv hexstrike-env
source hexstrike-env/bin/activate  # Linux/Mac
# hexstrike-env\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Install Security Tools

**Essential Tools:**
```bash
# Network & Reconnaissance
nmap rustscan masscan amass subfinder nuclei

# Web Application Security
gobuster feroxbuster ffuf httpx nikto sqlmap wpscan

# Container Security (optional)
trivy docker
```

Refer to the [Hexstrike-AI README](https://github.com/havij13/Hexstrike-AI#install-security-tools) for detailed installation instructions.

### 3. Start the Hexstrike-AI Server

```bash
# Default port 8888
python hexstrike_server.py

# Custom port
python hexstrike_server.py --port 9000

# Debug mode
python hexstrike_server.py --debug
```

### 4. Configure SOC Team Project

Update `Implementation/config.json`:
```json
{
    "hexstrike_url": "http://localhost:8888",
    ...
}
```

If using a different port or remote server:
```json
{
    "hexstrike_url": "http://192.168.1.100:9000",
    ...
}
```

### 5. Verify Integration

```python
from Implementation.src.Agents.HexstrikeClient import HexstrikeClient

client = HexstrikeClient()
health = client.health_check()
print(health)
# Should print: {"status": "healthy", ...}
```

## Available Tools

### Network Reconnaissance
- `nmap_scan()` - Advanced port scanning
- `rustscan_scan()` - Ultra-fast port scanning
- `masscan_scan()` - High-speed Internet-scale scanning
- `amass_enum()` - Subdomain enumeration
- `subfinder_enum()` - Fast passive subdomain discovery

### Web Application Security
- `nuclei_scan()` - Vulnerability scanner with 4000+ templates
- `sqlmap_scan()` - SQL injection testing
- `nikto_scan()` - Web server vulnerability scanner
- `gobuster_scan()` - Directory/file enumeration
- `feroxbuster_scan()` - Recursive content discovery
- `ffuf_scan()` - Fast web fuzzing
- `wpscan_scan()` - WordPress security scanner

### Container & Cloud Security
- `trivy_scan()` - Container vulnerability scanning
- `kube_hunter_scan()` - Kubernetes penetration testing

### AI Intelligence
- `analyze_target()` - AI-driven target analysis
- `select_tools()` - Optimal tool selection for objectives

## Configuration Options

### Red Team Options
```python
{
    "target_info": {
        "target": "example.com",          # Target domain/IP
        "scan_ports": True,                # Enable port scanning
        "vuln_scan": True,                 # Enable vulnerability scanning
        "web_target": True,                # Is this a web target?
        "fuzz_directories": False,         # Enable directory fuzzing
        "severity_filter": "critical,high" # Vulnerability severity filter
    }
}
```

### Blue Team Options
```python
{
    "threat_info": {...},                  # Threat information
    "system_state": "...",                 # Current system state
    "system_target": "myapp.com",          # Target to assess
    "scan_vulnerabilities": True,          # Enable vuln scanning
    "container_scan": False,               # Enable container scanning
    "container_image": "myapp:latest",     # Container image to scan
    "severity_filter": "critical,high,medium"
}
```

## Troubleshooting

### Connection Issues
```python
# Check if server is running
curl http://localhost:8888/health

# Check logs
tail -f hexstrike-ai/logs/server.log
```

### Tool Not Found Errors
Ensure the security tool is installed and accessible in PATH:
```bash
which nmap
which nuclei
```

### Timeout Issues
Increase timeout for long-running scans:
```python
client = HexstrikeClient(timeout=600)  # 10 minutes
```

## Security Considerations

> [!WARNING]
> **Legal and Ethical Use Only**
>
> The tools integrated via Hexstrike-AI are for penetration testing and security assessment. Only use them on:
> - Systems you own
> - Systems you have explicit written permission to test
>
> Unauthorized access to computer systems is illegal.

## Performance Tips

1. **Caching:** Hexstrike-AI includes smart caching. Enable it for repeated scans.
2. **Rate Limiting:** Be mindful of rate limits when scanning production systems.
3. **Parallel Execution:** Tools can run in parallel via the process management API.
4. **Resource Usage:** Monitor system resources during intensive scans.

## API Reference

See `HexstrikeClient.py` for full API documentation. Key methods:

- `health_check()` - Check server status
- `nmap_scan(target, scan_type, ports)` - Network scanning
- `nuclei_scan(target, templates, severity)` - Vulnerability detection
- `analyze_target(target, analysis_type)` - AI analysis
- `get_process_status(pid)` - Process monitoring
- `get_cache_stats()` - Cache statistics

## Future Enhancements

- [ ] Browser agent integration for web testing
- [ ] Exploit generation with AI
- [ ] Correlation of vulnerability chains
- [ ] Custom tool profiles
- [ ] Report generation integration

## Support

For issues with:
- **Hexstrike-AI:** https://github.com/havij13/Hexstrike-AI/issues
- **SOC Team Integration:** Contact project maintainers

## References

- [Hexstrike-AI GitHub](https://github.com/havij13/Hexstrike-AI)
- [MCP Protocol Documentation](https://github.com/modelcontextprotocol/specification)
- [Installation Video Tutorial](https://www.youtube.com/watch?v=pSoftCagCm8)
