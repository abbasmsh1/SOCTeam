"""
Tier Analyst Agent
==================
Unified agent supporting three SOC analyst tiers:

  - **Tier 1** – Alert triage, enrichment (geo-IP, AbuseIPDB), IDS scoring.
  - **Tier 2** – Deep investigation, correlation analysis, incident classification.
  - **Tier 3** – Incident response planning, forensics, remediation strategy.

Extends :class:`BaseAgent` for LLM and graph wiring.
"""

try:
    from .BaseAgent import BaseAgent, AgentState
    from .runtime_compat import StateGraph
except (ImportError, ValueError):
    from BaseAgent import BaseAgent, AgentState
    from runtime_compat import StateGraph

try:
    from .llm_perf import compress_prompt  # type: ignore
except Exception:  # pragma: no cover
    def compress_prompt(prompt: str) -> str:  # type: ignore
        return prompt

try:
    from Implementation.utils.Geolocator import GeoLocator
except (ImportError, ValueError):
    try:
        from ..utils.Geolocator import GeoLocator  # type: ignore
    except (ImportError, ValueError):
        try:
            from utils.Geolocator import GeoLocator  # type: ignore
        except ImportError:
            GeoLocator = None  # Fallback if utils not available
from typing import Dict, Any, Literal, Optional, List
import json
import logging
import datetime
import re
import uuid
try:
    import requests
except ImportError:  # pragma: no cover - optional during unit tests
    requests = None
import os

logger = logging.getLogger(__name__)

# Type alias for the three supported tier levels
TierLevel = Literal[1, 2, 3]

# Attack labels that automatically trigger high severity / escalation
_HIGH_SEVERITY_PATTERNS = ["DDOS", "BOTNET"]

# Attack labels used in heuristic severity scoring
_CRITICAL_ATTACK_LABELS = [
    "DOS", "DDOS", "BRUTEFORCE", "BOTNET",
    "INFILTRATION", "WEBATTACK", "CRYPTOMINING",
]
_MODERATE_ATTACK_LABELS = ["PORTSCAN", "SCAN"]

# Confidence thresholds for AbuseIPDB reputation classification
_ABUSE_MALICIOUS_THRESHOLD = 75
_ABUSE_SUSPICIOUS_THRESHOLD = 40


# ---------------------------------------------------------------------------
# Tier-specific system prompts
# ---------------------------------------------------------------------------

_TIER1_SYSTEM_MSG = """\
You are a Tier 1 SOC Analyst. Triage alerts with high precision.
You will be provided with an alert and its **HISTORICAL CONTEXT** (logs of
recent flows from the same Source IP).
Use the historical context to identify patterns (e.g., many flows in a short
time might indicate a brute force or scan).

You must provide a descriptive analysis and end your response with a JSON block:
{
  "severity": "Low/Medium/High/Critical",
  "false_positive": true/false,
  "recommended_actions": ["Action 1", ...],
  "escalate": true/false,
  "confidence": 0.0-1.0,
  "forensic_status": "NONE/COLLECTING/ENRICHED/INVESTIGATING/COMPLETE",
  "rationale": "..."
}
FORCE 'escalate': true for any DDoS or Botnet attack."""

_TIER2_SYSTEM_MSG = """\
You are a **Tier 2 SOC Analyst** conducting a deep investigation.
You will receive the Tier 1 triage results and **HISTORICAL CONTEXT** from
the flow database.
Analyze if the current activity is part of a broader trend (e.g., persistent
scanning, multi-stage attack).

Provide a detailed forensic report and end your response with a JSON block:
{
  "validated_severity": "Low/Medium/High/Critical",
  "incident_classification": "Confirmed Incident/False Positive/Suspicious Activity",
  "recommended_actions": ["Action 1", ...],
  "escalate": true/false,
  "confidence": 0.0-1.0,
  "forensic_status": "NONE/COLLECTING/ENRICHED/INVESTIGATING/COMPLETE",
  "investigation_summary": "..."
}
FORCE 'escalate': true for confirmed DDoS or Botnet threats."""

_TIER3_SYSTEM_MSG = """\
You are a **Tier 3 Incident Responder**.
Provide a remediation strategy and end your response with a JSON block:
{
  "credible_threat": true/false,
  "response_plan": "...",
  "summary": "...",
  "recommended_actions": ["Concrete step 1", "Concrete step 2"]
}
Include recommended_actions as short, executable items (no placeholders); they are merged into the sandbox rule engine."""

_NO_PLACEHOLDER_RULES = """
## Mandatory writing rules
- Do **not** use angle-bracket placeholders (e.g. <SOURCE_IP>, <TARGET>, <INCIDENT_ID>) or shell-style variables.
- Use **only** the exact IP addresses, ports, and protocol strings given under **OBSERVED FACTS** below when discussing endpoints.
- If an endpoint value is truly absent from OBSERVED FACTS, say **"Not present in telemetry"** — do not invent addresses.
- Prioritize **summarizing what is already observed** (Tier 1/2 text, HexStrike/AbuseIPDB snippets in the payload) over generic step lists of tools to run later.
- The response_plan must read as an operator-ready narrative referencing concrete values from OBSERVED FACTS, not a generic playbook.
"""


def _resolve_src_ip(alert: Dict[str, Any]) -> str:
    if not isinstance(alert, dict):
        return ""
    v = (
        alert.get("SourceIP")
        or alert.get("Source IP")
        or alert.get("src_ip")
        or alert.get("IPV4_SRC_ADDR")
    )
    return str(v).strip() if v not in (None, "") else ""


def _resolve_dst_ip(alert: Dict[str, Any]) -> str:
    if not isinstance(alert, dict):
        return ""
    v = (
        alert.get("DestinationIP")
        or alert.get("Destination IP")
        or alert.get("dst_ip")
        or alert.get("IPV4_DST_ADDR")
    )
    return str(v).strip() if v not in (None, "") else ""


def format_observed_facts_block(
    alert: Dict[str, Any],
    *,
    tier1_output: Optional[Dict[str, Any]] = None,
    hexstrike_enrichment: Optional[Dict[str, Any]] = None,
    extra_lines: Optional[List[str]] = None,
) -> str:
    """Human + LLM-facing facts block; anchors IPs for all tiers."""
    src = _resolve_src_ip(alert)
    dst = _resolve_dst_ip(alert)
    proto = str(
        alert.get("Protocol")
        or alert.get("PROTOCOL")
        or alert.get("protocol")
        or "N/A"
    )
    sp = alert.get("L4_SRC_PORT") or alert.get("Source Port") or alert.get("src_port", "")
    dp = alert.get("L4_DST_PORT") or alert.get("Destination Port") or alert.get("dst_port", "")
    attack = str(alert.get("Attack", alert.get("prediction", "Unknown")))
    lines = [
        "## OBSERVED FACTS (cite these exact values; never replace with placeholders)",
        f"- **Source IP:** `{src or 'Not present in telemetry'}`",
        f"- **Destination IP:** `{dst or 'Not present in telemetry'}`",
        f"- **Protocol / ports:** proto={proto}  src_port={sp or 'N/A'}  dst_port={dp or 'N/A'}",
        f"- **Attack label (alert):** {attack}",
    ]
    if tier1_output:
        ids_pred = tier1_output.get("ids_prediction") or {}
        if isinstance(ids_pred, dict) and ids_pred:
            lines.append(
                f"- **IDS model:** label=`{ids_pred.get('predicted_label', 'N/A')}`  "
                f"confidence={ids_pred.get('confidence', 'N/A')}"
            )
    if hexstrike_enrichment and isinstance(hexstrike_enrichment, dict):
        keys = list(hexstrike_enrichment.keys())[:12]
        lines.append(f"- **HexStrike keys populated:** {', '.join(keys) or 'none'}")
    if extra_lines:
        lines.extend(extra_lines)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class TierAnalystAgent(BaseAgent):
    """
    Unified Tier Analyst agent whose behaviour adapts to the assigned tier.

    Tier 1 additionally initialises a :class:`GeoLocator` and an optional
    IDS predictor for enrichment.
    """

    def __init__(self, tier: TierLevel = 1, api_key: Optional[str] = None, hexstrike_url: Optional[str] = None):
        """
        Initialise the Tier Analyst.

        Args:
            tier:    Analyst tier (1, 2, or 3).
            api_key: Mistral API key.
            hexstrike_url: Optional Hexstrike-AI MCP server URL.
        """
        self.tier = tier
        self.hexstrike_url = hexstrike_url

        # Temperature per tier (kept uniform for now; easy to differentiate later)
        temperature_map: Dict[int, float] = {1: 0.3, 2: 0.3, 3: 0.3}

        super().__init__(
            agent_name=f"Tier{tier}Analyst",
            temperature=temperature_map[tier],
            api_key=api_key,
            hexstrike_url=hexstrike_url,
            enable_hexstrike=True,  # Enable Hexstrike for Tier 1 enrichment
        )

        # ── Tier 1 specific components ──────────────────────────────────
        if tier == 1:
            self.geo_locator = GeoLocator() if GeoLocator is not None else None
            if self.geo_locator is None:
                logger.warning("Tier 1: GeoLocator unavailable — geo-enrichment disabled")
            self.internal_networks = ["192.168.", "10.", "172.16."]

            # Attempt to load the IDS neural-network predictor
            try:
                from ..IDS.IDS import IDSPredictor

                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                project_root = os.path.dirname(base_dir)
                model_path = os.path.join(project_root, "Models", "best_ids_model.pth")
                self.ids_predictor = IDSPredictor(model_path=model_path)
            except Exception as exc:
                logger.warning("Could not load IDS model: %s", exc)
                self.ids_predictor = None

    # ── Graph construction ──────────────────────────────────────────────

    def _create_graph(self) -> StateGraph:
        """Build a single-node graph that delegates to ``_process_node``."""
        workflow = StateGraph(AgentState)
        node_name = f"tier{self.tier}_analyst"
        workflow.add_node(node_name, self._process_node)
        workflow.set_entry_point(node_name)
        workflow.set_finish_point(node_name)
        return workflow

    def _process_node(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Graph node – invokes the LLM with the tier-appropriate prompt."""
        system_message = self._get_system_message()
        return self._call_model(state, system_message)

    # ── System prompts ──────────────────────────────────────────────────

    def _get_system_message(self) -> str:
        """Return the system prompt matching the current tier."""
        base = {1: _TIER1_SYSTEM_MSG, 2: _TIER2_SYSTEM_MSG, 3: _TIER3_SYSTEM_MSG}[self.tier]
        return base + "\n" + _NO_PLACEHOLDER_RULES

    def _stream_with_config(self, prompt: str, timeout_override: Optional[int] = None) -> Optional[str]:
        """
        Invoke the LLM with the tier-specific system prompt.

        BaseAgent falls back to a generic system string when ``self.llm`` is used
        without the compiled graph; tier analysts must always send tier rules.
        """
        try:
            compressed = compress_prompt(prompt)
            if self.app:
                thread_id = str(uuid.uuid4())
                config = {"configurable": {"thread_id": thread_id}}
                result = self.app.invoke(
                    {"messages": [{"role": "user", "content": compressed}]}, config
                )
                messages = result.get("messages", [])
                if messages:
                    msg = messages[-1]
                    content = msg.content if hasattr(msg, "content") else str(msg)
                    # Guard: some models (Ollama + tool binding) return empty content
                    # when they emit a tool_call token but no ToolNode handles it.
                    # Fall through to the direct LLM path so the tier still gets text.
                    if content and str(content).strip():
                        return content

            if self.llm:
                # Direct call without tool bindings so the model returns plain text.
                llm = getattr(self.llm, "bound", self.llm) if hasattr(self.llm, "bound") else self.llm
                response = llm.invoke(
                    [
                        {"role": "system", "content": self._get_system_message()},
                        {"role": "user", "content": compressed},
                    ]
                )
                return response.content if hasattr(response, "content") else str(response)
            return None
        except Exception as exc:
            logger.error("%s: Error during processing: %s", self.agent_name, exc)
            return None

    # ── Public processing entry point ───────────────────────────────────

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch to the tier-specific processing pipeline."""
        handler = {
            1: self._process_tier1,
            2: self._process_tier2,
            3: self._process_tier3,
        }[self.tier]
        return handler(input_data)

    # ── Tier 1 processing ───────────────────────────────────────────────

    def _process_tier1(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tier 1: triage the alert.

        Steps:
          1. Enrich the raw alert (geo-IP, AbuseIPDB).
          2. Run IDS prediction (if model loaded).
          3. Call the LLM for a triage verdict.
          4. Apply heuristic overrides for high-confidence attack patterns.
        """
        alert_data = input_data.get("alert_data", {})
        enriched_alert = self.enrich_log(alert_data)

        # IDS prediction (Tier 1 only)
        ids_prediction = None
        if self.ids_predictor:
            try:
                ids_prediction = self.ids_predictor.predict(alert_data)
                enriched_alert["ids_prediction"] = ids_prediction.get("predicted_label", "Unknown")
                enriched_alert["ids_confidence"] = ids_prediction.get("confidence", 0.0)
            except Exception:
                pass  # Gracefully degrade if IDS fails

        # Hexstrike enrichment for high-severity alerts
        src_ip = _resolve_src_ip(alert_data)
        dst_ip = _resolve_dst_ip(alert_data)
        attack_type = str(alert_data.get("Attack", "")).upper()

        # Determine if this is a high-severity alert warranting Hexstrike scans
        is_high_severity = any(p in attack_type for p in _HIGH_SEVERITY_PATTERNS)

        if self.hexstrike and (is_high_severity or src_ip):
            try:
                hexstrike_enrichment = {}

                # Quick AI analysis for any IP-based threat
                if src_ip:
                    logger.info(f"Tier 1: Running Hexstrike AI analysis on {src_ip}")
                    hexstrike_enrichment["ai_analysis"] = self.hexstrike.analyze_target(src_ip, "quick")

                # For web attacks, run quick vulnerability assessment
                if "WEB" in attack_type or "SQL" in attack_type or "XSS" in attack_type:
                    web_target = dst_ip if dst_ip else src_ip
                    if web_target and not self._is_internal_ip(web_target):
                        logger.info(f"Tier 1: Running Nuclei quick scan on {web_target}")
                        hexstrike_enrichment["vuln_scan"] = self.hexstrike.nuclei_scan(
                            f"http://{web_target}" if not web_target.startswith("http") else web_target,
                            severity="critical,high"
                        )

                # For network scans/port scans, run reverse recon on source
                if "PORTSCAN" in attack_type or "SCAN" in attack_type:
                    logger.info(f"Tier 1: Running reverse recon on scanner {src_ip}")
                    hexstrike_enrichment["reverse_recon"] = self.hexstrike.rustscan_scan(src_ip, ports="1-1000")

                # For DDoS/Botnet, get threat intelligence
                if "DDOS" in attack_type or "BOTNET" in attack_type:
                    logger.info(f"Tier 1: Getting threat intel for {src_ip}")
                    hexstrike_enrichment["threat_intel"] = self.hexstrike.analyze_target(src_ip, "comprehensive")

                enriched_alert["hexstrike_enrichment"] = hexstrike_enrichment

            except Exception as exc:
                logger.warning(f"Tier 1 Hexstrike enrichment failed: {exc}")
                enriched_alert["hexstrike_error"] = str(exc)

        # LLM triage — anchor on concrete endpoints + full JSON payload
        tier1_ids_snapshot: Dict[str, Any] = {}
        if ids_prediction and isinstance(ids_prediction, dict):
            tier1_ids_snapshot["ids_prediction"] = ids_prediction
        facts = format_observed_facts_block(
            alert_data,
            tier1_output=tier1_ids_snapshot or None,
            hexstrike_enrichment=enriched_alert.get("hexstrike_enrichment"),
        )
        ctx = (input_data.get("context_logs") or "").strip()
        if len(ctx) > 14000:
            ctx = ctx[:14000] + "\n... [context_logs truncated]"
        db_preamble = ""
        if ctx:
            db_preamble = (
                "### Flow database & operational context (IDS `flow_history.db` — cite this for historical behavior)\n"
                f"{ctx}\n\n"
            )
        prompt = (
            f"{facts}\n\n"
            f"{db_preamble}"
            f"### Enriched telemetry (machine-readable)\n"
            f"{json.dumps(enriched_alert, indent=2, default=str)}\n"
        )
        llm_response = self._sanitize_endpoint_placeholders(
            self._stream_with_config(prompt) or "LLM Error",
            _resolve_src_ip(alert_data),
            _resolve_dst_ip(alert_data),
        )

        # Parse structured block from LLM output
        metadata = self._extract_json_block(llm_response) or {}

        # ``.get("severity", "Medium")`` returns None if JSON had "severity": null
        final_severity = metadata.get("severity") or "Medium"
        should_escalate = bool(metadata.get("escalate", False))
        is_false_positive = metadata.get("false_positive", False)

        # Heuristic override: force escalation for DDoS / Botnet
        attack_type = str(alert_data.get("Attack", "")).upper()
        if any(p in attack_type for p in _HIGH_SEVERITY_PATTERNS):
            final_severity = "High"
            should_escalate = True
            is_false_positive = False

        return {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "raw_alert": alert_data,
            "enriched_alert": enriched_alert,
            "triage_response": llm_response,
            "severity": final_severity,
            "false_positive": is_false_positive,
            "escalate": should_escalate,
            "ids_prediction": ids_prediction,
            "forensic_status": metadata.get("forensic_status", "NONE"),
            "recommended_actions": metadata.get("recommended_actions", []),
        }

    # ── Tier 2 processing ───────────────────────────────────────────────

    def _process_tier2(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tier 2: deep investigation based on Tier 1 output.

        Applies heuristic overrides for DDoS / Botnet after the LLM response.
        """
        tier1_output = input_data.get("tier1_output", {})
        raw_alert = tier1_output.get("raw_alert") or {}
        enriched = tier1_output.get("enriched_alert") or {}
        hs_workflow = input_data.get("hexstrike_enrichment") or enriched.get("hexstrike_enrichment") or {}
        facts = format_observed_facts_block(
            raw_alert if isinstance(raw_alert, dict) else {},
            tier1_output=tier1_output,
            hexstrike_enrichment=hs_workflow if isinstance(hs_workflow, dict) else {},
        )
        ctx = input_data.get("context_logs", "")
        if isinstance(ctx, str) and len(ctx) > 6000:
            ctx = ctx[:6000] + "\n... [truncated]"

        prompt = f"""{facts}

### Forensic / workflow HexStrike payload (authoritative for open ports, reputation)
{json.dumps(hs_workflow, indent=2, default=str) if hs_workflow else "{}"}

### Historical / flow context (feeder logs)
{ctx}

### Similar past incidents (knowledge base)
{json.dumps(input_data.get("similar_incidents"), indent=2, default=str)}

### Tier 1 triage (model output)
{tier1_output.get("triage_response", "")}

### Tier 1 enriched telemetry (subset)
{json.dumps(
    {k: enriched.get(k) for k in (
        "SourceIP", "DestinationIP", "source_geolocation", "destination_geolocation",
        "src_ip_reputation", "dst_ip_reputation", "hexstrike_enrichment", "ids_prediction", "ids_confidence",
    ) if k in enriched},
    indent=2,
    default=str,
)}
"""
        llm_response = self._sanitize_endpoint_placeholders(
            self._stream_with_config(prompt) or "LLM Error",
            _resolve_src_ip(raw_alert if isinstance(raw_alert, dict) else {}),
            _resolve_dst_ip(raw_alert if isinstance(raw_alert, dict) else {}),
        )
        metadata = self._extract_json_block(llm_response) or {}

        val_severity = metadata.get("validated_severity") or metadata.get("severity") or "High"
        should_escalate = bool(metadata.get("escalate", False))

        # Heuristic override
        attack_type = str(tier1_output.get("raw_alert", {}).get("Attack", "")).upper()
        if any(p in attack_type for p in _HIGH_SEVERITY_PATTERNS):
            val_severity = "High"
            should_escalate = True

        return {
            "tier": "Tier 2",
            "validated_severity": val_severity,
            "incident_classification": metadata.get("incident_classification", "Suspicious"),
            "recommended_actions": metadata.get("recommended_actions", "N/A"),
            "escalate": "Yes" if should_escalate else "No",
            "confidence": float(metadata.get("confidence", 0.0)),
            "forensic_status": metadata.get("forensic_status", "INVESTIGATING"),
            "full_report": llm_response,
        }

    # ── Tier 3 processing ───────────────────────────────────────────────

    def _process_tier3(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Tier 3: generate an incident response plan."""
        tier1_output = input_data.get("tier1_output") or {}
        tier2_output = input_data.get("tier2_output") or {}
        raw_alert = tier1_output.get("raw_alert") or input_data.get("alert_data") or {}
        if not isinstance(raw_alert, dict):
            raw_alert = {}
        hs = input_data.get("hexstrike_enrichment") or (
            (tier1_output.get("enriched_alert") or {}).get("hexstrike_enrichment")
        )
        facts = format_observed_facts_block(
            raw_alert,
            tier1_output=tier1_output,
            hexstrike_enrichment=hs if isinstance(hs, dict) else {},
        )
        ctx = input_data.get("context_logs", "")
        if isinstance(ctx, str) and len(ctx) > 4000:
            ctx = ctx[:4000] + "\n... [truncated]"

        prompt = f"""{facts}

### Tier 2 investigation output (use concrete IPs from OBSERVED FACTS only)
{tier2_output.get("full_report", "")}

### Context for this incident (flows / logs)
{ctx}

### Workflow forensic enrichment (summary keys)
{json.dumps(list((hs or {}).keys()) if isinstance(hs, dict) else [], default=str)}
"""
        llm_response = self._sanitize_endpoint_placeholders(
            self._stream_with_config(prompt) or "LLM Error",
            _resolve_src_ip(raw_alert),
            _resolve_dst_ip(raw_alert),
        )
        metadata = self._extract_json_block(llm_response) or {}

        return {
            "tier": "Tier 3",
            "response_plan": llm_response,
            "status": "Plan Generated",
            "credible_threat": metadata.get("credible_threat", False),
            "recommended_actions": metadata.get("recommended_actions", []),
        }

    # ── Enrichment helpers ──────────────────────────────────────────────

    def enrich_log(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an alert with geolocation and IP reputation data.

        Queries both source and destination IPs when available.
        """
        enriched = dict(alert) if isinstance(alert, dict) else {}
        src_ip = _resolve_src_ip(enriched)
        dst_ip = _resolve_dst_ip(enriched)
        if src_ip:
            enriched["SourceIP"] = src_ip
        if dst_ip:
            enriched["DestinationIP"] = dst_ip

        if src_ip:
            rep_src = self.abuseipdb_check(src_ip)
            enriched["src_ip_reputation"] = rep_src
            enriched["ip_reputation"] = rep_src  # legacy key consumed by assess_severity
            if self.geo_locator:
                enriched["source_geolocation"] = self.geo_locator.locate_ip(src_ip)

        if dst_ip:
            enriched["dst_ip_reputation"] = self.abuseipdb_check(dst_ip)
            if self.geo_locator:
                enriched["destination_geolocation"] = self.geo_locator.locate_ip(dst_ip)

        return enriched

    def _sanitize_endpoint_placeholders(self, text: str, src_ip: str, dst_ip: str) -> str:
        """Replace common LLM placeholder tokens with resolved telemetry when available."""
        if not text:
            return text
        out = text
        if src_ip:
            for token in (
                "<SOURCE_IP>",
                "<source_ip>",
                "<SRC_IP>",
                "<IPv4_SRC>",
            ):
                out = out.replace(token, src_ip)
        if dst_ip:
            for token in (
                "<DESTINATION_IP>",
                "<destination_ip>",
                "<DST_IP>",
                "<TARGET_IP>",
                "<target_ip>",
                "<IPv4_DST>",
            ):
                out = out.replace(token, dst_ip)
        return out

    def _is_internal_ip(self, ip: str) -> bool:
        """
        Check if an IP address is internal/private.

        Args:
            ip: IP address to check

        Returns:
            True if the IP is in a private range
        """
        if not ip:
            return False

        internal_prefixes = ["192.168.", "10.", "172.16.", "172.17.", "172.18.",
                            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                            "172.29.", "172.30.", "172.31.", "127."]
        return any(ip.startswith(prefix) for prefix in internal_prefixes)

    def abuseipdb_check(self, ip: str) -> Dict[str, Any]:
        """
        Query the AbuseIPDB API for IP reputation.

        Returns a dict with confidence score, report count, country, and
        a derived ``status`` label (*malicious* / *suspicious* / *clean*).
        """
        try:
            if requests is None:
                return {"error": "requests dependency not available"}

            base_url = self.config.get("abuseipdb_base_url")
            api_key = self.config.get("abuseipdb_api_key")

            if not base_url or not api_key:
                return {"error": "AbuseIPDB configuration not found"}

            url = f"{base_url}?ipAddress={ip}&maxAgeInDays=90"
            headers = {"Accept": "application/json", "Key": api_key}

            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code != 200:
                logger.error("AbuseIPDB API error: %d", response.status_code)
                return {"error": f"AbuseIPDB API error {response.status_code}"}

            data = response.json().get("data", {})
            reputation = {
                "ip": ip,
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "isWhitelisted": data.get("isWhitelisted", False),
                "countryCode": data.get("countryCode", "Unknown"),
                "usageType": data.get("usageType", "Unknown"),
                "domain": data.get("domain", "N/A"),
                "lastReportedAt": data.get("lastReportedAt", "Unknown"),
            }

            # Classify based on confidence score thresholds
            score = reputation["abuseConfidenceScore"]
            if score >= _ABUSE_MALICIOUS_THRESHOLD:
                reputation["status"] = "malicious"
            elif score >= _ABUSE_SUSPICIOUS_THRESHOLD:
                reputation["status"] = "suspicious"
            else:
                reputation["status"] = "clean"

            return reputation

        except Exception as exc:
            logger.error("Error querying AbuseIPDB: %s", exc)
            return {"error": str(exc)}

    # ── Heuristic severity & false-positive helpers ─────────────────────

    def assess_severity(self, alert: Dict[str, Any]) -> str:
        """
        Compute a heuristic severity level from enrichment data.

        Scoring considers IP reputation, IDS prediction confidence,
        and known attack labels.  Falls back to the alert's own
        ``Severity`` field when present.
        """
        score = 0
        ip_rep = alert.get("ip_reputation", {})

        # IP reputation contribution
        if ip_rep.get("status") == "malicious":
            score += 5
        elif ip_rep.get("status") == "suspicious":
            score += 3

        # IDS prediction contribution
        ids_prediction = alert.get("ids_prediction", "")
        ids_confidence = alert.get("ids_confidence", 0.0)

        if ids_prediction and ids_prediction.upper() != "BENIGN":
            if ids_confidence > 0.8:
                score += 5
            elif ids_confidence > 0.6:
                score += 3
            elif ids_confidence > 0.4:
                score += 1

            if ids_prediction.upper() in _CRITICAL_ATTACK_LABELS:
                score += 5
            elif ids_prediction.upper() in _MODERATE_ATTACK_LABELS:
                score += 3

        # Label-based contribution
        label = alert.get("Attack", "").upper()
        if label in _CRITICAL_ATTACK_LABELS:
            score += 5
        elif label in _MODERATE_ATTACK_LABELS:
            score += 3

        # Prefer explicit severity if already set on the alert
        severity = alert.get("Severity", "").upper()
        if severity == "CRITICAL":
            return "Critical"
        elif severity == "HIGH":
            return "High"
        elif severity == "MEDIUM":
            return "Medium"
        elif severity == "LOW":
            return "Low"

        # Map cumulative score to a severity label
        if score <= 2:
            return "Low"
        elif score <= 5:
            return "Medium"
        elif score <= 8:
            return "High"
        return "Critical"

    def check_false_positive(self, alert: Dict[str, Any]) -> bool:
        """
        Heuristic false-positive check.

        Rules:
          - IDS predicts ``BENIGN`` with high confidence → FP.
          - Alert label itself is ``BENIGN`` → FP.
          - Clean IP + scan/portscan label → FP.
          - Internal source IP + BENIGN prediction → FP.
        """
        label = alert.get("Attack", "").upper()
        ip_status = alert.get("ip_reputation", {}).get("status", "clean")
        ids_prediction = alert.get("ids_prediction", "")
        ids_confidence = alert.get("ids_confidence", 0.0)

        if ids_prediction and ids_prediction.upper() == "BENIGN" and ids_confidence > 0.7:
            return True

        if label == "BENIGN":
            return True

        if ip_status == "clean" and label in _MODERATE_ATTACK_LABELS:
            return True

        if any(alert.get("SourceIP", "").startswith(net) for net in self.internal_networks):
            if label in _MODERATE_ATTACK_LABELS and ip_status == "clean":
                return True
            if ids_prediction and ids_prediction.upper() == "BENIGN":
                return True

        return False

    # ── Text extraction utility ─────────────────────────────────────────

    def extract_section(self, text: str, section_name: str) -> str:
        """Extract a markdown-bold section value (e.g. ``**Severity:** High``)."""
        match = re.search(rf"\*\*{section_name}:\*\*\s*(.+)", text, re.IGNORECASE)
        return match.group(1).strip() if match else "N/A"
