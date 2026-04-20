"""
Pluggable IP reputation sources.

The IPBlockingManager historically used a hard-coded IP-prefix heuristic to
"simulate" an AbuseIPDB lookup. This module extracts that behaviour behind a
small interface so real feeds (AbuseIPDB, VirusTotal, OTX, …) can be swapped
in without touching the rest of the SOC pipeline.

Selection is env-driven:
  REPUTATION_SOURCE=abuseipdb  # requires ABUSEIPDB_API_KEY
  REPUTATION_SOURCE=simulated  # default; offline
  REPUTATION_SOURCE=null       # disables reputation entirely
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Protocol, TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from .IPBlockingManager import IPReputation

logger = logging.getLogger(__name__)


class ReputationSource(Protocol):
    """Returns a fully-populated IPReputation for the given IP."""

    def fetch(self, ip: str, reputation: "IPReputation") -> "IPReputation": ...


class SimulatedReputationSource:
    """Legacy heuristic — kept for offline demos / unit tests."""

    def fetch(self, ip: str, reputation: "IPReputation") -> "IPReputation":
        if ip.startswith(("192.", "10.", "172.")):
            reputation.abuse_score = 10
        elif ip.startswith(("203.", "185.")):
            reputation.abuse_score = 35
        else:
            reputation.abuse_score = 20
        reputation.total_reports = int(reputation.abuse_score * 2)
        reputation.country = reputation.country or "Unknown"
        return reputation


class NullReputationSource:
    """Returns the reputation untouched. Useful when the feature is disabled."""

    def fetch(self, ip: str, reputation: "IPReputation") -> "IPReputation":
        return reputation


class AbuseIPDBReputationSource:
    """Real AbuseIPDB /api/v2/check adapter. Requires ABUSEIPDB_API_KEY."""

    ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, timeout: float = 4.0, max_age_days: int = 90):
        self.api_key = api_key
        self.timeout = timeout
        self.max_age_days = max_age_days

    def fetch(self, ip: str, reputation: "IPReputation") -> "IPReputation":
        try:
            resp = requests.get(
                self.ENDPOINT,
                params={"ipAddress": ip, "maxAgeInDays": self.max_age_days},
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            body = (resp.json() or {}).get("data") or {}
        except requests.RequestException as exc:
            logger.warning("[AbuseIPDB] fetch failed for %s: %s", ip, exc)
            return SimulatedReputationSource().fetch(ip, reputation)
        except ValueError as exc:
            logger.warning("[AbuseIPDB] invalid JSON for %s: %s", ip, exc)
            return SimulatedReputationSource().fetch(ip, reputation)

        reputation.abuse_score = float(body.get("abuseConfidenceScore", 0) or 0)
        reputation.total_reports = int(body.get("totalReports", 0) or 0)
        reputation.country = body.get("countryCode") or reputation.country
        reputation.isp = body.get("isp") or reputation.isp
        reputation.is_tor = bool(body.get("isTor"))
        usage_type = (body.get("usageType") or "").lower()
        reputation.is_vpn = "vpn" in usage_type or "hosting" in usage_type
        reputation.is_proxy = "proxy" in usage_type
        return reputation


def build_reputation_source(explicit: Optional[str] = None) -> ReputationSource:
    """Factory reading REPUTATION_SOURCE + ABUSEIPDB_API_KEY from env."""
    choice = (explicit or os.getenv("REPUTATION_SOURCE") or "simulated").strip().lower()

    if choice == "abuseipdb":
        key = os.getenv("ABUSEIPDB_API_KEY")
        if not key:
            logger.warning(
                "[reputation] REPUTATION_SOURCE=abuseipdb but ABUSEIPDB_API_KEY missing; "
                "falling back to simulated source."
            )
            return SimulatedReputationSource()
        return AbuseIPDBReputationSource(api_key=key)

    if choice == "null":
        return NullReputationSource()

    return SimulatedReputationSource()
