"""
Backwards Compatibility Layer
Maintains old agent API while using new optimized implementations.
"""

try:
    from .SecurityTeamAgent import SecurityTeamAgent
    from .TierAnalystAgent import TierAnalystAgent
    from .RemediationAgent import RemediationAgent
except (ImportError, ValueError):
    from SecurityTeamAgent import SecurityTeamAgent
    from TierAnalystAgent import TierAnalystAgent
    from RemediationAgent import RemediationAgent

from typing import Optional

# ==================== Security Team Compatibility ====================

# Compatibility: RedTeamAgent
class RedTeamAgent(SecurityTeamAgent):
    """Red Team Agent - Backwards compatible wrapper."""
    def __init__(self, api_key: Optional[str] = None, hexstrike_url: Optional[str] = None):
        super().__init__(role="red", api_key=api_key, hexstrike_url=hexstrike_url)


# Compatibility: BlueTeamAgent
class BlueTeamAgent(SecurityTeamAgent):
    """Blue Team Agent - Backwards compatible wrapper."""
    def __init__(self, api_key: Optional[str] = None, hexstrike_url: Optional[str] = None):
        super().__init__(role="blue", api_key=api_key, hexstrike_url=hexstrike_url)


# Compatibility: PurpleTeamAgent
class PurpleTeamAgent(SecurityTeamAgent):
    """Purple Team Agent - Backwards compatible wrapper."""
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(role="purple", api_key=api_key, hexstrike_url=None)
    
    # Keep the old analyze_exercise method name
    def analyze_exercise(self, red_output: dict, blue_output: dict):
        """Analyze Red/Blue exercise (compatibility method)."""
        return self.process({"red_output": red_output, "blue_output": blue_output})


# ==================== Tier Analyst Compatibility ====================

# Compatibility: Tier1Analyst
class Tier1Analyst(TierAnalystAgent):
    """Tier 1 Analyst - Backwards compatible wrapper."""
    def __init__(self, api_key: Optional[str] = None, hexstrike_url: Optional[str] = None):
        super().__init__(tier=1, api_key=api_key, hexstrike_url=hexstrike_url)


# Compatibility: Tier2Analyst
class Tier2Analyst(TierAnalystAgent):
    """Tier 2 Analyst - Backwards compatible wrapper."""
    def __init__(self, api_key: Optional[str] = None, hexstrike_url: Optional[str] = None):
        super().__init__(tier=2, api_key=api_key, hexstrike_url=hexstrike_url)


# Compatibility: Tier3Analyst
class Tier3Analyst(TierAnalystAgent):
    """Tier 3 Analyst - Backwards compatible wrapper."""
    def __init__(self, api_key: Optional[str] = None, hexstrike_url: Optional[str] = None):
        super().__init__(tier=3, api_key=api_key, hexstrike_url=hexstrike_url)


# Compatibility: RemediationAgent
class RemediationAgentCompat(RemediationAgent):
    """Remediation Agent - Backwards compatible wrapper."""
    def __init__(self, dry_run: bool = True):
        super().__init__(dry_run=dry_run)

