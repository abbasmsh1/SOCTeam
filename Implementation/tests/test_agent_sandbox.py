import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Implementation.src.Agents.AgentTools import get_agent_tools
from Implementation.src.Agents.DefensiveActionSandbox import DefensiveActionSandbox
from Implementation.src.Agents.RemediationAgent import RemediationAgent
from Implementation.src.Agents.SecurityTeamAgent import SecurityTeamAgent
from Implementation.src.Agents.SOCWorkflow import SOCWorkflow
from Implementation.src.Agents.TierAnalystAgent import TierAnalystAgent
from Implementation.src.Database.FlowHistoryManager import FlowHistoryManager


def test_sandbox_enforces_block_for_malicious_ip(tmp_path):
    sandbox = DefensiveActionSandbox(state_path=os.fspath(tmp_path / 'sandbox_state.json'))

    result = sandbox.execute_rule(
        {
            'action': 'BLOCK_IP',
            'target': '203.0.113.5',
            'reason': 'DDoS source',
            'duration': '1h',
        },
        threat_info={'Attack': 'DDOS', 'confidence': 0.99},
        auto_pilot=True,
    )

    assert result['status'] == 'ENFORCED'
    active = sandbox.list_active_rules()
    assert '203.0.113.5' in active['blocked_ips']


def test_sandbox_rejects_isolating_external_hosts(tmp_path):
    sandbox = DefensiveActionSandbox(state_path=os.fspath(tmp_path / 'sandbox_state.json'))

    result = sandbox.execute_rule(
        {'action': 'ISOLATE_HOST', 'target': '8.8.8.8', 'reason': 'Compromised host'},
        threat_info={'Attack': 'BOTNET', 'confidence': 0.98},
        auto_pilot=True,
    )

    assert result['status'] == 'REJECTED:ISOLATE_HOST_REQUIRES_INTERNAL_IP'


def test_remediation_agent_routes_actions_through_sandbox(tmp_path):
    agent = RemediationAgent(dry_run=False)
    agent.sandbox = DefensiveActionSandbox(state_path=os.fspath(tmp_path / 'sandbox_state.json'))
    agent.log_path = os.fspath(tmp_path / 'remediation_log.json')
    agent.active_rules_path = os.fspath(tmp_path / 'active_remediations.json')

    result = agent.process(
        {
            'threat_info': {'Attack': 'DDOS', 'SourceIP': '203.0.113.9', 'confidence': 0.96},
            'defense_plan': (
                '[ACTIONABLE_RULES]'
                '[{"action": "BLOCK_IP", "target": "203.0.113.9", "reason": "Malicious IP", "duration": "4h"}]'
                '[/ACTIONABLE_RULES]'
            ),
            'auto_pilot': True,
        }
    )

    assert result['remediation_status'] == 'COMPLETED'
    assert result['execution_log'][0]['status'] == 'ENFORCED'
    assert '203.0.113.9' in result['active_protections']['blocked_ips']


def test_remediation_agent_stages_rules_in_dry_run(tmp_path):
    agent = RemediationAgent(dry_run=True)
    agent.sandbox = DefensiveActionSandbox(state_path=os.fspath(tmp_path / 'sandbox_state.json'))
    agent.log_path = os.fspath(tmp_path / 'remediation_log.json')
    agent.active_rules_path = os.fspath(tmp_path / 'active_remediations.json')

    result = agent.process(
        {
            'threat_info': {'Attack': 'BRUTEFORCE', 'SourceIP': '203.0.113.11', 'confidence': 0.9},
            'defense_plan': (
                '[ACTIONABLE_RULES]'
                '[{"action": "BLOCK_IP", "target": "203.0.113.11", "reason": "Credential attack", "duration": "1h"}]'
                '[/ACTIONABLE_RULES]'
            ),
            'auto_pilot': True,
        }
    )

    assert result['execution_log'][0]['status'] == 'STAGED'
    assert result['active_protections']['blocked_ips'] == {}


def test_tier1_agent_exposes_local_defensive_tools(tmp_path):
    history = FlowHistoryManager(db_path=os.fspath(tmp_path / 'flows.db'))
    history.add_flow({'src_ip': '203.0.113.12', 'dst_ip': '10.0.0.5', 'Protocol': 'TCP'}, 'DDOS', 0.95)
    sandbox = DefensiveActionSandbox(state_path=os.fspath(tmp_path / 'sandbox_state.json'))

    tools = get_agent_tools(agent_name='Tier1Analyst', sandbox=sandbox, flow_history=history)
    names = {tool.name for tool in tools}

    assert 'lookup_ip_history' in names
    assert 'draft_block_rule' in names


def test_security_and_tier_agents_publish_tool_catalogs():
    tier1 = TierAnalystAgent(tier=1, api_key=None)
    blue = SecurityTeamAgent(role='blue', api_key=None)

    tier_tools = {tool['name'] for tool in tier1.list_tools()['tools']}
    blue_tools = {tool['name'] for tool in blue.list_tools()['tools']}

    assert 'draft_block_rule' in tier_tools
    assert 'lookup_ip_history' in tier_tools
    assert 'queue_target_enrichment' in blue_tools
    assert 'list_active_protections' in blue_tools


def test_soc_workflow_remediation_node_uses_sandbox(tmp_path):
    workflow = SOCWorkflow(api_key=None)
    workflow.remediation_executor = RemediationAgent(dry_run=False)
    workflow.remediation_executor.sandbox = DefensiveActionSandbox(
        state_path=os.fspath(tmp_path / 'sandbox_state.json')
    )
    workflow.remediation_executor.log_path = os.fspath(tmp_path / 'remediation_log.json')
    workflow.remediation_executor.active_rules_path = os.fspath(tmp_path / 'active_remediations.json')

    state = workflow._remediation_node(
        {
            'war_room_result': {},
            'tier1_result': {'ids_prediction': {'confidence': 0.97}},
            'tier2_result': {'confidence': 0.91},
            'tier3_result': {
                'response_plan': (
                    '[ACTIONABLE_RULES]'
                    '[{\"action\": \"BLOCK_IP\", \"target\": \"203.0.113.44\", \"reason\": \"Confirmed botnet\", \"duration\": \"permanent\"}]'
                    '[/ACTIONABLE_RULES]'
                )
            },
            'alert_data': {'Attack': 'BOTNET', 'SourceIP': '203.0.113.44', 'confidence': 0.98},
        }
    )

    remediation = state['remediation_result']
    assert remediation['remediation_status'] == 'COMPLETED'
    assert remediation['execution_log'][0]['status'] == 'ENFORCED'
    assert '203.0.113.44' in remediation['active_protections']['blocked_ips']
