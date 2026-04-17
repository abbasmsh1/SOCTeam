import os

path = r"e:\IMT\2nd Sem\Project\Implementation\src\Agents\SecurityTeamAgent.py"
with open(path, "r") as f:
    content = f.read()

# Add to Capability list
old_caps = '7. [TUNE_SIEM]: Adjust detection rules to reduce false positives or catch new variants.'
new_caps = old_caps + '\n        8. [FIREWALL_RULE]: Add granular IP/Port/Protocol rules to the mock firewall.'
content = content.replace(old_caps, new_caps)

# Add to Strategy
old_strat = '- SIEM/Detection Issues: Use TUNE_SIEM to suggest rule modifications.'
new_strat = old_strat + '\n        - Lateral Movement: Use FIREWALL_RULE to DENY high-port traffic between sensitive subnets.'
content = content.replace(old_strat, new_strat)

# Add to Example block
old_example = '          {{"action": "TUNE_SIEM", "target": "RULE_NAME", "reason": "High false positive rate"}}'
new_example = '          {{"action": "FIREWALL_RULE", "priority": 50, "action_type": "DENY", "src_ip": "SOURCE_IP", "port": 445, "protocol": "TCP", "reason": "SMB Lateral movement detected"}},\n' + old_example
content = content.replace(old_example, new_example)

with open(path, "w") as f:
    f.write(content)

print("Updated SecurityTeamAgent.py successfully.")
