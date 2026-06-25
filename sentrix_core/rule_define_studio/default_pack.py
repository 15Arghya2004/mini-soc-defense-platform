"""
sentrix_core/rule_define_studio/default_pack.py
Default Detection Content Pack.
"""
import os
import json
import logging
from typing import List

logger = logging.getLogger("sentrix.default_pack")

def _make_rule(rid, name, tactic, tech, cat, field, op, val, sev="medium"):
    return {
        "rule_id": rid,
        "rule_name": name,
        "description": f"Detects {name}",
        "category": cat,
        "severity": sev,
        "confidence": 80,
        "base_risk_score": 60 if sev == "high" else 40,
        "version": "1",
        "mitre_mapping": [{"tactic": tactic, "technique_id": tech}],
        "conditions": {
            "all": [{"field": field, "operator": op, "value": val}]
        },
        "recommended_actions": [{"step": 1, "action": "Investigate immediately."}]
    }

DEFAULT_RULES = [
    _make_rule("00000000-0000-4000-8000-000000000001", "Brute Force Authentication", "Credential Access", "T1110", "Authentication", "event_type", "equals", "auth_failure", "high"),
    _make_rule("00000000-0000-4000-8000-000000000002", "Network Port Scan", "Discovery", "T1046", "Reconnaissance", "event_type", "equals", "connection_attempt"),
    _make_rule("00000000-0000-4000-8000-000000000003", "DNS Tunneling Detection", "Command and Control", "T1071", "C2", "network.dns_query_length", "greater_than", 150, "high"),
    _make_rule("00000000-0000-4000-8000-000000000004", "C2 Beaconing Activity", "Command and Control", "T1071", "C2", "event_type", "equals", "outbound_connection", "high"),
    _make_rule("00000000-0000-4000-8000-000000000005", "Suspicious PowerShell Execution", "Execution", "T1059", "Execution", "process.command_line", "contains", "-EncodedCommand", "high"),
    _make_rule("00000000-0000-4000-8000-000000000006", "Ransomware File Extension", "Impact", "T1486", "Ransomware", "file.name", "contains", ".encrypted", "critical"),
    _make_rule("00000000-0000-4000-8000-000000000007", "Large Data Exfiltration", "Exfiltration", "T1048", "Exfiltration", "network.bytes_out", "greater_than", 500000000, "high"),
    _make_rule("00000000-0000-4000-8000-000000000008", "Privilege Escalation Attempt", "Privilege Escalation", "T1068", "Privilege Escalation", "process.name", "equals", "whoami.exe", "medium"),
    _make_rule("00000000-0000-4000-8000-000000000009", "Lateral Movement via SMB", "Lateral Movement", "T1021", "Lateral Movement", "destination.port", "equals", 445),
    _make_rule("00000000-0000-4000-8000-00000000000a", "Credential Dumping", "Credential Access", "T1003", "Credential Access", "process.name", "equals", "mimikatz.exe", "critical"),
    
    # 10 More to hit 20+ requirement
    _make_rule("00000000-0000-4000-8000-000000000011", "Suspicious Bash History Deletion", "Defense Evasion", "T1070", "Defense Evasion", "process.command_line", "contains", "rm ~/.bash_history", "high"),
    _make_rule("00000000-0000-4000-8000-000000000012", "Scheduled Task Creation", "Persistence", "T1053", "Persistence", "process.name", "equals", "schtasks.exe"),
    _make_rule("00000000-0000-4000-8000-000000000013", "Registry Run Keys", "Persistence", "T1547", "Persistence", "process.command_line", "contains", "CurrentVersion\\Run", "high"),
    _make_rule("00000000-0000-4000-8000-000000000014", "Tor Network Connection", "Command and Control", "T1090", "C2", "destination.ti_enrichment.source", "equals", "tor_exit_node", "high"),
    _make_rule("00000000-0000-4000-8000-000000000015", "Log Clearing", "Defense Evasion", "T1070", "Defense Evasion", "process.command_line", "contains", "wevtutil cl", "high"),
    _make_rule("00000000-0000-4000-8000-000000000016", "WMI Execution", "Execution", "T1047", "Execution", "process.name", "equals", "wmic.exe"),
    _make_rule("00000000-0000-4000-8000-000000000017", "Data Staging", "Collection", "T1074", "Collection", "process.command_line", "contains", "tar -czf"),
    _make_rule("00000000-0000-4000-8000-000000000018", "RDP Abuse", "Lateral Movement", "T1021", "Lateral Movement", "destination.port", "equals", 3389),
    _make_rule("00000000-0000-4000-8000-000000000019", "Kerberoasting", "Credential Access", "T1558", "Credential Access", "event_type", "equals", "ticket_request", "high"),
    _make_rule("00000000-0000-4000-8000-000000000020", "Suspicious Download", "Initial Access", "T1189", "Initial Access", "process.command_line", "contains", "Invoke-WebRequest"),
    _make_rule("00000000-0000-4000-8000-000000000021", "LSASS Memory Dump", "Credential Access", "T1003", "Credential Access", "process.command_line", "contains", "procdump", "critical")
]

def ensure_default_pack(rules_dir: str):
    """Loads default rules into the rules directory if they don't exist."""
    os.makedirs(rules_dir, exist_ok=True)
    count = 0
    for rule in DEFAULT_RULES:
        rule_id = rule["rule_id"]
        path = os.path.join(rules_dir, f"{rule_id}.json")
        if not os.path.exists(path):
            with open(path, "w") as f:
                json.dump(rule, f, indent=4)
            count += 1
    if count > 0:
        logger.info(f"Loaded {count} default detections into {rules_dir}")
