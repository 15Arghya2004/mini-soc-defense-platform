import logging

logger = logging.getLogger("sentrix.investigation.attack_path_analyzer")

class AttackPathAnalyzer:
    def analyze(self, source_ip: str, threat_findings: list) -> dict:
        """
        Maps path hops showing how the attack progressed from source to target.
        
        Parameters:
            source_ip       : attacker source IP
            threat_findings : list of alerts
            
        Returns:
            dict: Path nodes and edges
        """
        nodes = [{"id": source_ip, "label": f"Attacker ({source_ip})", "type": "attacker"}]
        edges = []
        
        # Track unique hosts
        hosts = {}
        for alert in threat_findings:
            host = alert.get("affected_host")
            if not host or host == "unknown":
                continue
            
            risk = alert.get("risk_score", 0)
            rule = alert.get("rule_name", "Unknown Rule")
            
            if host not in hosts:
                hosts[host] = {"max_risk": risk, "rules": {rule}}
            else:
                hosts[host]["max_risk"] = max(hosts[host]["max_risk"], risk)
                hosts[host]["rules"].add(rule)

        # Add target nodes and build edges
        for idx, (host, data) in enumerate(hosts.items()):
            node_id = f"host-{idx}"
            nodes.append({
                "id": node_id,
                "label": f"Target ({host})",
                "type": "target",
                "hostname": host,
                "max_risk": data["max_risk"]
            })
            
            edges.append({
                "from": source_ip,
                "to": node_id,
                "risk_score": data["max_risk"],
                "rules_triggered": list(data["rules"]),
                "details": f"Attacked via {len(data['rules'])} unique rules (Max Risk: {data['max_risk']}/100)"
            })

        # If no target hosts were found, add a generic target to form a path
        if len(nodes) == 1:
            nodes.append({"id": "target-unknown", "label": "Unknown Target", "type": "target"})
            edges.append({
                "from": source_ip,
                "to": "target-unknown",
                "risk_score": 0,
                "rules_triggered": [],
                "details": "Telemetry contains no destination host."
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "path_description": f"Attack path starts at source IP {source_ip} and targets {len(hosts)} unique system(s)."
        }
