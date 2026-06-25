import logging

logger = logging.getLogger("sentrix.investigation.evidence_graph")

class EvidenceGraph:
    def build(self, source_ip: str, threat_findings: list) -> dict:
        """
        Builds a comprehensive relationship graph for the incident.
        
        Parameters:
            source_ip       : Attacker IP
            threat_findings : List of threat alerts
            
        Returns:
            dict: Graph containing nodes and edges
        """
        nodes = []
        edges = []
        
        # Add primary Attacker node
        nodes.append({
            "id": source_ip,
            "label": f"Attacker IP: {source_ip}",
            "type": "attacker",
            "group": "threat_actor"
        })

        seen_nodes = {source_ip}
        for alert in threat_findings:
            alert_id = alert.get("alert_id")
            rule_name = alert.get("rule_name", "Unknown Rule")
            host = alert.get("affected_host", "unknown")
            
            # 1. Add Alert Node
            if alert_id not in seen_nodes:
                nodes.append({
                    "id": alert_id,
                    "label": f"Alert: {rule_name}",
                    "type": "alert",
                    "group": "rules",
                    "severity": alert.get("severity", "low"),
                    "risk": alert.get("risk_score", 0)
                })
                seen_nodes.add(alert_id)
                
                # Link Attacker -> Alert
                edges.append({
                    "from": source_ip,
                    "to": alert_id,
                    "label": "triggered"
                })

            # 2. Add Target Host Node
            if host != "unknown" and host not in seen_nodes:
                nodes.append({
                    "id": host,
                    "label": f"Host: {host}",
                    "type": "host",
                    "group": "infrastructure"
                })
                seen_nodes.add(host)
                
            # Link Alert -> Host
            if host != "unknown":
                edges.append({
                    "from": alert_id,
                    "to": host,
                    "label": "affected"
                })

            # 3. Add MITRE Techniques as separate Nodes
            techs = alert.get("mitre_techniques") or []
            for tech in techs:
                if tech and tech not in seen_nodes:
                    nodes.append({
                        "id": tech,
                        "label": f"MITRE Technique: {tech}",
                        "type": "technique",
                        "group": "mitre_attck"
                    })
                    seen_nodes.add(tech)
                
                # Link Alert -> Technique
                if tech:
                    edges.append({
                        "from": alert_id,
                        "to": tech,
                        "label": "maps_to"
                    })

        return {
            "nodes": nodes,
            "edges": edges
        }
