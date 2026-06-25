class AnomalyDetector:
    def __init__(self, matcher=None):
        self.matcher = matcher

    def detect_anomaly(self, event):
        """
        Runs fallback heuristics on a normalized event.
        Returns a synthetic rule dictionary if an anomaly is detected, or None.
        """
        category = str(event.get("event", {}).get("category", "")).lower()
        action = str(event.get("event", {}).get("action", "")).lower()
        user_name = str(event.get("user", {}).get("name", "")).lower()

        # 1. Unusual process execution by web service accounts
        if category == "process" and user_name in ["www-data", "apache", "nginx", "guest"]:
            proc_name = str(self.matcher.get_field_value(event, "process.name")).lower()
            suspicious_commands = ["bash", "sh", "whoami", "id", "net", "ipconfig", "wget", "curl", "uname"]
            if proc_name in suspicious_commands or any(cmd in proc_name for cmd in suspicious_commands):
                return {
                    "rule_id": "anomaly-proc-web-user",
                    "rule_name": "Anomalous System Execution by Web User",
                    "severity": "critical",
                    "confidence": 85,
                    "anomaly_type": "user_process_anomaly",
                    "recommended_actions": [
                        {"step": 1, "action": "Kill parent process spawning shells."},
                        {"step": 2, "action": "Isolate target web server from production subnets."}
                    ],
                    "explanation": {
                        "summary": f"Web user '{user_name}' executed system utility '{proc_name}', suggesting web exploitation."
                    }
                }

        # 2. High risk egress port connections
        if category == "network":
            dest_port = event.get("destination", {}).get("port")
            if dest_port in [4444, 31337, 8080]:
                return {
                    "rule_id": "anomaly-net-high-risk-port",
                    "rule_name": "Egress Traffic to High Risk Port",
                    "severity": "high",
                    "confidence": 90,
                    "anomaly_type": "network_anomaly",
                    "recommended_actions": [
                        {"step": 1, "action": "Block the destination IP at perimeter firewall."},
                        {"step": 2, "action": "Collect network sockets list from host."}
                    ],
                    "explanation": {
                        "summary": f"Detected outbound network socket connection targeting high-risk port {dest_port}."
                    }
                }

        # 3. Privilege escalation anomalies
        if category == "process":
            privilege = event.get("user", {}).get("privilege_level")
            parent_name = str(self.matcher.get_field_value(event, "process.parent.name")).lower()
            child_name = str(self.matcher.get_field_value(event, "process.name")).lower()
            if privilege == "admin" and parent_name in ["explorer.exe", "winword.exe", "excel.exe"]:
                return {
                    "rule_id": "anomaly-priv-escalation",
                    "rule_name": "Suspicious Privilege Escalation lineage",
                    "severity": "high",
                    "confidence": 75,
                    "anomaly_type": "privilege_anomaly",
                    "recommended_actions": [
                        {"step": 1, "action": "Audit active user sessions and RDP login logs."},
                        {"step": 2, "action": "Terminate administrative process."}
                    ],
                    "explanation": {
                        "summary": f"Process '{child_name}' executed with administrator privilege from non-admin parent '{parent_name}'."
                    }
                }

        # 4. Abnormal file modifications (large sizing or system modifications)
        if category == "file":
            file_path = str(self.matcher.get_field_value(event, "file.path")).lower()
            if any(sys_path in file_path for sys_path in ["system32", "etc/passwd", "etc/shadow"]):
                return {
                    "rule_id": "anomaly-sys-file-modification",
                    "rule_name": "Sensitive System File Access Anomaly",
                    "severity": "critical",
                    "confidence": 95,
                    "anomaly_type": "file_integrity_anomaly",
                    "recommended_actions": [
                        {"step": 1, "action": "Lock user account associated with modifications."},
                        {"step": 2, "action": "Run immediate host integrity diagnostic check."}
                    ],
                    "explanation": {
                        "summary": f"Unusual modification action performed on high-severity system file path '{file_path}'."
                    }
                }

        return None
