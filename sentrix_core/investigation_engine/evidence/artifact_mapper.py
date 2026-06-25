import logging

logger = logging.getLogger("sentrix.investigation.artifact_mapper")

class ArtifactMapper:
    def map_artifacts(self, threat_findings: list) -> dict:
        """
        Scans threat findings for Indicators of Compromise (IOCs) and system artifacts.
        
        Parameters:
            threat_findings : list of alerts
            
        Returns:
            dict: Categorized artifacts (processes, network, registry, users)
        """
        processes = set()
        command_lines = set()
        registry_keys = set()
        network_ports = set()
        users = set()

        for alert in threat_findings:
            raw_alert = alert.get("raw_alert") or {}
            
            # Helper to recursively scan dict for keys
            self._scan_dict(raw_alert, processes, command_lines, registry_keys, network_ports, users)
            
            # Also scan top-level alert details if any
            details = alert.get("details") or {}
            self._scan_dict(details, processes, command_lines, registry_keys, network_ports, users)
            
            # Check rule-specific details
            rule_name = alert.get("rule_name", "").lower()
            if "powershell" in rule_name:
                processes.add("powershell.exe")
            if "netcat" in rule_name or "relay tool" in rule_name:
                processes.add("nc.exe")
            if "port scan" in rule_name:
                processes.add("nmap")

        return {
            "processes": sorted(list(processes)),
            "command_lines": sorted(list(command_lines)),
            "registry_keys": sorted(list(registry_keys)),
            "network_ports": sorted(list(network_ports)),
            "users": sorted(list(users)),
            "total_artifacts_count": len(processes) + len(command_lines) + len(registry_keys) + len(network_ports) + len(users)
        }

    def _scan_dict(self, data: dict, processes: set, command_lines: set, 
                   registry_keys: set, network_ports: set, users: set):
        if not isinstance(data, dict):
            return

        for k, v in data.items():
            k_lower = k.lower()
            
            # Process mapping
            if k_lower in ("process", "process_name", "executable", "image", "proc") and isinstance(v, str):
                processes.add(v)
            
            # Command lines mapping
            elif k_lower in ("command_line", "cmdline", "arguments", "args") and isinstance(v, str):
                command_lines.add(v)
            
            # Registry mapping
            elif k_lower in ("registry_key", "reg_key", "registry_path", "key_path") and isinstance(v, str):
                registry_keys.add(v)
            
            # Network ports mapping
            elif k_lower in ("dest_port", "dst_port", "destination_port", "port") and v:
                network_ports.add(str(v))
            
            # Users mapping
            elif k_lower in ("user", "username", "target_user", "uid") and isinstance(v, str):
                users.add(v)
            
            # Recursively check sub-dictionaries or lists of dicts
            elif isinstance(v, dict):
                self._scan_dict(v, processes, command_lines, registry_keys, network_ports, users)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        self._scan_dict(item, processes, command_lines, registry_keys, network_ports, users)
