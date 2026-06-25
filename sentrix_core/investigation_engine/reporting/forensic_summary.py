class ForensicSummaryFormatter:
    def format(self, payload: dict) -> dict:
        """
        Formats list elements of indicators of compromise (IOCs) and mapping summaries.
        
        Returns:
            dict: Formatted markdown string lists for the forensic report
        """
        artifacts = payload.get("artifacts_map", {})
        sources = payload.get("sources_map", {})
        path = payload.get("attack_path", {})

        # Format processes
        procs = artifacts.get("processes", [])
        forensic_processes = "\n".join(f"- `{p}`" for p in procs) if procs else "*No process artifacts found.*"

        # Format command lines
        cmds = artifacts.get("command_lines", [])
        forensic_commands = "\n".join(f"- `{c}`" for c in cmds) if cmds else "*No command line artifacts found.*"

        # Format registry
        regs = artifacts.get("registry_keys", [])
        forensic_registry = "\n".join(f"- `{r}`" for r in regs) if regs else "*No registry indicators found.*"

        # Format ports
        ports = artifacts.get("network_ports", [])
        forensic_ports = ", ".join(f"`{p}`" for p in ports) if ports else "*No network indicators found.*"

        # Format sources
        sources_list = sources.get("source_distribution", {})
        forensic_sources = "\n".join(f"- **{src.upper()}**: {count} raw event(s)" for src, count in sources_list.items()) if sources_list else "*No raw event origins mapped.*"

        # Format path
        nodes = path.get("nodes", [])
        edges = path.get("edges", [])
        path_desc = path.get("path_description", "")
        
        forensic_path_graph = f"{path_desc}\n\n**Hops**:\n"
        for edge in edges:
            forensic_path_graph += f"- **{edge.get('from')}** ──► **{edge.get('to')}** : {edge.get('details')}\n"

        return {
            "processes": forensic_processes,
            "commands": forensic_commands,
            "registry": forensic_registry,
            "ports": forensic_ports,
            "sources": forensic_sources,
            "path_graph": forensic_path_graph
        }
