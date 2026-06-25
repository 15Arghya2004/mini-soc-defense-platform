import os
import logging
from datetime import datetime

logger = logging.getLogger("sentrix.investigation.html_exporter")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentrix Incident Report - {incident_id}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0d1117;
            --panel-bg: rgba(22, 27, 34, 0.7);
            --border-color: rgba(240, 246, 252, 0.1);
            --text-color: #c9d1d9;
            --text-header: #f0f6fc;
            --accent-primary: #58a6ff;
            --accent-success: #3fb950;
            --accent-warning: #d29922;
            --accent-danger: #f85149;
            --accent-info: #bc8cff;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Outfit', sans-serif;
            line-height: 1.6;
            padding: 40px 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        /* Header Glassmorphism */
        header {{
            background: linear-gradient(135deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.9));
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            backdrop-filter: blur(8px);
            position: relative;
            overflow: hidden;
        }}

        header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 6px;
            height: 100%;
            background-color: {color_accent};
        }}

        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}

        .incident-id {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.2rem;
            color: var(--accent-primary);
            font-weight: 600;
        }}

        .severity-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background-color: {badge_bg};
            color: {badge_color};
            border: 1px solid {badge_border};
        }}

        h1 {{
            color: var(--text-header);
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 10px;
        }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }}

        .meta-item span {{
            display: block;
            font-size: 0.85rem;
            color: #8b949e;
            text-transform: uppercase;
            margin-bottom: 4px;
        }}

        .meta-item p {{
            font-size: 1.05rem;
            color: var(--text-header);
            font-weight: 600;
        }}

        /* Section Layouts */
        .grid-layout {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
        }}

        @media (max-width: 900px) {{
            .grid-layout {{
                grid-template-columns: 1fr;
            }}
        }}

        section {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px 0 rgba(0, 0, 0, 0.15);
        }}

        h2 {{
            color: var(--text-header);
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            display: flex;
            align-items: center;
        }}

        /* Timeline & Chains */
        .timeline-table, .evidence-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 0.95rem;
        }}

        .timeline-table th, .evidence-table th {{
            text-align: left;
            padding: 12px;
            border-bottom: 2px solid var(--border-color);
            color: var(--text-header);
            font-weight: 600;
        }}

        .timeline-table td, .evidence-table td {{
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }}

        .timeline-table tr:hover, .evidence-table tr:hover {{
            background-color: rgba(240, 246, 252, 0.02);
        }}

        .timeline-time {{
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-primary);
        }}

        .attack-chain-box {{
            background: rgba(13, 17, 23, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            font-family: 'JetBrains Mono', monospace;
            margin-bottom: 20px;
            overflow-x: auto;
            white-space: nowrap;
            color: var(--accent-info);
        }}

        /* Metrics Lists */
        ul {{
            list-style: none;
        }}

        li {{
            margin-bottom: 12px;
            position: relative;
            padding-left: 20px;
        }}

        li::before {{
            content: '•';
            color: var(--accent-primary);
            font-size: 1.2rem;
            position: absolute;
            left: 0;
            top: -2px;
        }}

        code {{
            font-family: 'JetBrains Mono', monospace;
            background-color: rgba(110, 118, 129, 0.2);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
            color: #ff7b72;
        }}

        pre {{
            background-color: rgba(13, 17, 23, 0.8);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'JetBrains Mono', monospace;
            margin-top: 10px;
        }}

        /* Trace Cards */
        .trace-card {{
            border-left: 4px solid var(--accent-primary);
            padding: 15px;
            background: rgba(13, 17, 23, 0.3);
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
            border-top: 1px solid var(--border-color);
            border-right: 1px solid var(--border-color);
            border-bottom: 1px solid var(--border-color);
        }}

        .trace-card h4 {{
            margin-bottom: 8px;
            color: var(--text-header);
            text-transform: uppercase;
            font-size: 0.9rem;
            letter-spacing: 0.05em;
        }}

        /* Case status indicator */
        .status-pill {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-top: 5px;
            border: 1px solid rgba(240, 246, 252, 0.15);
        }}
        
        .status-open {{ background-color: rgba(210, 153, 34, 0.15); color: var(--accent-warning); }}
        .status-investigating {{ background-color: rgba(188, 140, 255, 0.15); color: var(--accent-info); }}
        .status-contained {{ background-color: rgba(88, 166, 255, 0.15); color: var(--accent-primary); }}
        .status-resolved {{ background-color: rgba(63, 185, 80, 0.15); color: var(--accent-success); }}
        .status-closed {{ background-color: rgba(110, 118, 129, 0.15); color: #8b949e; }}

        .evidence-gauge {{
            text-align: center;
            padding: 20px;
            border-radius: 12px;
            background: rgba(13, 17, 23, 0.4);
            border: 1px solid var(--border-color);
            margin-bottom: 20px;
        }}

        .gauge-num {{
            font-size: 3rem;
            font-weight: 700;
            color: var(--accent-primary);
        }}

        .gauge-label {{
            font-size: 0.85rem;
            color: #8b949e;
            text-transform: uppercase;
            margin-top: 5px;
        }}

    </style>
</head>
<body>
    <div class="container">
        <!-- Main Header -->
        <header>
            <div class="header-top">
                <span class="incident-id">{incident_id}</span>
                <span class="severity-badge">{severity}</span>
            </div>
            <h1>Sentrix Case Intelligence Report</h1>
            <p style="color: #8b949e;">Automated Attack Path Reconstruction & Threat Traceability Analysis</p>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <span>Source Attacker IP</span>
                    <p>{source_ip}</p>
                </div>
                <div class="meta-item">
                    <span>Target Host</span>
                    <p>{destination_host}</p>
                </div>
                <div class="meta-item">
                    <span>Attacker Origin</span>
                    <p>{attacker_origin}</p>
                </div>
                <div class="meta-item">
                    <span>Case Status</span>
                    <p><span class="status-pill status-{status_class}">{case_status}</span></p>
                </div>
            </div>
        </header>

        <!-- Main Body Grid Layout -->
        <div class="grid-layout">
            <!-- Left Column: Details -->
            <div class="left-col">
                <!-- Executive Summary -->
                <section>
                    <h2>Executive Brief</h2>
                    <div style="font-size: 1.1rem; line-height: 1.7; color: var(--text-header);">
                        {executive_summary}
                    </div>
                </section>

                <!-- Attack Timeline -->
                <section>
                    <h2>Chronological Attack Timeline</h2>
                    {attack_timeline}
                </section>

                <!-- Attack Chain Reconstructions -->
                <section>
                    <h2>Reconstructed Attack Chain</h2>
                    <p style="margin-bottom: 15px; color: #8b949e;">Derived from actual observed security alerts (no AI guessing):</p>
                    <div class="attack-chain-box">
                        {attack_chain}
                    </div>
                    {attack_chain_details}
                </section>

                <!-- Layer Trace -->
                <section>
                    <h2>Threat Engine Layer Traceability</h2>
                    <p style="margin-bottom: 20px; color: #8b949e;">Analysis showing how each Threat Engine layer contributed to the final incident decision:</p>
                    
                    <div class="trace-card" style="border-left-color: var(--accent-danger);">
                        <h4>1. Detection Layer</h4>
                        {trace_detection}
                    </div>
                    <div class="trace-card" style="border-left-color: var(--accent-warning);">
                        <h4>2. Correlation Layer</h4>
                        {trace_correlation}
                    </div>
                    <div class="trace-card" style="border-left-color: var(--accent-info);">
                        <h4>3. Context Layer</h4>
                        {trace_context}
                    </div>
                    <div class="trace-card" style="border-left-color: var(--accent-primary);">
                        <h4>4. Campaign Layer</h4>
                        {trace_campaign}
                    </div>
                    <div class="trace-card" style="border-left-color: var(--accent-success);">
                        <h4>5. Prediction Layer</h4>
                        {trace_prediction}
                    </div>
                    <div class="trace-card" style="border-left-color: #8b949e;">
                        <h4>6. Response Layer</h4>
                        {trace_response}
                    </div>
                </section>
            </div>

            <!-- Right Column: Metadata & Metrics Widgets -->
            <div class="right-col">
                <!-- Evidence Gauge Widget -->
                <section>
                    <h2>Evidence & Confidence</h2>
                    <div class="evidence-gauge">
                        <div class="gauge-num" style="color: {color_accent};">{evidence_strength}%</div>
                        <div class="gauge-label">Evidence Strength</div>
                    </div>
                    <div class="evidence-gauge">
                        <div class="gauge-num">{confidence}%</div>
                        <div class="gauge-label">Confidence Rating</div>
                    </div>
                    
                    <div style="margin-top: 20px;">
                        {evidence_brief}
                    </div>
                </section>

                <!-- MITRE Mapping Widget -->
                <section>
                    <h2>MITRE ATT&CK Mapping</h2>
                    <div class="evidence-gauge">
                        <div class="gauge-num" style="color: var(--accent-info);">{mitre_coverage}%</div>
                        <div class="gauge-label">Matrix Coverage</div>
                    </div>
                    <div style="margin-top: 15px;">
                        <p style="font-weight: 600; margin-bottom: 5px; color: var(--text-header);">Mapped Tactics:</p>
                        <p style="font-size: 0.9rem; margin-bottom: 15px;">{mitre_stages}</p>
                        
                        <p style="font-weight: 600; margin-bottom: 5px; color: var(--text-header);">Mapped Techniques:</p>
                        <p style="font-size: 0.9rem; font-family: 'JetBrains Mono', monospace;">{mitre_techniques}</p>
                    </div>
                </section>

                <!-- SOAR Remediation playbooks -->
                <section>
                    {remediations}
                </section>

                <!-- Case Details & Assignment -->
                <section>
                    <h2>Case Administration</h2>
                    <ul>
                        <li>Assigned Analyst: <strong>{assigned_analyst}</strong></li>
                        <li>Case Open Time: <strong>{created_at}</strong></li>
                        <li>Last Updated: <strong>{last_seen}</strong></li>
                    </ul>
                    
                    <h3 style="margin-top: 20px; font-size: 1.05rem; color: var(--text-header);">Analyst Notes Log:</h3>
                    <div style="font-size: 0.9rem; margin-top: 10px; padding: 10px; background: rgba(13, 17, 23, 0.4); border-radius: 8px; border: 1px solid var(--border-color);">
                        {analyst_notes_log}
                    </div>
                </section>
            </div>
        </div>
    </div>
</body>
</html>
"""

class HTMLExporter:
    def export(self, payload: dict, output_path: str) -> str:
        """
        Exports the incident report as a premium, glassmorphism-styled HTML file.
        """
        try:
            # 1. Resolve severities and colors
            severity = payload.get("severity", "LOW").upper()
            
            accent_map = {
                "CRITICAL": "#f85149",
                "HIGH": "#d29922",
                "MEDIUM": "#58a6ff",
                "LOW": "#3fb950",
                "INFORMATIONAL": "#bc8cff"
            }
            
            badge_bg_map = {
                "CRITICAL": "rgba(248, 81, 73, 0.15)",
                "HIGH": "rgba(210, 153, 34, 0.15)",
                "MEDIUM": "rgba(88, 166, 255, 0.15)",
                "LOW": "rgba(63, 185, 80, 0.15)",
                "INFORMATIONAL": "rgba(188, 140, 255, 0.15)"
            }
            
            color_accent = accent_map.get(severity, "#58a6ff")
            badge_bg = badge_bg_map.get(severity, "rgba(240, 246, 252, 0.1)")
            badge_color = color_accent
            badge_border = color_accent

            # 2. Import formatters to process report sections
            from sentrix_core.investigation_engine.reporting.executive_summary import ExecutiveSummaryFormatter
            from sentrix_core.investigation_engine.reporting.timeline_report import TimelineReportFormatter
            from sentrix_core.investigation_engine.reporting.attack_path_report import AttackPathReportFormatter
            from sentrix_core.investigation_engine.reporting.recommendation_report import RecommendationReportFormatter
            from sentrix_core.investigation_engine.reporting.layer_trace_report import LayerTraceReportFormatter
            from sentrix_core.investigation_engine.reporting.evidence_report import EvidenceReportFormatter

            exec_summary = ExecutiveSummaryFormatter().format(payload)
            timeline_tbl = TimelineReportFormatter().format(payload.get("timeline", []))
            
            chain_data = payload.get("attack_chain", {})
            chain_graph = chain_data.get("graph_text", "N/A")
            chain_details = AttackPathReportFormatter().format(chain_data)
            
            remediations = RecommendationReportFormatter().format(payload.get("response_findings", {}))
            evidence_brief = EvidenceReportFormatter().format(payload)
            
            traces = LayerTraceReportFormatter().format(payload.get("layer_trace", {}))

            # 3. Format analyst notes log
            notes = payload.get("analyst_notes", [])
            if isinstance(notes, list) and len(notes) > 0:
                notes_log = ""
                for n in notes:
                    ts = n.get("created_at", "")[:19].replace("T", " ")
                    notes_log += f"<p><strong>[{ts}] {n.get('analyst_name')}</strong>: {n.get('note_text')}</p><hr style='border:none; border-top:1px solid var(--border-color); margin: 6px 0;'>"
            else:
                notes_log = "<p style='color: #8b949e; font-style: italic;'>No analyst notes recorded.</p>"

            # 4. Render html using template
            html_content = HTML_TEMPLATE.format(
                incident_id=payload.get("incident_id"),
                severity=severity,
                source_ip=payload.get("source_ip"),
                destination_host=payload.get("destination_host", "unknown"),
                attacker_origin=payload.get("attacker_origin", "unknown").upper(),
                case_status=payload.get("case_status", "OPEN"),
                status_class=payload.get("case_status", "OPEN").lower(),
                assigned_analyst=payload.get("assigned_analyst", "unassigned"),
                created_at=payload.get("created_at")[:19].replace("T", " "),
                last_seen=payload.get("last_seen")[:19].replace("T", " "),
                executive_summary=exec_summary.replace("\n", "<br>"),
                attack_timeline=timeline_tbl,
                attack_chain=chain_graph,
                attack_chain_details=chain_details.replace("\n", "<br>"),
                trace_detection=traces["detection"].replace("\n", "<br>"),
                trace_correlation=traces["correlation"].replace("\n", "<br>"),
                trace_context=traces["context"].replace("\n", "<br>"),
                trace_campaign=traces["campaign"].replace("\n", "<br>"),
                trace_prediction=traces["prediction"].replace("\n", "<br>"),
                trace_response=traces["response"].replace("\n", "<br>"),
                evidence_strength=payload.get("evidence_scores", {}).get("strength", 0),
                confidence=payload.get("evidence_scores", {}).get("confidence", 0),
                evidence_brief=evidence_brief.replace("\n", "<br>"),
                mitre_coverage=payload.get("mitre_mapping", {}).get("matrix_coverage_percentage", 0),
                mitre_stages=", ".join(payload.get("mitre_mapping", {}).get("mapped_stages", [])),
                mitre_techniques=", ".join(payload.get("mitre_mapping", {}).get("mapped_techniques", [])),
                remediations=remediations,
                analyst_notes_log=notes_log,
                color_accent=color_accent,
                badge_bg=badge_bg,
                badge_color=badge_color,
                badge_border=badge_border
            )

            # 5. Save HTML report
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            logger.info(f"[HTMLExporter] Successfully exported report to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"[HTMLExporter] Failed to compile HTML: {e}")
            raise e
