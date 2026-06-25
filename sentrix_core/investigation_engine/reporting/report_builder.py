import os
import logging
import uuid
from datetime import datetime, timezone

# Import collectors
from sentrix_core.investigation_engine.collectors.threat_collector import ThreatCollector
from sentrix_core.investigation_engine.collectors.context_collector import ContextCollector
from sentrix_core.investigation_engine.collectors.campaign_collector import CampaignCollector
from sentrix_core.investigation_engine.collectors.prediction_collector import PredictionCollector
from sentrix_core.investigation_engine.collectors.response_collector import ResponseCollector
from sentrix_core.investigation_engine.collectors.rule_studio_collector import RuleStudioCollector

# Import analyzers
from sentrix_core.investigation_engine.analyzers.timeline_analyzer import TimelineAnalyzer
from sentrix_core.investigation_engine.analyzers.attacker_behavior_analyzer import AttackerBehaviorAnalyzer
from sentrix_core.investigation_engine.analyzers.mitre_analyzer import MitreAnalyzer
from sentrix_core.investigation_engine.analyzers.campaign_analyzer import CampaignAnalyzer
from sentrix_core.investigation_engine.analyzers.escalation_analyzer import EscalationAnalyzer
from sentrix_core.investigation_engine.analyzers.evidence_analyzer import EvidenceAnalyzer
from sentrix_core.investigation_engine.analyzers.attack_path_analyzer import AttackPathAnalyzer
from sentrix_core.investigation_engine.analyzers.threat_layer_analyzer import ThreatLayerAnalyzer

# Import evidence builders
from sentrix_core.investigation_engine.evidence.evidence_graph import EvidenceGraph
from sentrix_core.investigation_engine.evidence.attack_chain_builder import AttackChainBuilder
from sentrix_core.investigation_engine.evidence.artifact_mapper import ArtifactMapper
from sentrix_core.investigation_engine.evidence.source_tracker import SourceTracker
from sentrix_core.investigation_engine.evidence.evidence_score import EvidenceScorer

logger = logging.getLogger("sentrix.investigation.report_builder")

class ReportBuilder:
    def __init__(self, project_root=None):
        self.root = project_root
        self.threat_coll = ThreatCollector()
        self.context_coll = ContextCollector()
        self.campaign_coll = CampaignCollector()
        self.pred_coll = PredictionCollector()
        self.resp_coll = ResponseCollector()
        self.rule_coll = RuleStudioCollector(project_root)

        self.timeline_anz = TimelineAnalyzer()
        self.behavior_anz = AttackerBehaviorAnalyzer()
        self.mitre_anz = MitreAnalyzer()
        self.campaign_anz = CampaignAnalyzer()
        self.escalation_anz = EscalationAnalyzer()
        self.evidence_anz = EvidenceAnalyzer()
        self.path_anz = AttackPathAnalyzer()
        self.layer_anz = ThreatLayerAnalyzer()

        self.graph_bld = EvidenceGraph()
        self.chain_bld = AttackChainBuilder()
        self.artifact_map = ArtifactMapper()
        self.src_track = SourceTracker()
        self.scorer = EvidenceScorer()

    def build_report(self, source_ip: str, incident_id: str = None) -> dict:
        """
        Coordinates collection and analysis, returning the master report payload.
        """
        logger.info(f"Assembling incident report for {source_ip}...")
        
        # 1. Generate IDs and baseline dates
        if not incident_id:
            date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            rand_hex = uuid.uuid4().hex[:6].upper()
            incident_id = f"INC-{date_str}-{rand_hex}"
            
        created_at = datetime.now(timezone.utc).isoformat()

        # 2. Trigger Collectors
        threat_findings = self.threat_coll.collect(source_ip)
        context_findings = self.context_coll.collect(source_ip)
        campaign_findings = self.campaign_coll.collect(source_ip)
        prediction_findings = self.pred_coll.collect(source_ip)
        
        # Resolve affected host from threat findings for response collection
        affected_host = "unknown"
        if threat_findings:
            affected_host = threat_findings[0].get("affected_host", "unknown")
            
        response_findings = self.resp_coll.collect(source_ip, affected_host)

        # Collect rule details for all unique triggered rules
        unique_rule_ids = set()
        for alert in threat_findings:
            rule_id = alert.get("rule_id")
            if rule_id:
                unique_rule_ids.add(rule_id)
        
        rule_studio_findings = [self.rule_coll.collect(rid) for rid in unique_rule_ids]

        # 3. Trigger Analyzers
        timeline = self.timeline_anz.analyze(threat_findings, response_findings)
        behavior = self.behavior_anz.analyze(context_findings, threat_findings)
        mitre = self.mitre_anz.analyze(threat_findings)
        campaign = self.campaign_anz.analyze(campaign_findings)
        escalation = self.escalation_anz.analyze(prediction_findings)
        evidence = self.evidence_anz.analyze(threat_findings)
        path = self.path_anz.analyze(source_ip, threat_findings)
        
        layer_trace = self.layer_anz.analyze(
            threat_findings, context_findings, campaign_findings, 
            prediction_findings, response_findings, rule_studio_findings
        )

        # 4. Trigger Evidence Builders
        graph = self.graph_bld.build(source_ip, threat_findings)
        attack_chain = self.chain_bld.build(threat_findings)
        artifacts = self.artifact_map.map_artifacts(threat_findings)
        sources = self.src_track.track_sources(threat_findings)
        scores = self.scorer.calculate_scores(threat_findings)

        # 5. Resolve general metadata
        severity = "LOW"
        if threat_findings:
            # Get maximum severity in threat findings
            max_sev = max([a.get("severity", "low") for a in threat_findings], 
                          key=lambda x: {"informational":0,"low":1,"medium":2,"high":3,"critical":4}.get(x.lower(), 0))
            severity = max_sev.upper()
            
        first_seen = context_findings.get("first_seen", "unknown")
        last_seen = context_findings.get("last_seen", "unknown")
        
        if threat_findings:
            if first_seen == "unknown":
                first_seen = threat_findings[0].get("timestamp")
            if last_seen == "unknown":
                last_seen = threat_findings[-1].get("timestamp")

        attacker_origin = "unknown"
        if sources.get("sources_list"):
            attacker_origin = sources["sources_list"][0]

        # 6. Construct Master Payload
        master_report = {
            "incident_id": incident_id,
            "severity": severity,
            "source_ip": source_ip,
            "destination_host": affected_host,
            "attacker_origin": attacker_origin,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "created_at": created_at,
            "case_status": "OPEN",
            "assigned_analyst": "unassigned",
            "resolution_notes": "",
            "threat_findings": threat_findings,
            "context_findings": context_findings,
            "campaign_findings": campaign_findings,
            "prediction_findings": prediction_findings,
            "response_findings": response_findings,
            "rule_studio_findings": rule_studio_findings,
            "timeline": timeline,
            "behavior_analysis": behavior,
            "mitre_mapping": mitre,
            "campaign_analysis": campaign,
            "prediction_analysis": escalation,
            "evidence_analysis": evidence,
            "attack_path": path,
            "layer_trace": layer_trace,
            "evidence_graph": graph,
            "attack_chain": attack_chain,
            "artifacts_map": artifacts,
            "sources_map": sources,
            "evidence_scores": scores
        }
        
        return master_report
