"""
sentrix_core/threat_engine/engine.py
SentrixThreatEngine — V7 unified wrapper.
Fixes all import paths to use the sentrix_core package namespace.
"""
import os
import sys
import uuid
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger("sentrix.threat_engine")

from sentrix_core.threat_engine.rdf_runtime.rdf_loader import RDFLoader
from sentrix_core.threat_engine.rdf_runtime.rdf_registry import RDFRegistry
from sentrix_core.threat_engine.rdf_runtime.rdf_executor import RDFExecutor
from sentrix_core.threat_engine.rdf_runtime.rdf_cache import RDFRuleCache
from sentrix_core.threat_engine.rdf_runtime.rdf_hot_reload import RDFHotReloader
from sentrix_core.threat_engine.detection.amatcher import EventMatcher
from sentrix_core.threat_engine.detection.behavioral_detector import BehavioralDetector
from sentrix_core.threat_engine.detection.anomaly_detector import AnomalyDetector
from sentrix_core.threat_engine.correlation.sequence_engine import SequenceEngine
from sentrix_core.threat_engine.correlation.threshold_engine import ThresholdEngine
from sentrix_core.threat_engine.correlation.attack_chain_engine import AttackChainEngine
from sentrix_core.threat_engine.scoring.risk_calculator import RiskCalculator
from sentrix_core.threat_engine.scoring.threat_context import ThreatContextManager
from sentrix_core.threat_engine.scoring.asset_context import AssetContextManager
from sentrix_core.threat_engine.storytelling.attack_story import AttackStoryGenerator
from sentrix_core.threat_engine.storytelling.timeline_builder import TimelineBuilder
from sentrix_core.threat_engine.response.response_dispatcher import ResponseDispatcher
from sentrix_core.threat_engine.response.action_builder import SOARActionBuilder
from sentrix_core.threat_engine.crisis.crisis_mode import CrisisModeController
from sentrix_core.threat_engine.context.context_manager import ContextManager
from sentrix_core.threat_engine.scoring.risk_modifier_engine import RiskModifierEngine
from sentrix_core.threat_engine.profiles.profile_store import ProfileStore
from sentrix_core.threat_engine.profiles.attacker_profile import AttackerProfile
from sentrix_core.threat_engine.campaign_memory.campaign_tracker import CampaignTracker
from sentrix_core.config.settings import get_settings


class SentrixThreatEngine:
    def __init__(self, rules_dir: str = None, custom_rules_dir: str = None, schema_path: str = None):
        settings = get_settings()
        _engine_dir = os.path.dirname(os.path.abspath(__file__))

        from sentrix_core.normalization.normalizer import EventNormalizer
        from sentrix_core.enrichment.threat_intel import ThreatIntelEnricher
        from sentrix_core.enrichment.mitre_mapper import MitreMapper
        from sentrix_core.suppression.suppression_engine import SuppressionEngine
        from sentrix_core.metrics.metrics_collector import get_metrics

        self.normalizer = EventNormalizer()
        self.ti_enricher = ThreatIntelEnricher()
        self.mitre_mapper = MitreMapper()
        self.suppression_engine = SuppressionEngine()
        self.metrics_engine = get_metrics()

        self.rules_dir = rules_dir or settings.rules_dir
        self.custom_rules_dir = custom_rules_dir or settings.custom_rules_dir
        self.schema_path = schema_path or os.path.join(_engine_dir, "schemas", "rdf_schema.json")

        self.loader = RDFLoader([self.rules_dir, self.custom_rules_dir], self.schema_path)
        self.registry = RDFRegistry()

        self.cache = RDFRuleCache()
        self.matcher = EventMatcher()

        self.threshold_engine = ThresholdEngine(self.cache)
        self.sequence_engine = SequenceEngine(self.cache)
        self.attack_chain_engine = AttackChainEngine()

        self.executor = RDFExecutor(
            threshold_engine=self.threshold_engine,
            sequence_engine=self.sequence_engine,
            attack_chain_engine=self.attack_chain_engine,
        )

        self.threat_context = ThreatContextManager()
        self.asset_context = AssetContextManager()
        self.risk_calculator = RiskCalculator(self.threat_context, self.asset_context)
        self.crisis_controller = CrisisModeController()
        self.behavioral_detector = BehavioralDetector(self.matcher)
        self.anomaly_detector = AnomalyDetector(self.matcher)
        self.story_gen = AttackStoryGenerator()
        self.timeline_builder = TimelineBuilder()
        self.action_builder = SOARActionBuilder()
        
        from sentrix_core.response_engine.soar import SOAREngine
        self.soar_engine = SOAREngine()
        self.dispatcher = ResponseDispatcher(response_engine=self.soar_engine)
        
        self.context_manager = ContextManager()
        self.risk_modifier_engine = RiskModifierEngine()
        self.profile_store = ProfileStore()
        self.campaign_tracker = CampaignTracker()
        self.reloader = RDFHotReloader(self.registry, self.loader, self.cache)

        self.reload_rules()

    def reload_rules(self):
        rules = self.loader.load_all_rules()
        self.registry.update_rules(rules)
        self.cache.load_rules(rules)
        logger.info("[ThreatEngine] Loaded %d active rule definitions.", len(rules))
        if self.metrics_engine:
            self.metrics_engine.set_rules_loaded(len(rules))

    def set_crisis_mode(self, enabled: bool, scope=None):
        self.crisis_controller.set_crisis_mode(enabled, scope)
        logger.info("[ThreatEngine] Crisis Mode set to %s (Scope: %s)", enabled, scope)

    def process_scef_event(self, raw_event: dict) -> list:
        """Process a raw event by normalizing it first, then running through the full pipeline."""
        if self.metrics_engine:
            self.metrics_engine.inc_events()

        normalized_event = self.normalizer.normalize(raw_event)
        if self.metrics_engine:
            self.metrics_engine.inc_normalized()

        if isinstance(normalized_event, dict):
          scef_event = normalized_event.get("event", normalized_event)
        else:
          scef_event = normalized_event.dict_exclude_none()        
        # Threat Intelligence Enrichment
        scef_event = self.ti_enricher.enrich_event(scef_event)
        if self.metrics_engine:
            self.metrics_engine.inc_enrichments()
        
        matched_alerts = []
        rules = self.registry.get_all_rules()
        signature_matched = False

        event_copy = self.crisis_controller.apply_overrides_to_event(scef_event)

        # 1. Signature rule pass
        for rule in rules:
            start_time = time.perf_counter()
            triggered, matched_events = self.executor.execute_rule(event_copy, rule)
            exec_time_ms = (time.perf_counter() - start_time) * 1000.0

            if triggered:
                signature_matched = True
                alert = self._build_alert(rule, event_copy, matched_events)
                
                # Check alert suppression
                is_suppressed, reason = self.suppression_engine.should_suppress(alert)
                if is_suppressed:
                    alert["_suppressed"] = True
                    alert["_suppression_reason"] = reason
                    if self.metrics_engine:
                        self.metrics_engine.inc_suppressed()
                else:
                    triggered_actions = self.dispatcher.dispatch_alert(alert, rule)
                    if self.metrics_engine:
                        self.metrics_engine.inc_alerts()

                matched_alerts.append(alert)

                rule_id = rule.get("rule_id") or rule.get("metadata", {}).get("id")
                if self.metrics_engine:
                    try:
                        self.metrics_engine.record_metric_event(
                            metric_name="rule_execution_time",
                            value=exec_time_ms,
                            labels={"rule_id": str(rule_id), "triggered": str(triggered)}
                        )
                    except Exception as e:
                        logger.error("Metrics error for rule %s: %s", rule_id, e)

        # 2. Anomaly fallback pass (only if no signature matched)
        if not signature_matched:
            behavioral_rules = self.cache.get_behavioral_rules()
            for r in behavioral_rules:
                val = self.behavioral_detector.evaluate_rule(event_copy, r)
                if val:
                    alert = self._build_alert(r, event_copy, [event_copy], is_anomaly=True)
                    
                    is_suppressed, reason = self.suppression_engine.should_suppress(alert)
                    if is_suppressed:
                        alert["_suppressed"] = True
                        alert["_suppression_reason"] = reason
                        if self.metrics_engine:
                            self.metrics_engine.inc_suppressed()
                    else:
                        self.dispatcher.dispatch_alert(alert, r)
                        if self.metrics_engine:
                            self.metrics_engine.inc_alerts()

                    matched_alerts.append(alert)
                    signature_matched = True
                    break

            if not signature_matched:
                anomaly_rule = self.anomaly_detector.detect_anomaly(event_copy)
                if anomaly_rule:
                    alert = self._build_alert(anomaly_rule, event_copy, [event_copy], is_anomaly=True)
                    
                    is_suppressed, reason = self.suppression_engine.should_suppress(alert)
                    if is_suppressed:
                        alert["_suppressed"] = True
                        alert["_suppression_reason"] = reason
                        if self.metrics_engine:
                            self.metrics_engine.inc_suppressed()
                    else:
                        self.dispatcher.dispatch_alert(alert, anomaly_rule)
                        if self.metrics_engine:
                            self.metrics_engine.inc_alerts()

                    matched_alerts.append(alert)

        return matched_alerts

    def _build_alert(self, rule: dict, trigger_event: dict, triggering_events: list, is_anomaly: bool = False) -> dict:
        rule_id = rule.get("rule_id") or rule.get("metadata", {}).get("id") or str(uuid.uuid4())
        rule_name = rule.get("rule_name") or rule.get("metadata", {}).get("name") or "Unknown Event Anomaly"

        dest_ip = trigger_event.get("destination", {}).get("ip")
        src_ip = trigger_event.get("source", {}).get("ip")
        hostname = trigger_event.get("host", {}).get("hostname") or dest_ip or src_ip or "Unknown"
        username = trigger_event.get("user", {}).get("name", "N/A")

        crisis_state = self.crisis_controller.get_state()
        context = self.asset_context.build_context(trigger_event, crisis_state)
        prog_score = self.attack_chain_engine.get_progression_score(triggering_events)
        base_risk, confidence_score, severity = self.risk_calculator.calculate_risk(
            rule, context, trigger_event, prog_score
        )

        mitre_stage = "Discovery"
        metadata = rule.get("metadata", {})
        mitre_data = rule.get("mitre_mapping") or metadata.get("mitre_mapping") or metadata.get("mitre_attack") or rule.get("mitre_attack") or []
        
        mitre_enrichments = []
        if mitre_data and isinstance(mitre_data, list) and len(mitre_data) > 0:
            first_item = mitre_data[0]
            if isinstance(first_item, dict):
                mitre_stage = first_item.get("tactic", "Discovery")
                # Attempt to enrich based on technique ID if present
                technique_id = first_item.get("technique_id") or first_item.get("technique")
                if technique_id:
                    enriched = self.mitre_mapper.enrich(technique_id)
                    mitre_enrichments.append({"id": technique_id, **enriched})
            else:
                mitre_stage = str(first_item)
                enriched = self.mitre_mapper.enrich(mitre_stage)
                mitre_enrichments.append({"id": mitre_stage, **enriched})

        category_name = metadata.get("threat_category") or rule.get("threat_category") or mitre_stage
        attacker_context = self.context_manager.update_context(src_ip, category_name, base_risk)

        active_camp = self.campaign_tracker.update_campaign(src_ip, mitre_stage, base_risk)
        is_campaign_active = active_camp["current_stage"] != "Unknown"

        risk_score = self.risk_modifier_engine.apply_modifiers(
            base_score=base_risk,
            context=attacker_context,
            event_timestamp=trigger_event.get("timestamp"),
            is_campaign=is_campaign_active,
        )

        if risk_score <= 25:
            severity = "informational"
        elif risk_score <= 45:
            severity = "low"
        elif risk_score <= 65:
            severity = "medium"
        elif risk_score <= 85:
            severity = "high"
        else:
            severity = "critical"

        profile = self.profile_store.get_profile(src_ip)
        if not profile:
            profile = AttackerProfile(src_ip=src_ip, first_seen=attacker_context.first_seen)
        profile.total_alerts = attacker_context.alert_count
        profile.last_seen = attacker_context.last_seen
        profile.highest_risk = max(profile.highest_risk, risk_score)

        camp_id = active_camp.get("campaign_id")
        if camp_id and camp_id not in profile.campaigns:
            profile.campaigns.append(camp_id)
            attacker_context.campaign_count = len(profile.campaigns)
            self.context_manager.store.save_context(attacker_context)
        self.profile_store.save_profile(profile)

        timeline = (
            self.timeline_builder.build_timeline(triggering_events)
            if len(triggering_events) > 1
            else [f"{trigger_event.get('timestamp')}: Event matched {rule_name}"]
        )
        story = self.story_gen.build_narrative(rule, triggering_events, risk_score, timeline)
        recommendations = (
            rule.get("recommended_actions")
            or rule.get("explanation", {}).get("recommended_actions")
            or [{"step": 1, "action": "Investigate source event logs for further indications of compromise."}]
        )

        return {
            "alert_id":         f"alert-{int(time.time() * 1000)}",
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "rule_id":          rule_id,
            "rule_name":        rule_name,
            "severity":         severity,
            "risk_score":       risk_score,
            "confidence_score": confidence_score,
            "affected_host":    hostname,
            "user":             username,
            "source_ip":        src_ip or "unknown",
            "attack_story":     story,
            "recommendations":  recommendations,
            "mitre_enrichment": mitre_enrichments,
        }

    def get_status(self) -> dict:
        return {
            "status": "healthy",
            "rules_loaded": len(self.registry.get_all_rules()),
            "crisis_mode": self.crisis_controller.get_state().get("active", False),
        }
