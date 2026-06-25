"""
sentrix_core/rule_define_studio/rule_tester.py
Testing sandbox for custom rules.
"""
from sentrix_core.threat_engine.rdf_runtime.rdf_executor import RDFExecutor
from sentrix_core.threat_engine.correlation.threshold_engine import ThresholdEngine
from sentrix_core.threat_engine.correlation.sequence_engine import SequenceEngine
from sentrix_core.threat_engine.correlation.attack_chain_engine import AttackChainEngine
from sentrix_core.threat_engine.rdf_runtime.rdf_cache import RDFRuleCache
from sentrix_core.threat_engine.rdf_runtime.rdf_validator import RDFValidator

class RuleTester:
    def __init__(self):
        self.validator = RDFValidator()
        self.cache = RDFRuleCache()
        self.threshold = ThresholdEngine(self.cache)
        self.sequence = SequenceEngine(self.cache)
        self.attack_chain = AttackChainEngine()
        
        self.executor = RDFExecutor(
            threshold_engine=self.threshold,
            sequence_engine=self.sequence,
            attack_chain_engine=self.attack_chain
        )

    def test_rule(self, rule_dict: dict, sample_event: dict) -> dict:
        """
        Validates rule and executes it against the sample event.
        Returns detailed diagnostic info about the execution.
        """
        errors = self.validator.validate(rule_dict)
        if errors:
            return {
                "success": False,
                "error": "Validation failed",
                "details": errors
            }

        try:
            triggered, matched_events = self.executor.execute_rule(sample_event, rule_dict)
            return {
                "success": True,
                "triggered": triggered,
                "matched_events": matched_events,
                "details": "Rule executed successfully."
            }
        except Exception as e:
            return {
                "success": False,
                "error": "Execution exception",
                "details": str(e)
            }
