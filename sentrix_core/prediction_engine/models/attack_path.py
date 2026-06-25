"""
attack_path.py
──────────────
Per-attacker state tracker — records the observed kill-chain progression
for a single source IP across multiple alert events.
"""
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List


@dataclass
class AttackPath:
    """
    Tracks the observed MITRE ATT&CK stage progression for a single attacker.

    Fields
    ------
    source_ip           : Attacker source IP address
    stages_observed     : Ordered list of MITRE stages seen (may have duplicates)
    techniques_observed : Ordered list of technique IDs seen
    affected_hosts      : Set of target hostnames observed
    alert_count         : Total alerts processed for this attacker
    severity_history    : List of severity strings for each alert
    risk_history        : List of risk_score ints for each alert
    first_seen          : Timestamp of first observed alert
    last_seen           : Timestamp of most recent alert
    """
    source_ip:           str
    stages_observed:     List[str] = field(default_factory=list)
    techniques_observed: List[str] = field(default_factory=list)
    affected_hosts:      List[str] = field(default_factory=list)
    alert_count:         int = 0
    severity_history:    List[str] = field(default_factory=list)
    risk_history:        List[int] = field(default_factory=list)
    first_seen:          datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:           datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def update(self, alert_contract: dict):
        """Ingests a new AlertContract and updates the tracked path."""
        self.alert_count += 1
        self.last_seen = datetime.now(timezone.utc)

        # Update stages
        for stage in alert_contract.get("mitre_stages", []):
            self.stages_observed.append(stage)

        # Update techniques
        for tech in alert_contract.get("mitre_techniques", []):
            if tech not in self.techniques_observed:
                self.techniques_observed.append(tech)

        # Update affected hosts
        host = alert_contract.get("affected_host", "")
        if host and host not in self.affected_hosts:
            self.affected_hosts.append(host)

        # Track severity and risk history
        self.severity_history.append(alert_contract.get("severity", "low"))
        self.risk_history.append(int(alert_contract.get("risk_score", 0)))

    def get_unique_stages(self) -> list:
        """Returns deduplicated ordered list of observed stages."""
        seen = set()
        result = []
        for s in self.stages_observed:
            if s not in seen:
                seen.add(s)
                result.append(s)
        return result

    def get_latest_stage(self) -> str:
        """Returns the most recently observed stage, or 'Reconnaissance' if none."""
        return self.stages_observed[-1] if self.stages_observed else "Reconnaissance"

    def get_max_risk_score(self) -> int:
        """Returns the highest risk score observed across all alerts."""
        return max(self.risk_history) if self.risk_history else 0

    def get_average_risk_score(self) -> float:
        """Returns the mean risk score across all alerts."""
        if not self.risk_history:
            return 0.0
        return sum(self.risk_history) / len(self.risk_history)

    def get_elapsed_seconds(self) -> float:
        """Returns seconds elapsed between first and last observed alert."""
        delta = self.last_seen - self.first_seen
        return max(0.0, delta.total_seconds())

    def to_dict(self) -> dict:
        """Serializes the AttackPath to a JSON-serializable dict."""
        return {
            "source_ip":           self.source_ip,
            "stages_observed":     self.stages_observed,
            "unique_stages":       self.get_unique_stages(),
            "techniques_observed": self.techniques_observed,
            "affected_hosts":      self.affected_hosts,
            "alert_count":         self.alert_count,
            "severity_history":    self.severity_history,
            "risk_history":        self.risk_history,
            "max_risk_score":      self.get_max_risk_score(),
            "latest_stage":        self.get_latest_stage(),
            "first_seen":          self.first_seen.isoformat(),
            "last_seen":           self.last_seen.isoformat(),
            "elapsed_seconds":     self.get_elapsed_seconds(),
        }
