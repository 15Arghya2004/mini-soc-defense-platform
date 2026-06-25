# SOC ANALYST INVESTIGATION REPORT
**Incident ID**: {{incident_id}} | **Severity**: {{severity}} | **Status**: {{case_status}}
**Assigned Analyst**: {{assigned_analyst}}

---

## 1. Attack Timeline Reconstruction
The following is the chronological log of correlated alert events for target source **{{source_ip}}**:

{{attack_timeline}}

---

## 2. Reconstructed Attack Chain
Based strictly on observed telemetry (no AI guessing):

{{attack_chain}}

---

## 3. MITRE ATT&CK Matrix Mapping
* **Total Stages Traversed**: {{total_stages}}/14 ({{matrix_coverage}}% coverage)
* **Observed Tactics**: {{mitre_tactics}}
* **Triggered Techniques**: {{mitre_techniques}}

---

## 4. Analyst Actions & Recommendations
{{recommendations}}

---

## 5. Case Notes & History
{{analyst_notes}}

---
*Sentrix Command Center V4 — SOC Incident Report*
