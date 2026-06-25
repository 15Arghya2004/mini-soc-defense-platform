# services/investigation-service/queue/report_scheduler.py
import logging

logger = logging.getLogger("sentrix.investigation.queue.scheduler")

class ReportScheduler:
    def __init__(self, job_queue):
        self.q = job_queue

    def schedule_investigation(self, source_ip: str, incident_id: str, severity: str):
        # Translate alert severity to report generation threshold policy
        sev_upper = severity.upper()
        if sev_upper == "CRITICAL":
            policy = "CRITICAL"
        elif sev_upper == "HIGH":
            policy = "HIGH"
        elif sev_upper in ("MEDIUM", "MODERATE"):
            policy = "MEDIUM"
        else:
            policy = "LOW"
            
        job = {
            "source_ip": source_ip,
            "incident_id": incident_id,
            "policy": policy
        }
        self.q.put(job)
        logger.info(f"[Scheduler] Queued report generation job for IP={source_ip} (Policy={policy})")
        return policy
