"""
sentrix_core/investigation_engine/engine.py
InvestigationStudioEngine — V7 unified wrapper.
"""
import logging
from sentrix_core.config.settings import get_settings
from sentrix_core.investigation_engine.storage.report_store import ReportStore
from sentrix_core.investigation_engine.case_management.case_store import CaseStore
from sentrix_core.investigation_engine.queue.job_queue import JobQueue
from sentrix_core.investigation_engine.queue.report_scheduler import ReportScheduler
from sentrix_core.investigation_engine.queue.worker import InvestigationWorker
from sentrix_core.investigation_engine.reporting.report_builder import ReportBuilder
from sentrix_core.investigation_engine.exporters.json_exporter import JSONExporter
from sentrix_core.investigation_engine.exporters.pdf_exporter import PDFExporter

logger = logging.getLogger("sentrix.investigation_engine")

class InvestigationStudioEngine:
    def __init__(self):
        settings = get_settings()
        self.report_store = ReportStore(db_path=settings.investigations_db)
        self.case_store = CaseStore(db_path=settings.investigations_db)
        self.exports_dir = settings.exports_dir
        
        self.queue = JobQueue()
        self.scheduler = ReportScheduler(self.queue)
        self.worker = InvestigationWorker(self.queue, self)
        self.report_builder = ReportBuilder()
        self.json_exporter = JSONExporter()
        self.pdf_exporter = PDFExporter()
        
        self.worker.start()

    def shutdown(self):
        self.worker.stop()

    def trigger_investigation(self, source_ip: str, incident_id: str, severity: str):
        """Schedule a background investigation report generation."""
        self.scheduler.schedule_investigation(source_ip, incident_id, severity)

    def execute_policy_generation(self, source_ip: str, incident_id: str, policy: str):
        """Executed by worker thread to actually build the report."""
        import uuid
        if not incident_id:
            incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        report = self.report_builder.build_report(source_ip, incident_id)
        
        # Save to ReportStore
        severity = report.get("severity", "medium")
        self.report_store.save_incident(incident_id, source_ip, severity, report)
        
        # Ensure a case exists in CaseStore
        self.case_store.create_case_from_report(report)
        
        # Push to Central Event Store for Dashboard
        try:
            from sentrix_core.storage.event_store import get_event_store
            get_event_store().store_investigation(
                incident_id=incident_id,
                summary=report.get("summary", ""),
                evidence=str(report.get("evidence", [])),
                source_ip=source_ip,
                severity=severity,
                assigned_analyst="unassigned"
            )
        except Exception as e:
            logger.error(f"Failed to sync investigation to event store: {e}")
            
        logger.info(f"Report generation complete for {incident_id}")

    def get_incident(self, incident_id: str) -> dict:
        return self.report_store.get_incident(incident_id)

    def list_incidents(self) -> list:
        return self.report_store.get_all_incidents()

    def export_json(self, incident_id: str) -> str:
        report = self.get_incident(incident_id)
        if not report:
            return None
        import os
        output_path = os.path.join(self.exports_dir, f"{incident_id}.json")
        return self.json_exporter.export(report, output_path)

    def export_pdf(self, incident_id: str) -> str:
        report = self.get_incident(incident_id)
        if not report:
            return None
        import os
        output_path = os.path.join(self.exports_dir, f"{incident_id}.pdf")
        return self.pdf_exporter.export(report, output_path)

    def get_status(self) -> dict:
        return {
            "status": "healthy" if self.worker.running else "degraded",
            "queue_size": self.queue.q.qsize()
        }
