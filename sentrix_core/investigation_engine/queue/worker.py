# services/investigation-service/queue/worker.py
import threading
import logging
import time

logger = logging.getLogger("sentrix.investigation.queue.worker")

class InvestigationWorker:
    def __init__(self, job_queue, engine):
        self.q = job_queue
        self.engine = engine
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.thread.start()
        logger.info("[Worker] Background thread started.")
        return self.thread

    def stop(self):
        self.running = False
        if self.thread:
            self.q.put(None)
            self.thread.join(timeout=3)

    def _worker_loop(self):
        while self.running:
            try:
                task = self.q.get()
                if task is None:
                    self.q.task_done()
                    break
                
                source_ip = task.get("source_ip")
                incident_id = task.get("incident_id")
                policy = task.get("policy", "MEDIUM").upper()
                
                logger.info(f"[Worker] Ingested job: IP={source_ip}, ID={incident_id}, Policy={policy}")
                
                # Execute report generation based on the Severity Threshold Policy
                self.engine.execute_policy_generation(source_ip, incident_id, policy)
                self.q.task_done()
            except Exception as e:
                logger.error(f"[Worker] Error executing report generation job: {e}", exc_info=True)
                time.sleep(0.5)
