from .case_store import CaseStore

class AssignmentTracker:
    """
    Manager class for assigning incidents to SOC analysts and tracking the history.
    """
    def __init__(self, store: CaseStore = None):
        self.store = store or CaseStore()

    def assign_case(self, incident_id: str, assigned_by: str, assigned_to: str) -> bool:
        """Assigns an incident case to a target analyst and logs it in the history."""
        if not incident_id or not assigned_by or not assigned_to:
            return False
        return self.store.assign_case(incident_id, assigned_by, assigned_to)

    def get_history(self, incident_id: str) -> list:
        """Retrieves the complete assignment history log for an incident case."""
        if not incident_id:
            return []
        return self.store.get_assignment_history(incident_id)
