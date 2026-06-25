from .case_store import CaseStore

class AnalystNotes:
    """
    Manager class for creating and listing SOC analyst notes for incident cases.
    """
    def __init__(self, store: CaseStore = None):
        self.store = store or CaseStore()

    def add_note(self, incident_id: str, analyst_name: str, note_text: str) -> bool:
        """Adds a new text note from an analyst to an incident case."""
        if not incident_id or not analyst_name or not note_text.strip():
            return False
        return self.store.add_note(incident_id, analyst_name, note_text.strip())

    def get_notes(self, incident_id: str) -> list:
        """Retrieves all chronological analyst notes for a specific incident case."""
        if not incident_id:
            return []
        return self.store.get_notes(incident_id)
