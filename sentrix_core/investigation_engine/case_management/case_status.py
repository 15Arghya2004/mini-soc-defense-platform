from enum import Enum

class CaseStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

VALID_STATUSES = {status.value for status in CaseStatus}

def is_valid_status(status: str) -> bool:
    """Returns True if status is a valid CaseStatus."""
    if not status:
        return False
    return status.upper() in VALID_STATUSES

def get_allowed_transitions(current_status: str) -> list:
    """
    Returns a list of valid next statuses based on the current status.
    Implements a logical workflow for SOC incident management.
    """
    current = current_status.upper() if current_status else "OPEN"
    
    transitions = {
        "OPEN": ["INVESTIGATING", "CLOSED"],
        "INVESTIGATING": ["CONTAINED", "RESOLVED", "CLOSED"],
        "CONTAINED": ["RESOLVED", "CLOSED"],
        "RESOLVED": ["CLOSED", "INVESTIGATING"],
        "CLOSED": ["OPEN"]  # Allow reopening
    }
    return transitions.get(current, [])
