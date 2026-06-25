"""
sentrix_core/security/rbac.py
Role-based access control for Sentrix V7.

Roles:
  admin       — full access
  soc_analyst — read/write on threat, prediction, investigation; rule read
  read_only   — GET endpoints only
"""
from fastapi import Depends, HTTPException, status
from sentrix_core.security.auth import get_current_user

ROLE_HIERARCHY = {
    "admin": 3,
    "soc_analyst": 2,
    "read_only": 1,
}


def _require_role(minimum_role: str):
    min_level = ROLE_HIERARCHY.get(minimum_role, 0)

    def dependency(user: dict = Depends(get_current_user)) -> dict:
        role = user.get("role", "read_only")
        if ROLE_HIERARCHY.get(role, 0) < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{minimum_role}' or higher. Current role: '{role}'",
            )
        return user

    return dependency


# ── Exported role dependencies ────────────────────────────────────────────────
require_admin = _require_role("admin")
require_analyst = _require_role("soc_analyst")
require_read = _require_role("read_only")
