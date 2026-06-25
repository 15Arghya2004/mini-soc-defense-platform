"""
sentrix_core/security/auth.py
API Key + JWT authentication for Sentrix V7.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.security.auth")

# ── FastAPI security schemes ───────────────────────────────────────────────────
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

# ── JWT helpers ────────────────────────────────────────────────────────────────
try:
    from jose import JWTError, jwt as jose_jwt
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False
    logger.warning("python-jose not available — JWT auth disabled")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    settings = get_settings()
    if not _JWT_AVAILABLE:
        raise RuntimeError("JWT not available")
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jose_jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    settings = get_settings()
    if not _JWT_AVAILABLE:
        raise HTTPException(status_code=503, detail="JWT not available")
    try:
        payload = jose_jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Dependency: resolve caller identity ───────────────────────────────────────
def get_current_user(
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> dict:
    settings = get_settings()

    # If auth is disabled globally, allow everything as admin
    if not settings.AUTH_ENABLED:
        return {"sub": "anonymous", "role": "admin"}

    # Try API key first
    if api_key:
        if settings.SENTRIX_API_KEY and api_key == settings.SENTRIX_API_KEY:
            return {"sub": "api_key_user", "role": "admin"}
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    # Try JWT Bearer
    if bearer:
        return decode_token(bearer.credentials)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide X-API-Key header or Bearer token.",
    )


# ── Public dependency (no auth) ───────────────────────────────────────────────
def get_current_user_optional(
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> dict:
    """Returns anonymous user dict if auth is disabled or credentials are missing."""
    settings = get_settings()
    if not settings.AUTH_ENABLED:
        return {"sub": "anonymous", "role": "admin"}
    try:
        return get_current_user(api_key=api_key, bearer=bearer)
    except HTTPException:
        return {"sub": "anonymous", "role": "read_only"}


# ── Role-based access control dependencies ────────────────────────────────────
_ROLE_HIERARCHY = {"read_only": 0, "soc_analyst": 1, "admin": 2}


def _require_role(minimum_role: str):
    """Return a FastAPI dependency that enforces a minimum role level."""
    def dependency(user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role", "read_only")
        if _ROLE_HIERARCHY.get(user_role, 0) < _ROLE_HIERARCHY.get(minimum_role, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {minimum_role}",
            )
        return user
    return dependency


def require_soc_analyst(user: dict = Depends(get_current_user)) -> dict:
    """Require at least soc_analyst role."""
    user_role = user.get("role", "read_only")
    if _ROLE_HIERARCHY.get(user_role, 0) < _ROLE_HIERARCHY["soc_analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required role: soc_analyst",
        )
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Require admin role."""
    user_role = user.get("role", "read_only")
    if _ROLE_HIERARCHY.get(user_role, 0) < _ROLE_HIERARCHY["admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required role: admin",
        )
    return user
