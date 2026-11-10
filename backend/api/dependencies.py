"""FastAPI dependencies for authentication, agent extraction, and rate limiting."""

import hmac
from typing import Optional
from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.api.config import settings
from backend.api.rate_limiter import SlidingWindowRateLimiter
from backend.api.schemas import AgentInfo
from backend.api.storage_sink import EventStorageSink
from backend.correlation.repository import IncidentRepository
from backend.response.engine import ResponseEngine
from backend.response.repository import SQLiteResponseRepository

# Global rate limiter, storage sink, incident repository, and response engine instances
rate_limiter = SlidingWindowRateLimiter(
    limit=settings.RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
)
storage_sink = EventStorageSink(db_path=settings.DATABASE_PATH)
incident_repo = IncidentRepository(db_path=settings.DATABASE_PATH)
response_repo = SQLiteResponseRepository(db_path=settings.DATABASE_PATH)
response_engine = ResponseEngine(repository=response_repo)

security_bearer = HTTPBearer(auto_error=False)


def _is_valid_key(provided_key: str) -> bool:
    for valid_key in settings.VALID_API_KEYS:
        if hmac.compare_digest(provided_key.strip(), valid_key.strip()):
            return True
    return False


async def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    bearer_auth: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> str:
    """Verify API authentication via X-API-Key header or Bearer token."""
    token: Optional[str] = None
    if x_api_key:
        token = x_api_key
    elif bearer_auth and bearer_auth.credentials:
        token = bearer_auth.credentials

    if not token or not _is_valid_key(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing API key. Provide X-API-Key or Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


async def get_agent_info(
    request: Request,
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-ID"),
    x_agent_version: Optional[str] = Header(None, alias="X-Agent-Version"),
) -> AgentInfo:
    """Extract agent identification from request headers and remote address."""
    client_ip = request.client.host if request.client else "unknown"
    agent_id = x_agent_id or f"agent-{client_ip}"

    return AgentInfo(
        agent_id=agent_id,
        agent_version=x_agent_version,
        client_ip=client_ip,
    )


async def check_rate_limit(
    request: Request,
    agent_info: AgentInfo = Depends(get_agent_info),
) -> None:
    """Enforce rate limits per agent ID and client IP."""
    limiter_key = f"{agent_info.agent_id}:{agent_info.client_ip}"
    allowed, remaining, retry_after = rate_limiter.is_allowed(limiter_key)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )


def get_response_engine() -> ResponseEngine:
    """Return the global ResponseEngine singleton."""
    return response_engine
