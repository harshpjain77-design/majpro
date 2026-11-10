"""Custom middleware for request size limits and structured access logging."""

import json
import logging
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from backend.api.config import settings

logger = logging.getLogger("APIAccess")


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforce maximum incoming HTTP request payload size."""

    def __init__(self, app, max_bytes: int = settings.MAX_REQUEST_BYTES):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length_int = int(content_length)
                if length_int > self.max_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": f"Payload too large. Maximum permitted body is {self.max_bytes} bytes."
                        },
                    )
            except ValueError:
                pass

        return await call_next(request)


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """Log incoming HTTP requests with latency, client metadata, and response codes."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        agent_id = request.headers.get("X-Agent-ID", "-")

        response = await call_next(request)

        duration_ms = round((time.time() - start_time) * 1000, 2)
        log_payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client_ip": client_ip,
            "agent_id": agent_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "latency_ms": duration_ms,
        }
        logger.info(json.dumps(log_payload))

        response.headers["X-Process-Time-Ms"] = str(duration_ms)
        return response
