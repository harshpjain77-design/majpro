"""Main FastAPI application factory and entrypoint for Central Ingestion."""

import logging
import sys
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.config import settings
from backend.api.middleware import RequestSizeLimitMiddleware, StructuredLoggingMiddleware
from backend.api.routes import ai, alerts, events, health, incidents, ingest, ml, response

# Configure root logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("CentralIngestionAPI")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AI Cyber Defense Platform - Central Ingestion API",
        version="0.1.0",
        description="Authenticated central log ingestion, validation, and storage service.",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # 1. Custom Middlewares (Order: Logging wraps outer, SizeLimit checks body)
    app.add_middleware(StructuredLoggingMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.MAX_REQUEST_BYTES)

    # 2. CORS policy - restricted by default to local dashboard origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # 3. Custom exception handler for Pydantic validation errors
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        error_details = []
        for err in exc.errors():
            loc = " -> ".join(str(x) for x in err.get("loc", []))
            msg = err.get("msg", "Validation error")
            error_details.append(f"{loc}: {msg}")

        logger.warning(f"Validation error on {request.url.path}: {error_details}")
        return JSONResponse(
            status_code=422,
            content={
                "status": "error",
                "detail": "Invalid event schema payload.",
                "errors": error_details,
            },
        )

    # 4. Include Routers
    app.include_router(health.router)
    app.include_router(ingest.router)
    app.include_router(events.router)
    app.include_router(alerts.router)
    app.include_router(alerts.alerts_direct_router)
    app.include_router(incidents.router)
    app.include_router(ml.router)
    app.include_router(ai.router)
    app.include_router(response.router)

    from fastapi.responses import FileResponse
    from pathlib import Path

    @app.get("/collector.ps1")
    async def get_collector_script():
        ps1_path = Path("collectors/windows/collector.ps1")
        if ps1_path.exists():
            return FileResponse(ps1_path, media_type="text/plain", filename="collector.ps1")
        return JSONResponse(status_code=404, content={"error": "collector.ps1 not found"})

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    logger.info(
        f"Starting Central Ingestion Service on {settings.INGESTION_HOST}:{settings.INGESTION_PORT}"
    )
    uvicorn.run(
        "backend.api.main:app",
        host=settings.INGESTION_HOST,
        port=settings.INGESTION_PORT,
        log_level=settings.LOG_LEVEL.lower(),
        reload=False,
    )
