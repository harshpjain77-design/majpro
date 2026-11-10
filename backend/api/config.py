"""Configuration management for Central Ingestion Service."""

import os
from pathlib import Path
from typing import Set
from dotenv import load_dotenv

# Load .env file if available
load_dotenv()


class Settings:
    """Application settings loaded from environment with secure defaults."""

    def __init__(self) -> None:
        self.PLATFORM_ENV: str = os.getenv("PLATFORM_ENV", "development").lower()
        self.INGESTION_HOST: str = os.getenv("INGESTION_HOST", "0.0.0.0")
        self.INGESTION_PORT: int = int(os.getenv("INGESTION_PORT", "8000"))
        
        # Primary API key and allowed keys list
        raw_keys = os.getenv("INGESTION_API_KEY", "test-collector-api-key-replace-in-production")
        self.VALID_API_KEYS: Set[str] = {k.strip() for k in raw_keys.split(",") if k.strip()}

        # Storage
        self.DATABASE_PATH: str = os.getenv("DATABASE_PATH", "output/soc_events.sqlite")

        # Ingestion limits and abuse prevention
        self.MAX_BATCH_SIZE: int = int(os.getenv("MAX_BATCH_SIZE", "500"))
        self.MAX_REQUEST_BYTES: int = int(os.getenv("MAX_REQUEST_BYTES", str(5 * 1024 * 1024)))  # 5 MB
        self.RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))

        # Logging
        self.LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

        # Ensure output directory exists for database
        db_parent = Path(self.DATABASE_PATH).parent
        db_parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
