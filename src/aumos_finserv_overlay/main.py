"""AumOS Financial Services Overlay — service entry point."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from aumos_common.app import create_app
from aumos_common.database import init_database
from aumos_common.observability import get_logger

from aumos_finserv_overlay.settings import Settings

logger = get_logger(__name__)
settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage service startup and shutdown lifecycle."""
    logger.info(
        "aumos-finserv-overlay starting",
        sox_framework=settings.sox_control_framework,
        pci_dss_version=settings.pci_dss_version,
        dora_rto_hours=settings.dora_rto_threshold_hours,
        supported_regulators=settings.supported_regulators,
    )

    # Initialize database connection pool
    init_database(settings.database)

    # TODO: Initialize Kafka publisher
    # TODO: Initialize Redis client

    logger.info("aumos-finserv-overlay startup complete")
    yield

    logger.info("aumos-finserv-overlay shutting down")
    # TODO: Close Kafka producer
    # TODO: Close Redis connection


app = create_app(
    service_name="aumos-finserv-overlay",
    version="0.1.0",
    settings=settings,
    lifespan=lifespan,
    health_checks=[],
)

# Include finserv router
from aumos_finserv_overlay.api.router import router  # noqa: E402

app.include_router(router, prefix="/api/v1")
