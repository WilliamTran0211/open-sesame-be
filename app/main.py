import logging
import logging.config
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.deps import get_redis_client
from app.core.exception import register_exception_handlers
from app.core.scheduler import scheduler, setup_scheduler
from app.db.session import session_manager
from app.logger.config import LOGGING_CONFIG
from app.middleware.auth import AuthMiddleware
from app.middleware.csrf import CSRFMiddleware
from app.middleware.logging import LoggingMiddleware
from app.services.access_token import get_token_service

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    print("Starting application...")

    settings = get_settings()
    # Init DB
    session_manager.init(database_url=settings.database_url)

    # Init Redis
    redis_client = await get_redis_client()

    # setup job
    setup_scheduler(redis_client)

    if await session_manager.health_check():
        print("Database connected")
    else:
        print("Database connection failed")
        raise RuntimeError("Cannot connect to database")
    yield

    scheduler.shutdown(wait=False)
    await session_manager.close()


def create_app() -> FastAPI:
    app = FastAPI(title="OS - Open Sesame", version="0.0.1", lifespan=lifespan)

    register_exception_handlers(app)

    # middleware
    app.add_middleware(LoggingMiddleware)

    app.add_middleware(AuthMiddleware, token_service=get_token_service())

    app.add_middleware(CSRFMiddleware)

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["*"],
    )

    # routers
    app.include_router(api_router, prefix="/api/v1")

    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "ok"}

    return app


app = ProxyHeadersMiddleware(create_app(), trusted_hosts="*")
