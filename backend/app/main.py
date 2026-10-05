from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.database import init_db
from app.routers import alerts, devices, events, statistics
from app.security import (
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "SentinelFlow ingests network/IoT flow telemetry, runs it through a "
        "rule + Isolation Forest detection engine, maps hits to MITRE ATT&CK, "
        "and scores risk."
    ),
    lifespan=lifespan,
)

# Starlette runs the last-added middleware first, so the order below is
# outermost -> innermost: security headers wrap every response (including
# 413/429 rejections), then the body-size limit, then the rate limiter.
app.add_middleware(RateLimitMiddleware)
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(devices.router)
app.include_router(statistics.router)

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


@app.get("/")
def dashboard():
    index = FRONTEND_DIR / "index.html"
    return FileResponse(index)


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
