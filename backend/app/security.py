"""API hardening: write-endpoint authentication, rate limiting, request
size limits and security response headers.

Kept dependency-free on purpose (no slowapi / auth library) so the
controls are small enough to read in one sitting and audit by hand.

Scope and limits, stated plainly:
- Reads (GET) stay open so the dashboard works without a login. Writes
  (POST /events, PATCH /alerts/{id}) need the shared API key. That's the
  right shape for an ingestion API that sits behind a trusted collector;
  it is not per-user auth, and there is still no role model (see
  docs/threat-model.md).
- With no SENTINELFLOW_API_KEY set, writes are refused (fail closed),
  never silently allowed.
- The rate limiter is in-memory and per-process. Behind several Uvicorn
  workers or replicas, each one counts separately; a shared store (Redis)
  or the reverse proxy would have to enforce a global limit.
"""
import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import settings

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency guarding every write endpoint."""
    expected = settings.API_KEY
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Write endpoints are disabled: set SENTINELFLOW_API_KEY on the server.",
        )
    # Constant-time comparison so the key can't be recovered byte by byte
    # from response timing.
    if x_api_key is None or not hmac.compare_digest(
        x_api_key.encode(), expected.encode()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


class RateLimiter:
    """Sliding-window counter keyed by client address."""

    def __init__(self, limit: int, window_seconds: float = 60.0):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        """Record one hit; return (allowed, seconds until a slot frees up)."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                retry_after = int(self.window - (now - hits[0])) + 1
                return False, retry_after
            hits.append(now)
            # Stop the dict growing without bound under many distinct IPs.
            if len(self._hits) > 10_000:
                for stale in [k for k, v in self._hits.items() if not v]:
                    del self._hits[stale]
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


read_limiter = RateLimiter(settings.RATE_LIMIT_READS_PER_MINUTE)
write_limiter = RateLimiter(settings.RATE_LIMIT_WRITES_PER_MINUTE)


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        # request.client is the direct peer. Behind a reverse proxy this is
        # the proxy's address; X-Forwarded-For is deliberately not trusted
        # here because any client can set it.
        client = request.client.host if request.client else "unknown"
        limiter = write_limiter if request.method in WRITE_METHODS else read_limiter
        allowed, retry_after = limiter.allow(client)
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded."},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)


class BodySizeLimitMiddleware:
    """Reject oversized request bodies before they are parsed.

    Plain ASGI rather than BaseHTTPMiddleware, so the body can be counted
    as it streams in and then replayed to the app unchanged. Checks
    Content-Length up front and the bytes actually received, so leaving
    Content-Length out (chunked encoding) doesn't get around the limit.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = settings.MAX_REQUEST_BYTES
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > limit:
                    await self._reject(send, 413, f"Request body exceeds {limit} bytes.")
                    return
            except ValueError:
                await self._reject(send, 400, "Invalid Content-Length.")
                return

        body = b""
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
            if len(body) > limit:
                await self._reject(send, 413, f"Request body exceeds {limit} bytes.")
                return

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send, status_code: int, detail: str) -> None:
        response = JSONResponse({"detail": detail}, status_code=status_code)
        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": response.raw_headers,
        })
        await send({"type": "http.response.body", "body": response.body})


# The dashboard's JS lives in frontend/app.js (not inline) so script-src can
# be 'self' only. /docs and /redoc load Swagger UI / ReDoc from jsDelivr, so
# they get their own, slightly wider policy.
APP_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
)
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        is_docs = request.url.path in ("/docs", "/redoc")
        response.headers["Content-Security-Policy"] = DOCS_CSP if is_docs else APP_CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        # Only meaningful over HTTPS (TLS terminates at the reverse proxy),
        # and harmless over plain HTTP, where browsers ignore it.
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path.startswith(("/events", "/alerts", "/devices", "/statistics")):
            response.headers["Cache-Control"] = "no-store"
        return response
