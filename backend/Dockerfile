# Build context is the repository root (see docker-compose.yml), so this
# Dockerfile can pull in both backend/ and frontend/.
FROM python:3.11-slim

WORKDIR /app

# Pick up Debian security fixes released since the base image was built.
# No compiler or libpq headers are installed: psycopg2-binary ships a
# prebuilt wheel, and build tools in a runtime image are only extra attack
# surface.
RUN apt-get update && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Runtime dependencies only (test/scan tools live in requirements-dev.txt).
# setuptools and wheel come with the base image but the app never uses them
# at runtime, so they are removed along with their vendored packages; pip
# is upgraded rather than removed so the image can still be inspected.
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip uninstall -y setuptools wheel

COPY backend/app ./app
COPY frontend /frontend

ENV PYTHONUNBUFFERED=1

# Run as non-root.
RUN useradd --create-home --uid 10001 sentinelflow \
    && chown -R sentinelflow:sentinelflow /app
USER sentinelflow

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
