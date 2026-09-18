# Build context is the repository root (see docker-compose.yml), so this
# Dockerfile can pull in both backend/ and frontend/.
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY frontend /frontend

ENV PYTHONUNBUFFERED=1

# Run as a non-root user -- this is a security-focused project; there's no
# reason the API process needs root inside its own container, and a
# container-escape or dependency-RCE bug is strictly worse if it does.
RUN useradd --create-home --uid 10001 sentinelflow \
    && chown -R sentinelflow:sentinelflow /app
USER sentinelflow

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
