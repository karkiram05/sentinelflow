"""Application configuration, read from environment variables.

Kept deliberately small: a single Settings object with sane local defaults
so the app runs with zero configuration, and every value overridable via
env vars (see .env.example at the repo root).
"""
import os
from pathlib import Path

from dotenv import load_dotenv

# Pick up a repo-root .env for local runs. Real environment variables win
# (override=False), so Docker/CI settings are never replaced by a stray file.
load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)

# Default SQLite file lives in backend/, resolved from this file's location
# rather than the current working directory. A relative "./sentinelflow.db"
# meant scripts/load_dataset.py (run from the repo root) and uvicorn (run
# from backend/) silently used two different databases, so the dashboard
# came up empty after seeding.
DEFAULT_SQLITE_PATH = Path(__file__).resolve().parent.parent / "sentinelflow.db"


class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", f"sqlite:///{DEFAULT_SQLITE_PATH}"
    )
    APP_NAME: str = "SentinelFlow"
    APP_VERSION: str = "0.1.0"

    # Isolation Forest anomaly detector
    ML_CONTAMINATION: float = float(os.getenv("ML_CONTAMINATION", "0.15"))
    ML_RANDOM_STATE: int = int(os.getenv("ML_RANDOM_STATE", "42"))

    # Risk scoring (see app/detection/risk.py)
    # How much an Isolation Forest hit adds on top of a rule that already fired.
    ML_WEIGHT: float = float(os.getenv("ML_WEIGHT", "0.4"))
    # Ceiling for alerts raised by the Isolation Forest alone (no rule, no
    # ATT&CK mapping). 0.55 keeps them at MEDIUM at most before any
    # repeat-offender boost.
    ML_ONLY_MAX_CONFIDENCE: float = float(os.getenv("ML_ONLY_MAX_CONFIDENCE", "0.55"))

    # API hardening (see app/security.py). No default key: with none set,
    # write endpoints refuse every request instead of running open.
    API_KEY: str = os.getenv("SENTINELFLOW_API_KEY", "")
    RATE_LIMIT_READS_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_READS_PER_MINUTE", "300"))
    RATE_LIMIT_WRITES_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_WRITES_PER_MINUTE", "120"))
    MAX_REQUEST_BYTES: int = int(os.getenv("MAX_REQUEST_BYTES", "16384"))


settings = Settings()
