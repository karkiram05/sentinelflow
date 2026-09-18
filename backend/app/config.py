"""Application configuration, read from environment variables.

Kept deliberately small: a single Settings object with sane local defaults
so the app runs with zero configuration, and every value overridable via
env vars (see .env.example at the repo root).
"""
import os


class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "sqlite:///./sentinelflow.db"
    )
    APP_NAME: str = "SentinelFlow"
    APP_VERSION: str = "0.1.0"

    # Isolation Forest anomaly detector
    ML_CONTAMINATION: float = float(os.getenv("ML_CONTAMINATION", "0.15"))
    ML_RANDOM_STATE: int = int(os.getenv("ML_RANDOM_STATE", "42"))

    # Risk scoring weights
    RULE_WEIGHT: float = float(os.getenv("RULE_WEIGHT", "0.6"))
    ML_WEIGHT: float = float(os.getenv("ML_WEIGHT", "0.4"))


settings = Settings()
