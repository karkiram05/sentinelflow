import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Force an isolated, file-based SQLite DB for the test run, created fresh
# and removed at the end -- tests never touch a developer's real
# sentinelflow.db.
TEST_DB_PATH = Path(__file__).resolve().parent / "test_sentinelflow.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"
# Known key for the write-endpoint tests; never used outside the test run.
os.environ["SENTINELFLOW_API_KEY"] = "test-api-key"

import pytest  # noqa: E402

from app.database import Base, engine  # noqa: E402
from app.state import detection_state  # noqa: E402
from app.security import read_limiter, write_limiter  # noqa: E402


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    detection_state.anomaly_detector = None
    read_limiter.reset()
    write_limiter.reset()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True, scope="session")
def cleanup_db_file():
    yield
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
