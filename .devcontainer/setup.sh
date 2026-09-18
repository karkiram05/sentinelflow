#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r backend/requirements.txt -q

echo ""
echo "Seeding the database with the real NSL-KDD evaluation sample..."
python scripts/load_dataset.py --reset-db

echo ""
echo "Setup complete. To start the API + dashboard:"
echo "  source .venv/bin/activate"
echo "  cd backend && uvicorn app.main:app --host 0.0.0.0 --reload"
echo ""
echo "Codespaces will prompt you to open the forwarded port-8000 preview automatically."
echo "To run the tests instead:"
echo "  cd backend && python -m pytest tests/ -v"
