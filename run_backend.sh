#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/backend"
python3.13 -m venv .venv 2>/dev/null || true
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
