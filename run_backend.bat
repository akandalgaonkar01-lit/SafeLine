@echo off
cd /d "%~dp0backend"
if not exist .venv py -3.13 -m venv .venv
call .venv\Scripts\activate
python --version
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
