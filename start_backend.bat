@echo off
echo.
echo  [ScamShield] Starting FastAPI Backend...
echo  API: http://localhost:8000
echo  Docs: http://localhost:8000/docs
echo.
cd /d "%~dp0backend"
pip install -r requirements.txt -q
uvicorn app.main:app --reload --port 8000 --host 0.0.0.0
pause
