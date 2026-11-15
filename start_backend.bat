@echo off
title ThreadGrid SIEM Backend
echo ====================================================
echo Starting ThreadGrid Central Ingestion API
echo Listening on 0.0.0.0:8000 (Localhost and VMware)
echo ====================================================
.\.venv\Scripts\python.exe -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
pause
