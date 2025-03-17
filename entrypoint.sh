#!/bin/sh

# Iniciar cron en segundo plano
cron

# Iniciar uvicorn para FastAPI
uvicorn main:app --host 0.0.0.0 --port 8000
