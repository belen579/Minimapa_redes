#!/bin/bash

# Iniciar cron
service cron start || cron


exec uvicorn scanner:app --host 0.0.0.0 --port 8001