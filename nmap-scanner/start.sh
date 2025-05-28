#!/bin/bash
set -e

# Iniciar el servicio cron en primer plano
service cron start
echo "Servicio cron iniciado"
echo "Cron configurado para ejecutar main.py a las 12:00 y 17:00 horas"

# Para verificar que cron está funcionando correctamente
crontab -l

# Iniciar el servidor uvicorn en primer plano
echo "Iniciando uvicorn..."
exec uvicorn scanner:app --host 0.0.0.0 --port 8001 --reload 