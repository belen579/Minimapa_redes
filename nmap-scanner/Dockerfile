FROM python:3.9-slim

# Instalar dependencias del sistema
RUN apt-get update && \
    apt-get install -y nmap cron procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar las dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código del scanner y scripts
COPY scanner.py .
COPY main.py .
COPY start.sh .
COPY comandocontroller.py .
COPY models/models.py ./models/
RUN chmod +x main.py start.sh

# Configurar cron para ejecutar a las 12:00 y 17:00 horas
RUN echo "0 12 * * * /usr/local/bin/python /app/main.py --cron >> /var/log/cron.log 2>&1" > /etc/cron.d/scanner-cron && \
    echo "0 17 * * * /usr/local/bin/python /app/main.py --cron >> /var/log/cron.log 2>&1" >> /etc/cron.d/scanner-cron && \
    chmod 0644 /etc/cron.d/scanner-cron && \
    crontab /etc/cron.d/scanner-cron

# Crear el archivo de log con permisos correctos
RUN touch /var/log/cron.log && chmod 0666 /var/log/cron.log

# Instalar las dependencias específicas para ejecutar comandos remotos
RUN pip install --no-cache-dir pywinrm pypsrp paramiko

# Exponer el puerto para FastAPI
EXPOSE 8001

# Ejecutar el script de inicio
CMD ["./start.sh"]

