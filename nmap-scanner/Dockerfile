FROM python:3.9-slim

# Instalar nmap, cron y herramientas de debugging
RUN apt-get update && \
    apt-get install -y nmap cron procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar las dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código del scanner y scripts 
COPY start.sh .
RUN chmod +x start.sh

COPY scanner.py .

RUN chmod +x scanner.py 

FROM python:3.9-slim

# Instalar nmap, cron y herramientas de debugging
RUN apt-get update && \
    apt-get install -y nmap cron procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar las dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código del scanner y scripts 
COPY start.sh .
RUN chmod +x start.sh

COPY scanner.py .

RUN chmod +x scanner.py 

# Configurar cron para ejecutar a las 12:00 y 17:00 horas
RUN echo "0 12 * * * /usr/local/bin/python /app/scanner.py >> /var/log/cron.log 2>&1" > /etc/cron.d/scanner-cron-12 && \
    echo "0 17 * * * /usr/local/bin/python /app/scanner.py >> /var/log/cron.log 2>&1" > /etc/cron.d/scanner-cron-17 && \
    chmod 0644 /etc/cron.d/scanner-cron-12 /etc/cron.d/scanner-cron-17 && \
    crontab /etc/cron.d/scanner-cron-12 /etc/cron.d/scanner-cron-17

# Crear el archivo de log con permisos correctos
RUN touch /var/log/cron.log && chmod 0666 /var/log/cron.log

# Exponer el puerto para FastAPI
EXPOSE 8001

# Modificar el start.sh para ejecutar tanto cron como uvicorn
CMD ["./start.sh"]

