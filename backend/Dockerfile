# Usar una imagen base de Python
FROM python:3.11-slim

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar solo el requirements.txt primero para aprovechar el caché de Docker
COPY requirements.txt .

# Instalar dependencias en una sola capa para reducir el tamaño de la imagen
RUN apt-get update && \
    apt-get install -y nmap cron build-essential gcc python3-dev libssl-dev libffi-dev libkrb5-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install paramiko==3.1.0 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copiar todo el contenido del directorio de trabajo al contenedor
COPY . .


# Exponer el puerto 8000 para FastAPI
EXPOSE 8000

# Comando para ejecutar cron y FastAPI con uvicorn cuando el contenedor se inicie
CMD ["sh", "-c", "cron -f & uvicorn main:app --host 0.0.0.0 --port 8000"]
