from fastapi import APIRouter, HTTPException, Query
from pymongo import MongoClient
from models.models import Equipo, Device, ScanResponse
from typing import List
from bson import ObjectId
from datetime import datetime
from pydantic import BaseModel
import asyncio 
import subprocess 

# Crear la instancia de APIRouter
router = APIRouter(
    prefix="/equipos",
    tags=["equipos"],
    responses={404: {"description": "No encontrado"}}
)

# Configuración MongoDB
MONGO_URI = 'mongodb://root:secret@mongo:27017/'
client = MongoClient(MONGO_URI)
db = client['devices']
equipos_collection = db['equipos']
network_db = client['network_scan']
devices_collection = network_db['devices']

# Modelo para dispositivos escaneados
class Device(BaseModel):
    hostname: str
    ip: str
    mac: str
    status: str
    aula: str
    scan_date: datetime

def serialize_equipo(equipo):
    """Función auxiliar para serializar ObjectId y manejar campos específicos"""
    if '_id' in equipo:
        equipo['id'] = str(equipo['_id'])
        del equipo['_id']
    return equipo

# Tus endpoints existentes aquí...

@router.get("/scan/devices", response_model=List[Device])
async def get_scanned_devices(
    aula: str = Query(..., description="Nombre del aula"),
    fecha: str = Query(..., description="Fecha en formato YYYY-MM-DD")
):
    try:
        # Log de los parámetros recibidos
        print(f"Parámetros recibidos: aula={aula}, fecha={fecha}")

        # Veamos qué hay en la colección
        total_docs = devices_collection.count_documents({})
        print(f"Total de documentos en la colección: {total_docs}")

        # Ver un ejemplo de documento
        ejemplo = devices_collection.find_one()
        print(f"Ejemplo de documento en la colección: {ejemplo}")

        # Construir la consulta
        query = {
            "aula": aula,
            "date_str": fecha
        }
        print(f"Query a ejecutar: {query}")

        # Realizar la consulta a MongoDB
        devices = list(devices_collection.find(query))
        print(f"Número de dispositivos encontrados: {len(devices)}")

        if not devices:
            # Veamos qué aulas y fechas existen
            aulas_disponibles = devices_collection.distinct("aula")
            fechas_disponibles = devices_collection.distinct("date_str")
            print(f"Aulas disponibles: {aulas_disponibles}")
            print(f"Fechas disponibles: {fechas_disponibles}")
            return []

        # Formatear los resultados
        formatted_devices = []
        for device in devices:
            formatted_device = {
                "hostname": device.get("hostname", "Unknown"),
                "ip": device.get("ip", "Unknown"),
                "mac": device.get("mac", "Unknown"),
                "status": device.get("status", "offline"),
                "aula": device.get("aula", "Unknown"),
                "scan_date": device.get("scan_date", datetime.now())
            }
            formatted_devices.append(formatted_device)

        return formatted_devices

    except Exception as e:
        print(f"Error en la consulta: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    

@router.get("/scan/latest/hour/devices", response_model=List[Device])
async def get_latest_hour_scanned_devices(
    aula: str = Query(..., description="Nombre del aula"),
    fecha: str = Query(..., description="Fecha en formato YYYY-MM-DD")
):
    try:
        # Log de los parámetros recibidos
        print(f"Parámetros recibidos: aula={aula}, fecha={fecha}")
        
        # Convertir fecha a datetime para comparaciones
        fecha_inicio = datetime.strptime(fecha, "%Y-%m-%d").replace(hour=0, minute=0, second=0)
        fecha_fin = fecha_inicio.replace(hour=23, minute=59, second=59)
        
        # Encuentra la hora más reciente de escaneo para esta aula y fecha
        pipeline = [
            {
                "$match": {
                    "aula": aula,
                    "scan_date": {
                        "$gte": fecha_inicio,
                        "$lte": fecha_fin
                    }
                }
            },
            {
                "$sort": {"scan_date": -1}  # Ordena descendente por fecha de escaneo
            },
            {
                "$group": {
                    "_id": None,
                    "ultima_fecha": {"$first": "$scan_date"}  # Toma la primera (más reciente)
                }
            }
        ]
        
        # Ejecuta la agregación
        latest_time = list(devices_collection.aggregate(pipeline))
        print(f"Resultado de la búsqueda del último escaneo: {latest_time}")
        
        if not latest_time:
            print(f"No se encontraron escaneos para el aula {aula} en la fecha {fecha}")
            return []
        
        # Obtén la fecha y hora exacta del último escaneo
        ultima_fecha = latest_time[0]["ultima_fecha"]
        print(f"Fecha y hora del último escaneo: {ultima_fecha}")
        
        # Busca todos los dispositivos de ese último escaneo
        query = {
            "aula": aula,
            "scan_date": ultima_fecha
        }
        print(f"Query a ejecutar: {query}")
        
        devices = list(devices_collection.find(query))
        print(f"Número de dispositivos encontrados: {len(devices)}")
        
        # Formatear los resultados
        formatted_devices = []
        for device in devices:
            formatted_device = {
                "hostname": device.get("hostname", "Unknown"),
                "ip": device.get("ip", "Unknown"),
                "mac": device.get("mac", "Unknown"),
                "status": device.get("status", "offline"),
                "aula": device.get("aula", "Unknown"),
                "scan_date": device.get("scan_date", datetime.now())
            }
            formatted_devices.append(formatted_device)
        
        return formatted_devices
    
    except Exception as e:
        print(f"Error en la consulta: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/scan/summary/{aula}")
async def get_scan_summary(aula: str, fecha: str = Query(...)):
    try:
        # Obtener resumen de dispositivos
        pipeline = [
            {
                "$match": {
                    "aula": aula,
                    "date_str": fecha
                }
            },
            {
                "$group": {
                    "_id": "$status",
                    "count": {"$sum": 1}
                }
            }
        ]
        
        summary = list(devices_collection.aggregate(pipeline))
        
        return {
            "aula": aula,
            "fecha": fecha,
            "resumen": {item["_id"]: item["count"] for item in summary}
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.post("/scan/start")
async def start_scan():
    try:
        # Ejecutar el script en el contenedor nmap-scanner
        result = subprocess.run(
            ['docker', 'exec', 'nmap-scanner', 'python3', '/home/vboxuser/proyecto_redes/nmap-scanner/scanner.py'], 
            capture_output=True, 
            text=True,
            timeout=600  # 10 minutos de timeout
        )
        
        if result.returncode != 0:
            return {
                "status": "error", 
                "message": result.stderr
            }
        
        return {
            "status": "success",
            "message": "Scan completed",
            "output": result.stdout
        }
    
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": "Scan timeout expired"
        }
    except Exception as e:
        return {
            "status": "error", 
            "message": str(e)
        }