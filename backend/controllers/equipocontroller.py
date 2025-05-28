from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pymongo import MongoClient
from models.models import Equipo, Device, ScanResponse
from typing import List, Optional
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

async def sync_devices_to_equipos(background_tasks: Optional[BackgroundTasks] = None):
    """
    Sincroniza los dispositivos desde network_scan.devices hacia devices.equipos
    sin crear duplicados, usando IP+MAC como identificador único.
    Asegura que los documentos guardados sean compatibles con el modelo Device.
    """
    try:
        print("Iniciando sincronización de dispositivos a la colección equipos...")
        
        # Contadores para estadísticas
        new_count = 0
        updated_count = 0
        
        # Obtener todos los dispositivos actuales en equipos_collection (destino)
        existing_devices = {}
        for device in equipos_collection.find({}):
            # Usamos la combinación IP+MAC como clave única
            key = f"{device.get('ip')}_{device.get('mac')}"
            existing_devices[key] = device
        
        print(f"Dispositivos existentes en equipos (destino): {len(existing_devices)}")
        
        # Verificar si la colección devices_collection (origen) tiene documentos
        total_devices = devices_collection.count_documents({})
        print(f"Total de documentos en network_scan.devices (origen): {total_devices}")
        
        if total_devices == 0:
            print("No hay dispositivos en la colección de origen para sincronizar.")
            return {
                "status": "warning",
                "message": "No hay dispositivos en la colección de origen para sincronizar.",
                "new_devices": 0,
                "updated_devices": 0,
                "total_devices": 0
            }
        
        # Mostrar un ejemplo de documento para entender la estructura
        sample_device = devices_collection.find_one()
        print(f"Ejemplo de documento en network_scan.devices (origen): {sample_device}")
        
        # Crear un diccionario para almacenar los dispositivos más recientes por IP+MAC
        unique_devices = {}
        
        # Buscar todos los dispositivos ordenados por fecha de escaneo (más reciente primero)
        for device in devices_collection.find().sort("scan_date", -1):
            ip = device.get("ip")
            mac = device.get("mac")
            
            if not ip or not mac:
                continue
                
            device_key = f"{ip}_{mac}"
            
            # Si no hemos visto esta combinación IP+MAC antes, guárdala
            if device_key not in unique_devices:
                unique_devices[device_key] = device
        
        print(f"Dispositivos únicos encontrados en origen: {len(unique_devices)}")
        
        # Procesar cada dispositivo
        now = datetime.now()
        
        for device_key, device in unique_devices.items():
            ip = device.get("ip")
            mac = device.get("mac")
            
            print(f"Procesando dispositivo: {ip} / {mac}")
            
            # Preparar documento estrictamente compatible con el modelo Device
            device_doc = {
                "hostname": device.get("hostname", "Unknown"),
                "ip": ip,
                "mac": mac,
                "status": device.get("status", "offline"),
                "aula": device.get("aula", "Unknown"),
                "scan_date": device.get("scan_date", now)
            }
            
            # Mostrar el documento que vamos a guardar
            print(f"Documento a guardar en equipos (destino): {device_doc}")
            
            if device_key in existing_devices:
                # Es un dispositivo existente, actualizar
                existing = existing_devices[device_key]
                print(f"Dispositivo existente encontrado con _id: {existing.get('_id')}")
                
                # Si hay un _id, lo usamos para actualizar
                if "_id" in existing:
                    # Realizar la actualización - solo con los campos del modelo Device
                    result = equipos_collection.update_one(
                        {"_id": existing["_id"]},
                        {"$set": device_doc}
                    )
                    print(f"Resultado de actualización: matched={result.matched_count}, modified={result.modified_count}")
                    
                    if result.matched_count > 0:
                        updated_count += 1
                    
                else:
                    # Si no hay _id (raro, pero por si acaso)
                    print("Dispositivo existente sin _id, insertando como nuevo")
                    result = equipos_collection.insert_one(device_doc)
                    print(f"Resultado de inserción: inserted_id={result.inserted_id}")
                    new_count += 1
            else:
                # Es un dispositivo nuevo
                print("Dispositivo nuevo, insertando en equipos (destino)")
                result = equipos_collection.insert_one(device_doc)
                print(f"Resultado de inserción: inserted_id={result.inserted_id}")
                if result.inserted_id:
                    new_count += 1
                else:
                    print("¡Error! No se insertó el documento")
        
        # Verificar que los contadores sean correctos
        print(f"Sincronización completada: {new_count} nuevos dispositivos, {updated_count} actualizados")
        
        # Contar dispositivos después de la sincronización
        final_count = equipos_collection.count_documents({})
        print(f"Total de dispositivos en equipos (destino) después de la sincronización: {final_count}")
        
        return {
            "status": "success",
            "new_devices": new_count,
            "updated_devices": updated_count,
            "total_devices": new_count + updated_count,
            "total_in_collection": final_count
        }
    except Exception as e:
        print(f"Error durante la sincronización: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "message": str(e)
        }
    
@router.post("/sync_devices/")
async def trigger_sync(background_tasks: BackgroundTasks):
    """
    Endpoint para ejecutar la sincronización en segundo plano.
    """
    background_tasks.add_task(sync_devices_to_equipos)
    return {"status": "processing", "message": "Sincronización en curso..."}



@router.get("/scan/devices", response_model=List[Device])
async def get_scandevices(
    aula: str = Query(..., description="Nombre del aula"),
    fecha: str = Query(..., description="Fecha en formato YYYY-MM-DD")
):
    try:
        # Log de los parámetros recibidos
        print(f"Parámetros recibidos: aula={aula}, fecha={fecha}")
        
        # Convertir fecha a datetime para comparaciones
        fecha_inicio = datetime.strptime(fecha, "%Y-%m-%d").replace(hour=0, minute=0, second=0)
        fecha_fin = fecha_inicio.replace(hour=23, minute=59, second=59)
        
        # Construir la consulta para todos los dispositivos de ese día
        query = {
            "aula": aula,
            "scan_date": {
                "$gte": fecha_inicio,
                "$lte": fecha_fin
            }
        }
        print(f"Query a ejecutar: {query}")
        
        # Realizar la consulta a MongoDB
        devices = list(devices_collection.find(query))
        print(f"Número de dispositivos encontrados: {len(devices)}")
        
        if not devices:
            print(f"No se encontraron dispositivos para el aula {aula} en la fecha {fecha}")
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
async def start_scan(background_tasks: BackgroundTasks):
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
        
        background_tasks.add_task(sync_devices_to_equipos)
        
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
    
@router.post("/sync/now")
async def sync_devices_now():
    """Ejecuta una sincronización de dispositivos inmediatamente y devuelve los resultados"""
    try:
        result = await sync_devices_to_equipos()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    


# Endpoint para obtener todos los dispositivos únicos
@router.get("/all", response_model=List[Device])
async def get_all_devices(
    ip: Optional[str] = None,
    mac: Optional[str] = None,
    aula: Optional[str] = None,
    status: Optional[str] = None
):
    """Obtiene todos los dispositivos almacenados en la colección equipos, con filtros opcionales"""
    try:
        # Construir query basado en los filtros proporcionados
        query = {}
        if ip:
            query["ip"] = {"$regex": ip, "$options": "i"}
        if mac:
            query["mac"] = {"$regex": mac, "$options": "i"}
        if aula:
            query["aula"] = {"$regex": aula, "$options": "i"}
        if status:
            query["status"] = status
            
        # Ejecutar la consulta
        devices = list(equipos_collection.find(query))
        
        # Formatear resultados
        formatted_devices = []
        for device in devices:
            device_id = None
            if "_id" in device:
                device_id = str(device["_id"])
                del device["_id"]
                
            formatted_device = Device(**device)
            formatted_devices.append(formatted_device)
            
        return formatted_devices
    except Exception as e:
        print(f"Error al obtener dispositivos: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))