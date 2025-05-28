import nmap
from pymongo import MongoClient
from datetime import datetime, timezone, timedelta
import time
from fastapi import FastAPI, APIRouter
from typing import Optional
import uvicorn
import logging
import sys
from bson import ObjectId

# Configurar logging para mejor depuración
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI()
router = APIRouter()
app.include_router(router)

def get_madrid_timezone():
    # Verificar si estamos en horario de verano
    is_dst = time.localtime().tm_isdst > 0
    madrid_offset = 2 if is_dst else 1  # 2 horas en verano, 1 en invierno
    return timezone(timedelta(hours=madrid_offset))

# Función para obtener datetime con zona horaria de Madrid
def get_madrid_time():
    return datetime.now(get_madrid_timezone())




try:
        from comandocontroller import router as comando_router
        logger.info("Importando módulo de comandos Windows")
        app.include_router(comando_router)
        logger.info("Router de comandos Windows añadido correctamente")
except Exception as cmd_error:
        logger.error(f"Error al importar controlador de comandos: {cmd_error}")
        import traceback
        logger.error(traceback.format_exc())

class NetworkScanner:
    def __init__(self):
        # Conexión a MongoDB
        self.MONGO_URI = 'mongodb://root:secret@localhost:27017/devices?authSource=admin'
        
        # Intentar conectar con reintentos
        max_retries = 5
        for attempt in range(max_retries):
            try:
                logger.info(f"Intento de conexión {attempt + 1} de {max_retries}")
                self.client = MongoClient(self.MONGO_URI, serverSelectionTimeoutMS=5000)
                # Verificar la conexión
                self.client.admin.command('ping')
                logger.info("✓ Conexión exitosa a MongoDB")
                
                self.db = self.client['devices']
                self.aulas_collection = self.db['aulas']
                self.network_db = self.client['network_scan']
                self.devices_collection = self.network_db['devices']
                break
                
            except Exception as e:
                logger.error(f"Error al conectar a MongoDB (intento {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    logger.info("Reintentando en 5 segundos...")
                    time.sleep(5)
                else:
                    raise Exception("No se pudo conectar a MongoDB después de varios intentos")
        
        # Inicializar scanner nmap
        try:
            self.nm = nmap.PortScanner()
            logger.info("✓ Nmap inicializado correctamente")
        except Exception as e:
            logger.error(f"Error al inicializar Nmap: {e}")
            raise

    def get_aulas_ranges(self):
        """Obtiene los rangos IP de todas las aulas"""
        try:
            aulas = list(self.aulas_collection.find({}, {"nombre_aula": 1, "rango_ip": 1, "_id": 0}))
            if not aulas:
                logger.warning("⚠ No se encontraron aulas en la base de datos")
                # Si no hay aulas configuradas, escanear toda la red local
                logger.info("Usando rango IP predeterminado 192.168.0.0/24")
                return [{"nombre_aula": "Red Local", "rango_ip": "192.168.0.0/24"}]
            
            logger.info(f"✓ Se encontraron {len(aulas)} aulas:")
            for aula in aulas:
                logger.info(f"  - Aula: {aula.get('nombre_aula', 'Sin nombre')} - Rango IP: {aula.get('rango_ip', 'Sin rango')}")
            return aulas
        except Exception as e:
            logger.error(f"❌ Error al obtener datos de aulas: {e}")
            # Si hay error, usar un rango predeterminado
            logger.info("Usando rango IP predeterminado por error: 192.168.0.0/24")
            return [{"nombre_aula": "Red Local", "rango_ip": "192.168.0.0/24"}]

    def scan_network(self, ip_range, aula_nombre):
        """Realiza el escaneo de red para un rango de IP específico"""
        try:
            logger.info(f"\n🔍 Iniciando escaneo del aula {aula_nombre}")
            logger.info(f"   Rango IP: {ip_range}")
            
            # Usar argumentos más básicos para el escaneo
            arguments = '-sn'  # Solo ping scan para empezar
            logger.info(f"Ejecutando nmap con argumentos: {arguments} {ip_range}")
            
            self.nm.scan(hosts=ip_range, arguments=arguments)
            
            network_data = []
            fecha_actual = datetime.now()+ timedelta(hours=2)
           
            
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == "up":
                    # Intentar obtener MAC solo si está disponible
                    mac = "no disponible"
                    if 'addresses' in self.nm[host] and 'mac' in self.nm[host]['addresses']:
                        mac = self.nm[host]['addresses']['mac']
                    
                    device_data = {
                        'ip': host,
                        'hostname': self.nm[host].hostname(),
                        'mac': mac,
                        'status': self.nm[host].state(),
                        'aula': aula_nombre,
                        'scan_date': fecha_actual,
                        'date_str': fecha_actual
                    }
                    
                    network_data.append(device_data)
                    logger.info(f"  ✓ Dispositivo encontrado: {host}")
            
            logger.info(f"  ✓ Escaneo completado - {len(network_data)} dispositivos encontrados")
            return network_data
            
        except Exception as e:
            logger.error(f"❌ Error durante el escaneo del aula {aula_nombre}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return []

    def run_scan(self):
        """Ejecuta el escaneo completo"""
        try:
            logger.info("\n=== Iniciando proceso de escaneo ===")
            aulas = self.get_aulas_ranges()
            
            if not aulas:
                return False, "No hay aulas para escanear", []
            
            all_devices = []
            resultados_por_aula = {}
            
            for aula in aulas:
                if not aula.get('rango_ip'):
                    logger.warning(f"⚠ Aula {aula.get('nombre_aula')} no tiene rango IP configurado")
                    continue
                    
                devices = self.scan_network(aula['rango_ip'], aula['nombre_aula'])
                if devices:
                    all_devices.extend(devices)
                    resultados_por_aula[aula['nombre_aula']] = len(devices)
            
            if all_devices:
                # Insertar dispositivos en la base de datos
                logger.info(f"Insertando {len(all_devices)} dispositivos en la base de datos")
                result = self.devices_collection.insert_many(all_devices)
                logger.info(f"Insertados {len(result.inserted_ids)} documentos")
                
                resumen = {
                    "total_dispositivos": len(all_devices),
                    "dispositivos_por_aula": resultados_por_aula,
                    "fecha_escaneo": time.strftime('%Y-%m-%d %H:%M:%S')
                }
                logger.info("\n=== Resumen del escaneo ===")
                logger.info(f"Total de dispositivos: {len(all_devices)}")
                for aula, cantidad in resultados_por_aula.items():
                    logger.info(f"{aula}: {cantidad} dispositivos")
                return True, resumen, all_devices
            else:
                logger.warning("\n⚠ No se encontraron dispositivos")
                return True, "No se encontraron dispositivos", []
            
        except Exception as e:
            logger.error(f"\n❌ Error en el proceso de escaneo: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False, str(e), []
        finally:
            logger.info("\n=== Escaneo finalizado ===")

def run_cron_scan():
    """Función dedicada para ejecutar el escaneo desde cron"""
    try:
        logger.info("\n🕒 CRON: Iniciando escaneo automático a las " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        scanner = NetworkScanner()
        success, result, devices = scanner.run_scan()
        
        if success:
            logger.info("\n✅ CRON: Escaneo automático completado exitosamente")
            if isinstance(result, dict):
                logger.info("\nResumen del escaneo automático:")
                logger.info(f"Total dispositivos: {result['total_dispositivos']}")
                logger.info("Dispositivos por aula:")
                for aula, cantidad in result['dispositivos_por_aula'].items():
                    logger.info(f"  - {aula}: {cantidad}")
                logger.info(f"Fecha: {result['fecha_escaneo']}")
        else:
            logger.error(f"\n❌ CRON: Error en escaneo automático: {result}")
            
    except Exception as e:
        logger.error(f"\n❌ CRON: Error crítico en escaneo automático: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)
    
    logger.info("\n🏁 CRON: Finalizando escaneo automático")
    return True

@app.post("/ejecutar-scan/")
async def ejecutar_scan():
    try:
        # Registrar inicio con timestamp
        logger.info(f"[{datetime.now()}] API: Iniciando proceso de escaneo...")
        
        # Verificar que MongoDB esté disponible
        try:
            client = MongoClient('mongodb://root:secret@localhost:27017/', serverSelectionTimeoutMS=2000)
            client.admin.command('ping')
            logger.info(f"[{datetime.now()}] ✓ MongoDB disponible")
        except Exception as mongo_error:
            logger.error(f"[{datetime.now()}] ❌ Error de conexión a MongoDB: {mongo_error}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                "status": "error",
                "success": False,
                "message": f"Error de conexión a MongoDB: {str(mongo_error)}",
                "data": None
            }
        
        # Continuar con el escaneo
        try:
            scanner = NetworkScanner()
            logger.info(f"[{datetime.now()}] ✓ Scanner inicializado")
            
            success, result, all_devices = scanner.run_scan()
            logger.info(f"[{datetime.now()}] ✓ Scan ejecutado: success={success}, dispositivos={len(all_devices) if all_devices else 0}")
            
            if success and isinstance(result, dict):
                logger.info("Procesando resultados del escaneo...")
                # Añadir información detallada de dispositivos
                dispositivos_info = []
                
                try:
                    for i, device in enumerate(all_devices):
                        try:
                            # Convertir datetime a string para serialización JSON
                            device_copy = dict(device)
                            
                            # Verificar y convertir explícitamente cada campo datetime
                            if 'scan_date' in device_copy:
                                try:
                                    device_copy['scan_date'] = device_copy['scan_date'].strftime('%Y-%m-%d %H:%M:%S')
                                except AttributeError as e:
                                    logger.error(f"❌ Error al convertir scan_date: {e}, tipo: {type(device_copy['scan_date'])}")
                                    device_copy['scan_date'] = str(device_copy['scan_date'])
                            
                            # Asegurar que todos los campos sean serializables
                            for key, value in list(device_copy.items()):
                                if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                                    logger.warning(f"⚠ Convirtiendo campo no serializable: {key}, tipo: {type(value)}")
                                    device_copy[key] = str(value)
                            
                            dispositivos_info.append(device_copy)
                        except Exception as device_error:
                            logger.error(f"❌ Error procesando dispositivo {i}: {str(device_error)}")
                            # Añadir una versión simplificada del dispositivo
                            dispositivos_info.append({
                                "error": f"Error al procesar dispositivo: {str(device_error)}",
                                "ip": device.get('ip', 'desconocida')
                            })
                except Exception as processing_error:
                    logger.error(f"❌ Error general procesando dispositivos: {str(processing_error)}")
                    import traceback
                    logger.error(traceback.format_exc())
                    return {
                        "status": "error",
                        "success": False,
                        "message": f"Error procesando dispositivos: {str(processing_error)}",
                        "data": None
                    }
                
                logger.info(f"✓ Procesamiento completado. Dispositivos: {len(dispositivos_info)}")
                
                try:
                    response_data = {
                        "status": "success",
                        "success": True,
                        "message": "Escaneo completado exitosamente",
                        "data": {
                            "total_dispositivos": result.get('total_dispositivos', 0),
                            "dispositivos_por_aula": result.get('dispositivos_por_aula', {}),
                            "fecha_escaneo": result.get('fecha_escaneo', ''),
                            "dispositivos": dispositivos_info
                        }
                    }
                    
                    # Verificar serialización
                    import json
                    json.dumps(response_data)
                    logger.info("Respuesta JSON válida")
                    
                    return response_data
                except Exception as response_error:
                    logger.error(f"❌ Error creando respuesta JSON: {str(response_error)}")
                    import traceback
                    logger.error(traceback.format_exc())
                    
                    # Devolver respuesta simplificada
                    return {
                        "status": "partial_success",
                        "success": True,
                        "message": f"Escaneo completado pero hubo errores al formatear la respuesta: {str(response_error)}",
                        "data": {
                            "total_dispositivos": result.get('total_dispositivos', 0),
                            "dispositivos_simplificados": [{"ip": d.get('ip', 'desconocida')} for d in all_devices]
                        }
                    }
            
            elif success:
                return {
                    "status": "success",
                    "success": True,
                    "message": result,
                    "data": None
                }
            else:
                return {
                    "status": "error",
                    "success": False,
                    "message": f"Error en el escaneo: {result}",
                    "data": None
                }
                
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"[{datetime.now()}] ❌ Error durante el escaneo:\n{error_trace}")
            return {
                "status": "error",
                "success": False,
                "message": f"Error durante el escaneo: {str(e)}",
                "error_trace": error_trace,
                "data": None
            }
    
    except Exception as global_error:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"[{datetime.now()}] ❌ ERROR GLOBAL EN ENDPOINT: {global_error}\n{error_trace}")
        
        # Es crucial que siempre devuelva JSON, incluso en caso de error catastrófico
        return {
            "status": "critical_error",
            "success": False,
            "message": f"Error crítico en el servicio: {str(global_error)}",
            "data": None
        }

# Punto de entrada principal


if __name__ == "__main__":
   

   
    # Detectar si estamos siendo ejecutados desde cron (con argumento --cron) o como servidor
    if len(sys.argv) > 1 and sys.argv[1] == "--cron":
        logger.info("Ejecutando en modo CRON")
        run_cron_scan()
        sys.exit(0)
    else:
        # Asegurarse de que las colecciones existan antes de iniciar el servidor
        try:
            scanner = NetworkScanner()
            # Crear colecciones si no existen
            if "aulas" not in scanner.db.list_collection_names():
                logger.info("Creando colección 'aulas'")
                scanner.db.create_collection("aulas")
                
            if "devices" not in scanner.network_db.list_collection_names():
                logger.info("Creando colección 'devices'")
                scanner.network_db.create_collection("devices")



           
                
            logger.info("Iniciando servidor uvicorn en modo API")
        except Exception as e:
            logger.error(f"Error inicializando colecciones: {e}")
            import traceback
            logger.error(traceback.format_exc())


            
        
        uvicorn.run(app, host="0.0.0.0", port=8001)