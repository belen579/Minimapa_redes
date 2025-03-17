import nmap
import subprocess
import paramiko
from pymongo import MongoClient
from datetime import datetime
import os
import time
from fastapi import FastAPI, APIRouter, HTTPException
from typing import List, Optional
from pydantic import BaseModel
import uvicorn
import logging
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

# Modelo para comandos por IP
class CommandRequest(BaseModel):
    command: str
    fecha_scan: Optional[str] = None
    method: str = "ssh"
    user: str = "minimapa"
    password: str = "ri6d4kRob3gZyH2"

class NetworkScanner:
    def __init__(self):
        # Como estamos en network_mode: "host", usamos localhost
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
                self.commands_collection = self.network_db['commands_history']
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
            scan_date = datetime.now()
            
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
                        'scan_date': scan_date,
                        'timestamp': scan_date.timestamp(),
                        'date_str': scan_date.strftime('%Y-%m-%d')
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
                    "fecha_escaneo": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
            
    def execute_command_ssh(self, ip, command, user, password):
        """Ejecuta un comando a través de SSH en un dispositivo remoto"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=user, password=password, timeout=10)
            
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            client.close()
            
            return {
                'success': True,
                'output': output,
                'error': error if error else None
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e)
            }
    
    def execute_command_nmap(self, ip, command):
        """Ejecuta un comando nmap en un dispositivo específico"""
        try:
            full_command = f"nmap {command} {ip}"
            result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.stderr else None
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e)
            }
    
    def execute_command(self, ip, command, method="ssh", user="minimapa", password="ri6d4kRob3gZyH2"):
        """Ejecuta un comando en un dispositivo específico"""
        try:
            # Ejecutar según el método
            if method == "ssh":
                result = self.execute_command_ssh(ip, command, user, password)
            else:
                result = self.execute_command_nmap(ip, command)
            
            # Registrar el comando
            self.commands_collection.insert_one({
                'ip': ip,
                'command': command,
                'method': method,
                'timestamp': datetime.now(),
                'success': result['success'],
                'output': result['output'],
                'error': result['error']
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error ejecutando comando en {ip}: {e}")
            return {
                'success': False,
                'output': '',
                'error': str(e)
            }
    
    def execute_command_in_aula_by_id(self, aula_id, command, fecha_scan=None, method="ssh", user="minimapa", password="ri6d4kRob3gZyH2"):
        """
        Ejecuta un comando en todos los dispositivos de un aula específica identificada por su ID
        
        Parámetros:
        - aula_id: ID del aula donde ejecutar los comandos
        - command: Comando a ejecutar
        - fecha_scan: Fecha específica de escaneo (formato YYYY-MM-DD), si es None usa el más reciente
        - method: Método de ejecución (ssh o nmap)
        - user: Usuario para SSH
        - password: Contraseña para SSH
        """
        try:
            logger.info(f"\n=== Iniciando ejecución de comando en aula con ID {aula_id} ===")
            
            # Primero, obtener el nombre del aula a partir del ID
            aula = self.aulas_collection.find_one({"_id": ObjectId(aula_id)})
            
            if not aula:
                logger.warning(f"⚠ No se encontró un aula con el ID {aula_id}")
                return False, f"No se encontró un aula con el ID {aula_id}", []
            
            aula_nombre = aula.get("nombre_aula", "Sin nombre")
            logger.info(f"✓ Aula encontrada: {aula_nombre}")
            
            # Construir el pipeline para buscar dispositivos
            pipeline = [{"$match": {"aula": aula_nombre}}]
            
            # Si se especifica una fecha, filtrar por esa fecha
            if fecha_scan:
                try:
                    # Convertir a datetime para validar el formato
                    fecha_scan_dt = datetime.strptime(fecha_scan, "%Y-%m-%d")
                    
                    # Crear un filtro para la fecha específica
                    pipeline.append({
                        "$match": {
                            "date_str": fecha_scan
                        }
                    })
                    logger.info(f"Filtrando dispositivos escaneados el {fecha_scan}")
                except ValueError:
                    logger.warning(f"⚠ Formato de fecha incorrecto: {fecha_scan}. Utilizando el escaneo más reciente.")
                    fecha_scan = None
            
            # Si no hay fecha específica, agrupar por IP y tomar el más reciente
            if not fecha_scan:
                pipeline.extend([
                    {"$sort": {"scan_date": -1}},
                    {"$group": {"_id": "$ip", "doc": {"$first": "$$ROOT"}}},
                    {"$replaceRoot": {"newRoot": "$doc"}}
                ])
                logger.info("Utilizando los dispositivos del escaneo más reciente")
            
            devices = list(self.devices_collection.aggregate(pipeline))
            
            if not devices:
                message = f"No se encontraron dispositivos escaneados para el aula {aula_nombre}"
                if fecha_scan:
                    message += f" en la fecha {fecha_scan}"
                logger.warning(f"⚠ {message}")
                return False, message, []
            
            logger.info(f"✓ Se encontraron {len(devices)} dispositivos para el aula {aula_nombre}")
            
            # Ejecutar el comando en cada dispositivo
            results = []
            successful = 0
            
            for device in devices:
                ip = device['ip']
                try:
                    result = self.execute_command(
                        ip=ip,
                        command=command,
                        method=method,
                        user=user,
                        password=password
                    )
                    
                    if result['success']:
                        successful += 1
                        status = "✓"
                    else:
                        status = "✗"
                    
                    logger.info(f"  {status} Comando en {ip}: {result['success']}")
                    
                    results.append({
                        "ip": ip,
                        "hostname": device.get("hostname", ""),
                        "success": result['success'],
                        "output": result['output'],
                        "error": result['error']
                    })
                    
                except Exception as e:
                    logger.error(f"  ✗ Error al ejecutar comando en {ip}: {e}")
                    results.append({
                        "ip": ip,
                        "hostname": device.get("hostname", ""),
                        "success": False,
                        "output": "",
                        "error": str(e)
                    })
            
            logger.info(f"\n=== Resumen de ejecución ===")
            logger.info(f"Aula: {aula_nombre} (ID: {aula_id})")
            if fecha_scan:
                logger.info(f"Fecha: {fecha_scan}")
            logger.info(f"Comando: {command}")
            logger.info(f"Método: {method}")
            logger.info(f"Dispositivos: {len(devices)}")
            logger.info(f"Éxitos: {successful}/{len(devices)} ({int(successful/len(devices)*100 if len(devices) > 0 else 0)}%)")
            
            return True, f"Comando ejecutado en {successful} de {len(devices)} dispositivos", results
            
        except Exception as e:
            logger.error(f"❌ Error al ejecutar comando en aula: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False, str(e), []


def main():
    try:
        scanner = NetworkScanner()
        success, result, _ = scanner.run_scan()
        if success:
            logger.info("\n✓ Proceso completado exitosamente")
            if isinstance(result, dict):
                logger.info("\nResumen final:")
                logger.info(f"Total dispositivos: {result['total_dispositivos']}")
                logger.info("Dispositivos por aula:")
                for aula, cantidad in result['dispositivos_por_aula'].items():
                    logger.info(f"  - {aula}: {cantidad}")
                logger.info(f"Fecha: {result['fecha_escaneo']}")
        else:
            logger.error(f"\n❌ Error: {result}")
    except Exception as e:
        logger.error(f"\n❌ Error crítico: {e}")

@app.post("/ejecutar-scan/")
async def ejecutar_scan():
    try:
        # Registrar inicio con timestamp
        logger.info(f"[{datetime.now()}] Iniciando proceso de escaneo...")
        
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

@app.post("/ejecutar-comando-aula-id/{aula_id}")
async def ejecutar_comando_aula_by_id(
    aula_id: str,
    request: CommandRequest
):
    """
    Ejecuta un comando en todos los dispositivos de un aula específica identificada por su ID
    con un manejo de errores más detallado y registro de resultados.
    """
    try:
        # Validaciones iniciales
        if not aula_id:
            return {
                "status": "error",
                "message": "ID de aula no proporcionado",
                "data": None
            }
        
        if not request.command:
            return {
                "status": "error", 
                "message": "Comando no especificado",
                "data": None
            }

        # Instanciar el escáner de red
        scanner = NetworkScanner()

        # Ejecutar comando en dispositivos del aula
        success, message, results = scanner.execute_command_in_aula_by_id(
            aula_id=aula_id,
            command=request.command,
            fecha_scan=request.fecha_scan,
            method=request.method,
            user=request.user,
            password=request.password
        )

        # Procesamiento de resultados detallado
        if success:
            dispositivos_exitosos = sum(1 for r in results if r.get("success", False))
            dispositivos_fallidos = len(results) - dispositivos_exitosos

            response_data = {
                "status": "success",
                "data": {
                    "aula_id": aula_id,
                    "command": request.command,
                    "method": request.method,
                    "total_dispositivos": len(results),
                    "dispositivos_exitosos": dispositivos_exitosos,
                    "dispositivos_fallidos": dispositivos_fallidos,
                    "resultados_detallados": results,
                    "porcentaje_exito": round((dispositivos_exitosos / len(results)) * 100, 2) if results else 0
                },
                "message": message or f"Comando ejecutado en {dispositivos_exitosos} de {len(results)} dispositivos"
            }

            # Agregar fecha si se proporcionó
            if request.fecha_scan:
                response_data["data"]["fecha_scan"] = request.fecha_scan

            # Logging de resultados detallados
            for resultado in results:
                if not resultado.get("success", False):
                    logger.warning(f"Fallo en dispositivo {resultado.get('ip', 'Desconocido')}: {resultado.get('error', 'Error no especificado')}")

            return response_data
        else:
            # Manejo de error global
            return {
                "status": "error",
                "message": message or "Fallo en la ejecución del comando",
                "data": {
                    "aula_id": aula_id,
                    "command": request.command,
                    "method": request.method
                }
            }

    except Exception as e:
        # Captura de excepciones no controladas
        logger.error(f"Excepción en ejecución de comando: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "status": "error",
            "message": f"Error crítico durante la ejecución del comando: {str(e)}",
            "data": None
        }

# Si se ejecuta directamente, iniciar el servidor en el puerto 8001
if __name__ == "__main__":
    # Asegurarse de que las colecciones existan
    try:
        scanner = NetworkScanner()
        # Crear colecciones si no existen
        if "aulas" not in scanner.db.list_collection_names():
            logger.info("Creando colección 'aulas'")
            scanner.db.create_collection("aulas")
            
        if "devices" not in scanner.network_db.list_collection_names():
            logger.info("Creando colección 'devices'")
            scanner.network_db.create_collection("devices")
            
        if "commands_history" not in scanner.network_db.list_collection_names():
            logger.info("Creando colección 'commands_history'")
            scanner.network_db.create_collection("commands_history")
            
        logger.info("Iniciando servidor uvicorn")
    except Exception as e:
        logger.error(f"Error inicializando colecciones: {e}")
        import traceback
        logger.error(traceback.format_exc())
    
    uvicorn.run(app, host="0.0.0.0", port=8001)