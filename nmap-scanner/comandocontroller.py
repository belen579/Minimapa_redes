import time
import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pymongo import MongoClient
from bson import ObjectId
import paramiko
from models.models import ComandoEquipoRequest, ComandoAulaRequest, ResultadoComando, ResultadoComandoAula, ComandoMetodo

# Configuración del router de FastAPI
router = APIRouter(
    prefix="/comandos",
    tags=["comandos"],
    responses={404: {"description": "No encontrado"}},
)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("comandos.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuración MongoDB
MONGO_URI = 'mongodb://root:secret@localhost:27017/devices?authSource=admin'
client = MongoClient(MONGO_URI)
db = client['devices']
equipos_collection = db['equipos']
aulas_collection = db['aulas']
network_db = client['network_scan']
devices_collection = network_db['devices']




# Endpoints para obtener aulas y equipos
@router.get("/aulas", response_model=List[Dict])
async def obtener_aulas():
    """Obtiene la lista de todas las aulas disponibles"""
    try:
        aulas = list(aulas_collection.find({}, {'_id': 1, 'nombre_aula': 1}))
        # Convertir ObjectId a string para poder serializarlo
        for aula in aulas:
            aula['_id'] = str(aula['_id'])
        return aulas
    except Exception as e:
        logger.error(f"Error al obtener aulas: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener las aulas: {str(e)}"
        )

@router.get("/aulas/{aula_id}/equipos", response_model=List[Dict])
async def obtener_equipos_por_aula(aula_id: str):
    """Obtiene todos los equipos de un aula específica sin IPs duplicadas"""
    try:
        # Buscar por ID de aula si es un ObjectId válido, sino por nombre
        if len(aula_id) == 24:  # Posible ObjectId
            try:
                aula_filter = {"aula_id": ObjectId(aula_id)}
            except:
                aula_filter = {"aula_id": aula_id}
        else:
            aula_filter = {"aula_id": aula_id}
        
        equipos = list(equipos_collection.find(aula_filter))
        
        # Eliminar duplicados por IP
        equipos_sin_duplicados = {}
        for equipo in equipos:
            ip = equipo.get('ip')
            # Solo considerar el equipo si tiene una IP y no está duplicado o es más reciente
            if ip and (ip not in equipos_sin_duplicados or 
                      equipo.get('dia', datetime.min) > equipos_sin_duplicados[ip].get('dia', datetime.min)):
                equipos_sin_duplicados[ip] = equipo
        
        # Convertir a lista y formatear para respuesta
        resultado = []
        for equipo in equipos_sin_duplicados.values():
            equipo_formateado = dict(equipo)
            equipo_formateado['_id'] = str(equipo_formateado['_id'])
            if 'aula_id' in equipo_formateado and isinstance(equipo_formateado['aula_id'], ObjectId):
                equipo_formateado['aula_id'] = str(equipo_formateado['aula_id'])
            resultado.append(equipo_formateado)
        
        return resultado
    except Exception as e:
        logger.error(f"Error al obtener equipos del aula {aula_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener los equipos: {str(e)}"
        )
async def get_aula_equipos(aula_id: str):
    """
    Obtiene un aula y sus equipos desde la base de datos sin IPs duplicadas.
    Busca los equipos por el nombre del aula en el campo 'aula'.
    """
    try:
        logger.info(f"Buscando aula con ID: {aula_id}")
        
        # Intentar convertir a ObjectId primero
        try:
            obj_id = ObjectId(aula_id)
            aula = aulas_collection.find_one({"_id": obj_id})
            
            if aula:
                logger.info(f"Aula encontrada: {aula.get('nombre_aula')}")
            else:
                logger.warning(f"No se encontró aula con ObjectId: {aula_id}")
                return None
                
        except Exception as e:
            logger.warning(f"No es un ObjectId válido, tratando como string: {str(e)}")
            aula = aulas_collection.find_one({"_id": aula_id})
            
            if not aula:
                logger.warning(f"No se encontró aula con ID string: {aula_id}")
                return None
        
        # Nombre del aula para búsqueda
        nombre_aula = aula.get("nombre_aula")
        logger.info(f"Nombre del aula: {nombre_aula}")
        
        # Buscar equipos que tienen este nombre de aula
        filter_by_name = {"aula": nombre_aula}
        logger.info(f"Buscando equipos con filtro: {filter_by_name}")
        equipos = list(equipos_collection.find(filter_by_name))
        logger.info(f"Equipos encontrados: {len(equipos)}")
        
        # Si no encontramos equipos, probar con devices_collection
        if not equipos:
            equipos = list(devices_collection.find(filter_by_name))
            logger.info(f"Equipos encontrados en devices_collection: {len(equipos)}")
        
        # Eliminar duplicados por IP
        equipos_unicos = {}
        for equipo in equipos:
            ip = equipo.get("ip")
            if not ip:
                continue
                
            # Si la IP no existe o el equipo actual es más reciente, actualizar
            fecha_equipo = equipo.get("scan_date") or datetime.min
            fecha_actual = equipos_unicos.get(ip, {}).get("scan_date") or datetime.min
            
            if ip not in equipos_unicos or fecha_equipo > fecha_actual:
                equipos_unicos[ip] = equipo
        
        logger.info(f"Equipos únicos (sin duplicados por IP): {len(equipos_unicos)}")
        
        # Formatear resultado
        result = {
            "aula_id": str(aula.get("_id")),
            "nombre_aula": nombre_aula,
            "equipos": []
        }
        
        # Incluir equipos con status "up" o "activo"
        count_activos = 0
        
        for equipo in equipos_unicos.values():
            # Mostrar algunos equipos como ejemplo para depuración
            if count_activos < 14:
                logger.info(f"Equipo ejemplo - IP: {equipo.get('ip')}, Hostname: {equipo.get('hostname', '')}, Status: {equipo.get('status', '')}")
            
            # IMPORTANTE: El status "up" se considera activo
            status = str(equipo.get("status", "")).lower()
            if status == "up" or status == "activo" or status == "online":
                result["equipos"].append({
                    "ip": equipo.get("ip"),
                    "hostname": equipo.get("hostname", "Unknown"),
                    "status": equipo.get("status")
                })
                count_activos += 1
        
        logger.info(f"Equipos activos encontrados (status up/activo/online): {count_activos}")
        
        # Si no encontramos equipos activos, usar la búsqueda de respaldo pero mantener
        # los equipos del aula prioritariamente
        if count_activos == 0:
            logger.warning("No se encontraron equipos activos, usando todos los equipos del aula")
            
            # Usar todos los equipos del aula sin filtrar por status
            for equipo in equipos_unicos.values():
                result["equipos"].append({
                    "ip": equipo.get("ip"),
                    "hostname": equipo.get("hostname", "Unknown"),
                    "status": equipo.get("status", "unknown")
                })
                count_activos += 1
        
        logger.info(f"Total de equipos incluidos: {count_activos}")
        return result
        
    except Exception as e:
        logger.error(f"Error al obtener aula y equipos para {aula_id}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

@router.get("/estado_tarea/{task_id}", response_model=Dict[str, Any])
async def obtener_estado_tarea(task_id: str):
    """
    Obtiene el estado actual de una tarea de ejecución de comandos en aula.
    """
    try:
        # Buscar la tarea en la base de datos
        task_data = db.comandos_tareas.find_one({"task_id": task_id})
        
        if not task_data:
            logger.warning(f"No se encontró la tarea con ID {task_id}")
            raise HTTPException(
                status_code=404,
                detail=f"No se encontró la tarea con ID {task_id}"
            )
        
        # Convertir ObjectId a string para poder serializarlo
        if "_id" in task_data:
            task_data["_id"] = str(task_data["_id"])
        
        # Formatear resultados para evitar problemas de serialización
        if "resultados" in task_data:
            for resultado in task_data["resultados"]:
                # Asegurar que cualquier campo ObjectId se convierta a string
                for key, value in list(resultado.items()):
                    if isinstance(value, ObjectId):
                        resultado[key] = str(value)
        
        # Formatear fechas para serialización
        if "fecha_inicio" in task_data and isinstance(task_data["fecha_inicio"], datetime):
            task_data["fecha_inicio"] = task_data["fecha_inicio"].isoformat()
        
        if "fecha_fin" in task_data and isinstance(task_data["fecha_fin"], datetime):
            task_data["fecha_fin"] = task_data["fecha_fin"].isoformat()
        
        logger.info(f"Estado de tarea {task_id} recuperado correctamente: {task_data.get('estado')}")
        return task_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al obtener el estado de la tarea {task_id}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener el estado de la tarea"
        )
    

@router.post("/equipo", response_model=ResultadoComando)
async def ejecutar_comando_equipo(request: ComandoEquipoRequest):
    """Ejecuta un comando en un equipo Windows específico usando SSH + PowerShell"""
    try:
        inicio = time.time()
        
        # Solo permitimos SSH
        if request.metodo != ComandoMetodo.SSH:
            raise HTTPException(
                status_code=400, 
                detail="Solo se permite el método SSH"
            )
        
        # Reducir el timeout si es mayor a 60 segundos para evitar esperas muy largas
        timeout = min(request.timeout, 200)
        
        # Modificar el comando para asegurar que se capture la salida completa
        comando_modificado = request.comando
        
        # Para comandos tipo Get-Process o con formato tabular, asegurar formato completo
        if "Get-Process" in request.comando and "Out-String" not in request.comando:
            comando_modificado = f"{request.comando} | Format-Table -AutoSize | Out-String -Width 8192"
        elif "|" in request.comando and "Select-Object" in request.comando and "Out-String" not in request.comando:
            comando_modificado = f"({request.comando}) | Format-Table -AutoSize | Out-String -Width 8192"
        
        logger.info(f"Comando original: {request.comando}")
        logger.info(f"Comando modificado: {comando_modificado}")
        
        # Ejecutar el comando usando SSH usando to_thread para ejecutar una función sincrónica
        import asyncio
        resultado = await asyncio.to_thread(
            _ejecutar_ssh_sync,
            request.equipo_ip, 
            comando_modificado, 
            request.usuario, 
            request.password,
            timeout
        )
        
        fin = time.time()
        tiempo_ejecucion = fin - inicio
        
        # Construir el resultado
        resultado_comando = ResultadoComando(
            equipo_ip=request.equipo_ip,
            equipo_hostname=resultado.get("hostname"),
            exito=resultado.get("exito", False),
            salida=resultado.get("salida"),
            error=resultado.get("error"),
            codigo_retorno=resultado.get("codigo_retorno"),
            tiempo_ejecucion=tiempo_ejecucion
        )
        
        return resultado_comando
    
    except Exception as e:
        logger.error(f"Error al ejecutar comando en equipo {request.equipo_ip}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error al ejecutar el comando: {str(e)}"
        )



async def ejecutar_comando_en_equipo(
    ip: str, 
    comando: str, 
    metodo: str, 
    usuario: str, 
    password: str,
    timeout: int,
    hostname: Optional[str] = None
) -> ResultadoComando:
    """Ejecuta un comando en un equipo Windows y devuelve el resultado"""
    inicio = time.time()
    
    try:
        # Ejecutar comando usando SSH con el método mejorado
        import asyncio
        resultado = await asyncio.to_thread(_ejecutar_ssh_sync, ip, comando, usuario, password, timeout)
        
        fin = time.time()
        tiempo_ejecucion = fin - inicio
        
        # Construir el resultado
        return ResultadoComando(
            equipo_ip=ip,
            equipo_hostname=hostname or resultado.get("hostname"),
            exito=resultado.get("exito", False),
            salida=resultado.get("salida"),
            error=resultado.get("error"),
            codigo_retorno=resultado.get("codigo_retorno"),
            tiempo_ejecucion=tiempo_ejecucion
        )
    
    except Exception as e:
        fin = time.time()
        tiempo_ejecucion = fin - inicio
        
        logger.error(f"Error al ejecutar comando en equipo Windows {ip}: {str(e)}")
        return ResultadoComando(
            equipo_ip=ip,
            equipo_hostname=hostname,
            exito=False,
            error=str(e),
            tiempo_ejecucion=tiempo_ejecucion
        )

def _ejecutar_ssh_sync(ip, comando, usuario, password, timeout):
    """
    Implementación mejorada y unificada que maneja cualquier tipo de comando
    de manera consistente a través de SSH.
    """
    import paramiko
    import socket
    import time
    
    # Configurar cliente SSH
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    hostname = ip  # Valor por defecto
    output = ""
    error = ""
    success = False
    return_code = 1
    
    try:
        # 1. Conexión SSH al equipo
        logger.info(f"Conectando por SSH a {ip}...")
        ssh.connect(
            ip,
            username=usuario,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        
        # Obtener hostname primero
        try:
            _, stdout, _ = ssh.exec_command("hostname", timeout=5)
            hostname = stdout.read().decode('utf-8', errors='replace').strip()
            logger.info(f"Hostname obtenido: {hostname}")
        except Exception as e:
            logger.warning(f"No se pudo obtener hostname: {str(e)}")
            hostname = ip
        
        # 2. Determinar el tipo de comando y la mejor forma de ejecutarlo
        logger.info(f"Preparando ejecución del comando: {comando}")
        
        # Si es un comando cmd básico (systeminfor, ipconfig, etc.)
        if comando.strip().lower() in ["systeminfo", "ipconfig", "ipconfig /all", "dir", "netstat", "netstat -ano"]:
            cmd = f'cmd.exe /c "{comando}"'
            ejecutar_tipo = "cmd"
        # Si es un comando de Chocolatey
        elif comando.strip().startswith("choco"):
            cmd = f'cmd.exe /c "{comando}"'
            ejecutar_tipo = "cmd"
        # Para otros comandos, usar PowerShell
        else:
            cmd = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8; {comando} | Out-String -Width 9999"'
            ejecutar_tipo = "powershell"
        
        logger.info(f"Ejecutando como {ejecutar_tipo}: {cmd}")
        
        # 3. Ejecutar el comando con buffer de tamaño adecuado
        transport = ssh.get_transport()
        channel = transport.open_session()
        channel.settimeout(timeout)
        channel.exec_command(cmd)
        
        # 4. Leer salida de manera optimizada con timeout apropiado
        stdout_data = b""
        stderr_data = b""
        
        # Tiempo máximo de espera
        end_time = time.time() + timeout
        
        while time.time() < end_time:
            if channel.exit_status_ready():
                break
                
            # Leer stdout
            if channel.recv_ready():
                new_data = channel.recv(65536)  # Buffer grande para evitar truncamiento
                if new_data:
                    stdout_data += new_data
                else:
                    break
            
            # Leer stderr
            if channel.recv_stderr_ready():
                new_data = channel.recv_stderr(65536)
                if new_data:
                    stderr_data += new_data
                else:
                    break
            
            # Pequeña pausa para no saturar CPU
            time.sleep(0.05)
        
        # Obtener código de salida
        if channel.exit_status_ready():
            exit_status = channel.recv_exit_status()
        else:
            # Si no se completó a tiempo, cerrar el canal
            logger.warning(f"Comando excedió timeout, forzando cierre")
            channel.close()
            exit_status = -1
        
        # Decodificar salidas
        if stdout_data:
            output = stdout_data.decode('utf-8', errors='replace').strip()
            logger.info(f"Salida capturada ({len(output)} bytes)")
        else:
            logger.warning("No se recibió salida del comando")
            
        if stderr_data:
            error = stderr_data.decode('utf-8', errors='replace').strip()
            logger.warning(f"Error recibido: {error}")
        
        # Determinar éxito
        success = (exit_status == 0) or (exit_status == -1 and output)
        return_code = exit_status if exit_status != -1 else 1
        
        # 5. Si no hay salida pero debería haberla, intentar método alternativo
        if not output and not error and exit_status == 0:
            logger.warning("Comando exitoso pero sin salida, intentando método alternativo")
            
            # Método alternativo que funciona bien para muchos comandos
            if ejecutar_tipo == "cmd":
                alt_cmd = f'cmd.exe /c "{comando} > %TEMP%\\output.txt 2>&1 && type %TEMP%\\output.txt"'
            else:
                alt_cmd = f'powershell.exe -NoProfile -Command "$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8; {comando} | Out-String -Width 9999 | Out-File -FilePath $env:TEMP\\output.txt; Get-Content -Path $env:TEMP\\output.txt"'
            
            _, stdout, stderr = ssh.exec_command(alt_cmd, timeout=timeout)
            alt_output = stdout.read().decode('utf-8', errors='replace').strip()
            alt_error = stderr.read().decode('utf-8', errors='replace').strip()
            
            if alt_output:
                output = alt_output
                logger.info(f"Método alternativo exitoso, capturados {len(output)} bytes")
            if alt_error:
                error = error or alt_error
        
    except socket.timeout:
        error = f"Timeout al conectar o ejecutar comando en {ip}"
        logger.error(error)
    except paramiko.AuthenticationException:
        error = f"Error de autenticación al conectar a {ip}"
        logger.error(error)
    except paramiko.SSHException as e:
        error = f"Error SSH en {ip}: {str(e)}"
        logger.error(error)
    except Exception as e:
        error = f"Error al ejecutar comando en {ip}: {str(e)}"
        logger.error(error)
    finally:
        try:
            ssh.close()
        except:
            pass
    
    return {
        "exito": success,
        "hostname": hostname,
        "salida": output,
        "error": error if error else None,
        "codigo_retorno": return_code
    }
# Método alternativo ultra simple - enfoque pragmático
def _ejecutar_ssh_ultra_simple(ip, comando, usuario, password, timeout):
    """
    Versión ultra simple que utiliza la redirección estándar
    """
    import paramiko
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    hostname = ip
    output = ""
    error = ""
    success = False
    
    try:
        # Conectar
        ssh.connect(ip, username=usuario, password=password, timeout=timeout)
        
        # Obtener hostname
        _, stdout, _ = ssh.exec_command("hostname")
        hostname = stdout.read().decode('utf-8', errors='replace').strip()
        
        # Ejecutar comando con redirección
        cmd = f"powershell.exe {comando} 2>&1"
        _, stdout, _ = ssh.exec_command(cmd, timeout=timeout)
        
        # Leer toda la salida (incluidos errores gracias a 2>&1)
        output = stdout.read().decode('utf-8', errors='replace').strip()
        
        # Verificar si hay salida
        if output:
            success = True
        else:
            # Si no hay salida, intentar de otra manera
            cmd2 = f"cmd.exe /c \"powershell.exe {comando}\""
            _, stdout, stderr = ssh.exec_command(cmd2, timeout=timeout)
            
            output = stdout.read().decode('utf-8', errors='replace').strip()
            error = stderr.read().decode('utf-8', errors='replace').strip()
            
            if output or not error:
                success = True
            
    except Exception as e:
        error = f"Error: {str(e)}"
    finally:
        ssh.close()
    
    return {
        "exito": success,
        "hostname": hostname,
        "salida": output,
        "error": error if error else None,
        "codigo_retorno": 0 if success else 1
    }

# Método que ejecuta múltiples pasos como lo harías manualmente
def _ejecutar_ssh_interactivo(ip, comando, usuario, password, timeout):
    """
    Simula exactamente los pasos manuales:
    1. SSH al equipo
    2. Lanzar powershell
    3. Ejecutar comando
    4. Capturar salida
    """
    import paramiko
    import time
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    hostname = ip
    output = ""
    error = ""
    success = False
    
    try:
        # 1. Conexión SSH
        ssh.connect(ip, username=usuario, password=password, timeout=timeout)
        
        # Obtener hostname
        _, stdout, _ = ssh.exec_command("hostname")
        hostname = stdout.read().decode('utf-8', errors='replace').strip()
        
        # 2. Abrir sesión interactiva
        channel = ssh.invoke_shell()
        channel.settimeout(timeout)
        
        # Esperar prompt inicial
        time.sleep(1)
        buffer = ""
        while channel.recv_ready():
            buffer += channel.recv(1024).decode('utf-8', errors='replace')
        
        # 3. Lanzar PowerShell
        channel.send("powershell\n")
        time.sleep(2)
        
        # Limpiar buffer
        buffer = ""
        while channel.recv_ready():
            buffer += channel.recv(1024).decode('utf-8', errors='replace')
        
        # 4. Enviar comando
        channel.send(f"{comando}\n")
        
        # 5. Esperar y capturar salida
        all_output = []
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode('utf-8', errors='replace')
                all_output.append(chunk)
                start_time = time.time()  # Resetear timer si hay datos
            else:
                time.sleep(0.1)
                # Si han pasado 2 segundos sin datos nuevos, consideramos que terminó
                if time.time() - start_time > 2:
                    break
        
        # Unir toda la salida
        output = "".join(all_output)

        import re

        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)
        
        # Intentar limpiar la salida - eliminar el comando y prompt
        lines = output.splitlines()
        clean_lines = []
        command_found = False
        skip_next = False
        
        for line in lines:
         # Saltar la línea del comando
            if not command_found and comando in line:
                command_found = True
                continue
            # Saltar líneas de prompt PowerShell
            if "PS " in line and ">" in line:
                continue
            clean_lines.append(line)
        
        output = "\n".join(clean_lines).strip()
        success = True
        
        # 6. Salir de PowerShell y de SSH
        channel.send("exit\n")
        time.sleep(0.5)
        channel.send("exit\n")
        
    except Exception as e:
        error = f"Error: {str(e)}"
    finally:
        ssh.close()
    
    return {
        "exito": success,
        "hostname": hostname,
        "salida": output,
        "error": error if error else None,
        "codigo_retorno": 0 if success else 1
    }


def _preparar_comando_powershell(comando: str) -> str:
    """
    Prepara un comando de PowerShell para asegurar que se capture la salida completa.
    """
    # Caso especial para comandos Chocolatey
    if comando.strip().startswith("choco"):
        # Para comandos Chocolatey, usar enfoque simplificado pero efectivo
        return f'(choco {comando.strip()[6:]}) 2>&1'
    
    # Para comandos tipo Get-Process o con formato tabular, asegurar formato completo
    elif "Get-Process" in comando and "Out-String" not in comando:
        return f"{comando} | Format-Table -AutoSize | Out-String -Width 8192"
    elif "|" in comando and "Select-Object" in comando and "Out-String" not in comando:
        return f"({comando}) | Format-Table -AutoSize | Out-String -Width 8192"
    # Para otros comandos ejecutables, asegurar captura de salida
    elif comando.strip().startswith(("npm", "git", "pip")) or ".exe" in comando:
        return f'$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8; {comando} | Out-String -Width 8192'
    return comando

@router.post("/aula_semaforo", response_model=ResultadoComandoAula)
async def ejecutar_comando_aula_semaforo(request: ComandoAulaRequest, background_tasks: BackgroundTasks):
    """
     Versión optimizada que ejecuta un comando en todos los equipos Windows de un aula con mejor
    gestión de concurrencia, timeouts y recursos.
    """
    try:
        inicio = time.time()
        
        # Solo permitimos SSH
        if request.metodo != ComandoMetodo.SSH:
            raise HTTPException(
                status_code=400, 
                detail="Solo se permite el método SSH"
            )
        
        # Obtener información del aula y sus equipos
        aula = await get_aula_equipos(request.aula_id)
        if not aula or not aula.get("equipos"):
            raise HTTPException(
                status_code=404, 
                detail=f"Aula con ID {request.aula_id} no encontrada o sin equipos"
            )
        
        equipos = aula.get("equipos", [])
        total_equipos = len(equipos)
        
        if total_equipos == 0:
            raise HTTPException(
                status_code=404, 
                detail=f"No hay equipos activos en el aula {request.aula_id}"
            )
        
        # Modificar el comando para asegurar que se capture la salida completa
        comando_modificado = _preparar_comando_powershell(request.comando)
        
        # Resultado inicial
        resultado_aula = ResultadoComandoAula(
            aula_id=request.aula_id,
            comando=comando_modificado,
            metodo="ssh",
            total_equipos=total_equipos,
            equipos_exitosos=0,
            resultados=[],
            tiempo_total=0
        )
        
        # *** CAMBIOS IMPORTANTES AQUÍ ***
        # 1. Limitamos la concurrencia a un valor más razonable y fijo
        # 2. Aumentamos los timeouts de conexión individual
        # 3. Añadimos mejor manejo de errores y retries
        
        # Crear semáforo para controlar la concurrencia - valor fijo más conservador
        max_concurrencia = 3  # Valor fijo conservador para evitar sobrecarga
        semaforo = asyncio.Semaphore(max_concurrencia)
        
        logger.info(f"Ejecutando comando en {total_equipos} equipos con concurrencia máxima de {max_concurrencia}")
        
        # Función que ejecuta un comando en un equipo con el semáforo y reintentos
        async def ejecutar_con_semaforo(equipo):
            async with semaforo:
                try:
                    ip = equipo.get("ip")
                    hostname = equipo.get("hostname", "Unknown")
                    logger.info(f"Ejecutando comando en {ip} ({hostname}) (semáforo activo)")
                    
                    # Timeout extendido para dar más tiempo a la operación
                    # pero nunca menor a 30 segundos para operaciones básicas
                    timeout = max(30, min(request.timeout, 60))
                    
                    # Implementación de reintentos
                    max_reintentos = 2
                    reintentos = 0
                    ultima_excepcion = None
                    
                    while reintentos <= max_reintentos:
                        try:
                            # Usar tu método ejecutar_comando_en_equipo que ya funciona para un solo equipo
                            resultado_comando = await ejecutar_comando_en_equipo(
                                ip,
                                comando_modificado,
                                "ssh",
                                request.usuario,
                                request.password,
                                timeout,
                                hostname
                            )
                            
                            logger.info(f"Comando completado en {ip}: {'exitoso' if resultado_comando.exito else 'fallido'}")
                            return resultado_comando
                        
                        except asyncio.TimeoutError as e:
                            reintentos += 1
                            ultima_excepcion = e
                            logger.warning(f"Timeout en {ip}, reintento {reintentos}/{max_reintentos}")
                            # Esperar un momento antes de reintentar (backoff exponencial)
                            await asyncio.sleep(2 ** reintentos)
                        
                        except Exception as e:
                            # Para otros errores, reintentar también
                            reintentos += 1
                            ultima_excepcion = e
                            logger.warning(f"Error en {ip}, reintento {reintentos}/{max_reintentos}: {str(e)}")
                            await asyncio.sleep(1)
                    
                    # Si llegamos aquí, es porque fallaron todos los reintentos
                    logger.error(f"Fallaron todos los reintentos en {ip}: {str(ultima_excepcion)}")
                    return ResultadoComando(
                        equipo_ip=ip,
                        equipo_hostname=hostname,
                        exito=False,
                        error=f"Fallaron todos los reintentos: {str(ultima_excepcion)}",
                        tiempo_ejecucion=time.time() - inicio
                    )
                    
                except Exception as e:
                    logger.error(f"Error crítico al ejecutar comando en {equipo.get('ip')}: {str(e)}")
                    return ResultadoComando(
                        equipo_ip=equipo.get("ip"),
                        equipo_hostname=equipo.get("hostname", "Unknown"),
                        exito=False,
                        error=str(e),
                        tiempo_ejecucion=time.time() - inicio
                    )
        
        # Dividir los equipos en grupos para procesarlos por lotes
        # Esto evita crear demasiadas tareas simultáneas que podrían agotar recursos
        tamaño_grupo = 10  # Procesar hasta 10 equipos a la vez
        todos_resultados = []
        
        for i in range(0, total_equipos, tamaño_grupo):
            grupo_actual = equipos[i:i+tamaño_grupo]
            logger.info(f"Procesando grupo {i//tamaño_grupo + 1}, equipos {i+1}-{min(i+tamaño_grupo, total_equipos)}")
            
            # Crear tareas solo para este grupo
            tareas_grupo = [ejecutar_con_semaforo(equipo) for equipo in grupo_actual]
            
            # Ejecutar todas las tareas del grupo y esperar resultados
            resultados_grupo = await asyncio.gather(*tareas_grupo)
            todos_resultados.extend(resultados_grupo)
            
            # Pequeña pausa entre grupos para permitir liberación de recursos
            await asyncio.sleep(0.5)
        
        # Procesar resultados
        for resultado in todos_resultados:
            if resultado.exito:
                resultado_aula.equipos_exitosos += 1
            resultado_aula.resultados.append(resultado)
        
        # Calcular tiempo total
        fin = time.time()
        resultado_aula.tiempo_total = fin - inicio
        
        # Registrar el resultado en la base de datos para referencia futura
        try:
            registro_comandos = {
                "aula_id": request.aula_id,
                "comando": comando_modificado,
                "metodo": "ssh",
                "total_equipos": total_equipos,
                "equipos_exitosos": resultado_aula.equipos_exitosos,
                "fecha_ejecucion": datetime.now(),
                "tiempo_total": resultado_aula.tiempo_total,
                "usuario": request.usuario  # Registrar qué usuario ejecutó el comando
            }
            # Crear una colección para los registros si no existe
            if 'comandos_historial' not in db.list_collection_names():
                db.create_collection('comandos_historial')
            db.comandos_historial.insert_one(registro_comandos)
        except Exception as e:
            logger.error(f"Error al registrar historial de comandos: {str(e)}")
        
        return resultado_aula
    
    except Exception as e:
        logger.error(f"Error al ejecutar comando en aula con semáforo {request.aula_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al ejecutar el comando: {str(e)}"
        )


# También necesitamos optimizar la función que ejecuta SSH
# Esta es una versión mejorada de _ejecutar_ssh_sync con mejor manejo de recursos y timeout
def _ejecutar_ssh_optimizado(ip, comando, usuario, password, timeout):
    """
    Implementación optimizada que maneja mejor los recursos y timeouts
    """
    import paramiko
    import socket
    import time
    
    # Configurar cliente SSH con valores de timeout específicos
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    hostname = ip  # Valor por defecto
    output = ""
    error = ""
    success = False
    return_code = 1
    
    try:
        # Conexión con timeout específico para cada fase
        connection_timeout = min(10, timeout / 4)  # Menor timeout para la conexión inicial
        
        logger.info(f"Conectando por SSH a {ip} (timeout: {connection_timeout}s)...")
        ssh.connect(
            ip,
            username=usuario,
            password=password,
            timeout=connection_timeout,  # Timeout más corto para conexión
            banner_timeout=connection_timeout,  # Timeout para recibir banner
            auth_timeout=connection_timeout,  # Timeout para autenticación
            allow_agent=False,
            look_for_keys=False
        )
        
        # Obtener hostname con un timeout pequeño
        try:
            _, stdout, _ = ssh.exec_command("hostname", timeout=5)
            hostname = stdout.read().decode('utf-8', errors='replace').strip()
            logger.info(f"Hostname obtenido: {hostname}")
        except Exception as e:
            logger.warning(f"No se pudo obtener hostname: {str(e)}")
            hostname = ip
        
        # Comando con timeout específico para ejecución
        logger.info(f"Ejecutando comando con PowerShell (timeout: {timeout}s): {comando}")
        
        # Configurar comando con mejor codificación y captura de salida
        cmd = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8; {comando} | Out-String -Width 8192"'
        
        # Crear canal con límite de tiempo específico
        channel = ssh.get_transport().open_session()
        channel.settimeout(timeout)
        
        # Ejecutar comando con mejor manejo del tiempo
        channel.exec_command(cmd)
        
        # Leer la salida usando buffers más grandes y con timeouts específicos
        stdout_data = b""
        stderr_data = b""
        
        # Usar select para manejar los canales de manera no bloqueante
        import select
        
        # Tiempo máximo para esperar resultados
        end_time = time.time() + timeout
        
        while time.time() < end_time:
            if channel.exit_status_ready():
                break
                
            # Esperar datos con timeout pequeño para no bloquear
            if channel.recv_ready():
                chunk = channel.recv(16384)  # Buffer más grande
                if chunk:
                    stdout_data += chunk
                else:
                    break
                    
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(16384)  # Buffer más grande
                if chunk:
                    stderr_data += chunk
                else:
                    break
                    
            # Pequeña pausa para no saturar CPU
            time.sleep(0.1)
        
        # Verificar si el canal ya tiene un código de salida
        if channel.exit_status_ready():
            exit_status = channel.recv_exit_status()
        else:
            # Forzar cierre después de timeout
            logger.warning(f"Comando en {ip} no completó a tiempo, forzando cierre")
            channel.close()
            exit_status = -1  # Indicar timeout
        
        # Verificar si hay datos y convertir a string
        if stdout_data:
            output = stdout_data.decode('utf-8', errors='replace').strip()
            logger.info(f"Salida capturada: {len(output)} bytes")
        else:
            logger.warning("No se recibió salida del comando")
            
        if stderr_data:
            error = stderr_data.decode('utf-8', errors='replace').strip()
            logger.warning(f"Error recibido: {error}")
        
        # Determinar éxito basado en código de salida y presencia de salida
        success = (exit_status == 0 or (exit_status == -1 and output))
        return_code = exit_status if exit_status != -1 else 1
        
        logger.info(f"Comando ejecutado con código de salida: {exit_status}")
        
    except socket.timeout:
        error = f"Timeout al conectar o ejecutar comando en {ip}"
        logger.error(error)
    except paramiko.AuthenticationException:
        error = f"Error de autenticación al conectar a {ip}"
        logger.error(error)
    except paramiko.SSHException as e:
        error = f"Error SSH en {ip}: {str(e)}"
        logger.error(error)
    except Exception as e:
        error = f"Error al ejecutar comando en {ip}: {str(e)}"
        logger.error(error)
    finally:
        # Asegurarse de cerrar la conexión SSH para liberar recursos
        try:
            ssh.close()
        except:
            pass
    
    return {
        "exito": success,
        "hostname": hostname,
        "salida": output,
        "error": error if error else None,
        "codigo_retorno": return_code
    }

@router.get("/estado_tarea/{task_id}", response_model=Dict[str, Any])
async def obtener_estado_tarea(task_id: str):
    """
    Obtiene el estado actual de una tarea de ejecución de comandos en aula.
    """
    try:
        # Buscar la tarea en la base de datos
        task_data = db.comandos_tareas.find_one({"task_id": task_id})
        
        if not task_data:
            logger.warning(f"No se encontró la tarea con ID {task_id}")
            raise HTTPException(
                status_code=404,
                detail=f"No se encontró la tarea con ID {task_id}"
            )
        
        # Convertir ObjectId a string para poder serializarlo
        if "_id" in task_data:
            task_data["_id"] = str(task_data["_id"])
        
        # Formatear resultados para evitar problemas de serialización
        if "resultados" in task_data:
            for resultado in task_data["resultados"]:
                # Asegurar que cualquier campo ObjectId se convierta a string
                for key, value in list(resultado.items()):
                    if isinstance(value, ObjectId):
                        resultado[key] = str(value)
        
        # Formatear fechas para serialización
        if "fecha_inicio" in task_data and isinstance(task_data["fecha_inicio"], datetime):
            task_data["fecha_inicio"] = task_data["fecha_inicio"].isoformat()
        
        if "fecha_fin" in task_data and isinstance(task_data["fecha_fin"], datetime):
            task_data["fecha_fin"] = task_data["fecha_fin"].isoformat()
        
        logger.info(f"Estado de tarea {task_id} recuperado correctamente: {task_data.get('estado')}")
        return task_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al obtener el estado de la tarea {task_id}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener el estado de la tarea"
        )

async def ejecutar_comando_aula_background(
    task_id: str,
    aula_id: str, 
    comando: str, 
    usuario: str, 
    password: str,
    timeout: int,
    equipos: List[Dict]
):
    """
    Función para ejecutar en segundo plano que procesa los equipos de un aula
    y actualiza el estado en la base de datos.
    """
    inicio = time.time()
    try:
        logger.info(f"Iniciando tarea {task_id} en segundo plano para aula {aula_id}")
        
        # Actualizar estado a "en_progreso"
        db.comandos_tareas.update_one(
            {"task_id": task_id},
            {"$set": {"estado": "en_progreso"}}
        )
        
        # Crear semáforo para controlar la concurrencia
        max_concurrencia = 3
        semaforo = asyncio.Semaphore(max_concurrencia)
        
        # Función que ejecuta un comando en un equipo con el semáforo
        async def ejecutar_con_semaforo(equipo):
            async with semaforo:
                try:
                    ip = equipo.get("ip")
                    hostname = equipo.get("hostname", "Unknown")
                    logger.info(f"Tarea {task_id}: Ejecutando comando en {ip} ({hostname})")
                    
                    # Timeout extendido pero razonable
                    comando_timeout = max(30, min(timeout, 60))
                    
                    # Implementación de reintentos
                    max_reintentos = 1
                    reintentos = 0
                    ultima_excepcion = None
                    
                    while reintentos <= max_reintentos:
                        try:
                            resultado_comando = await ejecutar_comando_en_equipo(
                                ip,
                                comando,
                                "ssh",
                                usuario,
                                password,
                                comando_timeout,
                                hostname
                            )
                            
                            # Actualizar en base de datos
                            db.comandos_tareas.update_one(
                                {"task_id": task_id},
                                {
                                    "$inc": {"equipos_completados": 1},
                                    "$push": {"resultados": {
                                        "equipo_ip": ip,
                                        "equipo_hostname": hostname,
                                        "exito": resultado_comando.exito,
                                        "salida": resultado_comando.salida,
                                        "error": resultado_comando.error,
                                        "codigo_retorno": resultado_comando.codigo_retorno,
                                        "tiempo_ejecucion": resultado_comando.tiempo_ejecucion
                                    }}
                                }
                            )
                            
                            logger.info(f"Tarea {task_id}: Comando completado en {ip}")
                            return resultado_comando
                        
                        except Exception as e:
                            reintentos += 1
                            ultima_excepcion = e
                            if reintentos <= max_reintentos:
                                logger.warning(f"Tarea {task_id}: Error en {ip}, reintento {reintentos}: {str(e)}")
                                await asyncio.sleep(1)
                            else:
                                # Registrar el error en la base de datos también
                                db.comandos_tareas.update_one(
                                    {"task_id": task_id},
                                    {
                                        "$inc": {"equipos_completados": 1},
                                        "$push": {"resultados": {
                                            "equipo_ip": ip,
                                           "equipo_hostname": equipo.get("hostname", "Unknown"),
                                            "exito": False,
                                            "error": str(e),
                                            "codigo_retorno": 1,
                                            "tiempo_ejecucion": time.time() - inicio
                                        }}
                                    }
                                )
                                logger.error(f"Tarea {task_id}: Error final en {ip}: {str(e)}")
                                return ResultadoComando(
                                    equipo_ip=ip,
                                    equipo_hostname=hostname,
                                    exito=False,
                                    error=str(e),
                                    codigo_retorno=1,
                                    tiempo_ejecucion=time.time() - inicio
                                )
                
                except Exception as e:
                    # Actualizar en base de datos incluso en caso de error
                    db.comandos_tareas.update_one(
                        {"task_id": task_id},
                        {
                            "$inc": {"equipos_completados": 1},
                            "$push": {"resultados": {
                                "equipo_ip": equipo.get("ip"),
                                "equipo_hostname": equipo.get("hostname", "Unknown"),
                                "exito": False,
                                "error": str(e),
                                "tiempo_ejecucion": time.time() - inicio
                            }}
                        }
                    )
                    logger.error(f"Tarea {task_id}: Error crítico en {equipo.get('ip')}: {str(e)}")
                    return ResultadoComando(
                        equipo_ip=equipo.get("ip"),
                        equipo_hostname=equipo.get("hostname", "Unknown"),
                        exito=False,
                        error=str(e),
                        tiempo_ejecucion=time.time() - inicio
                    )
        
        # Procesar equipos por lotes para un mejor rendimiento
        tamaño_grupo = 10
        todos_resultados = []
        
        for i in range(0, len(equipos), tamaño_grupo):
            grupo_actual = equipos[i:i+tamaño_grupo]
            logger.info(f"Tarea {task_id}: Procesando grupo {i//tamaño_grupo + 1}, equipos {i+1}-{min(i+tamaño_grupo, len(equipos))}")
            
            # Crear tareas solo para este grupo
            tareas_grupo = [ejecutar_con_semaforo(equipo) for equipo in grupo_actual]
            
            # Ejecutar todas las tareas del grupo y esperar resultados
            resultados_grupo = await asyncio.gather(*tareas_grupo)
            todos_resultados.extend(resultados_grupo)
            
            # Pequeña pausa entre grupos para permitir liberación de recursos
            await asyncio.sleep(0.5)
            
            # Actualizar progreso
            progress = min(100, int((len(todos_resultados) / len(equipos)) * 100))
            db.comandos_tareas.update_one(
                {"task_id": task_id},
                {"$set": {"progreso": progress}}
            )
        
        # Calcular estadísticas
        fin = time.time()
        tiempo_total = fin - inicio
        equipos_exitosos = sum(1 for r in todos_resultados if r.exito)
        
        # Actualizar el estado final en la base de datos
        db.comandos_tareas.update_one(
            {"task_id": task_id},
            {
                "$set": {
                    "estado": "completado",
                    "fecha_fin": datetime.now(),
                    "tiempo_total": tiempo_total,
                    "equipos_exitosos": equipos_exitosos,
                    "progreso": 100
                }
            }
        )
        
        logger.info(f"Tarea {task_id} completada: {equipos_exitosos} de {len(equipos)} equipos exitosos en {tiempo_total:.2f} segundos")
        
    except Exception as e:
        # En caso de error global, actualizar el estado a "error"
        db.comandos_tareas.update_one(
            {"task_id": task_id},
            {
                "$set": {
                    "estado": "error",
                    "error_global": str(e),
                    "fecha_fin": datetime.now(),
                    "tiempo_total": time.time() - inicio
                }
            }
        )
        logger.error(f"Error global en tarea {task_id}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

@router.post("/aula_async", response_model=Dict[str, Any])
async def iniciar_comando_aula_async(request: ComandoAulaRequest, background_tasks: BackgroundTasks):
    """
    Inicia la ejecución de un comando en un aula en segundo plano y devuelve un ID de tarea.
    Permite al cliente recibir resultados a medida que se completan.
    """
    try:
        # Solo permitimos SSH
        if request.metodo != ComandoMetodo.SSH:
            raise HTTPException(
                status_code=400, 
                detail="Solo se permite el método SSH"
            )
        
        # Obtener información del aula y sus equipos
        aula = await get_aula_equipos(request.aula_id)
        if not aula or not aula.get("equipos"):
            raise HTTPException(
                status_code=404, 
                detail=f"Aula con ID {request.aula_id} no encontrada o sin equipos"
            )
        
        equipos = aula.get("equipos", [])
        total_equipos = len(equipos)
        
        if total_equipos == 0:
            raise HTTPException(
                status_code=404, 
                detail=f"No hay equipos activos en el aula {request.aula_id}"
            )
        
        # Modificar el comando para asegurar que se capture la salida completa
        comando_modificado = _preparar_comando_powershell(request.comando)
        
        # Crear un ID de tarea único
        from uuid import uuid4
        task_id = str(uuid4())
        
        # Registrar la tarea en la base de datos
        task_data = {
            "task_id": task_id,
            "aula_id": request.aula_id,
            "comando": comando_modificado,
            "metodo": "ssh",
            "usuario": request.usuario,
            "fecha_inicio": datetime.now(),
            "total_equipos": total_equipos,
            "equipos_completados": 0,
            "progreso": 0,
            "estado": "iniciado",
            "resultados": []
        }
        
        # Crear colección para las tareas si no existe
        if 'comandos_tareas' not in db.list_collection_names():
            db.create_collection('comandos_tareas')
        
        db.comandos_tareas.insert_one(task_data)
        
        # Iniciar la tarea en segundo plano - USAR LA NUEVA FUNCIÓN
        background_tasks.add_task(
            ejecutar_comando_aula_background,  # Cambiar a la nueva función
            task_id=task_id,
            aula_id=request.aula_id,
            comando=comando_modificado,
            usuario=request.usuario,
            password=request.password,
            timeout=min(request.timeout, 500),
            equipos=equipos
        )
        
        return {
            "task_id": task_id,
            "aula_id": request.aula_id,
            "total_equipos": total_equipos,
            "estado": "iniciado",
            "mensaje": "Comando iniciado en segundo plano. Use el endpoint /estado_tarea/{task_id} para consultar el estado."
        }
    
    except Exception as e:
        logger.error(f"Error al iniciar comando asíncrono en aula {request.aula_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al iniciar el comando: {str(e)}"
        )