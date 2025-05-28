from pydantic import BaseModel, Field
from typing import List
from datetime import datetime
from enum import Enum  
from typing import List, Dict, Optional, Any, Union 


class Equipo(BaseModel):
    ip: str
    hostname: str
    mac: str
    status: str
    aula_id: str            
    red: str = None
    dia: datetime          



class Aula(BaseModel):
    nombre_aula: str
    rango_ip: str
    equipos: List[Equipo]


class Device(BaseModel):
    hostname: str
    ip: str
    mac: str
    status: str
    aula: str
    scan_date: datetime


class ScanResponse(BaseModel):
    status: str
    message: str
    output: str


class Roseta(BaseModel):
    nombre: str
    estado: str  # Valores posibles: "Roto", "Sin Cable", etc.
    aula_id: str  # Relación con el aula

class Switch(BaseModel):
    nombre: str
    boca: str
    red: str
    roseta_id: str  # Relación con RosetaID por ID
    ubicacion:str


# Clases para los comandos
class ComandoMetodo(str, Enum):
    SSH = "ssh"
    TELNET = "telnet"
    HTTP = "http"
    WMI = "wmi"  # Para equipos Windows
    SNMP = "snmp"  # Para equipos de red


class ComandoRequest(BaseModel):
    """Petición para ejecutar un comando en un equipo o aula"""
    comando: str
    metodo: ComandoMetodo = ComandoMetodo.SSH
    usuario: str = "admin"
    password: str = "admin"
    timeout: int = 30  # segundos


class ComandoEquipoRequest(ComandoRequest):
    """Petición para ejecutar un comando en un equipo específico"""
    equipo_ip: str


class ComandoAulaRequest(ComandoRequest):
    """Petición para ejecutar un comando en todos los equipos de un aula"""
    aula_id: str
    paralelo: bool = True  # Si ejecutar en paralelo o secuencialmente


class ResultadoComando(BaseModel):
    """Resultado de un comando en un equipo"""
    equipo_ip: str
    equipo_hostname: Optional[str] = None
    exito: bool
    salida: Optional[str] = None
    error: Optional[str] = None
    codigo_retorno: Optional[int] = None
    tiempo_ejecucion: float  # en segundos


class ResultadoComandoAula(BaseModel):
    """Resultado de un comando en un aula completa"""
    aula_id: str
    comando: str
    metodo: str
    total_equipos: int
    equipos_exitosos: int
    resultados: List[ResultadoComando]
    tiempo_total: float  # en segundos


class ComandoProgramado(BaseModel):
    """Comando programado para ejecución futura"""
    id: Optional[str] = None
    comando: str
    metodo: ComandoMetodo
    usuario: str
    password: str
    destino_tipo: str  # "equipo" o "aula"
    destino_id: str  # IP del equipo o ID del aula
    programado_para: datetime
    recurrente: bool = False
    intervalo_horas: Optional[int] = None
    creado_en: datetime = Field(default_factory=datetime.now)
    ultima_ejecucion: Optional[datetime] = None
    proximo_ejecucion: Optional[datetime] = None
    estado: str = "pendiente"  # pendiente, ejecutando, completado, fallido


class ComandoTemplate(BaseModel):
    """Plantilla de comandos predefinidos"""
    id: Optional[str] = None
    nombre: str
    descripcion: str
    comando: str
    metodo: ComandoMetodo
    categoria: str  # diagnóstico, sistema, red, etc.
    creado_en: datetime = Field(default_factory=datetime.now)






    


    



