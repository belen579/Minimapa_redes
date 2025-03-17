from pydantic import BaseModel
from typing import List
from datetime import datetime



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






    


    



