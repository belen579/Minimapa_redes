from fastapi import APIRouter, HTTPException
from typing import List
from pymongo import MongoClient
from models.models import Aula  # Asegúrate de tener este modelo definido
from bson import ObjectId

# Crear la instancia de APIRouter
router = APIRouter(
    prefix="/aulas",
    tags=["aulas"],
    responses={404: {"description": "No encontrado"}}
)

# Configuración MongoDB
MONGO_URI = 'mongodb://root:secret@mongo:27017/'
client = MongoClient(MONGO_URI)
db = client['devices']
aulas_collection = db['aulas']

def serialize_aula(aula):
    """Función auxiliar para serializar ObjectId y manejar campos específicos"""
    if '_id' in aula:
        aula['id'] = str(aula['_id'])
        del aula['_id']
    return aula

@router.post("/", response_model=dict)
async def crear_aula(aula: Aula):
    try:
        # Verificar si ya existe un aula con el mismo nombre
        if aulas_collection.find_one({"nombre_aula": aula.nombre_aula}):
            raise HTTPException(
                status_code=400,
                detail=f"Ya existe un aula con el nombre {aula.nombre_aula}"
            )
        
        # Insertar el aula en la base de datos
        aula_dict = aula.dict(exclude_unset=True)
        resultado = aulas_collection.insert_one(aula_dict)
        
        # Verificar que la inserción fue exitosa
        if not resultado.acknowledged:
            raise HTTPException(
                status_code=500,
                detail="No se pudo crear el aula en la base de datos"
            )

        # Devolver la respuesta exitosa
        return {
            "id": str(resultado.inserted_id),
            "mensaje": "Aula creada exitosamente",
            "aula": serialize_aula(aula_dict)
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al crear el aula: {str(e)}"
        )

@router.get("/", response_model=List[dict])  # Cambiado a List[dict] para manejar mejor la serialización
async def obtener_aulas():
    try:
        aulas = list(aulas_collection.find())
        return [serialize_aula(aula) for aula in aulas]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener aulas: {str(e)}")

@router.get("/{nombre_aula}", response_model=dict)  # Cambiado a dict para manejar mejor la serialización
async def obtener_aula(nombre_aula: str):
    try:
        aula = aulas_collection.find_one({"nombre_aula": nombre_aula})
        if aula:
            return serialize_aula(aula)
        raise HTTPException(status_code=404, detail=f"Aula {nombre_aula} no encontrada")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{nombre_aula}", response_model=dict)  # Cambiado a dict para manejar mejor la serialización
async def actualizar_aula(nombre_aula: str, aula_actualizada: Aula):
    try:
        aula_dict = aula_actualizada.dict(exclude_unset=True)
        resultado = aulas_collection.find_one_and_update(
            {"nombre_aula": nombre_aula},
            {"$set": aula_dict},
            return_document=True
        )
        if resultado:
            return serialize_aula(resultado)
        raise HTTPException(status_code=404, detail=f"Aula {nombre_aula} no encontrada")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{nombre_aula}")
async def eliminar_aula(nombre_aula: str):
    try:
        resultado = aulas_collection.delete_one({"nombre_aula": nombre_aula})
        if resultado.deleted_count:
            return {"mensaje": f"Aula {nombre_aula} eliminada exitosamente"}
        raise HTTPException(status_code=404, detail=f"Aula {nombre_aula} no encontrada")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))