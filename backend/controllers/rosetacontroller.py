from fastapi import APIRouter, HTTPException
from typing import List
from pymongo import MongoClient
from models.models import Roseta  # Modelo actualizado sin campo lugar
from bson import ObjectId

# Crear la instancia de APIRouter
router = APIRouter(
    prefix="/rosetas",
    tags=["rosetas"],
    responses={404: {"description": "No encontrado"}}
)

# Configuración MongoDB
MONGO_URI = 'mongodb://root:secret@mongo:27017/'
client = MongoClient(MONGO_URI)
db = client['devices']
rosetas_collection = db['rosetas']

def serialize_roseta(roseta):
    """Función auxiliar para serializar ObjectId y manejar campos específicos"""
    if '_id' in roseta:
        roseta['id'] = str(roseta['_id'])
        del roseta['_id']
    return roseta

@router.post("/", response_model=dict)
async def crear_roseta(roseta: Roseta):
    try:
        # Verificar si ya existe una roseta con el mismo nombre en la misma aula
        roseta_id = f"{roseta.aula_id}_{roseta.nombre}"
        
        if rosetas_collection.find_one({"id": roseta_id}):
            raise HTTPException(
                status_code=400,
                detail=f"Ya existe una roseta con el ID {roseta_id}"
            )
        
        # Asegurar que el aula existe por su ObjectId
        try:
            aula_object_id = ObjectId(roseta.aula_id)
            aula = db['aulas'].find_one({"_id": aula_object_id})
            
            if not aula:
                # Para debugging, veamos qué aulas existen
                todas_aulas = list(db['aulas'].find({}, {"_id": 1, "nombre_aula": 1}))
                aulas_disponibles = [f"{a.get('nombre_aula', 'Sin nombre')}: {str(a.get('_id', ''))}" for a in todas_aulas]
                
                raise HTTPException(
                    status_code=404,
                    detail=f"El aula con ID '{roseta.aula_id}' no existe. Aulas disponibles: {aulas_disponibles}"
                )
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"ID de aula inválido: {roseta.aula_id}. Error: {str(e)}"
            )
        
        # Preparar el documento para inserción
        roseta_dict = roseta.dict(exclude_unset=True)
        roseta_dict['id'] = roseta_id  # Asignar el ID compuesto
        
        # Insertar la roseta en la base de datos
        resultado = rosetas_collection.insert_one(roseta_dict)
        
        # Verificar que la inserción fue exitosa
        if not resultado.acknowledged:
            raise HTTPException(
                status_code=500,
                detail="No se pudo crear la roseta en la base de datos"
            )
        
        # Devolver la respuesta exitosa
        return {
            "_id": str(resultado.inserted_id),
            "mensaje": "Roseta creada exitosamente",
            "roseta": serialize_roseta(roseta_dict)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al crear la roseta: {str(e)}"
        )

@router.get("/", response_model=List[dict])
async def obtener_rosetas():
    try:
        rosetas = list(rosetas_collection.find())
        return [serialize_roseta(roseta) for roseta in rosetas]
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error al obtener rosetas: {str(e)}"
        )

@router.get("/{roseta_id}", response_model=dict)
async def obtener_roseta(roseta_id: str):
    try:
        # Convertir el roseta_id en un ObjectId de MongoDB si es necesario
        # Si el ID en la base de datos es un ObjectId y el roseta_id es una cadena, lo convertimos
        try:
            object_id = ObjectId(roseta_id)  # Intentamos convertir a ObjectId
        except Exception:
            raise HTTPException(
                status_code=400, 
                detail=f"El ID proporcionado no es válido: {roseta_id}"
            )

        # Buscar la roseta en la colección usando ObjectId
        roseta = rosetas_collection.find_one({"_id": object_id})

        # Si no se encuentra la roseta, lanzar un error 404
        if not roseta:
            raise HTTPException(
                status_code=404, 
                detail=f"Roseta con ID {roseta_id} no encontrada"
            )

        # Serialización de la roseta
        return serialize_roseta(roseta)

    except PyMongoError as e:
        # Error de la base de datos
        raise HTTPException(
            status_code=500, 
            detail=f"Error en la base de datos: {str(e)}"
        )
    except Exception as e:
        # Excepción genérica
        raise HTTPException(
            status_code=500, 
            detail=f"Ocurrió un error inesperado: {str(e)}"
        )

@router.get("/aula/{aula_id}", response_model=List[dict])
async def obtener_rosetas_por_aula(aula_id: str):
    try:
        rosetas = list(rosetas_collection.find({"aula_id": aula_id}))
        return [serialize_roseta(roseta) for roseta in rosetas]
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error al obtener rosetas por aula: {str(e)}"
        )

@router.get("/estado/{estado}", response_model=List[dict])
async def obtener_rosetas_por_estado(estado: str):
    try:
        rosetas = list(rosetas_collection.find({"estado": estado}))
        return [serialize_roseta(roseta) for roseta in rosetas]
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error al obtener rosetas por estado: {str(e)}"
        )

from bson import ObjectId

@router.put("/{roseta_id}", response_model=dict)
async def actualizar_roseta(roseta_id: str, roseta_actualizada: Roseta):
    try:
        # Preparar el documento para actualización
        roseta_dict = roseta_actualizada.dict(exclude_unset=True)
        
        # Convertir roseta_id a ObjectId
        try:
            object_id = ObjectId(roseta_id)
        except:
            raise HTTPException(
                status_code=400, 
                detail="ID de roseta inválido"
            )
        
        # Buscar y actualizar por _id como ObjectId
        resultado = rosetas_collection.find_one_and_update(
            {"_id": object_id},
            {"$set": roseta_dict},
            return_document=True
        )
        
        if resultado:
            return serialize_roseta(resultado)
        
        raise HTTPException(
            status_code=404, 
            detail=f"Roseta {roseta_id} no encontrada"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=str(e)
        )
@router.delete("/{roseta_id}", response_model=dict)
async def eliminar_roseta(roseta_id: str):
    try:
        # Convertir roseta_id a ObjectId
        try:
            object_id = ObjectId(roseta_id)
        except:
            raise HTTPException(
                status_code=400,
                detail="ID de roseta inválido"
            )
        
        # Buscar y eliminar por _id como ObjectId
        resultado = rosetas_collection.find_one_and_delete(
            {"_id": object_id}
        )
        
        if resultado:
            return {"mensaje": f"Roseta {roseta_id} eliminada exitosamente"}
        
        raise HTTPException(
            status_code=404,
            detail=f"Roseta {roseta_id} no encontrada"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )