from fastapi import APIRouter, HTTPException
from typing import List
from pymongo import MongoClient
from models.models import Switch  # Asegúrate de tener este modelo definido
from bson import ObjectId
from bson.errors import InvalidId

# Crear la instancia de APIRouter
router = APIRouter(
    prefix="/switches",
    tags=["switches"],
    responses={404: {"description": "No encontrado"}}
)



# Configuración MongoDB - Reutilizando la misma conexión
MONGO_URI = 'mongodb://root:secret@mongo:27017/'
client = MongoClient(MONGO_URI)
db = client['devices']
switches_collection = db['switches']  # Nueva colección para switches

def serialize_switch(switch):
    """Función auxiliar para serializar ObjectId y manejar campos específicos"""
    if '_id' in switch:
        switch['id'] = str(switch['_id'])
        del switch['_id']
    return switch

@router.post("/", response_model=dict)
async def crear_switch(switch: Switch):
    try:
        # Verificar si ya existe un switch con el mismo ID
        switch_id = f"{switch.nombre}{switch.boca}"
        if switches_collection.find_one({"id": switch_id}):
            raise HTTPException(
                status_code=400,
                detail=f"Ya existe un switch con el ID {switch_id}"
            )
        
        # Log para depuración
        print(f"Datos recibidos: {switch.dict()}")
            
        # Manejo de roseta_id
        roseta_object_id = None
        if switch.roseta_id:
            try:
                roseta_object_id = ObjectId(switch.roseta_id)
                roseta = db['rosetas'].find_one({"_id": roseta_object_id})
                
                if not roseta:
                    # Para debugging, veamos qué rosetas existen con su ObjectId
                    todas_rosetas = list(db['rosetas'].find({}, {"_id": 1, "nombre": 1}))
                    rosetas_disponibles = [f"{r.get('nombre', 'Sin nombre')}: {str(r.get('_id', ''))}" for r in todas_rosetas]
                    
                    raise HTTPException(
                        status_code=404,
                        detail=f"La roseta con ObjectId '{switch.roseta_id}' no existe. Rosetas disponibles: {rosetas_disponibles}"
                    )
            except InvalidId as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"El ID de roseta '{switch.roseta_id}' no es un ObjectId válido: {str(e)}"
                )
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Error al buscar la roseta: {str(e)}"
                )

        # Preparar el documento para inserción
        switch_dict = switch.dict(exclude_unset=True)
        switch_dict['id'] = switch_id  # Asignar el ID compuesto
        
        # Solo incluir roseta_id si es válido
        if roseta_object_id:
            switch_dict['roseta_id'] = str(roseta_object_id)
        else:
            # Asegurarse que roseta_id es None si no se proporcionó o no es válido
            switch_dict['roseta_id'] = None
            
        # Asegurarse de que el campo ubicacion esté presente
        if 'ubicacion' not in switch_dict or not switch_dict['ubicacion']:
            switch_dict['ubicacion'] = "No especificada"
            
        # Log para depuración    
        print(f"Documento a insertar: {switch_dict}")
        
        # Insertar el switch en la base de datos
        resultado = switches_collection.insert_one(switch_dict)
        
        # Verificar que la inserción fue exitosa
        if not resultado.acknowledged:
            raise HTTPException(
                status_code=500,
                detail="No se pudo crear el switch en la base de datos"
            )
            
        # Devolver la respuesta exitosa
        return {
            "_id": str(resultado.inserted_id),
            "mensaje": "Switch creado exitosamente",
            "switch": serialize_switch(switch_dict)
        }
    except HTTPException:
        raise
    except Exception as e:
        # Agregar más detalles al error
        import traceback
        error_details = traceback.format_exc()
        print(f"Error en crear_switch: {error_details}")
        
        raise HTTPException(
            status_code=500,
            detail=f"Error al crear el switch: {str(e)}"
        )

@router.get("/", response_model=List[dict])
async def obtener_switches():
    try:
        switches = list(switches_collection.find())
        return [serialize_switch(switch) for switch in switches]
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error al obtener switches: {str(e)}"
        )

@router.get("/{switch_id}", response_model=dict)
async def obtener_switch(switch_id: str):
    try:
        # Intentar buscar primero por ID compuesto
        switch = switches_collection.find_one({"id": switch_id})
        
        # Si no se encuentra, intentar buscar por ObjectId
        if not switch:
            try:
                switch_object_id = ObjectId(switch_id)
                switch = switches_collection.find_one({"_id": switch_object_id})
            except:
                pass  # Si no es un ObjectId válido, ignoramos y seguimos
                
        if switch:
            return serialize_switch(switch)
            
        raise HTTPException(
            status_code=404, 
            detail=f"Switch {switch_id} no encontrado"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=str(e)
        )

@router.get("/red/{red}", response_model=List[dict])
async def obtener_switches_por_red(red: str):
    try:
        switches = list(switches_collection.find({"red": red}))
        return [serialize_switch(switch) for switch in switches]
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error al obtener switches por red: {str(e)}"
        )

@router.get("/roseta/{roseta_id}", response_model=List[dict])
async def obtener_switches_por_roseta(roseta_id: str):
    try:
        switches = list(switches_collection.find({"roseta_id": roseta_id}))
        return [serialize_switch(switch) for switch in switches]
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error al obtener switches por roseta: {str(e)}"
        )

@router.put("/{switch_id}", response_model=dict)
async def actualizar_switch(switch_id: str, switch_actualizado: Switch):
    try:
        # Identificar si estamos buscando por ID compuesto o por ObjectId
        switch = None
        switch_object_id = None
        
        # Primero buscar por ID compuesto
        switch = switches_collection.find_one({"id": switch_id})
        
        # Si no se encuentra, intentar buscar por ObjectId
        if not switch:
            try:
                switch_object_id = ObjectId(switch_id)
                switch = switches_collection.find_one({"_id": switch_object_id})
                
                if not switch:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Switch con ID {switch_id} no encontrado"
                    )
            except InvalidId as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"ID de switch inválido: {switch_id}. Error: {str(e)}"
                )
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Error con el ID de switch: {switch_id}. Error: {str(e)}"
                )
        else:
            # Si se encontró por ID compuesto, obtener el ObjectId para la actualización
            switch_object_id = switch["_id"]
            
        # Preparar el documento para actualización
        switch_dict = switch_actualizado.dict(exclude_unset=True)
        
        # Asegurar que la roseta existe si se proporciona
        if 'roseta_id' in switch_dict and switch_dict['roseta_id']:
            try:
                roseta_object_id = ObjectId(switch_dict['roseta_id'])
                roseta = db['rosetas'].find_one({"_id": roseta_object_id})
                
                if not roseta:
                    raise HTTPException(
                        status_code=404,
                        detail=f"La roseta con ID '{switch_dict['roseta_id']}' no existe"
                    )
                
                # Convertir a string para almacenar
                switch_dict['roseta_id'] = str(roseta_object_id)
            except InvalidId as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"ID de roseta inválido: {switch_dict['roseta_id']}. Error: {str(e)}"
                )
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Error con el ID de roseta: {switch_dict['roseta_id']}. Error: {str(e)}"
                )
        elif 'roseta_id' in switch_dict:
            # Si roseta_id está presente pero es vacío, establecerlo a None
            switch_dict['roseta_id'] = None
        
        # Actualizar el switch en la base de datos por su _id
        resultado = switches_collection.find_one_and_update(
            {"_id": switch_object_id},
            {"$set": switch_dict},
            return_document=True
        )
        
        if resultado:
            return serialize_switch(resultado)
            
        raise HTTPException(
            status_code=404, 
            detail=f"Error al actualizar switch con ID {switch_id}"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error al actualizar el switch: {str(e)}"
        )

@router.delete("/{switch_id}")
async def eliminar_switch(switch_id: str):
    try:
        # Intentar primero buscar por ID compuesto
        resultado = switches_collection.delete_one({"id": switch_id})
        
        # Si no se eliminó, intentar buscar por ObjectId
        if resultado.deleted_count == 0:
            try:
                switch_object_id = ObjectId(switch_id)
                resultado = switches_collection.delete_one({"_id": switch_object_id})
            except Exception:
                pass  # Si no es un ObjectId válido, ignoramos y seguimos
        
        if resultado.deleted_count:
            return {"mensaje": f"Switch con ID {switch_id} eliminado exitosamente"}
        
        raise HTTPException(
            status_code=404, 
            detail=f"Switch con ID {switch_id} no encontrado"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error al eliminar el switch: {str(e)}"
        )