
from fastapi import FastAPI
from pymongo import MongoClient
from controllers import aulacontroller, equipocontroller, rosetacontroller, switchcontroller




# Crear la instancia de FastAPI
app = FastAPI()

# Configuración de la conexión a MongoDB
MONGO_URI = "mongodb://root:secret@mongo:27017/"
DATABASE_NAME = "devices"

# Crear la conexión
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]

# Hacer la base de datos disponible para los routers
app.mongodb = db

# Incluir los routers
app.include_router(aulacontroller.router)
app.include_router(equipocontroller.router)
app.include_router(rosetacontroller.router)
app.include_router(switchcontroller.router)



@app.get("/")
async def root():
    return {"mensaje": "API de Gestión de Aulas"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


