import sys
import logging
import uvicorn
from scanner import app, run_cron_scan
from fastapi import FastAPI

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Asegurarnos de que solo se registra una vez
# Ya que el router podría estar siendo registrado desde scanner.py también
router_added = False

# Importar y registrar el router de comandos
try:
    from comandocontroller import router as comando_router
    
    # Comprobar si el router ya está registrado en la aplicación
    for route in app.routes:
        if '/comandos/equipo' in route.path:
            logger.info("El router de comandos ya está registrado en la aplicación")
            router_added = True
            break
    
    # Si no está registrado, registrarlo ahora
    if not router_added:
        logger.info("Importando módulo de comandos Windows")
        app.include_router(comando_router)
        logger.info("Router de comandos Windows añadido correctamente")
        
        # Listar las rutas para verificar que se han añadido correctamente
        logger.info("Rutas disponibles después de añadir el router:")
        for route in app.routes:
            logger.info(f"  - {route.path}")
    
except Exception as cmd_error:
    logger.error(f"Error al importar controlador de comandos: {cmd_error}")
    import traceback
    logger.error(traceback.format_exc())


    




if __name__ == "__main__":
    # Detectar si estamos siendo ejecutados desde cron (con argumento --cron) o como servidor
    if len(sys.argv) > 1 and sys.argv[1] == "--cron":
        logger.info("Ejecutando en modo CRON")
        run_cron_scan()
        sys.exit(0)
    else:
        from scanner import NetworkScanner
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
        
        # Imprimir todas las rutas disponibles antes de iniciar el servidor
        logger.info("Rutas disponibles en la aplicación antes de iniciar:")
        for route in app.routes:
            logger.info(f"  - {route.method} {route.path}")
        
        # Iniciar uvicorn con la aplicación FastAPI
        uvicorn.run(app, host="0.0.0.0", port=8001)