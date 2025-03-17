db = db.getSiblingDB("network_scan");
db.createCollection("devices");
print("Base de datos y colección creadas");