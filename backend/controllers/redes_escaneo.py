import nmap
import json  # Asegúrate de importar json

# Crear un escáner de Nmap
nm = nmap.PortScanner()

# Definir el rango de IPs que deseas escanear (ajusta según tu red)
ip_range = "192.168.56.0/16"

nm.scan(hosts=ip_range, arguments='-p 1-65535')  



# Obtener los datos escaneados y almacenarlos en una lista
network_data = []
for host in nm.all_hosts():
    data = {
        'ip': host,
        'hostname': nm[host].hostname(),
        'mac': nm[host]['addresses'].get('mac', 'no disponible'),
        'status': nm[host].state(),
    }
    network_data.append(data)

# Convertir los datos a JSON
print(json.dumps(network_data))

# Guardar los datos en un archivo JSON
with open("datosip.json", "w", encoding="utf-8") as archivo:
    json.dump(network_data, archivo, ensure_ascii=False, indent=4)

print("archivo json guardado")

# Si deseas imprimir los datos de 'mac' de todos los hosts
for host_data in network_data:
    print("Datos MAC para IP", host_data['ip'], ":", host_data['mac'])
