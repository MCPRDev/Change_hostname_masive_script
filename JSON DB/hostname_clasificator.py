import json
import os

# Archivos en la misma carpeta del script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARCHIVO_ESTRUCTURA = os.path.join(BASE_DIR, "estructura.json")
ARCHIVO_INPUT = os.path.join(BASE_DIR, "hostnames.txt")
ARCHIVO_OUTPUT = os.path.join(BASE_DIR, "salida.json")

TIPOS_VALIDOS = ["PC", "LP"]

def cargar_estructura(path_estructura):
    with open(path_estructura, 'r', encoding='utf-8') as f:
        return json.load(f)

def guardar_salida(data, path_salida):
    with open(path_salida, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def extraer_puesto(nombre_restante, puestos_disponibles):
    for puesto in puestos_disponibles:
        if nombre_restante.startswith(puesto):
            return puesto
    return "Desconocido"

def extraer_tipo(nombre):
    for tipo in TIPOS_VALIDOS:
        if nombre.endswith(tipo):
            return tipo
    return "Desconocido"

def clasificar_nomenclaturas(path_input, estructura):
    with open(path_input, 'r', encoding='utf-16') as f:
        lineas = [line.strip() for line in f if line.strip()]

    hostnames = estructura.get("Hostname_existentes", {})

    for nombre in lineas:
        # Excluir nombres con guiones
        if '-' in nombre or '_' in nombre:
            continue

        if len(nombre) < 6:
            continue  # Muy corto

        lugar = nombre[:3]
        restante = nombre[3:]
        tipo = extraer_tipo(nombre)

        if lugar in hostnames:
            puestos_disponibles = hostnames[lugar].keys()
            puesto = extraer_puesto(restante, puestos_disponibles)
        else:
            lugar = "Desconocido"
            puesto = "Desconocido"

        if lugar != "Desconocido" and puesto not in hostnames[lugar]:
            puesto = "Desconocido"

        if lugar not in hostnames:
            hostnames[lugar] = {}
        if puesto not in hostnames[lugar]:
            hostnames[lugar][puesto] = {"PC": [], "LP": [], "Desconocido": []}
        if tipo not in hostnames[lugar][puesto]:
            hostnames[lugar][puesto][tipo] = []

        if nombre not in hostnames[lugar][puesto][tipo]:
            hostnames[lugar][puesto][tipo].append(nombre)

    estructura["Hostname_existentes"] = hostnames
    return estructura

if __name__ == "__main__":
    try:
        estructura_base = cargar_estructura(ARCHIVO_ESTRUCTURA)
        resultado = clasificar_nomenclaturas(ARCHIVO_INPUT, estructura_base)
        guardar_salida(resultado, ARCHIVO_OUTPUT)
        print("✅ Clasificación completada correctamente.")
    except Exception as e:
        print(f"❌ Error: {e}")
