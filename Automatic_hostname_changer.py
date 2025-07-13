import sys
import os
import json
import re
import socket
import logging
import subprocess
import ctypes
import time
import win32security
import win32con
import random
from datetime import datetime
from ldap3 import Server, Connection, ALL, SIMPLE

# Configuración global - AJUSTAR ESTOS VALORES!
CONFIG = {
    "SHARED_FOLDER": r"\\ip\carpeta\carpeta",  # Cambiar IP/ruta real
    "CREDENCIALES": {
        "username": r".\Administrator",  # Usuario local
        "password": "PasswordSegura",   # Contraseña local
    },
    "DOMINIO_CORPORATIVO": "dominio.corp"
}

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Configuración de logging
def setup_logging(hostname_actual):
    logger = logging.getLogger('hostname_manager')
    logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Handler local (siempre activo)
    local_log_path = f"C:\\Log_cambio_hostname_{datetime.now().strftime('%Y%m%d')}_{hostname_actual}.txt"
    file_handler = logging.FileHandler(local_log_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

def setup_shared_logging(logger, hostname_actual):
    """Configura logging para carpeta compartida (en subdirectorio logs)"""
    try:
        # Crear subdirectorio 'logs' si no existe
        log_dir = os.path.join(CONFIG["SHARED_FOLDER"], "logs")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            logger.info(f"Directorio de logs creado: {log_dir}")
        
        # Construir ruta del archivo de log compartido
        filename = f"Log_cambio_hostname_{datetime.now().strftime('%Y%m%d')}_{hostname_actual}.txt"
        shared_log_path = os.path.join(log_dir, filename)
        
        # Configurar handler para shared log
        shared_handler = logging.FileHandler(shared_log_path)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        shared_handler.setFormatter(formatter)
        logger.addHandler(shared_handler)
        logger.info(f"Log compartido configurado: {shared_log_path}")
        return True
    except Exception as e:
        logger.error(f"FALLO CRÍTICO: No se puede escribir en carpeta compartida: {str(e)}")
        return False

def conectar_carpeta_compartida(logger):
    """Conecta a carpeta compartida usando net use (compatible con cuentas locales)"""
    try:
        # Limpiar conexiones previas
        logger.info("Limpiando conexiones previas...")
        subprocess.run('net use * /delete /y', shell=True, capture_output=True, text=True)
        
        # Comando de conexión
        comando = (
            f'net use "{CONFIG["SHARED_FOLDER"]}" '
            f'/user:{CONFIG["CREDENCIALES"]["username"]} '
            f'"{CONFIG["CREDENCIALES"]["password"]}"'
        )
        
        logger.info(f"Conectando a carpeta compartida....")
        resultado = subprocess.run(
            comando,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if resultado.returncode == 0:
            logger.info("Conexión exitosa a carpeta compartida")
            return True
        else:
            logger.error(f"Error de conexión: {resultado.stderr.strip()}")
            return False
    except Exception as e:
        logger.error(f"Excepción en conexión: {str(e)}")
        return False

def cargar_json_hostnames(logger):
    json_path = os.path.join(CONFIG["SHARED_FOLDER"], "hostnames.json")
    json_local = "C:\\hostnames_backup.json"
    
    try:
        # Intentar cargar desde recurso compartido
        with open(json_path, 'r', encoding='utf-8') as f:
            logger.info("JSON cargado desde carpeta compartida")
            return json.load(f)
    except Exception as e:
        logger.warning(f"No se pudo cargar JSON compartido: {str(e)}")
        try:
            # Fallback a copia local
            if os.path.exists(json_local):
                with open(json_local, 'r', encoding='utf-8') as f:
                    logger.info("JSON cargado desde copia local")
                    return json.load(f)
        except:
            pass
    
    logger.warning("Usando estructura JSON vacía")
    return {"Hostname_existentes": {}}

def guardar_json_hostnames(data, logger):
    json_path = os.path.join(CONFIG["SHARED_FOLDER"], "hostnames.json")
    json_local = "C:\\hostnames_backup.json"
    
    try:
        # Guardar en recurso compartido
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info("JSON guardado en carpeta compartida")
    except Exception as e:
        logger.error(f"No se pudo guardar en compartido: {str(e)}")
    
    try:
        # Guardar copia local siempre
        with open(json_local, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info("JSON guardado en copia local")
    except Exception as e:
        logger.error(f"No se pudo guardar copia local: {str(e)}")

def obtener_tipo_dispositivo(logger):
    try:
        # Método 1: Modelo del sistema
        output = subprocess.check_output(
            'wmic computersystem get model /value',
            shell=True,
            text=True
        ).lower()
        
        # Patrones de laptop
        if any(p in output for p in ['laptop', 'notebook', 'portátil', 'ultrabook']):
            return "LP"

        # Método 2: Batería
        bateria = subprocess.check_output(
            'wmic path Win32_Battery get DeviceID',
            shell=True,
            text=True
        ).strip()  # Elimina espacios en blanco y saltos de línea
        
        # Si la batería está vacía o no hay instancias, es una PC
        if not bateria or "No Instance(s) Available" in bateria:
            return "PC"
        return "LP"  # Si hay contenido en bateria, es una laptop
    except Exception as e:
        logger.warning(f"Error detectando tipo: {str(e)} - Usando PC por defecto")
        return "PC"  # En caso de error, asumimos que es una PC

def extraer_componentes_hostname(hostname, logger):
    """
    Extrae componentes con nuevo patrón:
    - Lugar: primeros 3 caracteres (pueden ser letras o números)
    - Puesto: siguientes 3-6 caracteres (letras o números)
    - Número: 2 dígitos al final (antes del tipo de dispositivo)
    """
    # Intento 1: Usar expresión regular mejorada
    match = re.match(r"^([A-Za-z0-9]{3})([A-Za-z0-9]{3,6})(\d{2})", hostname)
    if match:
        lugar = match.group(1).upper()
        puesto = match.group(2).upper()
        numero = match.group(3)
        logger.info(f"Componentes extraídos (regex): Lugar={lugar}, Puesto={puesto}, Número={numero}")
        return lugar, puesto, numero
    
    # Intento 2: Búsqueda adaptativa si falla el regex
    lugar = None
    puesto = None
    numero = None
    
    # Lugar: primeros 3 caracteres
    if len(hostname) >= 3:
        lugar = hostname[:3].upper()
        restante = hostname[3:]
    
    # Puesto: 3-6 caracteres siguientes
    if lugar and len(restante) >= 3:
        # Probar desde 6 hasta 3 caracteres
        for length in range(6, 2, -1):
            if len(restante) >= length:
                candidato = restante[:length]
                # Verificar si los siguientes caracteres son números (indicador de número de dispositivo)
                if len(restante) > length and restante[length:length+2].isdigit():
                    puesto = candidato.upper()
                    restante = restante[length:]
                    break
    
    # Número: 2 dígitos al final
    if restante and len(restante) >= 2 and restante[:2].isdigit():
        numero = restante[:2]
    
    logger.info(f"Componentes extraídos (adaptativo): Lugar={lugar}, Puesto={puesto}, Número={numero}")
    return lugar, puesto, numero

def verificar_hostname_correcto(hostname_actual, hostnames_data, tipo, logger):
    """
    Verifica si el hostname actual es correcto según el JSON
    Retorna True si es válido, False en caso contrario
    """
    try:
        # Extraer componentes del hostname actual
        lugar, puesto, numero = extraer_componentes_hostname(hostname_actual, logger)
        
        if not lugar or not puesto or not numero:
            logger.warning("Hostname actual no cumple con el formato esperado")
            return False
            
        # Construir hostname esperado (sin número final)
        base_hostname = f"{lugar}{puesto}"
        
        # Verificar si el lugar existe en el JSON
        if lugar not in hostnames_data["Hostname_existentes"]:
            logger.warning(f"Lugar '{lugar}' no existe en JSON")
            return False
            
        # Verificar si el puesto existe en ese lugar
        if puesto not in hostnames_data["Hostname_existentes"][lugar]:
            logger.warning(f"Puesto '{puesto}' no existe en lugar '{lugar}'")
            return False
            
        # Buscar el hostname en todas las categorías del puesto
        categorias = hostnames_data["Hostname_existentes"][lugar][puesto]
        encontrado = False
        
        for categoria, hostnames in categorias.items():
            if hostname_actual in hostnames:
                encontrado = True
                # Verificar si está en la categoría correcta
                if categoria == tipo:
                    logger.info(f"Hostname encontrado en categoría correcta ({tipo})")
                    return True
                else:
                    logger.warning(f"Hostname encontrado en categoría incorrecta ({categoria} en lugar de {tipo})")
                    return False
                    
        if not encontrado:
            logger.warning("Hostname actual no encontrado en el JSON")
            return False
            
    except Exception as e:
        logger.error(f"Error verificando hostname: {str(e)}")
        return False

def encontrar_numero_disponible(lugar, puesto, tipo, hostnames_data, logger):
    """
    Encuentra el primer número disponible SOLO para el tipo específico (PC/LP)
    """
    try:
        # Verificar existencia de lugar y puesto
        lugares = hostnames_data.get("Hostname_existentes", {})
        if lugar not in lugares:
            logger.error(f"Lugar '{lugar}' no existe en JSON")
            return None
        
        puestos = lugares[lugar]
        if puesto not in puestos:
            logger.error(f"Puesto '{puesto}' no existe en lugar '{lugar}'")
            return None
        
        # Obtener números ocupados SOLO para el tipo específico
        numeros_ocupados = set()
        categorias = puestos[puesto]
        
        # Solo considerar la categoría específica (PC o LP)
        if tipo in categorias:
            for host in categorias[tipo]:
                # Verificar que el host comience con lugar+puesto
                if host.startswith(lugar + puesto):
                    # Extraer número (2 dígitos después de lugar+puesto)
                    resto = host[len(lugar) + len(puesto):]
                    match = re.match(r"(\d{2})", resto)
                    if match:
                        try:
                            numeros_ocupados.add(int(match.group(1)))
                        except ValueError:
                            continue
        
        # Buscar número disponible (1-99)
        for num in range(1, 100):
            if num not in numeros_ocupados:
                return f"{num:02d}"
        
        return None
    except Exception as e:
        logger.error(f"Error buscando número: {str(e)}")
        return None

# Función mejorada para validar credenciales
def validar_credenciales_ad(username, password, domain, logger):
    try:
        token = win32security.LogonUser(
            username,
            domain,
            password,
            win32con.LOGON32_LOGON_NETWORK,  # No inicia sesión interactiva
            win32con.LOGON32_PROVIDER_DEFAULT
        )
        token.Close()  # Cerrar el token
        logger.info("Credenciales válidas")
        return True
    except Exception as e:
        logger.error(f"Credenciales inválidas o error: {str(e)}")
        return False

# Función mejorada para verificar hostname en AD usando ldap3
def verificar_hostname_en_ad(hostname, username, password, domain_controller, logger):
    try:
        correct_username = username + "@dominio.corp" # Se corrige el username para SIMPLE 
        # Crear conexión al controlador de dominio
        server = Server(domain_controller, get_info=ALL)
        conn = Connection(
            server,
            user=correct_username,
            password=password,
            authentication=SIMPLE,
            auto_bind=True
        )

        # Obtener automáticamente el search_base
        search_base = conn.server.info.other['defaultNamingContext'][0]

        # Formato de sAMAccountName: "hostname$"
        search_filter = f'(&(objectClass=computer)(sAMAccountName={hostname}$))'

        # Ejecutar búsqueda
        conn.search(search_base, search_filter, attributes=['sAMAccountName'])

        if conn.entries:
            logger.info(f"Hostname {hostname} existe en Active Directory")
            conn.unbind()
            return False
        else:
            logger.info(f"Hostname {hostname} no encontrado en Active Directory")
            conn.unbind()
            return True

    except Exception as e:
        logger.error(f"Error verificando hostname en AD: {str(e)}")
        return False

# Función cambiar_hostname corregida con tiempo de espera aumentado
def cambiar_hostname(nuevo_hostname, domain_user, domain_password, logger):
    try:
        # Validar credenciales primero
        if not validar_credenciales_ad(domain_user, domain_password, 'ni' ,logger):
            logger.error("Credenciales inválidas, abortando cambio de hostname")
            return False

        comando_ps = (
            f"$securePass = ConvertTo-SecureString '{domain_password}' -AsPlainText -Force; "
            f"$cred = New-Object System.Management.Automation.PSCredential('{domain_user}', $securePass); "
            f"Rename-Computer -NewName '{nuevo_hostname}' -DomainCredential $cred -Force -ErrorAction Stop"
        )
        
        resultado = subprocess.run(
            ["powershell.exe", "-Command", comando_ps],
            capture_output=True,
            text=True,
            shell=True,
            timeout=60
        )
        
        if resultado.returncode == 0:
            logger.info(f"Comando rename ejecutado exitosamente para {nuevo_hostname}")
            
            # Aumentar tiempo de espera para propagación en AD
            logger.info("Esperando 360 segundos para propagación en AD...")
            time.sleep(360)
            
            # Verificar en AD después del cambio
            if not verificar_hostname_en_ad(nuevo_hostname, domain_user, domain_password, CONFIG["DOMINIO_CORPORATIVO"] ,logger):
                return True
            logger.error("El cambio no se reflejó en Active Directory")
            return False
        else:
            logger.error(f"Error en PowerShell: {resultado.stderr.strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("Timeout: PowerShell no respondió")
        return False
    except Exception as e:
        logger.error(f"Excepción no controlada: {str(e)}")
        return False

# --- NUEVAS FUNCIONES PARA GESTIÓN DE RESERVAS ---
def reservar_hostname_en_json(hostnames_data, nuevo_hostname, tipo, logger):
    """
    Agrega el nuevo_hostname al JSON sin eliminar el antiguo (reserva).
    """
    try:
        # Extraer componentes del nuevo hostname
        lugar, puesto, _ = extraer_componentes_hostname(nuevo_hostname, logger)
        
        if not lugar or not puesto:
            logger.error("No se pueden determinar componentes para nuevo hostname")
            return hostnames_data
        
        # Crear estructura si no existe
        if lugar not in hostnames_data["Hostname_existentes"]:
            hostnames_data["Hostname_existentes"][lugar] = {}
        if puesto not in hostnames_data["Hostname_existentes"][lugar]:
            hostnames_data["Hostname_existentes"][lugar][puesto] = {
                "PC": [], "LP": [], "Desconocido": []
            }
        
        # Determinar categoría
        cat = tipo if tipo in ["PC", "LP"] else "Desconocido"
        
        # Agregar hostname (reserva)
        if nuevo_hostname not in hostnames_data["Hostname_existentes"][lugar][puesto][cat]:
            hostnames_data["Hostname_existentes"][lugar][puesto][cat].append(nuevo_hostname)
            logger.info(f"Hostname reservado en JSON: {lugar}/{puesto}/{cat}")
        else:
            logger.warning(f"Hostname ya estaba reservado en JSON")
        
        return hostnames_data
    except Exception as e:
        logger.error(f"Error reservando hostname: {str(e)}")
        return hostnames_data

def liberar_hostname_en_json(hostnames_data, hostname_a_liberar, logger):
    """
    Elimina un hostname del JSON (libera reserva).
    """
    try:
        eliminado = False
        for lugar in list(hostnames_data["Hostname_existentes"].keys()):
            for puesto in list(hostnames_data["Hostname_existentes"][lugar].keys()):
                for cat in ["PC", "LP", "Desconocido"]:
                    if cat in hostnames_data["Hostname_existentes"][lugar][puesto]:
                        lista = hostnames_data["Hostname_existentes"][lugar][puesto][cat]
                        if hostname_a_liberar in lista:
                            lista.remove(hostname_a_liberar)
                            eliminado = True
                            logger.info(f"Reserva liberada: {lugar}/{puesto}/{cat}")
        
        if not eliminado:
            logger.warning("Hostname no encontrado en JSON para liberar")
        
        return hostnames_data
    except Exception as e:
        logger.error(f"Error liberando hostname: {str(e)}")
        return hostnames_data

def actualizar_json_remover_antiguo(hostnames_data, hostname_antiguo, logger):
    """
    Elimina el hostname antiguo del JSON después de un cambio exitoso.
    """
    try:
        eliminado = False
        for lugar in list(hostnames_data["Hostname_existentes"].keys()):
            for puesto in list(hostnames_data["Hostname_existentes"][lugar].keys()):
                for cat in ["PC", "LP", "Desconocido"]:
                    if cat in hostnames_data["Hostname_existentes"][lugar][puesto]:
                        lista = hostnames_data["Hostname_existentes"][lugar][puesto][cat]
                        if hostname_antiguo in lista:
                            lista.remove(hostname_antiguo)
                            eliminado = True
                            logger.info(f"Hostname antiguo eliminado: {lugar}/{puesto}/{cat}")
        
        if not eliminado:
            logger.warning("Hostname antiguo no encontrado en JSON")
        
        return hostnames_data
    except Exception as e:
        logger.error(f"Error eliminando hostname antiguo: {str(e)}")
        return hostnames_data
# --- FIN DE NUEVAS FUNCIONES ---

def verificar_dominio():
    try:
        dominio_completo = socket.getfqdn()
        if '.' in dominio_completo:
            dominio = dominio_completo.split('.', 1)[1]
            return dominio.lower() == CONFIG["DOMINIO_CORPORATIVO"].lower()
        return False
    except:
        return False

def main():
    # Códigos de salida personalizados
    EXIT_SUCCESS = 0
    EXIT_GENERAL_ERROR = 1
    EXIT_SHARED_FOLDER_FAIL = 2
    EXIT_DOMAIN_FAIL = 3
    EXIT_HOSTNAME_COMPONENTS_FAIL = 4
    EXIT_NO_AVAILABLE_NUMBER = 5
    EXIT_CREDENTIALS_OR_CHANGE_FAIL = 6
    EXIT_NO_ADMIN_PERMISSION = 7
    EXIT_NO_HOSTNAME = 8
    EXIT_HOSTNAME_CORRECTO = 9
    EXIT_HOSTNAME_DUPLICADO = 10
    EXIT_INVALID_CREDENTIALS = 11
    EXIT_AD_VERIFICATION_FAIL = 12 

    if not is_admin():
        return EXIT_NO_ADMIN_PERMISSION
    
    # Obtener hostname actual
    hostname_actual = socket.gethostname().upper()
    try:
        # Configurar logging local
        logger = setup_logging(hostname_actual)
        logger.info(f"==== INICIO DE PROCESO - {hostname_actual} ====")
    except Exception as e:
        logger.error("FALLO CRÍTICO: No se obtuvo los permisos para crear el log en C:\\. Abortando.")
        return EXIT_NO_ADMIN_PERMISSION
    
    # ===== DESINCRONIZACIÓN INICIAL =====
    # Espera aleatoria entre 0 y 300 segundos (5 minutos)
    espera_inicial = random.uniform(0, 300)
    logger.info(f"Espera inicial aleatoria: {espera_inicial:.2f} segundos")
    time.sleep(espera_inicial)
    # ===================================
    
    try:
        # Paso 1: Conectar a carpeta compartida (CRÍTICO)
        if not conectar_carpeta_compartida(logger):
            logger.error("FALLO CRÍTICO: No se pudo conectar a carpeta compartida. Abortando.")
            return EXIT_SHARED_FOLDER_FAIL
        
        # Paso 1.1: Configurar logging en carpeta compartida
        if not setup_shared_logging(logger, hostname_actual):
            return EXIT_SHARED_FOLDER_FAIL
    except Exception as e:
        logger.error(f"FALLO CRÍTICO: Error al conectar a carpeta compartida: {str(e)}")
        return EXIT_SHARED_FOLDER_FAIL

    maximo_intentos = 10
    intentos = 1
    success_process = False

    # Variables que se calculan una vez
    tipo = None
    lugar = None
    puesto = None
    usuario = None
    password = None

    while intentos <= maximo_intentos and not success_process:
        logger.info(f"Intento {intentos} de {maximo_intentos}")
        try:
            # Paso 2: Cargar JSON de hostnames
            hostnames_data = cargar_json_hostnames(logger)
            logger.info("JSON de hostnames cargado")
            if intentos == 1:
               # Paso 3: Verificar dominio
                if not verificar_dominio():
                    logger.error("Equipo no está en dominio corporativo. Abortando.")
                    return EXIT_DOMAIN_FAIL
                
                # Paso 4: Obtener tipo de dispositivo
                tipo = obtener_tipo_dispositivo(logger)
                logger.info(f"Tipo dispositivo: {tipo}")

                # Paso 5: Verificar si el hostname actual ya es correcto
                if verificar_hostname_correcto(hostname_actual, hostnames_data, tipo, logger):
                    logger.info("Hostname actual es válido. No se requiere cambio.")
                    return EXIT_HOSTNAME_CORRECTO
                
                # Paso 6: Extraer componentes
                lugar, puesto, numero = extraer_componentes_hostname(hostname_actual, logger)
                
                # Validar componentes (crítico)
                if not lugar or not puesto:
                    logger.error("FALLO CRÍTICO: No se pudo extraer lugar/puesto válido. Abortando.")
                    return EXIT_HOSTNAME_COMPONENTS_FAIL
                
                # Paso 7: Verificar existencia en JSON
                lugares = hostnames_data.get("Hostname_existentes", {})
                if lugar not in lugares:
                    logger.error(f"Lugar '{lugar}' no existe en JSON. Abortando.")
                    return EXIT_HOSTNAME_COMPONENTS_FAIL
                
                if puesto not in lugares[lugar]:
                    logger.error(f"Puesto '{puesto}' no existe en lugar. Abortando.")
                    return EXIT_HOSTNAME_COMPONENTS_FAIL
                
                # Paso 8: Cambiar hostname
                usuario = 'user_ad' # Aqui ingresas el usuario de AD (con los permisos necesarios)
                password = 'Password_ad' # Aqui la contraseña de AD (con los permisos necesarios)
                
                # 8.1: Primero validar credenciales
                if not validar_credenciales_ad(usuario, password, 'ni',logger):
                    return EXIT_INVALID_CREDENTIALS
                
            # Paso 9: Buscar número disponible
            nuevo_numero = encontrar_numero_disponible(lugar, puesto, tipo, hostnames_data, logger)
            if not nuevo_numero:
                logger.error("FALLO CRÍTICO: No se encontró número disponible. Abortando.")
                return EXIT_NO_AVAILABLE_NUMBER
            
            # Paso 10: Construir nuevo hostname
            nuevo_hostname = f"{lugar}{puesto}{nuevo_numero}{tipo}"
            logger.info(f"Nuevo hostname propuesto: {nuevo_hostname}")
                
            # 2. Verificar disponibilidad en AD
            if not verificar_hostname_en_ad(nuevo_hostname, usuario, password, CONFIG["DOMINIO_CORPORATIVO"], logger):
                tiempo_base_espera = 3 + (intentos * 0.8)
                tiempo_aleatorio = random.uniform(0, 8)
                tiempo_espera = tiempo_base_espera + tiempo_aleatorio
                logger.error(f"El hostname {nuevo_hostname} ya existe en AD. Esperando {tiempo_espera:.2f} segundos antes de reintentar...")
                time.sleep(tiempo_espera)
                intentos += 1
                continue
            
            # 3. RESERVAR HOSTNAME EN JSON ANTES DE CAMBIO
            hostnames_data = reservar_hostname_en_json(hostnames_data, nuevo_hostname, tipo, logger)
            guardar_json_hostnames(hostnames_data, logger)
            logger.info(f"Hostname {nuevo_hostname} reservado en JSON")
            
            # 4. Intentar cambio de hostname
            if cambiar_hostname(nuevo_hostname, usuario, password, logger):
                # Paso 11: Actualizar JSON (remover antiguo)
                hostnames_data = actualizar_json_remover_antiguo(hostnames_data, hostname_actual, logger)
                guardar_json_hostnames(hostnames_data, logger)
                logger.info("Proceso completado exitosamente! Hostname cambiado y JSON actualizado.")
                success_process = True
            else:
                # Liberar reserva si falla el cambio
                hostnames_data = liberar_hostname_en_json(hostnames_data, nuevo_hostname, logger)
                guardar_json_hostnames(hostnames_data, logger)
                logger.warning(f"Reserva liberada para {nuevo_hostname}")
                
                tiempo_base_espera = 5 * intentos
                tiempo_aleatorio = random.uniform(0, 10)
                tiempo_espera = tiempo_base_espera + tiempo_aleatorio
                logger.error(f"Falló el cambio de hostname. Reintentando en {tiempo_espera:.2f} segundos...")
                time.sleep(tiempo_espera)
                intentos += 1
                
        except Exception as e:
            logger.error(f"ERROR NO CONTROLADO: {str(e)}")
            return EXIT_GENERAL_ERROR
    # Limpiar conexión de red
    try:
        subprocess.run(f'net use "{CONFIG["SHARED_FOLDER"]}" /delete /y', 
                      shell=True, capture_output=True)
        logger.info("Conexión de red limpiada")
    except:
        pass

    if success_process:
        logger.info("Proceso completado exitosamente.")
        logger.info("==== FIN DE PROCESO ====")
        return EXIT_SUCCESS
    else:
        logger.error("No se pudo completar el proceso después de varios intentos.")
        logger.info("==== FIN DE PROCESO ====")
        return EXIT_CREDENTIALS_OR_CHANGE_FAIL

if __name__ == "__main__":
    sys.exit(main())