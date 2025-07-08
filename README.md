# Automatic Hostname Changer

Este proyecto facilita el **renombrado masivo y automático de hostnames** en un entorno corporativo Windows, minimizando la intervención manual y evitando errores comunes.

---

## 📋 1. Descripción general

En entornos con cientos o miles de equipos, es frecuente encontrar hostnames con errores de formato o duplicados. Este proyecto consta de dos componentes:

1. **Automatic\_hostname\_changer** (`.exe` o `.py`):

   - Conecta a una carpeta compartida donde reside un JSON con la base de datos de hostnames actuales extraídos desde Active Directory.
   - Detecta hostnames que no siguen el patrón configurado o que carecen del sufijo de tipo de dispositivo.
   - Asigna el siguiente número disponible para el `Lugar` – `Puesto` – `Tipo de dispositivo`.
   - Cambia el hostname en el sistema **sin reiniciar** (el cambio se aplica en el próximo arranque).
   - Genera registros de ejecución tanto en local como en la carpeta compartida.

2. **hostname\_clasificator.py**:

   - Lee una lista plana de hostnames (por ejemplo, desde `hostnames.txt`).
   - Clasifica cada nombre en la jerarquía `Lugar > Puesto > Tipo de dispositivo`.
   - Produce un archivo `salida.json` listo para actualizar la estructura principal.

---

## 🔎 2. Lógica y flujo de trabajo

### 2.1. Estructura JSON esperada

El JSON base (`estructura.json`) debe tener este formato:

```json
{
  "Hostname_existentes": {
    "LugarA": {
      "Puesto1": { "PC": [], "LP": [], "Desconocido": [] },
      "Puesto2": { "PC": [], "LP": [], "Desconocido": [] }
    },
    "LugarB": { ... }
  }
}
```

- ``: Puede ser cualquier identificador de ubicación (p. ej., oficina, campus).
- ``: Área o estación de trabajo dentro del lugar.
- ``: Ej. `PC`, `LP` (laptop) u otros.
- ``: Aquí se almacenan temporalmente los hostnames que no coincidan con ninguna categoría.

### 2.2. Proceso de clasificación (`hostname_clasificator.py`)

1. Carga `estructura.json`.
2. Lee `hostnames.txt` (o la fuente definida) con un hostname por línea.
3. Para cada hostname:
   - Extrae las 3 primeras letras como **Lugar**.
   - Identifica el **Puesto** hasta el primer dígito.
   - Determina el **Tipo de dispositivo** por sufijo (`PC`, `LP`, etc.).
   - Si no encuentra coincidencia, asigna la categoría `Desconocido`.
4. Guarda la estructura actualizada en `salida.json`, conservando los arrays de nombres.

### 2.3. Ejecución principal (`Automatic_hostname_changer`)

1. **Chequeo de permisos**: Verifica que el usuario ejecute con privilegios de administrador local. Si no, sale con código **7**.
2. **Obtención del hostname actual**: Si no lo obtiene, sale con código **8**.
3. **Configuración de logging**:
   - Llamada a `setup_shared_logging()`: crea carpeta de logs en local (`C:\...`) y en la carpeta compartida (subcarpeta configurable).
   - Registra cada paso con fecha, hora y hostname involucrado.
4. **Carga del JSON**:
   - Intenta leer `hostnames.json` desde la carpeta compartida.
   - Si falla, intenta `C:\hostnames_backup.json`.
   - Si ambos fallan, parte con una estructura vacía.
5. **Validación de dominio**: Si el equipo no está unido al dominio, sale con código **3**.
6. **Verificación de hostname**:
   - Usa `verificar_hostname_correcto()`. Si cumple el patrón, sale con código **9**.
7. **Extracción de componentes**: Lugar, Puesto y número de dispositivo. Si falla, sale con código **4**.
8. **Búsqueda de número libre**:
   - En el JSON, busca los números ocupados para ese Lugar>Puesto>Tipo.
   - Asigna el menor número disponible (p.ej., si están 1,2,4, asigna 3). Si no hay hueco, asigna siguiente secuencial.
   - Si no hay categoría o no hay números, sale con código **5**.
9. **Validación LDAP**:
   - Usa `validar_credenciales_ad()` y `verificar_hostname_en_ad()`.
   - Si el nombre propuesto ya existe, sale con código **10** o **12**.
10. **Cambio de nombre**:
    - Ejecuta `Rename-Computer` vía PowerShell.
    - Espera 30 segundos y vuelve a confirmar en AD.
11. **Actualización del JSON**:
    - Agrega el nuevo hostname al array correspondiente.
    - Guarda de nuevo `hostnames.json` en la carpeta compartida.
12. **Salida**:
    - Retorna `0` en caso de éxito.

---

## ⚙️ 3. Configuración detallada

1. **Variables de entorno y archivo de configuración** (`CONFIG`):

   ```python
   CONFIG = {
     "SHARED_FOLDER": r"\\IP_SERVIDOR\ruta_compartida",
     "CREDENCIALES": {"username": r"DOMINIO\\UsuarioAD", "password": "MiPassword"},
     "DOMINIO_CORPORATIVO": "midominio.corp"
   }
   ```

   - Ajusta `SHARED_FOLDER` a la ruta UNC.
   - Asegúrate de que el usuario tenga permisos de escritura en AD.

2. **Logs compartidos**:

   - Por defecto, la subcarpeta es `logs`. Para cambiarla, edita:
     ```python
     log_dir = os.path.join(CONFIG["SHARED_FOLDER"], "mi_carpeta_logs")
     ```

3. **JSON de hostnames**:

   - Nombre por defecto: `hostnames.json`. Modifícalo si lo renombraste.
   - Copia de respaldo local en `C:\hostnames_backup.json`.

4. **Ejecución**:

   - **Windows Powershell**: `.\Automatic_hostname_changer.exe Usuario Password`
   - **Modo desarrollo**: `python Automatic_hostname_changer.py Usuario Password`
   - **Produccion**: `python Automatic_hostname_changer.exe (User and Password compilados en el .exe)`

---

## 💡 4. Buenas prácticas y recomendaciones

- **Pruebas**: Primero valida en un entorno de prueba con pocos equipos.
- **Backups**: Mantén siempre copia local del JSON antes de ejecuciones masivas.
- **Permisos**: Usa cuentas de servicio con privilegios mínimos (prin. renombrado). 
- **Monitoreo**: Revisa los logs periódicamente para detectar hostnames duplicados o fallos LDAP.

---

## 📝 5. Códigos de salida y resolución de errores

| Código | Significado                            | Acción sugerida                                  |
| ------ | -------------------------------------- | ------------------------------------------------ |
| 0      | Éxito                                  | —                                                |
| 1      | Error general                          | Revisar logs locales y compartidos               |
| 2      | Falló conexión a carpeta compartida    | Verificar red y permisos en carpeta compartida   |
| 3      | No está unido al dominio               | Unir equipo al dominio                           |
| 4      | Extracción de componentes fallida      | Revisar patrón de hostname actual                |
| 5      | Sin número disponible                  | Inspeccionar JSON; quizá faltan categorías       |
| 6      | Credenciales o cambio fallido          | Verificar usuario/contraseña AD                  |
| 7      | Sin permisos de administrador local    | Ejecutar como admin                              |
| 8      | No obtuvo hostname actual              | Comprobar `socket.gethostname()`                 |
| 9      | Hostname ya cumple patrón (sin acción) | Ninguna                                          |
| 10     | Hostname sugerido ya existe en AD      | Incrementar número o revisar JSON                |
| 11     | Credenciales inválidas                 | Validar credenciales con otro método (LDAP3, AD) |
| 12     | Verificación en AD fallida             | Inspeccionar conectividad LDAP/AD                |

---

## 🤝 6. Contribuciones

1. *Fork* del repositorio.
2. Crear rama: `git checkout -b feature/nueva-funcionalidad`.
3. Hacer *commit* con descripciones claras.
4. Abrir *Pull Request*.

---

## 📄 7. Licencia

Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

*Documentación generada por ChatGPT, adaptada a tu flujo de trabajo.*

