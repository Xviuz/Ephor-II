# Port Scanner Security App

Aplicación en Python para escanear periódicamente puertos locales en Windows, detectar puertos abiertos, cerrados e inactivos, y gestionar el cierre de puertos abiertos pero inactivos. Pensada para uso en ciberseguridad local.

---

## Características / Features

- Escaneo automático y periódico configurable de puertos en escucha.  
  Automatic and configurable periodic scanning of listening ports.
- Registro de estados de puertos (abiertos activos, inactivos, cerrados, whitelist).  
  Logging port states (open active, inactive, closed, whitelist).
- Logs en formato JSON con rotación para evitar saturación.  
  JSON logs with rotation to prevent saturation.
- GUI para modificar configuración: periodicidad, whitelist, alertas.  
  GUI to modify settings: scan period, whitelist, alerts.
- Alertas visuales cuando se detectan puertos inactivos.  
  Visual alerts when inactive ports are detected.
- Posibilidad de cerrar procesos asociados a puertos inactivos con confirmación.  
  Ability to close processes tied to inactive ports with confirmation.
- Función para abrir carpeta con logs desde la interfaz.  
  Button to open logs folder from the interface.
- Configuración persistente en archivo JSON.  
  Persistent configuration in JSON file.
- Pensado para uso en Windows (aunque podría funcionar en Linux con ajustes).  
  Designed for Windows (may work on Linux with adjustments).

---

## Requisitos / Requirements

- Python 3.7+  
- Librerías Python / Python libraries:  
  - [psutil](https://pypi.org/project/psutil/)

Instalar librerías con / Install libraries with:

```bash
pip install -r requirements.txt
