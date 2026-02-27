# Guía de Usuario - MISP SIEM Integration

## Tabla de Contenidos
1. [Descripción General](#1-descripción-general)
2. [Requisitos Previos](#2-requisitos-previos)
3. [Instalación](#3-instalación)
4. [Configuración](#4-configuración)
5. [Primera Ejecución](#5-primera-ejecución)
6. [Modos de Ejecución](#6-modos-de-ejecución)
7. [Monitoreo](#7-monitoreo)
8. [Troubleshooting](#8-troubleshooting)
9. [Mantenimiento](#9-mantenimiento)

---

## 1. Descripción General

**MISP SIEM Integration** es un servicio de polling que automatiza la transferencia de Indicadores de Compromiso (IoCs) desde IBM QRadar hacia MISP (Malware Information Sharing Platform).

**Flujo de operación:**
```
QRadar (offenses) → Polling Service → MISP (events + attributes)
```

Cada vez que se genera una offense en QRadar, el servicio:
1. Detecta la nueva offense vía la API REST de QRadar
2. Extrae los IoCs asociados (IPs, dominios, URLs, hashes)
3. Crea un evento en MISP con todos los IoCs como atributos
4. Registra el estado para no reprocesar offenses

---

## 2. Requisitos Previos

### Servidor Intermediario
El servicio necesita un servidor que tenga conectividad de red hacia **ambos** sistemas:

| Requisito | Mínimo | Recomendado |
|-----------|--------|-------------|
| CPU | 1 vCPU | 2 vCPU |
| RAM | 512 MB | 1 GB |
| Disco | 100 MB | 500 MB |
| SO | Linux (cualquier distro) | Ubuntu 22.04+ / RHEL 8+ |
| Python | 3.10+ | 3.12+ |
| Red | HTTPS a QRadar y MISP | HTTPS a QRadar y MISP |

**Alternativa:** Puede ejecutarse como contenedor Docker en cualquier servidor existente.

### Acceso de Red
```
Servidor Intermediario → QRadar Console (HTTPS/443) [Lectura]
Servidor Intermediario → MISP Server (HTTPS/443)    [Escritura]
```

Asegúrate de que las reglas de firewall permitan estas conexiones.

### Credenciales Necesarias
- **QRadar API Token**: Token de solo lectura (ver [Configuración QRadar](configuracion_qradar.md))
- **MISP API Key**: Key con permisos de escritura (ver [Configuración MISP](configuracion_misp.md))

---

## 3. Instalación

### Opción A: Instalación con Python (recomendada para desarrollo)

```bash
# 1. Clonar el repositorio
git clone https://github.com/benchobeat/MISP_INTEGRATION.git
cd MISP_INTEGRATION

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Copiar y configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores reales
nano .env
```

### Opción B: Instalación con Docker (recomendada para producción)

```bash
# 1. Clonar el repositorio
git clone https://github.com/benchobeat/MISP_INTEGRATION.git
cd MISP_INTEGRATION

# 2. Copiar y configurar variables de entorno
cp .env.example .env
nano .env  # Completar MISP_API_KEY, QRADAR_API_TOKEN, URLs

# 3. Construir y ejecutar
cd docker
docker-compose up -d
```

### Opción C: Instalación como servicio systemd

```bash
# 1. Instalar (seguir pasos de Opción A primero)

# 2. Crear archivo de servicio
sudo tee /etc/systemd/system/misp-integration.service << 'EOF'
[Unit]
Description=MISP SIEM Integration Polling Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=misp-integration
Group=misp-integration
WorkingDirectory=/opt/misp-integration
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=/opt/misp-integration/.env
ExecStart=/opt/misp-integration/venv/bin/python -m src.main
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

# 3. Habilitar y arrancar
sudo systemctl daemon-reload
sudo systemctl enable misp-integration
sudo systemctl start misp-integration
```

---

## 4. Configuración

### Archivo `.env` (Secrets)
```bash
# OBLIGATORIO: API Keys (nunca commitear en git)
MISP_API_KEY=tu_api_key_de_misp_aqui
MISP_URL=https://misp.tu-empresa.com
QRADAR_API_TOKEN=tu_token_de_qradar_aqui
QRADAR_URL=https://qradar.tu-empresa.com
```

### Archivo `config/settings.yaml` (Configuración general)

Los parámetros más importantes a ajustar:

| Parámetro | Default | Descripción |
|-----------|---------|-------------|
| `general.polling_interval_seconds` | 300 | Cada cuántos segundos se consulta QRadar (5 min) |
| `general.initial_lookback_hours` | 24 | En primera ejecución, cuántas horas atrás consultar |
| `misp.distribution` | 0 | 0=Solo tu org, 1=Comunidad, 2=Conectadas, 3=Todas |
| `misp.publish` | false | Si los eventos se publican automáticamente |
| `misp.tags` | ["tlp:amber", "automated:true"] | Tags por defecto en cada evento |
| `qradar.min_magnitude` | 3 | Ignorar offenses con magnitude menor a este valor |
| `qradar.offense_status_filter` | "OPEN" | Solo procesar offenses con este estado |

---

## 5. Primera Ejecución

### Paso 1: Verificar conectividad
```bash
# Ejecutar un solo ciclo de prueba
cd /path/to/MISP_INTEGRATION
source venv/bin/activate  # Si usas Python nativo
python -m src.main --once
```

Deberías ver en la salida:
```
2026-02-27 10:00:00 | INFO     | misp_integration | MISP SIEM Integration starting...
2026-02-27 10:00:00 | INFO     | misp_integration | Testing connection to QRadar...
2026-02-27 10:00:01 | INFO     | connectors.qradar_connector | Connected to QRadar 7.5.0 at https://qradar.example.com
2026-02-27 10:00:01 | INFO     | misp_integration | Testing connection to MISP...
2026-02-27 10:00:02 | INFO     | core.misp_client | Connected to MISP as siem@company.com (org: 1)
2026-02-27 10:00:02 | INFO     | misp_integration | All connections verified successfully.
```

### Paso 2: Verificar procesamiento
Si hay offenses en QRadar de las últimas 24 horas:
```
2026-02-27 10:00:02 | INFO     | connectors.qradar_connector | Found 3 new/updated offenses
2026-02-27 10:00:03 | INFO     | connectors.qradar_connector | Extracted 5 unique IoCs from offense 12345
2026-02-27 10:00:04 | INFO     | core.misp_client | Created MISP event 100 for offense 12345 with 5 IoCs
...
2026-02-27 10:00:10 | INFO     | misp_integration | === Poll cycle complete: 3 fetched, 3 new, 0 skipped, 0 failed, 12 IoCs pushed, 3 MISP events ===
```

### Paso 3: Verificar en MISP
1. Inicia sesión en tu instancia MISP
2. Ve a Events → List Events
3. Deberías ver eventos con el formato: `[QRADAR] Offense #12345: Descripción`
4. Cada evento tendrá los tags `siem:qradar`, `tlp:amber`, `automated:true`
5. Los atributos del evento serán los IoCs extraídos (IPs, dominios, etc.)

### Paso 4: Iniciar en modo continuo
```bash
# Python nativo
python -m src.main

# Docker
docker-compose up -d

# Systemd
sudo systemctl start misp-integration
```

---

## 6. Modos de Ejecución

### Modo Continuo (default)
```bash
python -m src.main
```
Ejecuta el polling en un loop infinito con el intervalo configurado. Se detiene con SIGINT (Ctrl+C) o SIGTERM.

### Modo Único (--once)
```bash
python -m src.main --once
```
Ejecuta un solo ciclo de polling y termina. Ideal para:
- Pruebas iniciales
- Ejecución vía cron job
- Debugging

### Modo Estadísticas (--stats)
```bash
python -m src.main --stats
```
Muestra estadísticas acumuladas:
```
SIEM Type: qradar
Total Offenses Processed: 142
Total IoCs Pushed: 387
Last Poll: 2026-02-27T15:30:00+00:00
```

### Configuración Personalizada (--config)
```bash
python -m src.main --config /path/to/custom_settings.yaml
```

---

## 7. Monitoreo

### Logs
- **Python nativo**: Stdout (redirigir a archivo si se desea)
- **Docker**: `docker logs misp-siem-integration`
- **Systemd**: `journalctl -u misp-integration -f`

### Niveles de Log
| Nivel | Qué muestra |
|-------|-------------|
| ERROR | Fallos de conexión, errores de API, offenses que no se pudieron procesar |
| WARNING | Reintentos de API, offenses sin IoCs |
| INFO | Resumen de cada ciclo (offenses procesadas, IoCs creados) |
| DEBUG | Detalle de cada operación (cada IoC, cada llamada API) |

### Verificación de Salud
```bash
# Verificar que el proceso está corriendo
docker ps | grep misp-siem
# o
systemctl status misp-integration

# Ver las últimas líneas de log
docker logs --tail 20 misp-siem-integration

# Consultar estadísticas
python -m src.main --stats
```

---

## 8. Troubleshooting

### "Cannot connect to QRadar"
- Verificar que `QRADAR_URL` es correcto y accesible desde el servidor
- Verificar que el API token es válido: `curl -H "SEC: YOUR_TOKEN" https://qradar:443/api/system/about`
- Verificar reglas de firewall (puerto 443)

### "Cannot connect to MISP"
- Verificar que `MISP_URL` es correcto
- Verificar que el API key es válido: `curl -H "Authorization: YOUR_KEY" https://misp/servers/getPyMISPVersion.json`
- Verificar certificado SSL (`verify_ssl: false` para testing)

### "No new offenses found"
- Verificar `initial_lookback_hours` en primera ejecución
- Verificar `offense_status_filter` (¿las offenses están en estado OPEN?)
- Verificar `min_magnitude` (¿la magnitude de las offenses es suficiente?)

### "Failed to create MISP event"
- Verificar que el usuario MISP tiene permisos de creación de eventos
- Verificar la distribución configurada (permisos de la organización)
- Revisar logs en nivel DEBUG para ver la respuesta completa de MISP

### El servicio se detiene inesperadamente
- Verificar logs para excepciones no manejadas
- Aumentar `log_level` a DEBUG
- Con Docker: `docker-compose up` (sin -d) para ver output en consola

---

## 9. Mantenimiento

### Rotación de API Keys
1. Generar nuevo API key en MISP/QRadar
2. Actualizar `.env` con el nuevo key
3. Reiniciar el servicio

```bash
# Docker
docker-compose restart

# Systemd
sudo systemctl restart misp-integration
```

### Limpieza de Estado
El archivo de estado SQLite crece con cada offense procesada. Para limpiar:
```bash
# Ver tamaño
ls -lh data/state.db

# Si necesitas reiniciar desde cero (reprocesará offenses):
rm data/state.db
```

### Actualización del Servicio
```bash
git pull origin main
pip install -r requirements.txt  # Si hay nuevas dependencias
sudo systemctl restart misp-integration  # o docker-compose up -d --build
```
