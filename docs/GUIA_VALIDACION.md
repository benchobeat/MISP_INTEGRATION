# Guia de Validacion de Bugs — MISP-QRadar Integration

## Tabla de Contenidos

1. [Prerequisitos](#1-prerequisitos)
2. [Configuracion del Ambiente](#2-configuracion-del-ambiente)
3. [Ejecucion del Script](#3-ejecucion-del-script)
4. [Modos de Ejecucion](#4-modos-de-ejecucion)
5. [Interpretacion de Resultados](#5-interpretacion-de-resultados)
6. [Referencia de Bugs Validados](#6-referencia-de-bugs-validados)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Prerequisitos

### Software requerido

| Componente | Version minima | Verificar con |
|---|---|---|
| Python | 3.10+ | `python3 --version` |
| pip | 21.0+ | `pip --version` |
| Acceso de red | — | Conexion a MISP y QRadar |

### Credenciales necesarias

| Variable | Descripcion | Donde obtenerla |
|---|---|---|
| `MISP_API_KEY` | API key de tu usuario MISP | MISP Web UI > Administration > My Profile > Auth key |
| `MISP_URL` | URL del servidor MISP | Ej: `https://misp.tuempresa.com` |
| `QRADAR_API_TOKEN` | Token de autorizacion (SEC header) | QRadar > Admin > Authorized Services > Add |
| `QRADAR_URL` | URL de la consola QRadar | Ej: `https://qradar.tuempresa.com` |

### Permisos necesarios

**MISP:**
- Rol minimo: `User` (lectura de eventos y atributos)
- Para validar BUG-3 completamente: `Publisher` (verificar estado de publicacion)

**QRadar:**
- Security Profile: acceso a `/api/siem/offenses` y `/api/system/about`
- User Role: `Admin` no es necesario; basta con un rol que tenga acceso de lectura a offenses

---

## 2. Configuracion del Ambiente

### Paso 1: Clonar e instalar dependencias

```bash
cd /ruta/a/MISP_INTEGRATION

# Crear entorno virtual (recomendado)
python3 -m venv .venv
source .venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

### Paso 2: Configurar variables de entorno

**Opcion A — Archivo .env (recomendado):**

```bash
# Copiar el ejemplo
cp .env.example .env

# Editar con tus valores reales
nano .env
```

Contenido del `.env`:
```
MISP_API_KEY=tu_api_key_real_aqui
MISP_URL=https://misp.tuempresa.com
QRADAR_API_TOKEN=tu_token_sec_real_aqui
QRADAR_URL=https://qradar.tuempresa.com
```

**Opcion B — Variables de entorno directas:**

```bash
export MISP_API_KEY="tu_api_key_real_aqui"
export MISP_URL="https://misp.tuempresa.com"
export QRADAR_API_TOKEN="tu_token_sec_real_aqui"
export QRADAR_URL="https://qradar.tuempresa.com"
```

### Paso 3: Verificar conectividad basica

Antes de ejecutar el script, verifica que puedes alcanzar ambos servidores:

```bash
# Verificar QRadar (debe retornar JSON con version)
curl -k -s -H "SEC: $QRADAR_API_TOKEN" \
  -H "Accept: application/json" \
  "$QRADAR_URL/api/system/about" | python3 -m json.tool

# Verificar MISP (debe retornar info del usuario)
curl -k -s -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  "$MISP_URL/users/view/me" | python3 -m json.tool
```

Si obtienes respuestas JSON validas, la conectividad es correcta.

---

## 3. Ejecucion del Script

### Ejecucion completa (todas las validaciones)

```bash
# Desde la raiz del proyecto
python tests/validate_bugs.py
```

Esto ejecutara las 11 validaciones. Las que requieren MISP/QRadar se omitiran automaticamente si las variables de entorno no estan configuradas.

### Con detalles adicionales (recomendado para primera ejecucion)

```bash
python tests/validate_bugs.py --verbose
```

El modo verbose muestra:
- Valores intermedios de cada prueba
- Respuestas raw de las APIs
- Detalles de cada comparacion

---

## 4. Modos de Ejecucion

### Solo validaciones locales (sin MISP/QRadar)

```bash
python tests/validate_bugs.py --local-only
```

Ejecuta: BUG-2, BUG-3, ISSUE-6, ISSUE-7, ISSUE-8, ISSUE-9, ISSUE-12, ISSUE-13, ISSUE-15

Estas validaciones analizan el codigo fuente localmente sin necesidad de conectarse a servidores externos. Util para una primera validacion rapida.

### Solo validaciones contra QRadar

```bash
python tests/validate_bugs.py --qradar-only
```

Ejecuta: BUG-1, ISSUE-4

Requiere: `QRADAR_URL` y `QRADAR_API_TOKEN`

### Solo validaciones contra MISP

```bash
python tests/validate_bugs.py --misp-only
```

Ejecuta: BUG-3 (con verificacion adicional contra MISP real)

Requiere: `MISP_URL` y `MISP_API_KEY`

### Un bug especifico

```bash
# Validar solo BUG-1
python tests/validate_bugs.py --bug BUG-1

# Validar solo ISSUE-4
python tests/validate_bugs.py --bug ISSUE-4

# Con detalles
python tests/validate_bugs.py --bug BUG-2 --verbose
```

IDs disponibles: `BUG-1`, `BUG-2`, `BUG-3`, `ISSUE-4`, `ISSUE-6`, `ISSUE-7`, `ISSUE-8`, `ISSUE-9`, `ISSUE-12`, `ISSUE-13`, `ISSUE-15`

---

## 5. Interpretacion de Resultados

### Iconos de estado

| Icono | Significado | Accion requerida |
|---|---|---|
| `✗ BUG CONFIRMADO` (rojo) | El bug esta presente en el codigo | Debe corregirse segun severidad |
| `✓ NO PRESENTE` (verde) | El bug no se manifesta actualmente | Revisar si es latente |
| `⊘ OMITIDO` (amarillo) | No se pudo ejecutar la validacion | Configurar variables de entorno |

### Ejemplo de salida

```
======================================================================
  MISP-QRadar Integration — Validacion de Bugs
======================================================================
  Fecha: 2026-02-27 15:30:45
  Python: 3.12.1
  QRADAR_URL: https://qradar.example.com
  MISP_URL: https://misp.example.com
  Validaciones a ejecutar: 11

[BUG-1] Filtro QRadar status sin comillas
  Severidad: CRITICO
  ────────────────────────────────────────────────────────
  Probando filtro SIN comillas (como lo genera el codigo actual)...
  Probando filtro CON comillas (forma correcta)...
  Resultado: ✗ BUG CONFIRMADO
  Ambas formas retornaron HTTP 200. Tu version de QRadar es tolerante,
  pero el codigo sigue siendo incorrecto segun la especificacion de la API.
  Esto puede romperse al actualizar QRadar.

[BUG-2] datetime.utcnow() naive vs timezone-aware
  Severidad: CRITICO
  ────────────────────────────────────────────────────────
  Resultado: ✗ BUG CONFIRMADO
  El default de NormalizedOffense.timestamp usa datetime.utcnow()
  que produce un datetime naive. Al compararlo con datetimes
  timezone-aware (del StateManager), lanza TypeError.

======================================================================
  RESUMEN DE VALIDACION
======================================================================

  Total de validaciones: 11
  Bugs confirmados:   8
  No presentes:       0
  Omitidos:           3

  BUGS CONFIRMADOS:
    [CRITICO] BUG-1: Filtro QRadar status sin comillas
    [CRITICO] BUG-2: datetime.utcnow() naive vs timezone-aware
    [CRITICO] BUG-3: Flag publish aceptado pero nunca ejecutado
    ...

  ⚠  Se encontraron 3 bug(s) CRITICO(S) que deben corregirse antes de produccion.
```

### Severidades

| Severidad | Descripcion | Prioridad |
|---|---|---|
| **CRITICO** | Causa fallos directos en produccion | Corregir inmediatamente |
| **SIGNIFICATIVO** | Causa problemas a escala o bajo ciertas condiciones | Planificar correccion |
| **MODERADO** | Afecta calidad, rendimiento o mantenibilidad | Incluir en siguiente sprint |

---

## 6. Referencia de Bugs Validados

| ID | Severidad | Que valida | Requiere |
|---|---|---|---|
| BUG-1 | CRITICO | Filtro QRadar: `status = OPEN` vs `status = 'OPEN'` | QRadar |
| BUG-2 | CRITICO | `datetime.utcnow()` genera datetime naive sin timezone | Local |
| BUG-3 | CRITICO | Flag `publish` nunca ejecuta `PyMISP.publish()` | Local + MISP (opcional) |
| ISSUE-4 | SIGNIFICATIVO | API retorna max 50 offenses sin header Range | QRadar |
| ISSUE-6 | SIGNIFICATIVO | Retry reintenta errores no-retryable (401, 404) | Local |
| ISSUE-7 | SIGNIFICATIVO | `fetch_offenses` ignora respuestas de error (dict) | Local |
| ISSUE-8 | SIGNIFICATIVO | PyMISP sin timeout — puede bloquear indefinidamente | Local + MISP (opcional) |
| ISSUE-9 | MODERADO | Regex de dominios matchea `config.yaml`, `file.txt` | Local |
| ISSUE-12 | MODERADO | `docker-compose.yaml` usa campo `version` deprecado | Local |
| ISSUE-13 | MODERADO | Dockerfile separa ENTRYPOINT/CMD de forma fragil | Local |
| ISSUE-15 | MODERADO | MISPSighting se crea sin timestamp del offense | Local |

---

## 7. Troubleshooting

### "Variables de entorno requeridas no configuradas"

```bash
# Verificar que las variables estan definidas
echo $MISP_URL
echo $QRADAR_URL

# Si usas .env, asegurate de que estan cargadas
source .env  # o
export $(grep -v '^#' .env | xargs)
```

### "SSL: CERTIFICATE_VERIFY_FAILED"

El script deshabilita verificacion SSL por defecto para ambientes de prueba. Si aun asi falla:

```bash
# Opcion 1: Agregar el certificado CA de tu organizacion
export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt

# Opcion 2: Desactivar verificacion completamente
export PYTHONHTTPSVERIFY=0
```

### "Connection refused" o timeout al conectar a QRadar/MISP

1. Verifica que puedes alcanzar el servidor desde tu maquina:
   ```bash
   curl -k -s -o /dev/null -w "%{http_code}" "$QRADAR_URL/api/system/about"
   ```
2. Verifica reglas de firewall y VPN
3. Verifica que el token/API key no hayan expirado

### "ModuleNotFoundError: No module named 'pymisp'"

```bash
# Instalar dependencias
pip install -r requirements.txt

# O solo PyMISP
pip install pymisp
```

### El script se ejecuta pero todos los tests son "OMITIDOS"

Ejecuta con `--local-only` primero para validar los bugs que no requieren conexion:

```bash
python tests/validate_bugs.py --local-only --verbose
```

### Errores de importacion de modulos del proyecto

Asegurate de ejecutar desde la raiz del proyecto:

```bash
cd /ruta/a/MISP_INTEGRATION
python tests/validate_bugs.py
```

---

## Siguiente paso

Una vez validados los bugs, el equipo puede priorizar las correcciones usando el plan de correccion documentado en el review. Se recomienda:

1. Corregir los 3 bugs CRITICOS antes de cualquier despliegue a produccion
2. Planificar los issues SIGNIFICATIVOS para el siguiente sprint
3. Incluir los issues MODERADOS como deuda tecnica

Para ejecutar las correcciones automaticamente, consulta al equipo de desarrollo o solicita la implementacion basada en el plan de revision detallado.
