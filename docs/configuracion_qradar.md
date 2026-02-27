# Configuración de IBM QRadar - Guía Paso a Paso

## Objetivo
Configurar QRadar para que el servicio de integración pueda leer offenses y extraer IoCs vía la API REST.

---

## 1. Crear un API Token en QRadar

### Paso 1: Acceder a Authorized Services
1. Inicia sesión en la consola de QRadar como administrador
2. Navega a: **Admin** → **Authorized Services** (en la sección "User Management")

### Paso 2: Crear nuevo servicio autorizado
1. Click en **Add Authorized Service**
2. Completa los campos:
   - **Service Name**: `MISP Integration (Read Only)`
   - **Authentication Token**: Se generará automáticamente, o puedes ingresar uno personalizado
   - **User Role**: `Admin` (necesario para leer offenses, pero con token de solo lectura)
   - **Security Profile**: Selecciona el perfil que tenga acceso a los dominios relevantes
   - **Expiry Date**: Configura una fecha de expiración (recomendado: 1 año, con rotación planificada)
3. Click en **Save**
4. **IMPORTANTE**: Copia el token generado. Solo se muestra una vez.

### Paso 3: Verificar permisos del token
El token necesita acceso a los siguientes endpoints:
- `GET /api/siem/offenses` - Listar offenses
- `GET /api/siem/source_addresses/{id}` - Resolver IPs origen
- `GET /api/siem/local_destination_addresses/{id}` - Resolver IPs destino
- `GET /api/system/about` - Verificar conectividad

---

## 2. Verificar Acceso a la API

### Desde el servidor intermediario:
```bash
# Reemplaza con tus valores
QRADAR_URL="https://qradar.tu-empresa.com"
QRADAR_TOKEN="tu_token_aqui"

# Test 1: Verificar conectividad
curl -k -s -H "SEC: ${QRADAR_TOKEN}" \
     "${QRADAR_URL}/api/system/about" | python3 -m json.tool

# Respuesta esperada:
# {
#     "external_version": "7.5.0 (Build 20230101)",
#     ...
# }

# Test 2: Listar offenses (última hora)
curl -k -s -H "SEC: ${QRADAR_TOKEN}" \
     "${QRADAR_URL}/api/siem/offenses?filter=status%3DOPEN&Range=items%3D0-5" \
     | python3 -m json.tool

# Test 3: Verificar resolución de IPs
# (Reemplaza 101 con un source_address_id real de una offense)
curl -k -s -H "SEC: ${QRADAR_TOKEN}" \
     "${QRADAR_URL}/api/siem/source_addresses/101" \
     | python3 -m json.tool
```

---

## 3. Configurar Reglas de Firewall

El servidor intermediario donde corre el servicio de polling necesita:

```
ALLOW: Servidor_Intermediario → QRadar_Console : TCP/443 (HTTPS)
```

Si QRadar usa un puerto diferente para la API:
```
ALLOW: Servidor_Intermediario → QRadar_Console : TCP/{puerto_api}
```

---

## 4. Configuración en settings.yaml

```yaml
qradar:
  url: "https://qradar.tu-empresa.com"
  verify_ssl: true          # false si usas certificado autofirmado
  api_version: "14.0"       # Versión de la API de QRadar
  offense_status_filter: "OPEN"  # Solo offenses abiertas
  min_magnitude: 3          # Ignorar offenses con magnitude < 3
  offense_fields:           # Campos a recuperar (optimiza el payload)
    - "id"
    - "description"
    - "offense_source"
    - "offense_type"
    - "source_address_ids"
    - "local_destination_address_ids"
    - "magnitude"
    - "severity"
    - "relevance"
    - "credibility"
    - "status"
    - "start_time"
    - "last_updated_time"
    - "categories"
    - "rules"
```

El token de API va en la variable de entorno:
```bash
export QRADAR_API_TOKEN="tu_token_aqui"
```

---

## 5. Entender los Campos de QRadar

### Offense Types (offense_type)
El campo `offense_source` cambia de significado según `offense_type`:

| ID | Tipo | offense_source contiene |
|----|------|------------------------|
| 0 | Source IP | Dirección IP origen |
| 1 | Destination IP | Dirección IP destino |
| 2 | Event Name | Nombre del evento |
| 3 | Username | Nombre de usuario |
| 7 | Hostname | Nombre de host |
| 10 | Source IPv6 | Dirección IPv6 origen |
| 11 | Destination IPv6 | Dirección IPv6 destino |

### Magnitude vs Severity
- **Magnitude** (1-10): Métrica compuesta que combina severity, relevance y credibility. Es el indicador principal de importancia.
- **Severity** (1-10): Qué tan grave es la amenaza detectada.
- **Relevance** (1-10): Qué tan relevante es para tu red.
- **Credibility** (1-10): Qué tan creíble es la detección.

El servicio usa **magnitude** para mapear al threat_level de MISP.

### Estados de Offense
| Estado | Descripción |
|--------|-------------|
| OPEN | Activa, sin resolver |
| HIDDEN | Oculta por un analista |
| CLOSED | Cerrada/resuelta |

Por defecto, el servicio solo procesa offenses en estado **OPEN**.

---

## 6. Queries AQL (Referencia)

Estas son las queries AQL que el conector podría usar para enriquecer offenses (actualmente se usa resolución de IPs vía API directa, pero pueden habilitarse en futuras versiones):

```sql
-- Obtener eventos asociados a una offense
SELECT sourceip, destinationip, LOGSOURCENAME(logsourceid), category,
       UTF8(payload) as payload
FROM events
WHERE INOFFENSE({offense_id})
LIMIT 100
START '{start_time}'
STOP '{end_time}'

-- Obtener dominios DNS asociados
SELECT "DNS Request Domain" as domain, sourceip, destinationip
FROM events
WHERE INOFFENSE({offense_id})
  AND "DNS Request Domain" IS NOT NULL
LIMIT 50

-- Obtener URLs asociadas
SELECT URL, sourceip, destinationip
FROM events
WHERE INOFFENSE({offense_id})
  AND URL IS NOT NULL
LIMIT 50
```

---

## 7. Troubleshooting de QRadar

### Error: "401 Unauthorized"
- El token ha expirado → Generar nuevo token
- El token fue eliminado → Crear nuevo Authorized Service
- El token no tiene permisos → Verificar User Role y Security Profile

### Error: "422 Unprocessable Entity"
- El filtro AQL tiene sintaxis incorrecta
- Los campos solicitados no existen en la versión de QRadar
- Solución: Verificar `api_version` en settings.yaml

### Error: "Connection timed out"
- QRadar está procesando muchos datos
- Solución: Aumentar el timeout en el conector (default: 30s)

### Pocas offenses devueltas
- Verificar `offense_status_filter`: ¿las offenses están OPEN?
- Verificar `min_magnitude`: ¿es demasiado alto?
- Verificar el rango de tiempo: ¿`initial_lookback_hours` es suficiente?

### Resolución de IPs falla
- Algunas offenses pueden tener `source_address_ids` vacío
- Esto es normal para ciertos tipos de offense
- El servicio lo maneja gracefully y continúa con otros IoCs
