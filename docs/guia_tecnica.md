# Guía Técnica - MISP SIEM Integration

## Para Desarrolladores: Cómo Funciona el Sistema

---

## 1. Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────────┐
│                   SERVIDOR INTERMEDIARIO                        │
│                                                                 │
│  ┌─────────┐    ┌──────────────┐    ┌────────────────┐         │
│  │  main.py │───►│  QRadar      │───►│  IoC           │        │
│  │ (loop)   │    │  Connector   │    │  Extractor +   │        │
│  │          │    │              │    │  Mapper        │        │
│  └────┬─────┘    └──────┬───────┘    └───────┬────────┘        │
│       │                 │                    │                  │
│       │          ┌──────▼───────┐    ┌───────▼────────┐        │
│       │          │  QRadar API  │    │  MISP Client   │        │
│       │          │  (requests)  │    │  (PyMISP)      │        │
│       │          └──────────────┘    └───────┬────────┘        │
│       │                                      │                  │
│  ┌────▼─────┐                                │                  │
│  │  State   │    SQLite                      │                  │
│  │  Manager │◄─── state.db                   │                  │
│  └──────────┘                                │                  │
└──────────────────────────────────────────────┼──────────────────┘
                                               │
                    ┌──────────────┐    ┌───────▼────────┐
                    │   QRadar     │    │   MISP         │
                    │   Console    │    │   Server       │
                    │   (API)      │    │   (API)        │
                    └──────────────┘    └────────────────┘
```

---

## 2. Cómo Funciona el Polling

### El Patrón High-Water Mark

El polling utiliza un patrón de **high-water mark** para rastrear qué offenses ya fueron procesadas. Funciona así:

```
Ciclo 1 (primera ejecución):
  - No hay estado previo → consulta offenses de últimas 24h
  - Procesa offenses con last_updated_time: 10:00, 10:05, 10:10
  - Guarda high-water mark: 10:10

Ciclo 2 (5 minutos después):
  - Lee high-water mark: 10:10
  - Consulta offenses con last_updated_time > 10:10
  - Procesa offenses con timestamps: 10:12, 10:14
  - Actualiza high-water mark: 10:14

Ciclo 3 (5 minutos después):
  - Lee high-water mark: 10:14
  - Consulta offenses con last_updated_time > 10:14
  - No hay nuevas offenses → no actualiza high-water mark
  - Próximo ciclo usará el mismo punto: 10:14
```

**Persistencia**: El high-water mark se guarda en SQLite (`data/state.db`). Si el servicio se reinicia, retoma desde el último punto guardado.

**Doble protección contra duplicados**:
1. **Timestamp filter**: Solo consulta offenses más nuevas que el high-water mark
2. **Processed set**: La tabla `processed_offenses` en SQLite registra cada offense procesada individualmente. Esto protege contra re-procesamiento si QRadar actualiza una offense ya procesada (su `last_updated_time` cambia).

### Ciclo Completo Paso a Paso

```python
# Pseudocódigo del ciclo (ver main.py:run_poll_cycle)

def run_poll_cycle(connector, misp_client, state):
    # 1. Leer punto de partida
    since = state.get_last_poll_timestamp("qradar")

    # 2. Consultar QRadar
    # GET /api/siem/offenses?filter=last_updated_time>{timestamp}&sort=+last_updated_time
    for offense in connector.fetch_offenses(since):

        # 3. Verificar duplicado
        if state.is_offense_processed("qradar", offense.id):
            continue  # Ya fue procesada

        # 4. Enriquecer con IoCs
        #    - Resolver source_address_ids → IPs reales
        #    - Resolver local_destination_address_ids → IPs reales
        #    - Mapear offense_source según offense_type
        #    - Extraer IoCs del texto de descripción (regex)
        #    - Deduplicar IoCs por (tipo, valor)
        offense = connector.get_offense_iocs(offense)

        # 5. Buscar evento existente en MISP (por tag qradar:offense_id=X)
        #    - Si existe: agregar nuevos atributos + sighting
        #    - Si no existe: crear evento nuevo
        misp_event = misp_client.create_event_from_offense(offense)

        # 6. Registrar en estado
        state.mark_offense_processed("qradar", offense.id, misp_event.id)

    # 7. Actualizar high-water mark
    state.update_last_poll_timestamp("qradar", latest_timestamp)
```

---

## 3. Modelo de Datos

### NormalizedOffense
Representación intermedia de una alerta SIEM, independiente del vendor:

```python
@dataclass
class NormalizedOffense:
    offense_id: str          # ID único en el SIEM
    siem_type: str           # "qradar", "fortisiem", "netwitness"
    title: str               # Título/descripción de la alerta
    description: str         # Descripción completa
    severity: int            # 1-10 normalizado
    source_ip: str | None    # IP origen principal
    destination_ip: str | None  # IP destino principal
    timestamp: datetime      # Cuándo ocurrió
    raw_event: dict          # Datos crudos del SIEM (para debugging)
    iocs: list[IoC]          # IoCs extraídos (se llena en get_offense_iocs)
    categories: list[str]    # Categorías de la alerta
    rules: list[str]         # Reglas que dispararon la alerta
```

### IoC
Un indicador individual:

```python
@dataclass
class IoC:
    type: IoCType    # Enum: ip-src, ip-dst, domain, url, md5, sha256, etc.
    value: str       # El valor del indicador
    comment: str     # Contexto de dónde se extrajo
    to_ids: bool     # Si MISP lo debe usar para detección (default: True)
```

### Mapeo QRadar → NormalizedOffense

| Campo QRadar | Campo Normalizado |
|-------------|-------------------|
| `id` | `offense_id` (como string) |
| `description` | `title` y `description` |
| `magnitude` | `severity` (1-10) |
| `last_updated_time` | `timestamp` (convertido de epoch ms) |
| `offense_source` + `offense_type` | Primer IoC (tipo depende de offense_type) |
| `source_address_ids` | IoCs ip-src (resueltos vía API) |
| `local_destination_address_ids` | IoCs ip-dst (resueltos vía API) |
| `categories` | `categories` |
| `rules[].name` | `rules` |

### Mapeo NormalizedOffense → MISP Event

| Campo Normalizado | Campo MISP |
|-------------------|-----------|
| `title` | `Event.info` = "[QRADAR] Offense #ID: title" |
| `severity` (8-10) | `threat_level_id` = 1 (High) |
| `severity` (6-7) | `threat_level_id` = 2 (Medium) |
| `severity` (4-5) | `threat_level_id` = 3 (Low) |
| `severity` (1-3) | `threat_level_id` = 4 (Undefined) |
| `timestamp` | `Event.date` |
| `siem_type` | Tag: `siem:qradar` |
| `offense_id` | Tag: `qradar:offense_id=12345` |
| `iocs[]` | `Event.Attribute[]` (cada IoC es un atributo) |

---

## 4. Flujo de Datos Detallado

### Paso 1: QRadar API → Raw JSON

```
GET /api/siem/offenses?filter=last_updated_time>1740646200000&sort=+last_updated_time
Authorization: SEC {token}

Response:
[
  {
    "id": 12345,
    "description": "Excessive Firewall Denies from 203.0.113.50",
    "offense_source": "203.0.113.50",
    "offense_type": 0,
    "source_address_ids": [101, 102],
    "local_destination_address_ids": [201],
    "magnitude": 8,
    ...
  }
]
```

### Paso 2: Resolución de IPs

```
GET /api/siem/source_addresses/101 → {"source_ip": "203.0.113.50"}
GET /api/siem/source_addresses/102 → {"source_ip": "198.51.100.5"}
GET /api/siem/local_destination_addresses/201 → {"local_destination_ip": "10.0.0.5"}
```

### Paso 3: Extracción de IoCs

```
Del offense_source (type=0 → IP):  IoC(ip-src, "203.0.113.50")
De source_addresses resueltas:     IoC(ip-src, "203.0.113.50")  ← duplicado, se elimina
                                   IoC(ip-src, "198.51.100.5")
De destination_addresses:          IoC(ip-dst, "10.0.0.5")     ← IP privada, se incluye
Del texto (regex):                 IoC(ip-src, "203.0.113.50") ← duplicado, se elimina

Resultado final: [
  IoC(ip-src, "203.0.113.50"),
  IoC(ip-src, "198.51.100.5"),
  IoC(ip-dst, "10.0.0.5")
]
```

### Paso 4: Creación de Evento MISP

```
POST /events/add
{
  "Event": {
    "info": "[QRADAR] Offense #12345: Excessive Firewall Denies from 203.0.113.50",
    "distribution": 0,
    "threat_level_id": 1,    // magnitude 8 → High
    "analysis": 1,            // Ongoing
    "date": "2026-02-27",
    "Tag": [
      {"name": "tlp:amber"},
      {"name": "automated:true"},
      {"name": "siem:qradar"},
      {"name": "qradar:offense_id=12345"}
    ],
    "Attribute": [
      {"type": "ip-src", "value": "203.0.113.50", "category": "Network activity", "to_ids": true},
      {"type": "ip-src", "value": "198.51.100.5", "category": "Network activity", "to_ids": true},
      {"type": "ip-dst", "value": "10.0.0.5", "category": "Network activity", "to_ids": true},
      {"type": "comment", "value": "Excessive Firewall...", "category": "Other", "to_ids": false}
    ]
  }
}
```

---

## 5. Cómo Agregar un Nuevo Conector SIEM

Para agregar soporte para otro SIEM (ej: FortiSIEM):

### Paso 1: Crear el conector

```python
# src/connectors/fortisiem_connector.py

from connectors.base_connector import BaseSIEMConnector
from core.models import NormalizedOffense

class FortiSIEMConnector(BaseSIEMConnector):

    @property
    def siem_type(self) -> str:
        return "fortisiem"

    def test_connection(self) -> bool:
        # Verificar conectividad a FortiSIEM API
        ...

    def fetch_offenses(self, since: datetime) -> Iterator[NormalizedOffense]:
        # Consultar incidentes de FortiSIEM
        # GET /phoenix/rest/query/events (ejemplo)
        # Convertir cada incidente a NormalizedOffense
        ...

    def get_offense_iocs(self, offense: NormalizedOffense) -> NormalizedOffense:
        # Extraer IoCs de los datos de FortiSIEM
        # Usar ioc_extractor.extract_iocs_from_text() para texto libre
        # Usar ioc_mapper para campos conocidos
        ...
```

### Paso 2: Agregar configuración

En `config/settings.yaml`:
```yaml
fortisiem:
  url: "https://fortisiem.example.com"
  username: "api_user"
  verify_ssl: true
```

### Paso 3: Registrar en main.py

Agregar la lógica para seleccionar el conector basado en configuración.

### Interfaces a implementar

```python
class BaseSIEMConnector(ABC):
    @property
    def siem_type(self) -> str:            # Retorna "fortisiem"
    def test_connection(self) -> bool:      # True si puede conectar
    def fetch_offenses(self, since) -> Iterator[NormalizedOffense]:  # Obtiene alertas
    def get_offense_iocs(self, offense) -> NormalizedOffense:        # Extrae IoCs
```

Todo lo demás (MISP client, state manager, main loop) es reutilizable sin cambios.

---

## 6. Manejo de Errores y Retry

### Estrategia de Retry

```
Llamada API falla
  → Espera 2s → Retry 1
    → Espera 4s → Retry 2
      → Espera 8s → Retry 3
        → Log error → Continúa con siguiente offense
```

**Configuración en código:**
- `MISPClient`: 3 reintentos con backoff exponencial base 2
- `QRadarConnector`: 3 reintentos con backoff exponencial base 2
- `main.py`: Si un ciclo completo falla, el siguiente ciclo lo intenta de nuevo

### Aislamiento de Errores

Cada offense se procesa independientemente. Si la offense #123 falla al crear el evento MISP:
1. Se registra el error en logs
2. **No** se marca como procesada (se reintentará en el próximo ciclo)
3. Se continúa con la offense #124
4. El high-water mark se actualiza con el timestamp de la última offense exitosa

### Errores Comunes

| Error | Causa | Acción |
|-------|-------|--------|
| `ConnectionError` | Red caída | Retry automático, log warning |
| `401 Unauthorized` | API key inválida | Log error, continúa (todas las offenses fallarán) |
| `429 Too Many Requests` | Rate limit | Retry con backoff |
| `500 Internal Server Error` | Error en MISP/QRadar | Retry automático |
| `SSL Certificate Error` | Cert inválido | Configurar `verify_ssl: false` para testing |

---

## 7. Cómo Ejecutar los Tests

```bash
# Instalar dependencias de testing
pip install -r requirements.txt

# Ejecutar todos los tests
pytest tests/ -v

# Ejecutar tests de un módulo específico
pytest tests/test_ioc_extractor.py -v

# Ejecutar con cobertura
pytest tests/ --cov=src --cov-report=term-missing

# Ejecutar un test específico
pytest tests/test_integration.py::TestFullPollCycle::test_full_cycle_with_new_offenses -v
```

### Estructura de Tests

| Archivo | Qué prueba |
|---------|-----------|
| `test_ioc_extractor.py` | Extracción de IoCs desde texto libre (regex) |
| `test_ioc_mapper.py` | Mapeo de tipos QRadar → MISP |
| `test_state_manager.py` | Persistencia SQLite, high-water mark |
| `test_misp_client.py` | Creación de eventos, deduplicación, retry |
| `test_qradar_connector.py` | Fetch de offenses, resolución de IPs |
| `test_integration.py` | Ciclo completo end-to-end con todos los mocks |

Todos los tests usan **mocks** - no requieren conexión a QRadar ni MISP reales.
