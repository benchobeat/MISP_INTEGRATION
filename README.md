# MISP SIEM Integration

Servicio automatizado que transfiere Indicadores de Compromiso (IoCs) desde SIEMs hacia [MISP](https://www.misp-project.org/) (Malware Information Sharing Platform).

## Arquitectura

```
┌──────────────┐     HTTPS       ┌────────────────────┐     HTTPS       ┌──────────┐
│   QRadar     │ ◄────────────── │  Polling Service    │ ──────────────► │   MISP   │
│   Console    │  GET offenses   │  (este proyecto)    │  POST events    │  Server  │
│              │                 │                     │                 │          │
│  Solo lectura│                 │  Python 3.10+       │                 │ Escritura│
│  (API Token) │                 │  Corre en servidor  │                 │ (API Key)│
│              │                 │  intermediario      │                 │          │
└──────────────┘                 └────────────────────┘                 └──────────┘
```

El servicio consulta periódicamente la API de QRadar para nuevas offenses, extrae los IoCs asociados (IPs, dominios, URLs, hashes) y crea eventos en MISP con todos los indicadores.

## Inicio Rápido

### 1. Instalar
```bash
git clone https://github.com/benchobeat/MISP_INTEGRATION.git
cd MISP_INTEGRATION
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configurar
```bash
cp .env.example .env
# Editar .env con tus API keys y URLs
```

### 3. Ejecutar
```bash
# Un solo ciclo (para pruebas)
python -m src.main --once

# Modo continuo (producción)
python -m src.main

# Con Docker
cd docker && docker-compose up -d
```

## Características

- **Polling automático** de offenses de QRadar con intervalo configurable
- **Extracción inteligente de IoCs**: IPs, dominios, URLs, hashes MD5/SHA1/SHA256, emails
- **Deduplicación**: Evita crear eventos duplicados en MISP (busca por tag de offense)
- **Mapeo de severidad**: QRadar magnitude (1-10) → MISP threat level (High/Medium/Low)
- **Persistencia de estado**: SQLite para rastrear offenses procesadas (tolerante a reinicios)
- **Retry con backoff exponencial**: Maneja errores transitorios de red
- **Shutdown graceful**: Responde a SIGINT/SIGTERM terminando el ciclo actual
- **Diseño modular**: Fácil de extender para otros SIEMs (FortiSIEM, RSA NetWitness)

## Estructura del Proyecto

```
├── config/settings.yaml       # Configuración principal
├── src/
│   ├── core/
│   │   ├── models.py          # Modelos de datos (IoC, NormalizedOffense)
│   │   ├── misp_client.py     # Cliente MISP (PyMISP wrapper)
│   │   ├── ioc_mapper.py      # Mapeo tipos QRadar → MISP
│   │   ├── ioc_extractor.py   # Extracción de IoCs desde texto (regex)
│   │   └── state_manager.py   # Persistencia SQLite
│   ├── connectors/
│   │   ├── base_connector.py  # Interfaz abstracta para SIEMs
│   │   └── qradar_connector.py
│   └── main.py                # Entry point y loop de polling
├── tests/                     # Tests unitarios y de integración
├── docker/                    # Dockerfile y docker-compose
└── docs/                      # Guías de configuración
```

## Documentación

| Guía | Descripción |
|------|-------------|
| [Guía de Usuario](docs/guia_usuario.md) | Instalación, configuración, despliegue y monitoreo |
| [Guía Técnica](docs/guia_tecnica.md) | Arquitectura, flujo de datos, cómo agregar nuevos SIEMs |
| [Configuración QRadar](docs/configuracion_qradar.md) | Crear API token, verificar acceso, troubleshooting |
| [Configuración MISP](docs/configuracion_misp.md) | Crear usuario, API key, warninglists, tags |

## Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

Todos los tests usan mocks - no requieren conexión a QRadar ni MISP reales.

## Requisitos

- Python 3.10+
- Conectividad HTTPS al servidor QRadar y MISP
- QRadar API Token (solo lectura)
- MISP API Key (escritura)
