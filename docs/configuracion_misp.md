# Configuración de MISP - Guía Paso a Paso

## Objetivo
Configurar MISP para recibir eventos automáticos desde el servicio de integración con QRadar.

---

## 1. Crear Usuario Dedicado

### Paso 1: Crear la cuenta
1. Inicia sesión en MISP como administrador
2. Navega a: **Administration** → **Add User**
3. Completa los campos:
   - **Email**: `siem-integration@tu-empresa.com`
   - **Password**: Genera una contraseña fuerte (no se usará para login, solo para el API key)
   - **Organisation**: Selecciona tu organización
   - **Role**: `Org Admin` o un rol personalizado (ver paso 2)
   - **Autoalert**: Deshabilitado (evita emails automáticos)
   - **NIDS SID**: Dejar vacío
   - **GnuPG key**: Dejar vacío
4. Click en **Submit**

### Paso 2: Crear rol personalizado (recomendado)
Para el principio de mínimo privilegio, crea un rol específico:

1. Navega a: **Administration** → **List Roles** → **Add Role**
2. Nombre: `SIEM Integration`
3. Permisos mínimos requeridos:
   - ✅ `perm_add` - Crear eventos
   - ✅ `perm_modify` - Modificar eventos propios
   - ✅ `perm_tag_editor` - Gestionar tags
   - ✅ `perm_sighting` - Agregar sightings
   - ✅ `perm_auth` - Acceso a la API (automation)
   - ❌ `perm_admin` - No necesita administración
   - ❌ `perm_site_admin` - No necesita admin del sitio
   - ❌ `perm_publish` - No debería publicar automáticamente (a menos que lo desees)
   - ❌ `perm_delegate` - No necesita delegación
   - ❌ `perm_sync` - No necesita sincronización
   - ❌ `perm_regexp_access` - No necesita acceso a regex
4. Click en **Submit**
5. Edita el usuario `siem-integration` y asígnale este rol

---

## 2. Generar API Key

### Paso 1: Obtener el Automation Key
1. Inicia sesión como el usuario `siem-integration` (o como admin)
2. Navega a: **My Profile** (click en tu email arriba a la derecha)
3. Busca la sección **Automation** → **Auth Key**
4. El API Key se muestra ahí. Cópialo.

### Paso 2: Crear Auth Key dedicada (recomendado, MISP 2.4.159+)
Para mayor seguridad, crea un key específico:

1. Navega a: **Administration** → **List Auth Keys** → **Add authentication key**
2. Completa:
   - **User**: Selecciona `siem-integration@tu-empresa.com`
   - **Comment**: `QRadar Integration Service`
   - **Allowed IPs**: IP del servidor intermediario (ej: `10.0.1.50`)
   - **Expiration**: Fecha de expiración (recomendado: 1 año)
   - **Read Only**: ❌ No (necesita escribir)
3. Click en **Submit**
4. **IMPORTANTE**: Copia el key generado. Solo se muestra una vez.

### Paso 3: Configurar IP Allowlisting
La restricción de IP en el auth key es crítica:
- Solo permite conexiones desde la IP del servidor intermediario
- Si el key es comprometido, solo puede ser usado desde esa IP
- Si el servidor intermediario cambia de IP, actualiza el allowlist

---

## 3. Verificar Acceso a la API

### Desde el servidor intermediario:
```bash
MISP_URL="https://misp.tu-empresa.com"
MISP_KEY="tu_api_key_aqui"

# Test 1: Verificar autenticación
curl -k -s -H "Authorization: ${MISP_KEY}" \
     -H "Accept: application/json" \
     "${MISP_URL}/users/view/me" | python3 -m json.tool

# Respuesta esperada:
# {
#     "User": {
#         "email": "siem-integration@tu-empresa.com",
#         "org_id": "1",
#         ...
#     }
# }

# Test 2: Verificar versión
curl -k -s -H "Authorization: ${MISP_KEY}" \
     -H "Accept: application/json" \
     "${MISP_URL}/servers/getPyMISPVersion.json" | python3 -m json.tool

# Test 3: Listar eventos recientes
curl -k -s -H "Authorization: ${MISP_KEY}" \
     -H "Accept: application/json" \
     "${MISP_URL}/events/index" | python3 -m json.tool | head -50

# Test 4: Crear un evento de prueba
curl -k -s -X POST \
     -H "Authorization: ${MISP_KEY}" \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{"Event": {"info": "[TEST] Integration Test - Delete Me", "distribution": 0, "threat_level_id": 4, "analysis": 0}}' \
     "${MISP_URL}/events/add" | python3 -m json.tool

# Nota: Elimina el evento de prueba después desde la interfaz web
```

---

## 4. Habilitar Warninglists

Las warninglists filtran falsos positivos conocidos (IPs de CDNs, IPs de AWS, etc.).

### Paso 1: Actualizar warninglists
1. Navega a: **Administration** → **Warning Lists**
2. Click en **Update Warninglists** para descargar las más recientes

### Paso 2: Habilitar warninglists recomendadas
Habilita al menos estas:

| Warninglist | Propósito |
|-------------|-----------|
| List of RFC 1918 CIDR blocks | IPs privadas (10.x, 172.16.x, 192.168.x) |
| List of known IPv6 public DNS resolvers | DNS públicos como 2001:4860:4860::8888 |
| List of known google domains | Dominios legítimos de Google |
| List of known microsoft domains | Dominios legítimos de Microsoft |
| List of known Office 365 URLs | URLs del servicio O365 |
| List of known Amazon AWS IP ranges | Rangos IP de AWS |
| List of known Cloudflare IP ranges | Rangos IP de Cloudflare |
| List of known Akamai IP ranges | Rangos IP de Akamai |
| Top 1000 website from Alexa | Sitios populares que suelen ser falsos positivos |

### Paso 3: Habilitar
Para cada warninglist que quieras activar:
1. Click en el checkbox junto al nombre
2. Click en **Enable selected**

---

## 5. Configurar Tags y Taxonomías

### Habilitar taxonomías necesarias
1. Navega a: **Event Actions** → **List Taxonomies**
2. Habilita las siguientes taxonomías (click en Enable):
   - **tlp** - Traffic Light Protocol (para clasificación)
   - **admiralty-scale** - Escala de confiabilidad
   - **type** - Tipo de evento (OSINT, etc.)

### Tags que el servicio crea automáticamente
El servicio usa estos tags (se crean automáticamente si no existen):

| Tag | Propósito |
|-----|-----------|
| `siem:qradar` | Identifica eventos originados desde QRadar |
| `automated:true` | Identifica eventos creados automáticamente |
| `tlp:amber` | Nivel de compartición por defecto |
| `qradar:offense_id=XXXXX` | Enlaza al ID de offense original (para deduplicación) |
| `qradar:category=XXX` | Categoría de la offense en QRadar |

Si prefieres otros tags por defecto, modifícalos en `config/settings.yaml`:
```yaml
misp:
  tags:
    - "tlp:green"        # En lugar de amber
    - "automated:true"
    - "source:siem"
```

---

## 6. Configurar Distribución

### Niveles de distribución

| Nivel | Nombre | Quién ve los eventos |
|-------|--------|---------------------|
| 0 | Your organisation only | Solo tu organización |
| 1 | This community only | Tu organización + organizaciones en tu instancia MISP |
| 2 | Connected communities | Tu comunidad + instancias MISP conectadas vía sync |
| 3 | All communities | Todos los servidores MISP interconectados |

### Recomendación
- **Comenzar con 0** (Your organisation only) hasta validar que los eventos son correctos
- **Subir a 1** cuando confíes en la calidad de los datos
- **Usar 2 o 3** solo si participas activamente en comunidades de sharing

Configuración en `settings.yaml`:
```yaml
misp:
  distribution: 0  # Cambiar cuando estés listo
```

---

## 7. Configurar Reglas de Firewall

```
ALLOW: Servidor_Intermediario → MISP_Server : TCP/443 (HTTPS)
```

Si MISP corre en un puerto personalizado:
```
ALLOW: Servidor_Intermediario → MISP_Server : TCP/{puerto}
```

---

## 8. Verificar la Integración

Después de ejecutar el servicio por primera vez:

1. **En MISP**: Ve a **Events** → **List Events**
2. Filtra por tag: `siem:qradar`
3. Verifica que:
   - Los eventos tienen títulos con formato `[QRADAR] Offense #ID: Descripción`
   - Cada evento tiene los tags correctos
   - Los atributos (IoCs) son del tipo correcto (ip-src, ip-dst, domain, etc.)
   - El threat level corresponde a la severity de QRadar

### Verificación via API
```bash
# Buscar eventos con tag siem:qradar
curl -k -s -X POST \
     -H "Authorization: ${MISP_KEY}" \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{"tags": ["siem:qradar"], "limit": 5}' \
     "${MISP_URL}/events/restSearch" | python3 -m json.tool
```

---

## 9. Troubleshooting de MISP

### "Could not add Event: No permissions"
- Verificar que el usuario tiene el rol con `perm_add` habilitado
- Verificar que la organización del usuario coincide con la configuración

### "Invalid distribution level"
- El nivel de distribución configurado excede los permisos del usuario
- Solución: Reducir `distribution` en settings.yaml a 0

### "Authentication failed"
- API key inválido o expirado
- IP del servidor no está en el allowlist del auth key
- Solución: Verificar el key y el allowlist en Administration → List Auth Keys

### Los eventos no aparecen
- Verificar que `publish: false` → los eventos están en estado "draft"
- Buscarlos en Events → List Events sin filtro de publicación
- Los eventos no publicados solo son visibles para tu organización

### Warninglist no filtra
- Verificar que las warninglists están habilitadas
- El servicio de integración **no** filtra por warninglists (MISP lo hace internamente)
- Los atributos que coinciden con una warninglist mostrarán un icono de advertencia en MISP
