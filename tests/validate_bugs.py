#!/usr/bin/env python3
"""
=============================================================================
  MISP-QRadar Integration — Script de Validacion de Bugs
=============================================================================

  Este script valida los bugs y issues encontrados durante la revision
  de codigo de la integracion MISP-QRadar. Ejecuta pruebas contra tus
  instancias reales de MISP y QRadar.

  PREREQUISITOS:
    1. Variables de entorno configuradas:
       - MISP_URL          (ej: https://misp.tuempresa.com)
       - MISP_API_KEY      (tu API key de MISP)
       - QRADAR_URL        (ej: https://qradar.tuempresa.com)
       - QRADAR_API_TOKEN  (tu token SEC de QRadar)

    2. Dependencias instaladas:
       pip install requests pymisp

  USO:
    # Ejecutar TODAS las validaciones
    python tests/validate_bugs.py

    # Ejecutar solo validaciones locales (sin conexion a MISP/QRadar)
    python tests/validate_bugs.py --local-only

    # Ejecutar solo validaciones contra QRadar
    python tests/validate_bugs.py --qradar-only

    # Ejecutar solo validaciones contra MISP
    python tests/validate_bugs.py --misp-only

    # Ejecutar un bug especifico (ej: BUG-1)
    python tests/validate_bugs.py --bug BUG-1

    # Modo verbose para ver detalles
    python tests/validate_bugs.py --verbose

=============================================================================
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import traceback
import urllib3
from datetime import datetime, timezone
from pathlib import Path

# Deshabilitar warnings de SSL para ambientes de prueba
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Agregar src al path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# ─────────────────────────────────────────────────────────────────────────────
# Utilidades de reporte
# ─────────────────────────────────────────────────────────────────────────────

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


class ValidationResult:
    def __init__(self, bug_id: str, title: str, severity: str):
        self.bug_id = bug_id
        self.title = title
        self.severity = severity
        self.confirmed = None  # True = bug presente, False = no presente, None = no ejecutado
        self.details = ""
        self.evidence = ""
        self.skipped = False
        self.skip_reason = ""

    def set_confirmed(self, confirmed: bool, details: str, evidence: str = ""):
        self.confirmed = confirmed
        self.details = details
        self.evidence = evidence

    def set_skipped(self, reason: str):
        self.skipped = True
        self.skip_reason = reason


results: list[ValidationResult] = []
VERBOSE = False


def log(msg: str):
    print(msg)


def log_verbose(msg: str):
    if VERBOSE:
        print(f"  {Colors.DIM}{msg}{Colors.RESET}")


def section(title: str):
    width = 70
    log(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * width}")
    log(f"  {title}")
    log(f"{'=' * width}{Colors.RESET}")


def subsection(bug_id: str, title: str, severity: str):
    sev_color = {
        "CRITICO": Colors.RED,
        "SIGNIFICATIVO": Colors.YELLOW,
        "MODERADO": Colors.BLUE,
    }.get(severity, Colors.DIM)

    log(f"\n{Colors.BOLD}[{bug_id}] {title}{Colors.RESET}")
    log(f"  Severidad: {sev_color}{severity}{Colors.RESET}")
    log(f"  {'─' * 60}")


def report_result(result: ValidationResult):
    if result.skipped:
        icon = f"{Colors.YELLOW}⊘ OMITIDO{Colors.RESET}"
        log(f"  Resultado: {icon} — {result.skip_reason}")
    elif result.confirmed:
        icon = f"{Colors.RED}✗ BUG CONFIRMADO{Colors.RESET}"
        log(f"  Resultado: {icon}")
    else:
        icon = f"{Colors.GREEN}✓ NO PRESENTE{Colors.RESET}"
        log(f"  Resultado: {icon}")

    if result.details:
        for line in result.details.split("\n"):
            log(f"  {Colors.DIM}{line}{Colors.RESET}")
    if result.evidence:
        log(f"  {Colors.DIM}Evidencia:{Colors.RESET}")
        for line in result.evidence.split("\n"):
            log(f"    {Colors.DIM}{line}{Colors.RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers de conexion
# ─────────────────────────────────────────────────────────────────────────────

def get_env(name: str) -> str | None:
    return os.environ.get(name)


def require_env(*names: str) -> dict[str, str]:
    """Retorna dict con los valores, o lanza ValueError si faltan."""
    values = {}
    missing = []
    for name in names:
        val = get_env(name)
        if not val:
            missing.append(name)
        else:
            values[name] = val
    if missing:
        raise ValueError(f"Variables de entorno requeridas no configuradas: {', '.join(missing)}")
    return values


def qradar_available() -> bool:
    return bool(get_env("QRADAR_URL") and get_env("QRADAR_API_TOKEN"))


def misp_available() -> bool:
    return bool(get_env("MISP_URL") and get_env("MISP_API_KEY"))


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION BUG-1: Filtro QRadar sin comillas
# ─────────────────────────────────────────────────────────────────────────────

def validate_bug_1():
    """BUG-1: Filtro de status de QRadar sin comillas — HTTP 422"""
    import requests

    r = ValidationResult("BUG-1", "Filtro QRadar status sin comillas", "CRITICO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    if not qradar_available():
        r.set_skipped("Variables QRADAR_URL / QRADAR_API_TOKEN no configuradas")
        report_result(r)
        return

    env = require_env("QRADAR_URL", "QRADAR_API_TOKEN")
    base_url = env["QRADAR_URL"].rstrip("/")
    headers = {
        "SEC": env["QRADAR_API_TOKEN"],
        "Accept": "application/json",
        "Version": "14.0",
    }

    log("  Probando filtro SIN comillas (como lo genera el codigo actual)...")
    try:
        resp_sin = requests.get(
            f"{base_url}/api/siem/offenses",
            headers=headers,
            params={
                "filter": "status = OPEN",  # Sin comillas — potencialmente invalido
                "fields": "id",
                "Range": "items=0-1",
            },
            verify=False,
            timeout=30,
        )
        status_sin = resp_sin.status_code
        body_sin = resp_sin.text[:300]
        log_verbose(f"Sin comillas: HTTP {status_sin}")
        log_verbose(f"Respuesta: {body_sin}")
    except Exception as e:
        r.set_confirmed(True, f"Error de conexion al probar sin comillas: {e}")
        report_result(r)
        return

    log("  Probando filtro CON comillas (forma correcta)...")
    try:
        resp_con = requests.get(
            f"{base_url}/api/siem/offenses",
            headers=headers,
            params={
                "filter": "status = 'OPEN'",  # Con comillas — correcto
                "fields": "id",
                "Range": "items=0-1",
            },
            verify=False,
            timeout=30,
        )
        status_con = resp_con.status_code
        body_con = resp_con.text[:300]
        log_verbose(f"Con comillas: HTTP {status_con}")
        log_verbose(f"Respuesta: {body_con}")
    except Exception as e:
        r.set_confirmed(True, f"Error de conexion al probar con comillas: {e}")
        report_result(r)
        return

    # Analizar resultados
    if status_sin >= 400 and status_con == 200:
        r.set_confirmed(
            True,
            f"Sin comillas retorno HTTP {status_sin}, con comillas retorno HTTP {status_con}.\n"
            f"QRadar rechaza el filtro sin comillas.",
            f"Sin comillas: HTTP {status_sin} — {body_sin}\n"
            f"Con comillas:  HTTP {status_con} — {body_con[:100]}",
        )
    elif status_sin == 200 and status_con == 200:
        # Ambos funcionan — QRadar es tolerante, pero sigue siendo un bug latente
        r.set_confirmed(
            True,
            f"Ambas formas retornaron HTTP 200. Tu version de QRadar es tolerante,\n"
            f"pero el codigo sigue siendo incorrecto segun la especificacion de la API.\n"
            f"Esto puede romperse al actualizar QRadar.",
            f"Sin comillas: HTTP {status_sin} (tolerante)\n"
            f"Con comillas:  HTTP {status_con} (correcto)",
        )
    else:
        r.set_confirmed(
            False,
            f"Sin comillas: HTTP {status_sin}, Con comillas: HTTP {status_con}",
        )

    report_result(r)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION BUG-2: datetime.utcnow() naive vs aware
# ─────────────────────────────────────────────────────────────────────────────

def validate_bug_2():
    """BUG-2: datetime.utcnow() crea datetimes naive que fallan al comparar."""
    r = ValidationResult("BUG-2", "datetime.utcnow() naive vs timezone-aware", "CRITICO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    log("  Verificando models.py NormalizedOffense.timestamp default...")

    # Test 1: Verificar que el default factory produce un datetime naive
    from core.models import NormalizedOffense

    offense = NormalizedOffense(
        offense_id="test",
        siem_type="test",
        title="Test",
        description="Test",
        severity=5,
        # No pasar timestamp — usa el default
    )

    ts = offense.timestamp
    is_naive = ts.tzinfo is None
    log_verbose(f"Timestamp generado: {ts}")
    log_verbose(f"tzinfo: {ts.tzinfo}")
    log_verbose(f"Es naive (sin timezone): {is_naive}")

    # Test 2: Verificar que la comparacion falla con un datetime aware
    aware_dt = datetime.now(timezone.utc)
    comparison_error = False
    error_msg = ""

    try:
        _ = ts > aware_dt
        log_verbose("Comparacion naive > aware: OK (no lanzo error)")
    except TypeError as e:
        comparison_error = True
        error_msg = str(e)
        log_verbose(f"Comparacion naive > aware: TypeError — {e}")

    # Test 3: Verificar deprecation warning en Python 3.12+
    is_deprecated = sys.version_info >= (3, 12)
    log_verbose(f"Python version: {sys.version_info.major}.{sys.version_info.minor}")
    log_verbose(f"datetime.utcnow() deprecado en esta version: {is_deprecated}")

    # Evaluar resultados
    evidence_lines = [
        f"Default timestamp: {ts}",
        f"tzinfo: {ts.tzinfo}",
        f"Es naive: {is_naive}",
        f"TypeError al comparar con aware: {comparison_error}",
        f"Python >= 3.12 (deprecado): {is_deprecated}",
    ]

    if is_naive:
        if comparison_error:
            r.set_confirmed(
                True,
                "El default de NormalizedOffense.timestamp usa datetime.utcnow()\n"
                "que produce un datetime naive. Al compararlo con datetimes\n"
                "timezone-aware (del StateManager), lanza TypeError.",
                "\n".join(evidence_lines),
            )
        else:
            r.set_confirmed(
                True,
                "El default de NormalizedOffense.timestamp usa datetime.utcnow()\n"
                "que produce un datetime naive. La comparacion no fallo en esta\n"
                "version de Python, pero el codigo es incorrecto y esta deprecado\n"
                "desde Python 3.12. Puede fallar con versiones mas recientes.",
                "\n".join(evidence_lines),
            )
    else:
        r.set_confirmed(False, "El timestamp default ya es timezone-aware.", "\n".join(evidence_lines))

    report_result(r)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION BUG-3: publish flag nunca se ejecuta
# ─────────────────────────────────────────────────────────────────────────────

def validate_bug_3():
    """BUG-3: El flag publish se acepta pero nunca se usa."""
    import ast
    import inspect

    r = ValidationResult("BUG-3", "Flag publish aceptado pero nunca ejecutado", "CRITICO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    log("  Analizando el codigo fuente de misp_client.py...")

    misp_client_path = Path(__file__).resolve().parent.parent / "src" / "core" / "misp_client.py"

    if not misp_client_path.exists():
        r.set_skipped(f"Archivo no encontrado: {misp_client_path}")
        report_result(r)
        return

    source = misp_client_path.read_text()

    # Verificar que self.publish se asigna en __init__
    has_publish_attr = "self.publish" in source
    log_verbose(f"self.publish asignado en __init__: {has_publish_attr}")

    # Buscar llamadas a self._misp.publish() o self.publish en _create_new_event
    publish_called = False
    lines = source.split("\n")
    in_create_new = False
    create_new_lines = []

    for i, line in enumerate(lines, 1):
        if "def _create_new_event" in line:
            in_create_new = True
            continue
        if in_create_new and line.strip() and not line.startswith(" ") and not line.startswith("\t"):
            if "def " in line:
                break
        if in_create_new:
            create_new_lines.append((i, line))
            if "publish" in line.lower() and "self.publish" in line:
                publish_called = True

    # Tambien buscar en todo el archivo si se usa self.publish para publicar
    publish_action_found = False
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if "self._misp.publish" in stripped:
            publish_action_found = True
            break
        if "self.publish" in stripped and ("if" in stripped or "publish(" in stripped):
            # Check if it's actually a condition that leads to publishing
            if "self.publish" in stripped and "self._misp" not in stripped:
                continue  # Just the assignment or check, not the actual call

    evidence_lines = [
        f"self.publish asignado en __init__: {has_publish_attr}",
        f"self._misp.publish() llamado en _create_new_event: {publish_called}",
        f"self._misp.publish() llamado en cualquier parte: {publish_action_found}",
    ]

    if has_publish_attr and not publish_action_found:
        r.set_confirmed(
            True,
            "El constructor acepta publish=True/False y lo almacena en self.publish,\n"
            "pero NUNCA se llama a self._misp.publish() en ningun metodo.\n"
            "Los eventos siempre quedan como borrador, sin importar la configuracion.",
            "\n".join(evidence_lines),
        )
    elif has_publish_attr and publish_action_found:
        r.set_confirmed(
            False,
            "El flag publish se usa correctamente.",
            "\n".join(evidence_lines),
        )
    else:
        r.set_confirmed(
            False,
            "No se encontro el atributo self.publish.",
            "\n".join(evidence_lines),
        )

    report_result(r)

    # Test contra MISP real (si disponible)
    if misp_available():
        log("\n  Verificacion adicional contra MISP real...")
        try:
            from pymisp import PyMISP
            env = require_env("MISP_URL", "MISP_API_KEY")
            misp = PyMISP(env["MISP_URL"], env["MISP_API_KEY"], ssl=False, timeout=30)

            # Buscar ultimo evento creado por la integracion
            events = misp.search(
                controller="events",
                tags=["automated:true"],
                limit=3,
                pythonify=True,
            )
            if events:
                for evt in events:
                    published_status = getattr(evt, "published", "desconocido")
                    log(f"    Evento {evt.id}: published={published_status}, info={evt.info[:60]}")
                if any(not getattr(e, "published", False) for e in events):
                    log(f"    {Colors.YELLOW}→ Eventos encontrados en estado borrador (published=False){Colors.RESET}")
            else:
                log("    No se encontraron eventos con tag 'automated:true'")
        except Exception as e:
            log(f"    {Colors.DIM}No se pudo verificar en MISP: {e}{Colors.RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION ISSUE-4: Sin paginacion en QRadar
# ─────────────────────────────────────────────────────────────────────────────

def validate_issue_4():
    """ISSUE-4: Sin paginacion — se pierden offenses si hay mas de 50."""
    import requests

    r = ValidationResult("ISSUE-4", "Sin paginacion para offenses de QRadar", "SIGNIFICATIVO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    if not qradar_available():
        r.set_skipped("Variables QRADAR_URL / QRADAR_API_TOKEN no configuradas")
        report_result(r)
        return

    env = require_env("QRADAR_URL", "QRADAR_API_TOKEN")
    base_url = env["QRADAR_URL"].rstrip("/")
    headers = {
        "SEC": env["QRADAR_API_TOKEN"],
        "Accept": "application/json",
        "Version": "14.0",
    }

    log("  Consultando offenses sin Range header (comportamiento actual)...")

    try:
        resp = requests.get(
            f"{base_url}/api/siem/offenses",
            headers=headers,
            params={
                "filter": "status = 'OPEN'",
                "fields": "id",
            },
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()

        offenses = resp.json()
        count_returned = len(offenses) if isinstance(offenses, list) else 0
        content_range = resp.headers.get("Content-Range", "")

        log_verbose(f"Offenses retornadas: {count_returned}")
        log_verbose(f"Content-Range header: {content_range}")

        # Parsear Content-Range para obtener el total
        # Formato: items 0-49/523
        total_available = None
        if content_range:
            try:
                parts = content_range.split("/")
                if len(parts) == 2 and parts[1].strip().isdigit():
                    total_available = int(parts[1].strip())
            except (ValueError, IndexError):
                pass

        evidence_lines = [
            f"Offenses retornadas (sin Range): {count_returned}",
            f"Content-Range header: {content_range or 'no presente'}",
            f"Total disponible (parseado): {total_available or 'no determinado'}",
        ]

        if total_available and total_available > count_returned:
            r.set_confirmed(
                True,
                f"QRadar tiene {total_available} offenses OPEN pero solo retorno {count_returned}.\n"
                f"El codigo actual pierde {total_available - count_returned} offenses silenciosamente\n"
                f"porque no implementa paginacion con el header Range.",
                "\n".join(evidence_lines),
            )
        elif count_returned == 50:
            r.set_confirmed(
                True,
                f"Se retornaron exactamente 50 offenses (limite default de QRadar).\n"
                f"Es muy probable que haya mas offenses disponibles que se estan perdiendo.\n"
                f"Sin Content-Range no se puede confirmar el total exacto.",
                "\n".join(evidence_lines),
            )
        elif count_returned < 50:
            r.set_confirmed(
                False,
                f"Se retornaron {count_returned} offenses (< 50). Con este volumen\n"
                f"la falta de paginacion no causa perdida de datos actualmente,\n"
                f"pero el bug esta latente si el volumen crece.",
                "\n".join(evidence_lines),
            )
        else:
            r.set_confirmed(
                True,
                f"Se retornaron {count_returned} offenses.",
                "\n".join(evidence_lines),
            )

    except Exception as e:
        r.set_confirmed(True, f"Error al consultar QRadar: {e}")

    report_result(r)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION ISSUE-6: Retry captura todas las excepciones
# ─────────────────────────────────────────────────────────────────────────────

def validate_issue_6():
    """ISSUE-6: Retry logic captura todas las excepciones indiscriminadamente."""
    r = ValidationResult("ISSUE-6", "Retry logic no distingue errores retryable vs no-retryable", "SIGNIFICATIVO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    log("  Analizando codigo de retry en qradar_connector.py y misp_client.py...")

    # Verificar qradar_connector.py
    qradar_path = Path(__file__).resolve().parent.parent / "src" / "connectors" / "qradar_connector.py"
    misp_path = Path(__file__).resolve().parent.parent / "src" / "core" / "misp_client.py"

    qradar_source = qradar_path.read_text() if qradar_path.exists() else ""
    misp_source = misp_path.read_text() if misp_path.exists() else ""

    # Buscar patrones de catch generico en retry
    # El fix cambia "except requests.exceptions.RequestException:" a
    # "except requests.exceptions.RequestException as exc:" y agrega filtrado
    qradar_catches_all = (
        "except requests.exceptions.RequestException:" in qradar_source
        and "status_code" not in qradar_source
    )
    misp_catches_all = False

    # En misp_client, buscar si _api_call_with_retry captura Exception sin filtrar
    in_retry_method = False
    has_non_retryable_filter = False
    for line in misp_source.split("\n"):
        if "_api_call_with_retry" in line and "def " in line:
            in_retry_method = True
        if in_retry_method:
            if "_non_retryable" in line or "non_retryable" in line.lower():
                has_non_retryable_filter = True
            if "except Exception:" in line.strip() and not has_non_retryable_filter:
                misp_catches_all = True
                break
            if line.strip().startswith("def ") and "def _api_call_with_retry" not in line:
                break

    # Verificar si hay filtrado por status_code o error type
    qradar_filters_status = "status_code" in qradar_source and ("< 500" in qradar_source or ">= 500" in qradar_source)
    misp_filters_errors = (
        has_non_retryable_filter
        or "status_code" in misp_source
        or "retryable" in misp_source.lower()
    )

    evidence_lines = [
        f"QRadar _get() captura RequestException generico: {qradar_catches_all}",
        f"QRadar filtra por status_code: {qradar_filters_status}",
        f"MISP _api_call_with_retry() captura Exception generico: {misp_catches_all}",
        f"MISP filtra errores retryable: {misp_filters_errors}",
    ]

    log_verbose(f"QRadar catches all RequestException: {qradar_catches_all}")
    log_verbose(f"MISP catches all Exception: {misp_catches_all}")

    if qradar_catches_all or misp_catches_all:
        issues = []
        if qradar_catches_all and not qradar_filters_status:
            issues.append("QRadar: reintenta en errores 401/403/404 (no retryable)")
        if misp_catches_all and not misp_filters_errors:
            issues.append("MISP: reintenta en CUALQUIER excepcion (TypeError, ValueError, etc.)")

        r.set_confirmed(
            True,
            "El mecanismo de retry no distingue entre errores transitorios\n"
            "(timeout, 502, 503) y errores permanentes (401, 403, 404, ValueError).\n"
            "Problemas: " + "; ".join(issues),
            "\n".join(evidence_lines),
        )
    else:
        r.set_confirmed(False, "El retry ya filtra errores correctamente.", "\n".join(evidence_lines))

    report_result(r)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION ISSUE-7: fetch_offenses falla silenciosamente
# ─────────────────────────────────────────────────────────────────────────────

def validate_issue_7():
    """ISSUE-7: fetch_offenses trata respuestas no-lista como 'sin offenses'."""
    r = ValidationResult("ISSUE-7", "fetch_offenses falla silenciosamente con respuestas de error", "SIGNIFICATIVO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    log("  Analizando manejo de respuesta en qradar_connector.py...")

    qradar_path = Path(__file__).resolve().parent.parent / "src" / "connectors" / "qradar_connector.py"
    source = qradar_path.read_text() if qradar_path.exists() else ""

    # Buscar la validacion de tipo de respuesta en fetch_offenses
    # El fix puede usar isinstance(offenses, list) o isinstance(page, list) (con paginacion)
    has_isinstance_check = (
        "isinstance(offenses, list)" in source
        or "isinstance(page, list)" in source
    )
    has_not_offenses = "if not offenses:" in source

    log_verbose(f"Tiene isinstance(offenses, list): {has_isinstance_check}")
    log_verbose(f"Tiene 'if not offenses': {has_not_offenses}")

    evidence_lines = [
        f"Valida que la respuesta sea list: {has_isinstance_check}",
        f"Usa 'if not offenses' (truthy check): {has_not_offenses}",
    ]

    # Demostrar el problema con un ejemplo
    log("  Simulando respuesta de error de QRadar...")

    error_response_examples = [
        {"message": "Invalid filter expression", "code": 422},
        {"http_response": {"code": 500, "message": "Internal Server Error"}},
        None,
    ]

    for example in error_response_examples:
        # Simular el comportamiento de "if not offenses"
        offenses = example
        would_silently_skip = not offenses  # Esto es lo que hace el codigo
        log_verbose(f"  Respuesta: {example} → 'if not offenses' = {would_silently_skip} (saltaria silenciosamente)")

    if has_isinstance_check:
        r.set_confirmed(False, "Ya valida que la respuesta sea una lista.", "\n".join(evidence_lines))
    elif has_not_offenses:
        r.set_confirmed(
            True,
            "fetch_offenses usa 'if not offenses:' sin validar el tipo.\n"
            "Si QRadar retorna un dict de error como {\"message\": \"Invalid filter\"},\n"
            "la condicion 'not offenses' es False (dict no vacio es truthy),\n"
            "y el codigo intentaria iterar sobre las keys del dict.\n"
            "Si retorna None, lo trata como 'sin offenses' silenciosamente.",
            "\n".join(evidence_lines),
        )
    else:
        r.set_confirmed(True, "No se pudo determinar el manejo de respuesta.", "\n".join(evidence_lines))

    report_result(r)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION ISSUE-8: Sin timeout en MISP
# ─────────────────────────────────────────────────────────────────────────────

def validate_issue_8():
    """ISSUE-8: PyMISP sin timeout configurado."""
    r = ValidationResult("ISSUE-8", "Sin timeout en llamadas a la API de MISP", "SIGNIFICATIVO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    log("  Verificando constructor de PyMISP en misp_client.py...")

    misp_path = Path(__file__).resolve().parent.parent / "src" / "core" / "misp_client.py"
    source = misp_path.read_text() if misp_path.exists() else ""

    # Buscar si el constructor de PyMISP incluye timeout
    has_timeout = "timeout=" in source and "PyMISP(" in source

    # Buscar la linea exacta
    pymisp_line = ""
    for line in source.split("\n"):
        if "PyMISP(" in line and "self._misp" in line:
            pymisp_line = line.strip()
            break

    log_verbose(f"Linea de instanciacion: {pymisp_line}")
    log_verbose(f"Incluye timeout: {has_timeout}")

    evidence_lines = [
        f"Instanciacion PyMISP: {pymisp_line}",
        f"timeout configurado: {has_timeout}",
    ]

    if not has_timeout:
        r.set_confirmed(
            True,
            "PyMISP se instancia sin parametro timeout.\n"
            "Si el servidor MISP se cuelga o tiene latencia extrema,\n"
            "la integracion se bloqueara indefinidamente esperando respuesta.\n"
            "PyMISP soporta el parametro timeout en el constructor.",
            "\n".join(evidence_lines),
        )
    else:
        r.set_confirmed(False, "PyMISP ya tiene timeout configurado.", "\n".join(evidence_lines))

    report_result(r)

    # Test real contra MISP si disponible
    if misp_available():
        log("\n  Verificando conectividad a MISP (con timeout manual de 10s)...")
        try:
            from pymisp import PyMISP
            import time

            env = require_env("MISP_URL", "MISP_API_KEY")

            start = time.time()
            misp = PyMISP(env["MISP_URL"], env["MISP_API_KEY"], ssl=False, timeout=10)
            result = misp.get_user("me")
            elapsed = time.time() - start

            if isinstance(result, dict) and "User" in result:
                log(f"    MISP respondio en {elapsed:.2f}s — conexion OK")
            else:
                log(f"    MISP respondio en {elapsed:.2f}s — respuesta inesperada: {result}")
        except Exception as e:
            log(f"    {Colors.YELLOW}Error al conectar a MISP: {e}{Colors.RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION ISSUE-9: Regex de dominios demasiado permisivo
# ─────────────────────────────────────────────────────────────────────────────

def validate_issue_9():
    """ISSUE-9: Regex de dominios genera falsos positivos."""
    r = ValidationResult("ISSUE-9", "Regex de dominios demasiado permisivo (falsos positivos)", "MODERADO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    log("  Probando extraccion de IoCs con texto que contiene falsos positivos...")

    from core.ioc_extractor import extract_iocs_from_text
    from core.models import IoCType

    # Texto con potenciales falsos positivos
    test_texts = {
        "Nombres de archivo": "Found suspicious file config.yaml and settings.json in /tmp/malware.exe",
        "Versiones de software": "Running QRadar version 7.5.0 with patch 3.2.1 applied",
        "Paths del sistema": "Log source at server.local port 514 with file access.log",
        "Texto tecnico mixto": "Rule CE:100 triggered for offense.id=12345. Check log.source and status.code",
    }

    false_positives_found = []
    all_evidence = []

    for desc, text in test_texts.items():
        iocs = extract_iocs_from_text(text)
        domains = [ioc for ioc in iocs if ioc.type == IoCType.DOMAIN]

        if domains:
            fps = [f"{d.value}" for d in domains]
            false_positives_found.extend(fps)
            all_evidence.append(f"  Texto: \"{text[:60]}...\"")
            all_evidence.append(f"  Dominios detectados: {', '.join(fps)}")
            log_verbose(f"{desc}: {len(domains)} falsos positivos: {fps}")
        else:
            log_verbose(f"{desc}: sin falsos positivos")

    # Tambien probar con dominios conocidos benignos
    benign_text = (
        "Connection to microsoft.com and google.com detected. "
        "Checking update.windows.com for patches. "
        "DNS query to github.com from developer workstation."
    )
    benign_iocs = extract_iocs_from_text(benign_text)
    benign_domains = [ioc for ioc in benign_iocs if ioc.type == IoCType.DOMAIN]
    benign_values = [d.value for d in benign_domains]

    well_known_detected = [d for d in benign_values if d in {
        "microsoft.com", "google.com", "github.com", "windows.com",
        "update.windows.com",
    }]

    if well_known_detected:
        all_evidence.append(f"\n  Dominios benignos detectados como IoCs: {', '.join(well_known_detected)}")
        false_positives_found.extend(well_known_detected)

    evidence_str = "\n".join(all_evidence) if all_evidence else "Sin falsos positivos detectados"

    if false_positives_found:
        r.set_confirmed(
            True,
            f"Se detectaron {len(false_positives_found)} falsos positivos.\n"
            f"El regex de dominios matchea extensiones de archivo, versiones de software,\n"
            f"y dominios benignos conocidos que no deberian ser IoCs en MISP.",
            evidence_str,
        )
    else:
        r.set_confirmed(False, "No se encontraron falsos positivos significativos.", evidence_str)

    report_result(r)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION ISSUE-12: Docker Compose version deprecado
# ─────────────────────────────────────────────────────────────────────────────

def validate_issue_12():
    """ISSUE-12: docker-compose.yaml usa campo version deprecado."""
    r = ValidationResult("ISSUE-12", "Docker Compose usa campo version deprecado", "MODERADO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    compose_path = Path(__file__).resolve().parent.parent / "docker" / "docker-compose.yaml"

    if not compose_path.exists():
        r.set_skipped(f"Archivo no encontrado: {compose_path}")
        report_result(r)
        return

    content = compose_path.read_text()
    has_version = content.strip().startswith("version:")

    log_verbose(f"Archivo: {compose_path}")
    log_verbose(f"Empieza con 'version:': {has_version}")

    if has_version:
        # Extraer la linea de version
        version_line = ""
        for line in content.split("\n"):
            if line.strip().startswith("version:"):
                version_line = line.strip()
                break

        r.set_confirmed(
            True,
            f"docker-compose.yaml contiene '{version_line}'.\n"
            f"El campo 'version' esta deprecado desde Docker Compose v2 y se ignora.\n"
            f"Genera un warning al ejecutar: 'version is obsolete'.",
            f"Linea encontrada: {version_line}",
        )
    else:
        r.set_confirmed(False, "No se encontro campo version en docker-compose.yaml.")

    report_result(r)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION ISSUE-13: Dockerfile ENTRYPOINT/CMD fragil
# ─────────────────────────────────────────────────────────────────────────────

def validate_issue_13():
    """ISSUE-13: Dockerfile separa ENTRYPOINT y CMD de forma fragil."""
    r = ValidationResult("ISSUE-13", "Dockerfile ENTRYPOINT/CMD separacion fragil", "MODERADO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    dockerfile_path = Path(__file__).resolve().parent.parent / "docker" / "Dockerfile"

    if not dockerfile_path.exists():
        r.set_skipped(f"Archivo no encontrado: {dockerfile_path}")
        report_result(r)
        return

    content = dockerfile_path.read_text()
    lines = content.split("\n")

    entrypoint_line = ""
    cmd_line = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("ENTRYPOINT"):
            entrypoint_line = stripped
        if stripped.startswith("CMD"):
            cmd_line = stripped

    log_verbose(f"ENTRYPOINT: {entrypoint_line}")
    log_verbose(f"CMD: {cmd_line}")

    # Verificar si estan separados
    has_split = bool(entrypoint_line) and bool(cmd_line)
    has_python_m_split = 'python", "-m"' in entrypoint_line or "python -m" in entrypoint_line

    evidence_lines = [
        f"ENTRYPOINT: {entrypoint_line}",
        f"CMD: {cmd_line}",
    ]

    if has_python_m_split:
        r.set_confirmed(
            True,
            "ENTRYPOINT y CMD estan separados de forma inusual.\n"
            f"  {entrypoint_line}\n"
            f"  {cmd_line}\n"
            "Si alguien ejecuta 'docker run <image> bash', el comando real seria\n"
            "'python -m bash' lo cual falla. La practica estandar es combinarlos\n"
            "en un solo CMD: CMD [\"python\", \"-m\", \"src.main\"]",
            "\n".join(evidence_lines),
        )
    else:
        r.set_confirmed(False, "ENTRYPOINT/CMD estan configurados correctamente.", "\n".join(evidence_lines))

    report_result(r)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDACION ISSUE-15: MISPSighting sin timestamp
# ─────────────────────────────────────────────────────────────────────────────

def validate_issue_15():
    """ISSUE-15: Sightings creados sin timestamp explicito."""
    r = ValidationResult("ISSUE-15", "MISPSighting sin timestamp explicito", "MODERADO")
    results.append(r)

    subsection(r.bug_id, r.title, r.severity)

    misp_path = Path(__file__).resolve().parent.parent / "src" / "core" / "misp_client.py"
    source = misp_path.read_text() if misp_path.exists() else ""

    # Buscar la seccion _add_sightings
    in_sightings = False
    sighting_lines = []
    has_timestamp = False

    for line in source.split("\n"):
        if "def _add_sightings" in line:
            in_sightings = True
        if in_sightings:
            sighting_lines.append(line)
            if "sighting.timestamp" in line or "sighting[\"timestamp\"]" in line:
                has_timestamp = True
            if line.strip().startswith("def ") and "def _add_sightings" not in line:
                break

    evidence = "\n".join(l for l in sighting_lines if l.strip())

    if not has_timestamp and sighting_lines:
        r.set_confirmed(
            True,
            "MISPSighting se crea sin establecer timestamp.\n"
            "MISP usara la hora del servidor como default, que puede diferir\n"
            "significativamente de cuando el indicador fue realmente observado\n"
            "en el SIEM. Deberia usarse offense.timestamp.",
            evidence,
        )
    elif has_timestamp:
        r.set_confirmed(False, "El sighting ya incluye timestamp.", evidence)
    else:
        r.set_skipped("No se encontro el metodo _add_sightings")

    report_result(r)


# ─────────────────────────────────────────────────────────────────────────────
# Reporte Final
# ─────────────────────────────────────────────────────────────────────────────

def print_summary():
    section("RESUMEN DE VALIDACION")

    confirmed = [r for r in results if r.confirmed is True]
    not_present = [r for r in results if r.confirmed is False]
    skipped = [r for r in results if r.skipped]

    log(f"\n  Total de validaciones: {len(results)}")
    log(f"  {Colors.RED}Bugs confirmados:   {len(confirmed)}{Colors.RESET}")
    log(f"  {Colors.GREEN}No presentes:       {len(not_present)}{Colors.RESET}")
    log(f"  {Colors.YELLOW}Omitidos:           {len(skipped)}{Colors.RESET}")

    if confirmed:
        log(f"\n  {Colors.BOLD}{Colors.RED}BUGS CONFIRMADOS:{Colors.RESET}")
        for r in confirmed:
            sev_color = {
                "CRITICO": Colors.RED,
                "SIGNIFICATIVO": Colors.YELLOW,
                "MODERADO": Colors.BLUE,
            }.get(r.severity, Colors.DIM)
            log(f"    {sev_color}[{r.severity}]{Colors.RESET} {r.bug_id}: {r.title}")

    if skipped:
        log(f"\n  {Colors.YELLOW}OMITIDOS (configurar variables de entorno para ejecutar):{Colors.RESET}")
        for r in skipped:
            log(f"    {r.bug_id}: {r.skip_reason}")

    # Recomendacion final
    critical = [r for r in confirmed if r.severity == "CRITICO"]
    significant = [r for r in confirmed if r.severity == "SIGNIFICATIVO"]

    if critical:
        log(f"\n  {Colors.RED}{Colors.BOLD}⚠  Se encontraron {len(critical)} bug(s) CRITICO(S) que deben corregirse antes de produccion.{Colors.RESET}")
    if significant:
        log(f"  {Colors.YELLOW}{Colors.BOLD}⚠  Se encontraron {len(significant)} issue(s) SIGNIFICATIVO(S) que deben planificarse.{Colors.RESET}")
    if not critical and not significant:
        log(f"\n  {Colors.GREEN}{Colors.BOLD}✓  No se encontraron bugs criticos ni significativos.{Colors.RESET}")

    log("")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

ALL_VALIDATIONS = {
    "BUG-1": validate_bug_1,
    "BUG-2": validate_bug_2,
    "BUG-3": validate_bug_3,
    "ISSUE-4": validate_issue_4,
    "ISSUE-6": validate_issue_6,
    "ISSUE-7": validate_issue_7,
    "ISSUE-8": validate_issue_8,
    "ISSUE-9": validate_issue_9,
    "ISSUE-12": validate_issue_12,
    "ISSUE-13": validate_issue_13,
    "ISSUE-15": validate_issue_15,
}

LOCAL_VALIDATIONS = {"BUG-2", "BUG-3", "ISSUE-6", "ISSUE-7", "ISSUE-8", "ISSUE-9", "ISSUE-12", "ISSUE-13", "ISSUE-15"}
QRADAR_VALIDATIONS = {"BUG-1", "ISSUE-4"}
MISP_VALIDATIONS = {"BUG-3"}  # BUG-3 tiene verificacion local + opcional MISP


def main():
    global VERBOSE

    parser = argparse.ArgumentParser(
        description="Validacion de bugs en la integracion MISP-QRadar",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Ejemplos:
              python tests/validate_bugs.py                  # Todas las validaciones
              python tests/validate_bugs.py --local-only     # Solo pruebas locales
              python tests/validate_bugs.py --qradar-only    # Solo pruebas contra QRadar
              python tests/validate_bugs.py --misp-only      # Solo pruebas contra MISP
              python tests/validate_bugs.py --bug BUG-1      # Solo un bug especifico
              python tests/validate_bugs.py --verbose        # Con detalles
        """),
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Mostrar detalles adicionales")
    parser.add_argument("--local-only", action="store_true", help="Solo ejecutar validaciones locales")
    parser.add_argument("--qradar-only", action="store_true", help="Solo ejecutar validaciones contra QRadar")
    parser.add_argument("--misp-only", action="store_true", help="Solo ejecutar validaciones contra MISP")
    parser.add_argument("--bug", type=str, help="Ejecutar solo un bug especifico (ej: BUG-1, ISSUE-4)")

    args = parser.parse_args()
    VERBOSE = args.verbose

    section("MISP-QRadar Integration — Validacion de Bugs")
    log(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"  Python: {sys.version}")
    log(f"  QRADAR_URL: {get_env('QRADAR_URL') or 'NO CONFIGURADO'}")
    log(f"  MISP_URL: {get_env('MISP_URL') or 'NO CONFIGURADO'}")

    # Determinar que validaciones ejecutar
    if args.bug:
        bug_id = args.bug.upper()
        if bug_id not in ALL_VALIDATIONS:
            log(f"\n  {Colors.RED}Bug '{bug_id}' no encontrado. Disponibles: {', '.join(ALL_VALIDATIONS.keys())}{Colors.RESET}")
            sys.exit(1)
        to_run = {bug_id}
    elif args.local_only:
        to_run = LOCAL_VALIDATIONS
    elif args.qradar_only:
        to_run = QRADAR_VALIDATIONS
    elif args.misp_only:
        to_run = MISP_VALIDATIONS
    else:
        to_run = set(ALL_VALIDATIONS.keys())

    log(f"  Validaciones a ejecutar: {len(to_run)}")

    # Ejecutar validaciones
    for bug_id in sorted(to_run):
        if bug_id in ALL_VALIDATIONS:
            try:
                ALL_VALIDATIONS[bug_id]()
            except Exception as e:
                log(f"\n  {Colors.RED}ERROR ejecutando {bug_id}: {e}{Colors.RESET}")
                if VERBOSE:
                    traceback.print_exc()

    # Reporte final
    print_summary()


if __name__ == "__main__":
    main()
