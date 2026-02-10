import os
import re
import json
import time
import logging
from datetime import datetime
from typing import List, Tuple, Optional, Any

import requests
from dotenv import load_dotenv

from APIException import APIException

# ==========================
# ENV
# ==========================
load_dotenv()

API_URL = os.getenv("API_URL")
API_USER = os.getenv("API_USER")
API_PASS = os.getenv("API_PASS")

# ==========================
# LOGGING
# ==========================
# Error log (archivo)
logging.basicConfig(
    filename="mac_ise_errors.log",
    level=logging.ERROR,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
error_logger = logging.getLogger("MAC_ISE_ERROR")

# Execution log (archivo)
exec_logger = logging.getLogger("MAC_ISE_EXEC")
exec_logger.setLevel(logging.INFO)

# Evita handlers duplicados si importas varias veces
if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "").endswith("mac_ise_execution.log")
           for h in exec_logger.handlers):
    exec_handler = logging.FileHandler("mac_ise_execution.log")
    exec_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    exec_logger.addHandler(exec_handler)

# (Opcional) quitar warnings SSL por verify=False
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# ==========================
# HELPERS
# ==========================
def _ensure_dirs() -> None:
    os.makedirs("./jobs_executed", exist_ok=True)
    os.makedirs("./backup", exist_ok=True)


def _get_creds(api_user: Optional[str], api_pass: Optional[str]) -> tuple[str, str]:
    user = (api_user or "").strip() or (API_USER or "")
    pwd = (api_pass or "").strip() or (API_PASS or "")

    if not user or not pwd:
        raise APIException("Credenciales vacías: ingresa Username y Password (GUI) o configura .env")

    return user, pwd


# ==========================
# API
# ==========================
def get_endpoints(api_user: Optional[str] = None, api_pass: Optional[str] = None) -> Any:
    """
    Obtiene endpoints desde API_URL. Devuelve el JSON parseado (lo que devuelva tu API).
    """
    if not API_URL:
        raise APIException("API_URL no está configurado en .env")

    user, pwd = _get_creds(api_user, api_pass)
    api_fetch_time = datetime.now()

    t0 = time.perf_counter()
    try:
        req = requests.get(API_URL, auth=(user, pwd), verify=False, timeout=30)

        if req.status_code == 401:
            raise APIException("Username or Password error (401)")

        if req.status_code != 200:
            raise APIException(f"unexpected response: {req.status_code}")

        payload = req.json()

        t1 = time.perf_counter()
        exec_logger.info(
            f"user running: {user} | "
            f"API fetch at {api_fetch_time.isoformat()} | "
            f"fetch_time={(t1 - t0):.3f}s"
        )
        return payload

    except requests.exceptions.RequestException as e:
        error_logger.error(f"GET endpoints error: {e}")
        raise APIException(f"Error de conexion: {e}")


def remove_endpoint(
    endpoint: str,
    api_user: Optional[str] = None,
    api_pass: Optional[str] = None
) -> Tuple[datetime, str, str, str, int]:
    """
    Borra un endpoint. endpoint debe venir en formato ISE (ej: AA%3ABB%3A...).
    Devuelve: (api_fetch_time, user, job_title, mac_format, status_code)

    Reglas:
    - 200 -> Removed
    - 404 -> Not Found
    - 401 -> error credenciales
    - other -> APIException
    """
    _ensure_dirs()

    if not API_URL:
        raise APIException("API_URL no está configurado en .env")

    user, pwd = _get_creds(api_user, api_pass)

    endpoint = (endpoint or "").strip()
    if not endpoint:
        raise APIException("Endpoint vacío")

    mac_format = endpoint.replace("%3A", ":")
    api_fetch_time = datetime.now()

    del_api = f"{API_URL}/{endpoint}"
    t0 = time.perf_counter()

    # Job log (por ejecución)
    job_title = f"{api_fetch_time.year}{api_fetch_time.month}{api_fetch_time.day}_{api_fetch_time.hour}{api_fetch_time.minute}_{user}.log"
    job_path = f"./jobs_executed/{job_title}"

    try:
        req = requests.delete(del_api, auth=(user, pwd), verify=False, timeout=30)
        status = req.status_code

        if status == 401:
            raise APIException("Username or Password error (401)")

        # Escribe job log detallado
        with open(job_path, "a", encoding="utf-8") as log:
            if status == 200:
                log.write(f"{datetime.now().isoformat()} | INFO | {endpoint} removed\n")
            elif status == 404:
                log.write(f"{datetime.now().isoformat()} | WARN | {endpoint} not found\n")
            else:
                log.write(f"{datetime.now().isoformat()} | ERROR | unexpected response: {status}\n")

        # Registro de ejecución (mac_ise_execution.log)
        t1 = time.perf_counter()
        exec_logger.info(
            f"user running: {user} | "
            f"API remove endpoint at {api_fetch_time.isoformat()} | "
            f"Job {job_title} | "
            f"status={status} | "
            f"mac={mac_format} | "
            f"fetch_time={(t1 - t0):.3f}s"
        )

        # History log acumulativo (FIX: 200 vs 404)
        history_path = "./jobs_executed/history.log"
        with open(history_path, "a", encoding="utf-8") as hist_log:
            if status == 200:
                hist_log.write(
                    f"{api_fetch_time} | User: {user} | Detailed Log: {job_title} | Endpoint Removed: {mac_format}\n"
                )
            elif status == 404:
                hist_log.write(
                    f"{api_fetch_time} | User: {user} | Detailed Log: {job_title} | Endpoint Not Found: {mac_format}\n"
                )
            else:
                hist_log.write(
                    f"{api_fetch_time} | User: {user} | Detailed Log: {job_title} | Endpoint Status {status}: {mac_format}\n"
                )

        if status not in (200, 404):
            raise APIException(f"unexpected response: {status}")

        return api_fetch_time, user, job_title, mac_format, status

    except requests.exceptions.RequestException as e:
        error_logger.error(f"DELETE endpoint error: {e}")
        raise APIException(f"Error de conexion: {e}")


def create_database_copy(api_user: Optional[str] = None, api_pass: Optional[str] = None) -> str:
    """
    Crea un backup JSON de lo que regrese get_endpoints() en ./backup.
    Retorna el nombre del archivo creado.
    """
    _ensure_dirs()

    payload = get_endpoints(api_user=api_user, api_pass=api_pass)
    current_dt = datetime.now()
    backup_db = f"backup_{current_dt.year}{current_dt.month}{current_dt.day}_{current_dt.hour}{current_dt.minute}.json"

    path = os.path.join("./backup", backup_db)
    with open(path, "w", encoding="utf-8") as db_file:
        json.dump(payload, db_file, indent=4, ensure_ascii=False)

    return backup_db


# ==========================
# MAC VALIDATION / NORMALIZATION
# ==========================
def normalize_mac(mac: str, output: str = "plain") -> str:
    """
    Normaliza MAC:
      - input: 'AA:AA:BB:BB:CC:CC' o 'aaaa.bbbb.cccc'
      - output:
          'plain' -> 'AAAABBBBCCCC'
          'colon' -> 'AA:AA:BB:BB:CC:CC'
          'ise'   -> 'AA%3AAA%3ABB%3ABB%3ACC%3ACC'
    """
    mac = (mac or "").strip()

    pattern_colon = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    pattern_dot   = re.compile(r'^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$')

    if pattern_colon.match(mac):
        raw = mac.replace(":", "")
    elif pattern_dot.match(mac):
        raw = mac.replace(".", "")
    else:
        raise ValueError(f"Formato de MAC inválido: {mac}")

    raw = raw.upper()

    if len(raw) != 12:
        raise ValueError(f"MAC inválida después de normalizar: {mac}")

    if output == "plain":
        return raw

    if output == "colon":
        return ":".join(raw[i:i+2] for i in range(0, 12, 2))

    if output == "ise":
        return "%3A".join(raw[i:i+2] for i in range(0, 12, 2))

    raise ValueError("output debe ser 'plain' o 'colon' o 'ise'")


def validate_macs(file_location: str) -> Tuple[bool, List[str]]:
    """
    Lee un .txt, valida cada línea como MAC (colon o dot), y regresa:
      (is_correct, lst_endpoint_ise)

    lst_endpoint_ise contiene MACs en formato ISE para borrar (AA%3ABB%3A...).
    """
    is_correct = True
    lst_endpoint: List[str] = []

    with open(file_location, "r", encoding="utf-8", errors="ignore") as tmp_db:
        for line in tmp_db:
            line = line.strip()
            if not line:
                continue

            try:
                lst_endpoint.append(normalize_mac(line, "ise"))
            except Exception:
                is_correct = False

    return is_correct, lst_endpoint
