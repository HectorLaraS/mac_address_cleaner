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

# =========================
# ENV
# =========================
load_dotenv()

API_URL = os.getenv("API_URL")  # base URL
API_USER = os.getenv("API_USER")
API_PASS = os.getenv("API_PASS")

# =========================
# HTTP / RETRY SETTINGS
# =========================
DEFAULT_TIMEOUT = 30
RETRY_MAX_ATTEMPTS = 5
RETRY_BASE_SLEEP = 1.0
RETRY_STATUS_CODES = {429, 503}  # retry only for these status codes
RETRY_EXCEPTIONS = (
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError,
    requests.exceptions.ChunkedEncodingError,
    requests.exceptions.RequestException,
)

# =========================
# LOGGING
# =========================
logging.basicConfig(
    filename="mac_ise_errors.log",
    level=logging.ERROR,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
error_logger = logging.getLogger("MAC_ISE_ERROR")

exec_logger = logging.getLogger("MAC_ISE_EXEC")
exec_logger.setLevel(logging.INFO)

if not any(isinstance(h, logging.FileHandler) and "mac_ise_execution.log" in getattr(h, "baseFilename", "")
           for h in exec_logger.handlers):
    handler = logging.FileHandler("mac_ise_execution.log")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    exec_logger.addHandler(handler)

# Silence SSL warnings
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# =========================
# INTERNAL HELPERS
# =========================
def _ensure_dirs() -> None:
    os.makedirs("./jobs_executed", exist_ok=True)
    os.makedirs("./backup", exist_ok=True)
    os.makedirs("./reports", exist_ok=True)
    os.makedirs("./input_files", exist_ok=True)


def _get_creds(api_user: Optional[str], api_pass: Optional[str]) -> Tuple[str, str]:
    user = (api_user or "").strip() or (API_USER or "")
    pwd = (api_pass or "").strip() or (API_PASS or "")

    if not user or not pwd:
        raise APIException("Missing API credentials (username/password)")
    return user, pwd


def _append_job_log(job_log_name: str, line: str) -> None:
    _ensure_dirs()
    if not job_log_name:
        return
    path = os.path.join("./jobs_executed", job_log_name)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _request_with_retry(method: str, url: str, *, auth: Tuple[str, str], timeout: int = DEFAULT_TIMEOUT) -> requests.Response:
    """
    HTTP request with exponential backoff retry for:
      - 429 / 503
      - timeouts / connection errors

    FATAL (no retry):
      - 401 Authentication failed
      - 403 Forbidden / insufficient privileges
    """
    last_exc: Optional[Exception] = None

    for attempt in range(1, RETRY_MAX_ATTEMPTS + 1):
        try:
            resp = requests.request(method, url, auth=auth, verify=False, timeout=timeout)

            # Fatal auth / authorization errors: DO NOT RETRY
            if resp.status_code == 401:
                raise APIException("Authentication failed (401)")
            if resp.status_code == 403:
                raise APIException("Authorization failed / forbidden (403)")

            if resp.status_code in RETRY_STATUS_CODES:
                sleep_s = RETRY_BASE_SLEEP * (2 ** (attempt - 1))
                exec_logger.info(
                    f"retryable_status={resp.status_code} | attempt={attempt}/{RETRY_MAX_ATTEMPTS} | "
                    f"sleep={sleep_s:.1f}s | url={url}"
                )
                time.sleep(sleep_s)
                continue

            return resp

        except APIException:
            raise
        except RETRY_EXCEPTIONS as e:
            last_exc = e
            sleep_s = RETRY_BASE_SLEEP * (2 ** (attempt - 1))
            exec_logger.info(
                f"retry_exception={type(e).__name__} | attempt={attempt}/{RETRY_MAX_ATTEMPTS} | "
                f"sleep={sleep_s:.1f}s | url={url}"
            )
            time.sleep(sleep_s)
            continue

    if last_exc:
        error_logger.error(f"HTTP retry exhausted: {method} {url} | last_exception={last_exc}")
        raise APIException(f"Request failed after retries: {type(last_exc).__name__}: {last_exc}")
    raise APIException("Request failed after retries")


# =========================
# MAC NORMALIZATION
# =========================
def normalize_mac(mac: str, output: str = "plain") -> str:
    mac = (mac or "").strip()

    pattern_colon = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    pattern_dot = re.compile(r'^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$')

    if pattern_colon.match(mac):
        raw = mac.replace(":", "")
    elif pattern_dot.match(mac):
        raw = mac.replace(".", "")
    else:
        raise ValueError(f"Invalid MAC format: {mac}")

    raw = raw.upper()
    if len(raw) != 12:
        raise ValueError(f"Invalid MAC length: {mac}")

    if output == "plain":
        return raw
    if output == "colon":
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    if output == "ise":
        return "%3A".join(raw[i:i + 2] for i in range(0, 12, 2))

    raise ValueError("Invalid output format requested")


# =========================
# VALIDATION (FRIENDLY)
# =========================
def validate_macs(file_location: str) -> Tuple[bool, List[str], List[Tuple[int, str, str]]]:
    endpoints: List[str] = []
    errors: List[Tuple[int, str, str]] = []

    with open(file_location, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, raw in enumerate(f, start=1):
            value = raw.strip()
            if not value:
                continue
            try:
                endpoints.append(normalize_mac(value, "ise"))
            except Exception as e:
                errors.append((line_no, value, str(e)))

    ok = (len(errors) == 0 and len(endpoints) > 0)
    return ok, endpoints, errors


# =========================
# API FUNCTIONS
# =========================
def get_endpoints(api_user: Optional[str] = None, api_pass: Optional[str] = None) -> Any:
    if not API_URL:
        raise APIException("API_URL not configured in .env")

    user, pwd = _get_creds(api_user, api_pass)
    t0 = time.perf_counter()

    resp = _request_with_retry("GET", API_URL, auth=(user, pwd), timeout=DEFAULT_TIMEOUT)
    if resp.status_code != 200:
        raise APIException(f"Unexpected response: {resp.status_code}")

    exec_logger.info(f"user={user} | GET endpoints | time={(time.perf_counter() - t0):.3f}s")
    return resp.json()


def create_database_copy(api_user: Optional[str] = None, api_pass: Optional[str] = None) -> str:
    """
    Creates a readable JSON backup of get_endpoints() under ./backup.
    Returns the created filename.
    """
    _ensure_dirs()
    payload = get_endpoints(api_user, api_pass)

    now = datetime.now()
    filename = f"backup_{now.strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join("./backup", filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)

    return filename


def remove_endpoint(
    endpoint: str,
    api_user: Optional[str] = None,
    api_pass: Optional[str] = None,
    job_log_name: str = ""
) -> Tuple[datetime, str, str, str, int]:
    """
    Deletes an endpoint from ISE.
    Writes to the SINGLE run log (job_log_name).

    Returns:
      api_time, user, job_log_name, mac_colon, status_code
    """
    _ensure_dirs()

    if not API_URL:
        raise APIException("API_URL not configured in .env")

    user, pwd = _get_creds(api_user, api_pass)
    endpoint = (endpoint or "").strip()
    if not endpoint:
        raise APIException("Endpoint value is empty")

    mac_colon = endpoint.replace("%3A", ":")
    api_time = datetime.now()
    url = f"{API_URL}/{endpoint}"
    t0 = time.perf_counter()

    resp = _request_with_retry("DELETE", url, auth=(user, pwd), timeout=DEFAULT_TIMEOUT)
    status = resp.status_code

    # Write to the single run log
    if status == 200:
        _append_job_log(job_log_name, f"{datetime.now().isoformat()} | REMOVED   | {mac_colon}")
    elif status == 404:
        _append_job_log(job_log_name, f"{datetime.now().isoformat()} | NOT_FOUND | {mac_colon}")
    else:
        _append_job_log(job_log_name, f"{datetime.now().isoformat()} | STATUS_{status} | {mac_colon}")

    exec_logger.info(
        f"user={user} | DELETE | mac={mac_colon} | status={status} | time={(time.perf_counter() - t0):.3f}s"
    )

    # history.log (audit trail)
    history_path = os.path.join("./jobs_executed", "history.log")
    with open(history_path, "a", encoding="utf-8") as h:
        if status == 200:
            h.write(f"{api_time} | User: {user} | Run Log: {job_log_name} | Endpoint Removed: {mac_colon}\n")
        elif status == 404:
            h.write(f"{api_time} | User: {user} | Run Log: {job_log_name} | Endpoint Not Found: {mac_colon}\n")
        else:
            h.write(f"{api_time} | User: {user} | Run Log: {job_log_name} | Endpoint Status {status}: {mac_colon}\n")

    return api_time, user, job_log_name, mac_colon, status
