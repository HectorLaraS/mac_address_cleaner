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
DEFAULT_TIMEOUT = 30  # seconds
RETRY_MAX_ATTEMPTS = 5
RETRY_BASE_SLEEP = 1.0  # seconds (exponential backoff)
RETRY_STATUS_CODES = {429, 503}
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

# Avoid duplicate handlers on reload
if not any(isinstance(h, logging.FileHandler) and "mac_ise_execution.log" in getattr(h, "baseFilename", "")
           for h in exec_logger.handlers):
    handler = logging.FileHandler("mac_ise_execution.log")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    exec_logger.addHandler(handler)

# Silence SSL warnings (common in internal ISE deployments)
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


def _build_job_name(api_time: datetime, user: str) -> str:
    # same-second collisions are possible; add a short suffix
    suffix = f"{int(time.time() * 1000) % 100000}"
    return f"{api_time.strftime('%Y%m%d_%H%M%S')}_{user}_{suffix}.log"


def _request_with_retry(method: str, url: str, *, auth: Tuple[str, str], timeout: int = DEFAULT_TIMEOUT) -> requests.Response:
    """
    Performs an HTTP request with exponential backoff retry for:
      - 429 / 503
      - timeouts / connection errors

    Returns the final response if no fatal condition occurs.
    Raises APIException on repeated failures.
    """
    last_exc: Optional[Exception] = None

    for attempt in range(1, RETRY_MAX_ATTEMPTS + 1):
        try:
            resp = requests.request(method, url, auth=auth, verify=False, timeout=timeout)

            # auth errors are fatal
            if resp.status_code == 401:
                raise APIException("Authentication failed (401)")

            if resp.status_code in RETRY_STATUS_CODES:
                # retry with backoff
                sleep_s = RETRY_BASE_SLEEP * (2 ** (attempt - 1))
                exec_logger.info(
                    f"retryable_status={resp.status_code} | attempt={attempt}/{RETRY_MAX_ATTEMPTS} | "
                    f"sleep={sleep_s:.1f}s | url={url}"
                )
                time.sleep(sleep_s)
                continue

            return resp

        except APIException:
            # re-raise our own controlled exception
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

    # if we got here, retries exhausted
    if last_exc:
        error_logger.error(f"HTTP retry exhausted: {method} {url} | last_exception={last_exc}")
        raise APIException(f"Request failed after retries: {type(last_exc).__name__}: {last_exc}")
    raise APIException("Request failed after retries")


# =========================
# MAC NORMALIZATION
# =========================
def normalize_mac(mac: str, output: str = "plain") -> str:
    """
    Normalize MAC address.

    Accepted formats:
      - AA:AA:BB:BB:CC:CC
      - aaaa.bbbb.cccc

    output:
      - plain  -> AAAABBBBCCCC
      - colon  -> AA:AA:BB:BB:CC:CC
      - ise    -> AA%3AAA%3ABB%3ABB%3ACC%3ACC
    """
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
    """
    Validates MAC addresses from a text file.

    Returns:
      ok        -> bool
      endpoints -> list of MACs in ISE format (AA%3ABB%3A...)
      errors    -> list of (line_number, raw_value, reason)
    """
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
    api_pass: Optional[str] = None
) -> Tuple[datetime, str, str, str, int]:
    """
    Deletes an endpoint from ISE.

    endpoint: must be in ISE-encoded format (AA%3ABB%3A...)
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
    job_name = _build_job_name(api_time, user)
    job_path = os.path.join("./jobs_executed", job_name)

    url = f"{API_URL}/{endpoint}"
    t0 = time.perf_counter()

    try:
        resp = _request_with_retry("DELETE", url, auth=(user, pwd), timeout=DEFAULT_TIMEOUT)
        status = resp.status_code

        # Write job log
        with open(job_path, "a", encoding="utf-8") as log:
            if status == 200:
                log.write(f"{datetime.now().isoformat()} | REMOVED | {mac_colon}\n")
            elif status == 404:
                log.write(f"{datetime.now().isoformat()} | NOT_FOUND | {mac_colon}\n")
            else:
                log.write(f"{datetime.now().isoformat()} | STATUS_{status} | {mac_colon}\n")

        # Execution log
        exec_logger.info(
            f"user={user} | DELETE | mac={mac_colon} | status={status} | time={(time.perf_counter() - t0):.3f}s"
        )

        # History log (audit)
        history_path = os.path.join("./jobs_executed", "history.log")
        with open(history_path, "a", encoding="utf-8") as h:
            if status == 200:
                h.write(f"{api_time} | User: {user} | Detailed Log: {job_name} | Endpoint Removed: {mac_colon}\n")
            elif status == 404:
                h.write(f"{api_time} | User: {user} | Detailed Log: {job_name} | Endpoint Not Found: {mac_colon}\n")
            else:
                h.write(f"{api_time} | User: {user} | Detailed Log: {job_name} | Endpoint Status {status}: {mac_colon}\n")

        return api_time, user, job_name, mac_colon, status

    except APIException:
        # already logged by retry helper or auth
        raise
    except Exception as e:
        error_logger.error(f"DELETE unexpected error: {e}")
        raise APIException(f"Unexpected error: {e}")
