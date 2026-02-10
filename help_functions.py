import requests
from dotenv import load_dotenv
from datetime import datetime
import logging
from typing import Dict, List, Any, Tuple
from APIException import APIException
import json 
import os
import time
import re

load_dotenv()

API_URL = os.getenv("API_URL")
API_USER = os.getenv("API_USER")
API_PASS = os.getenv("API_PASS")

# ==========================
# 📝 LOGGING
# ==========================
# ERROR log
logging.basicConfig(
    filename="mac_ise_errors.log",
    level=logging.ERROR,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
error_logger = logging.getLogger("MAC_ISE_ERROR")

# EXECUTION log (nuevo)
exec_logger = logging.getLogger("MAC_ISE_EXEC")
exec_logger.setLevel(logging.INFO)

exec_handler = logging.FileHandler("mac_ise_execution.log")
exec_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
exec_logger.addHandler(exec_handler)

def get_endpoints():
    api_fetch_time = datetime.now()

    t_fetch_start = time.perf_counter()
    try:
        req = requests.get(API_URL,auth=(API_USER,API_PASS), verify=False,timeout=30)

        if req.status_code == 401:
            raise APIException("Username or Password error (401)")
        
        if req.status_code != 200:
                raise APIException(f"unexpected response: {req.status_code}")
        
        payload = req.json()

        t_fetch_end = time.perf_counter()
        exec_logger.info(
            f"user running: {API_USER} | "
            f"API fetch at {api_fetch_time.isoformat()} | "
            f"Endpoints={len(payload)} | "
            f"fetch_time={(t_fetch_end - t_fetch_start):.3f}s"
        )

        return payload

    except requests.exceptions.RequestException as e:

        raise APIException(f"Error de conexion: {e}")
    
def remove_endpoint(endpoint):
    mac_format = endpoint.replace("%3A",":")
    api_fetch_time = datetime.now()
    total_removed = 0
    del_api = f"{API_URL}/{endpoint}"
    t_fetch_start = time.perf_counter()
    job_title = f"{api_fetch_time.year}{api_fetch_time.month}{api_fetch_time.day}_{api_fetch_time.hour}{api_fetch_time.minute}_{API_USER}.log"
    with open(f".//jobs_executed//{job_title}","a") as log: 
        try:
            req = requests.delete(del_api,auth=(API_USER,API_PASS), verify=False,timeout=30)

            if req.status_code == 401:
                raise APIException("Username or Password error (401)")
            
            if req.status_code == 404:
                log.write(f"{datetime.now().isoformat()} | WARN | {endpoint} not found \n")
            
            if req.status_code == 200:
                log.write(f"{datetime.now().isoformat()} | INFO | {endpoint} removed \n")
                total_removed += 1 

            if req.status_code != 200 and req.status_code != 404:
                    raise APIException(f"unexpected response: {req.status_code}")

        except requests.exceptions.RequestException as e:

            raise APIException(f"Error de conexion: {e}")
        
    t_fetch_end = time.perf_counter()
    exec_logger.info(
        f"user running: {API_USER} | "
        f"API remove endpoint at {api_fetch_time.isoformat()} | "
        f"Job {job_title} removes {mac_format} | "
        f"fetch_time={(t_fetch_end - t_fetch_start):.3f}s"
    )
    with open(".//jobs_executed//history.log","a") as hist_log:
        hist_log.write(f"{api_fetch_time} | User: {API_USER} | Detailed Log: {job_title} | Endpoint Removed: {mac_format} \n")


def create_database_copy():
    payload = get_endpoints()
    current_dt = datetime.now()
    backup_db = f"backup_{current_dt.year}{current_dt.month}{current_dt.day}_{current_dt.hour}{current_dt.minute}.json"

    with open(f".\\backup\\{backup_db}","a",encoding="utf-8") as db_file:
        json.dump(
            payload,
            db_file,
            indent=4,
            ensure_ascii=False
        )

def normalize_mac(mac: str, output: str = "plain") -> str:
    mac = mac.strip()

    # Detectar formatos válidos
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

    raise ValueError("output debe ser 'plain' o 'colon'")

def validate_macs(file_location: str) -> bool:
    is_correct = False
    lst_endpoint: list[str] = []
    with open(file_location,"r") as tmp_db:
        for endpoint in tmp_db:
            try:
                new_mac = normalize_mac(endpoint,"ise")
                is_correct = True
                lst_endpoint.append(new_mac)
            except Exception as e:
                is_correct = False
    return is_correct, lst_endpoint