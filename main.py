import requests
from dotenv import load_dotenv
from datetime import datetime
import logging
import time
from typing import Dict, List, Any, Tuple
from help_functions import *
from APIException import APIException
import json 
import os
import asyncio


async def main():

    # ==========================
    # VALIDATION 
    # ==========================
    file_name = "test.txt"
    if validate_macs(f".\\input_files\\{file_name}")[0]:
        print(True)
        # ==========================
        # CALL - Database Copy 
        # ==========================
        create_database_copy()
        lst_endpoints = validate_macs(f".\\input_files\\{file_name}")[1]

        # ==========================
        # CALL - Remove endpoints
        # ==========================
        for endp in lst_endpoints:
            remove_endpoint(endp)
    else:
        print(f"❌ FIX THE FILE")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        error_logger.error(
            f"Fallo en MAC_ADDRESS_CLEANER: {e}", exc_info=True
        )
        print(f"❌ Error: {e}")