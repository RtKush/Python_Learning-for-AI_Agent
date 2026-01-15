import subprocess
import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import re
import requests
import hashlib
import json
import queue
import time
import psutil
import threading
import glob
from datetime import datetime
import asyncio
import logging
from logging.handlers import RotatingFileHandler
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
import shutil
import binascii
import pwd
import concurrent.futures
from nats.aio.client import Client as NATS
from nats.js.api import DeliverPolicy, ConsumerConfig, AckPolicy
import aiohttp
import urllib.parse
import websockets
import pty
import ssl
import signal
import select
import certifi
import fcntl
import termios

# CHANGE THE FOLLOWING ENV_VARIABLE FROM DEV/TEST/PROD
# ----------------------------------------------------
ENVIRONMENT = "DEMO"
CERT_NEEDED = True
LOGS_NEEDED = False
# ----------------------------------------------------

if ENVIRONMENT == "PROD":
    HOSTNAME = "https://cyberauditor.in"
elif ENVIRONMENT == "TEST":
    HOSTNAME = "https://test.cyberauditor.in"
elif ENVIRONMENT == "DEV":
    HOSTNAME = "https://dev.cyberauditor.in"
else:
    HOSTNAME = "https://nishar.ca.in"

# ===================CONSTANTS===================
TRIGGER_TYPE = sys.argv[-1] if len(sys.argv) > 1 else ""
LOGS_DESTINATION_DIRECTORY = "/var/log/cyberauditor_linux_agent_logs"
ENCRYPTED_AUDIT_LOGS_DIRECTORY = LOGS_DESTINATION_DIRECTORY + '/ca-audit-logs'
VISIBLE_CMD_LOGS_DESTINATION_DIRECTORY = LOGS_DESTINATION_DIRECTORY + '/ca-raw-cmd-logs'
ENCRYPTED_CMD_LOGS_DESTINATION_DIRECTORY = LOGS_DESTINATION_DIRECTORY + '/ca-cmd-logs'
DESTINATION_WORKING_DIRECTORY = "/etc/cyberauditor_linux_agent/"
BACKUP_WORKING_DIRECTORY = "/tmp/backup_cyberauditor_linux_agent/"
AUDIT_EXE_DIRECTORY_NAME = "/etc/cyberauditor_linux_agent/audit_exe/"
AGENT_FILE_NAME = "audit-agent"
TIMEOUT_SUBPROCESS = 10
PIDS_MAINTAIN_FILE_PATH = "/tmp/cyberauditor_linux_pids.txt"
CMD_TIMESTAMP_FILE_PATH = "/var/lib/cyberauditor-linux-agent/cmd_previous_time.txt"
ORG_FEATURES_FILE_PATH = "/var/lib/cyberauditor-linux-agent/org_features.txt"
RAM_DUMP_LOGS_FOLDER = LOGS_DESTINATION_DIRECTORY + '/ca-mem-dump-logs'
ACCESS_CODE_FILE = LOGS_DESTINATION_DIRECTORY + "/access_code.json"
AVML_BINARY = DESTINATION_WORKING_DIRECTORY + "avml"
FANOTIFY_BINARY = DESTINATION_WORKING_DIRECTORY + "ca-fanotify"
CA_FILE = os.path.join(DESTINATION_WORKING_DIRECTORY, "ca.crt") if CERT_NEEDED else None
ACCEPTED = 0
REJECTED = 42
ERROR = -1

# ===================URLS===================
BACKEND_API_URL = f"{HOSTNAME}/api/v1/linux/ingest/main"
FETCH_API_PACKAGE = f"{HOSTNAME}/api/v1/linux/download"
BACKEND_CONFIG_API = f"{HOSTNAME}/api/v1/linux/config"
WATCHDOG_ALERT_API_URL = f'{HOSTNAME}/api/v1/organization/save/pc/alert'
WATCHER_API_URL = f"{HOSTNAME}/api/v1/organization/ingest/file-transfer/data"
CMD_API_URL = f"{HOSTNAME}/api/v1/command-history-info/ingest/command/data/Linux"
NATS_URL = f"wss:{HOSTNAME.replace('https:', '')}/nats"
PATCH_DOWNLOAD_API = f"{HOSTNAME}/api/v1/patch-management/download/patch-update"
STATUS_SEND_URL = f"{HOSTNAME}/api/v1/patch-management/update-patch-status"
ASK_FOR_CAMMANDS_URL = f"{HOSTNAME}/api/v1/command-management/fetchCommands"
SEND_COMMANDS_URL = f"{HOSTNAME}/api/v1/command-management/save-command-result"
INIT_DUMP_URL = f"{HOSTNAME}/api/v1/command-management/init-ram-dump"
UPLOAD_CHUNK_URL = f"{HOSTNAME}/api/v1/command-management/upload-chunk"
COMPLETE_URL = f"{HOSTNAME}/api/v1/command-management/complete-ram-dump"
WEBSOCKET_URL = f"wss:{HOSTNAME.replace('https:', '')}/ws"

# ===================KEYS===================
CA_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtkqRhn4d0+v2OLBQuvP8
rWY7CM418Tu0UoS6LuRdGEEFt/AE4lMD+rXTzGYkvRIskGCZ+otnQt2hg8MO+qHC
upylXcHkNpKgCdkDn5D+hB71OcJQDnzTkTzBEJIymZyGIea4YBPIsqhjQyPxdYel
0HMmRYPz0/okwUyJIsmiVaG+U5FW1VeIdtFhf02qCdbIndiWFdIbkP3OG32EJIUY
YEdF3aT3qxDH49qiNTI6D/V526EJmTCqjcOeeAt4sxoUgVxgqyL6YvOyYgBmTgeV
iZKI8VZ8+uRCnkwDBDsDCk6e7xEd7mGOk11lMJiyMj7kmttvlRbFbvb6FbVYxX5j
mwIDAQAB
-----END PUBLIC KEY-----"""

p_key = base64.urlsafe_b64decode('nAy7rLX4teIS2CR_2lpV8mt67VvTQT53o2D_-ErE6Ng=')
iv = b'1234567890123456'


def setup_logger(logger_name="CYBERAUDITOR", log_filename="/tmp/cyberauditor_ca_agent.log", max_bytes=52_428_800,
                 backup_count=5):
    """
    Set up a logger with rotating file handler.
    
    Args:
        logger_name (str): The Key of the the logger.
        log_filename (str): The name of the log file.
        max_bytes (int): Maximum size of the log file in bytes before it rotates.
        backup_count (int): Number of backup files to keep when rotation happens.
    
    Returns:
        logger: Configured logger instance.
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    # Create a rotating file handler
    file_handler = RotatingFileHandler(
        log_filename, maxBytes=max_bytes, backupCount=backup_count
    )
    file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


def encrypt_string(file_path_incoming, file_content_to_encrypt):
    try:
        key = p_key[:32]  # Ensure the key is 32 bytes

        # Create cipher object and encrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_content_value = cipher.encrypt(pad(file_content_to_encrypt.encode(), AES.block_size))

        # Encode the encrypted content with base64
        encoded_content = base64.b64encode(encrypted_content_value)

        # Make the file if does not exist
        os.makedirs(os.path.dirname(file_path_incoming), exist_ok=True)

        # Write the encrypted content to the file
        with open(file_path_incoming, 'wb') as file_to_write:
            file_to_write.write(encoded_content)

        return encoded_content

    except Exception as encrypted_content_err:
        print(f"encrypt_string Error: {encrypted_content_err}")

    return b""


def decrypt_string(file_path_incoming):
    try:
        key = p_key[:32]  # Ensure the key is 32 bytes

        # Read the encrypted content from the file
        with open(file_path_incoming, 'rb') as file_to_read:
            encoded_content = file_to_read.read()

        # Decode the base64 encoded content
        encrypted_content_value = base64.b64decode(encoded_content)

        if encrypted_content_value:
            # Create cipher object and decrypt the data
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_content_value = unpad(cipher.decrypt(encrypted_content_value), AES.block_size).decode()

            return decrypted_content_value

    except Exception as decrypted_content_err:
        print(f"decrypt_string Error: {decrypted_content_err}")

    return ""


def generate_visible_agent_log_file(dir_name, logged_messages, log_file_name):
    try:
        current_log_time = time.strftime("%d-%m-%Y-%H-%M-%S")
        if not os.path.exists(dir_name):
            print(f"Creating directory named {dir_name}.")
            os.mkdir(dir_name)
        ca_raw_agent_log_output_file_name = (
            os.path.join(dir_name,
                         f"{log_file_name}-{current_log_time}.log"))
        with open(ca_raw_agent_log_output_file_name, "w") as ca_raw_agent_logger_file:
            ca_raw_agent_logger_file.write(json.dumps(logged_messages, indent=4))
    except Exception as gen_visible_agent_log_file_error:
        print(f"Error: {repr(gen_visible_agent_log_file_error)}")


def generate_encrypted_agent_log_file(dir_name, payload_logged_messages, log_file_name):
    try:
        try:
            # Ensure the public key is imported correctly
            public_key = RSA.import_key(CA_PUBLIC_KEY)
        except ValueError as e:
            print(f"Error importing public key: {e}")
            return False

        # Encrypt JSON data in chunks
        chunk_size = 190
        encrypted_chunks = []
        data_bytes = payload_logged_messages.encode('utf-8')
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        for i in range(0, len(data_bytes), chunk_size):
            chunk = data_bytes[i:i + chunk_size]
            encrypted_chunk = cipher.encrypt(chunk)

            # Append the encrypted chunk to the list
            encrypted_chunks.append(encrypted_chunk)

        encrypted_data = b''.join(encrypted_chunks)
        encrypted_base64_data = base64.b64encode(encrypted_data)

        if not os.path.exists(dir_name):
            print(f"Creating encrypted agent log file in {dir_name}.")
            os.mkdir(dir_name)

        # Create a timestamp for the ca_log_output_file_name
        current_time = time.strftime("%d-%m-%Y-%H-%M-%S")

        pc_identity_key = get_pc_id_without_lickey()

        ca_log_output_file_name = (
            os.path.join(dir_name,
                         f"{log_file_name}-{pc_identity_key}-{current_time}.log"))

        # Write the encrypted content to the file
        with open(ca_log_output_file_name, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_base64_data)

        def check_log_file():
            try:
                if os.path.exists(ca_log_output_file_name):
                    if os.path.getsize(ca_log_output_file_name) > 0:
                        print(f"File {ca_log_output_file_name} exists and is not empty.")
                        return True
                    else:
                        print(f"File {ca_log_output_file_name} exists but is empty.")
                        return False
                else:
                    print(f"File {ca_log_output_file_name} does not exist.")
                    return False
            except Exception as check_log_file_error:
                print(f"File Check Error: {check_log_file_error}")
                return False

        print(f"Calling check_log_file() function.")
        return check_log_file()

    except Exception as gen_enc_agent_err:
        print(f"Error during enc agent:{gen_enc_agent_err}")
        return None


def generate_encrypted_symmetric_log_file(dir_name, payload_logged_messages, log_file_name):
    try:
        # --- Hybrid Encryption for Sending Results ---
        sym_key = get_random_bytes(32)   # AES-256
        iv = get_random_bytes(16)

        cipher_aes = AES.new(sym_key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(pad(json.dumps(payload_logged_messages).encode(), AES.block_size))
        ciphertext_b64 = base64.b64encode(ciphertext).decode()

        meta_dict = {"key": base64.b64encode(sym_key).decode(), "iv": base64.b64encode(iv).decode()}
        meta_enc = encrypt_using_public_key(json.dumps(meta_dict)).decode('utf-8')

        payload = {
            "meta": meta_enc,
            "encryptedData": ciphertext_b64
        }

        if not os.path.exists(dir_name):
            print(f"Creating encrypted agent log file in {dir_name}.")
            os.mkdir(dir_name)

        # Create a timestamp for the ca_log_output_file_name
        current_time = time.strftime("%d-%m-%Y-%H-%M-%S")

        pc_identity_key = get_pc_id_without_lickey()

        ca_log_output_file_name = (
            os.path.join(dir_name,
                         f"{log_file_name}-{pc_identity_key}-{current_time}.log"))

        encrypted_base64_data = base64.b64encode(json.dumps(payload).encode())
        # Write the encrypted content to the file
        with open(ca_log_output_file_name, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_base64_data)

        def check_log_file():
            try:
                if os.path.exists(ca_log_output_file_name):
                    if os.path.getsize(ca_log_output_file_name) > 0:
                        print(f"File {ca_log_output_file_name} exists and is not empty.")
                        return True
                    else:
                        print(f"File {ca_log_output_file_name} exists but is empty.")
                        return False
                else:
                    print(f"File {ca_log_output_file_name} does not exist.")
                    return False
            except Exception as check_log_file_error:
                print(f"File Check Error: {check_log_file_error}")
                return False

        print(f"Calling check_log_file() function.")
        return check_log_file()

    except Exception as gen_enc_agent_err:
        print(f"Error during enc agent:{gen_enc_agent_err}")
        return None


def send_remaining_encrypted_log_files_to_backend(var_log_folder, api_url):
    try:
        if not os.path.exists(var_log_folder):
            return None

        # List log files in the var log folder ending with ".log"
        log_files = [
            os.path.join(var_log_folder, file_name)
            for file_name in os.listdir(var_log_folder)
            if file_name.endswith(".log")
        ]

        # Sort log files by creation time in descending order
        encrypted_log_files_list = sorted(
            log_files,
            key=os.path.getctime,
        )
        try:
            print("Looping through all LOG files...")
            pc_id = get_pc_id()
            for file_name in encrypted_log_files_list:
                if file_name.endswith(".log"):
                    encrypted_log_file_name_with_path = os.path.join(var_log_folder, file_name)
                    if os.path.exists(encrypted_log_file_name_with_path):
                        try:
                            # Read the encrypted file
                            with open(encrypted_log_file_name_with_path, 'rb') as encrypted_file:
                                encrypted_audit_data_to_send = encrypted_file.read()

                            log_sent_status = send_encrypted_log_to_backend_api(
                                encrypted_audit_data_to_send,
                                api_url, pc_id)

                            if log_sent_status:
                                os.remove(encrypted_log_file_name_with_path)

                            else:
                                print(f"Failed to send LOG data to backend API.")

                        except Exception as backend_api_error:
                            print(f"Error while sending LOG data to backend API: "
                                  f"{repr(backend_api_error)}")
        except Exception as maintain_at_backend_error:
            print(f"Error in maintaining log files: {repr(maintain_at_backend_error)}")

    except Exception as log_maintain_at_backend_error:
        print(f"Error in function->send_remaining_encrypted_log_files_to_backend: "
              f"{repr(log_maintain_at_backend_error)}")

    return None


def send_encrypted_log_to_backend_api(logs_to_send, ca_api_url, pc_id):
    try:
        print("Sending the encrypted log to the backend API...")

        # Convert bytes-like object to string using UTF-8 decoding
        encrypted_log_string = logs_to_send.decode('utf-8')

        if ca_api_url.endswith("/linux/ingest/main"):
            json_data_to_send = {"encryptedData": encrypted_log_string}
            api_response = requests.post(
                ca_api_url,
                json=json_data_to_send,
                timeout=500,
                verify=CA_FILE
            )
        elif "command-history-info/ingest/" in ca_api_url:
            json_data = json.loads(base64.b64decode(logs_to_send))
            payload = json.dumps({"pcId": pc_id, "data": json_data})
            api_response = requests.post(
                ca_api_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                verify=CA_FILE
            )
        else:
            json_data_to_send = json.dumps({"pcId": pc_id, "data": encrypted_log_string})
            api_response = requests.post(
                ca_api_url,
                data=json_data_to_send,
                headers={"Content-Type": "application/json"},
                verify=CA_FILE
            )
        print(f"API Response Status Code: {api_response.status_code}")
        print(f"API Response Text: {api_response.text}")
        return api_response.ok
    except requests.ConnectionError as conn_error:
        print(f"Connection error occurred: {conn_error}")
        return False
    except requests.Timeout as timeout_error:
        print(f"Request timed out: {timeout_error}")
        return False
    except requests.RequestException as request_exception:
        print(f"Request exception occurred: {request_exception}")
        return False
    except Exception as backend_api_post_error:
        print(f"An backend_api_post_error: {backend_api_post_error}")
        return False


def get_hostname_from_env():
    try:
        global HOSTNAME
        global BACKEND_API_URL
        global FETCH_API_PACKAGE
        global BACKEND_CONFIG_API
        global WATCHDOG_ALERT_API_URL
        global WATCHER_API_URL
        global CMD_API_URL
        global PATCH_DOWNLOAD_API
        global STATUS_SEND_URL
        global NATS_URL
        global ASK_FOR_CAMMANDS_URL
        global SEND_COMMANDS_URL
        global INIT_DUMP_URL
        global UPLOAD_CHUNK_URL
        global COMPLETE_URL
        global WEBSOCKET_URL
        if os.path.exists("/etc/environment"):
            with open("/etc/environment", "r") as file_name:
                for line in file_name.readlines():
                    if "CA_HOST_NAME" in line:
                        HOSTNAME = line.split("=")[1].strip()[1:-1]
                        BACKEND_API_URL = f"{HOSTNAME}/api/v1/linux/ingest/main"
                        FETCH_API_PACKAGE = f"{HOSTNAME}/api/v1/linux/download"
                        BACKEND_CONFIG_API = f"{HOSTNAME}/api/v1/linux/config"
                        WATCHDOG_ALERT_API_URL = f"{HOSTNAME}/api/v1/organization/save/pc/alert"
                        WATCHER_API_URL = f"{HOSTNAME}/api/v1/organization/ingest/file-transfer/data"
                        CMD_API_URL = f"{HOSTNAME}/api/v1/command-history-info/ingest/command/data/Linux"
                        PATCH_DOWNLOAD_API = f"{HOSTNAME}/api/v1/patch-management/download/patch-update"
                        STATUS_SEND_URL = f"{HOSTNAME}/api/v1/patch-management/update-patch-status"
                        ASK_FOR_CAMMANDS_URL = f"{HOSTNAME}/api/v1/command-management/fetchCommands"
                        SEND_COMMANDS_URL = f"{HOSTNAME}/api/v1/command-management/save-command-result"
                        INIT_DUMP_URL = f"{HOSTNAME}/api/v1/command-management/init-ram-dump"
                        UPLOAD_CHUNK_URL = f"{HOSTNAME}/api/v1/command-management/upload-chunk"
                        COMPLETE_URL = f"{HOSTNAME}/api/v1/command-management/complete-ram-dump"

                        if HOSTNAME.startswith("https://"):
                            WEBSOCKET_URL = f"wss:{HOSTNAME.replace('https:', '')}/ws"
                            NATS_URL = f"wss:{HOSTNAME.replace('https:', '')}/nats"
                        else:
                            WEBSOCKET_URL = f"ws:{HOSTNAME.replace('http:', '')}/ws"
                            NATS_URL = f"ws:{HOSTNAME.replace('http:', '')}/nats"

    except Exception as hostname_err:
        print(f"An error occurred while getting hostname: {hostname_err}")


def get_os_distributor_name():
    try:
        os_distributor_command = """cat /etc/os-release | grep '^NAME=' | awk -F= '{print $2}' | tr -d '"'"""
        os_distributor_output = subprocess.check_output(os_distributor_command, shell=True, universal_newlines=True,
                                                        stderr=subprocess.PIPE,
                                                        timeout=TIMEOUT_SUBPROCESS).lower()

        os_id_like_command = """cat /etc/os-release | grep '^ID_LIKE=' | awk -F= '{print $2}' | tr -d '"'"""
        os_id_like_output = subprocess.check_output(os_id_like_command, shell=True, universal_newlines=True,
                                                    stderr=subprocess.PIPE,
                                                    timeout=TIMEOUT_SUBPROCESS).lower().strip()

        print(f"Extracted os-distributor name method 1: {os_distributor_output}")
        if "ubuntu" in os_distributor_output or os_id_like_output == "debian":
            return "ubuntu", ".deb"
        elif "red hat" in os_distributor_output or "almalinux" in os_distributor_output \
            or os_id_like_output == "fedora":
            return "rhel", ".rpm"
        elif "centos" in os_distributor_output:
            return "centos", ".rpm"
        else:
            os_distributor_command = 'hostnamectl | grep "Operating System:"'
            os_distributor_output = \
                subprocess.check_output(os_distributor_command, shell=True, universal_newlines=True,
                                        stderr=subprocess.PIPE,
                                        timeout=TIMEOUT_SUBPROCESS).strip().split(":")[1].strip().lower()
            print(f"Extracted os-distributor name method 2: {os_distributor_output}")
            if "ubuntu" in os_distributor_output or "kali" in os_distributor_output:
                return "ubuntu", ".deb"
            elif "red hat" in os_distributor_output or "almalinux" in os_distributor_output:
                return "rhel", ".rpm"
            elif "centos" in os_distributor_output:
                return "centos", ".rpm"
            else:
                return "ubuntu", ".deb"
    except Exception as os_dis_err:
        print(f"Error occurred while getting os-distributor name: {repr(os_dis_err)}")
        return "ubuntu", ".deb"


def get_lickey_from_env():
    try:
        lic_key = ""
        print("Getting License key fron env")
        if os.path.exists("/etc/environment"):
            with open("/etc/environment", "r") as env_file:
                for line in env_file.readlines():
                    if "CA_LICENSE_KEY" in line:
                        lic_key = line.split("=")[1].strip()[1:-1]
        return lic_key
    except Exception as lic_env_err:
        print(f"Erron in get_lic_from_env: {lic_env_err}")
        return ""


def get_system_serial_from_file():
    try:
        with open('/sys/class/dmi/id/product_serial', 'r') as file_serial:
            serial_number = file_serial.read().strip()
            return serial_number if serial_number and " " not in serial_number else ""
    except FileNotFoundError:
        print("Serial number file not found.")
        return ""
    except Exception as system_serial_from_file_error:
        print(f"An error occurred while reading system serial number: "
              f"{system_serial_from_file_error}")
        return ""


def get_motherboard_serial_from_file():
    try:
        with open('/sys/class/dmi/id/board_serial', 'r') as file_mother_board:
            motherboard_serial = file_mother_board.read().strip()
            return motherboard_serial if motherboard_serial and " " not in motherboard_serial else ""
    except FileNotFoundError:
        print("Motherboard serial file not found.")
        return ""
    except Exception as motherboard_serial_from_file_error:
        print(f"An error occurred while reading motherboard serial number: "
              f"{motherboard_serial_from_file_error}")
        return ""


def get_device_uuid_from_file():
    try:
        with open('/sys/class/dmi/id/product_uuid', 'r') as file_uuid:
            uuid = file_uuid.read().strip()
            return uuid if uuid else ""
    except FileNotFoundError:
        print("UUID file not found.")
        return ""
    except Exception as device_uuid_from_file_error:
        print(f"An error occurred while reading device UUID: "
              f"{device_uuid_from_file_error}")
        return ""


def get_system_serial_number():
    try:
        print("Getting system serial number")
        bios_serial_cmd = r"dmidecode -t system | grep 'Serial Number'"
        subprocess_serial_output = subprocess.run(bios_serial_cmd, capture_output=True,
                                                  shell=True, timeout=TIMEOUT_SUBPROCESS, text=True)
        system_serial_output = subprocess_serial_output.stdout.strip()
        system_serial = system_serial_output.split(":")[1].strip()
        if system_serial is None or system_serial == "" or " " in system_serial:
            print("System Serial number could not be retrieved.")
            return ""
        else:
            return system_serial.replace("/", "")
    except Exception as system_serial_output_error:
        print(f"An error occurred while getting system serial number: "
              f"{system_serial_output_error}")
        return ""


def get_motherboard_serial_number():
    try:
        print("Getting motherboard serial number")
        motherboard_serial_cmd = r"dmidecode -t baseboard | grep 'Serial Number'"
        subprocess_motherboard_serial_output = subprocess.run(motherboard_serial_cmd, capture_output=True,
                                                              shell=True, timeout=TIMEOUT_SUBPROCESS, text=True)
        motherboard_serial_output = subprocess_motherboard_serial_output.stdout.strip()
        motherboard_serial = motherboard_serial_output.split(":")[1].strip()
        if motherboard_serial is None or motherboard_serial == "" or " " in motherboard_serial:
            print("Motherboard Serial number could not be retrieved.")
            return ""
        else:
            return motherboard_serial.replace("/", "")
    except Exception as motherboard_serial_output_error:
        print(f"An error occurred while getting motherboard serial number: "
              f"{motherboard_serial_output_error}")
        return ""


def get_device_uuid():
    try:
        print("Getting device uuid number")
        uuid_cmd = r"dmidecode -t system | grep 'UUID'"
        uuid_serial_output = subprocess.run(uuid_cmd, capture_output=True, shell=True,
                                            timeout=TIMEOUT_SUBPROCESS, text=True)
        uuid_serial_output = uuid_serial_output.stdout.strip()
        uuid_serial = uuid_serial_output.split(":")[1].strip()
        if uuid_serial is None or uuid_serial == "":
            print("UUID could not be retrieved.")
            return ""
        else:
            return uuid_serial.replace("/", "")
    except Exception as uuid_serial_output_error:
        print(f"An error occurred while getting uuid: "
              f"{uuid_serial_output_error}")
        return ""


def get_pc_id():
    try:
        print("Getting pc id")
        bios_serial = get_system_serial_number() or get_system_serial_from_file()
        motherb_serial = get_motherboard_serial_number() or get_motherboard_serial_from_file()
        lic_key = get_lickey_from_env()
        if bios_serial == motherb_serial:
            device_uuid = get_device_uuid() or get_device_uuid_from_file()
            pc_id_v = device_uuid + '-' + lic_key
        elif motherb_serial == "":
            pc_id_v = bios_serial + '-' + lic_key
        elif bios_serial == "":
            pc_id_v = motherb_serial + '-' + lic_key
        else:
            pc_id_v = motherb_serial + '-' + bios_serial + '-' + lic_key
        pc_id_v = pc_id_v.replace("/", "")
        return pc_id_v
    except Exception as pc_id_error:
        print(f"An error occurred while getting pc id: {pc_id_error}")
        return ""


def get_pc_id_without_lickey():
    try:
        print("Getting pc id without lic key")
        bios_serial = get_system_serial_number() or get_system_serial_from_file()
        motherb_serial = get_motherboard_serial_number() or get_motherboard_serial_from_file()
        if bios_serial == "" and motherb_serial == "":
            pc_id_v = get_device_uuid() or get_device_uuid_from_file()
        elif motherb_serial == "":
            pc_id_v = bios_serial
        elif bios_serial == "":
            pc_id_v = motherb_serial
        else:
            pc_id_v = motherb_serial + '-' + bios_serial
        pc_id_v = pc_id_v.replace("/", "")
        return pc_id_v
    except Exception as pc_id_error:
        print(f"An error occurred while getting pc id: {pc_id_error}")
        return ""


def get_current_loggedin_user():
    current_loggedin_user = ""
    try:
        result = subprocess.run(['loginctl', 'list-sessions', '--no-legend'], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        if result.stdout:
            sessions = result.stdout.splitlines()
            for session in sessions:
                session_no = session.strip().split(" ")[0].strip()
                show_result = subprocess.run(['loginctl', 'show-session', session_no, '-p', 'Active'],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if show_result.stdout:
                    active_line = show_result.stdout.strip()
                    if 'Active=yes' in active_line:
                        username = subprocess.run(['loginctl', 'show-session', session_no, '-p', 'Name'],
                                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        if username.stdout:
                            current_loggedin_user = username.stdout.split("=")[-1].strip()
                            break
    except Exception as loggedin_user_error:
        print(f"Error in get_current_login_user: {loggedin_user_error}")
    return current_loggedin_user


def encrypt_using_public_key(payload_logged_messages):
    try:
        try:
            # Ensure the public key is imported correctly
            public_key = RSA.import_key(CA_PUBLIC_KEY)
        except ValueError as e:
            logger.warning(f"Error importing public key: {e}")
            return False

        # Encrypt JSON data in chunks
        chunk_size = 190
        encrypted_chunks = []
        data_bytes = payload_logged_messages.encode('utf-8')
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        for i in range(0, len(data_bytes), chunk_size):
            chunk = data_bytes[i:i + chunk_size]
            encrypted_chunk = cipher.encrypt(chunk)

            # Append the encrypted chunk to the list
            encrypted_chunks.append(encrypted_chunk)

        encrypted_data = b''.join(encrypted_chunks)
        encrypted_base64_data = base64.b64encode(encrypted_data)
        return encrypted_base64_data
    except Exception as enc_using_pub_key_err:
        logger.warning(f"enc_using_pub_key_err: {enc_using_pub_key_err}")
        return None


def add_process_id_to_maintain():
    try:
        pid = os.getpid()
        ppid = os.getppid()
        file_path = PIDS_MAINTAIN_FILE_PATH
        with open(file_path, "a") as pid_file:
            if ppid == 1:
                pid_file.write(f"{pid}\n")
            else:
                pid_file.write(f"{pid}\n{ppid}\n")
        print(f"pid: {pid}, ppid: {ppid}")
    except Exception as add_process_id_to_maintain_err:
        print(f"Error in add_process_id_to_maintain: {add_process_id_to_maintain_err}")


def main_logic_for_command_history():
    logger = None
    try:
        logger = setup_logger("CMD_LOGGER", log_filename="/tmp/cyberauditor_agent_cmd_history.log")
        logger.info("-------------------------------------------")
    except Exception as patch_logger_exception:
        print(f"Patch logger exception occurred: {patch_logger_exception}")

    def get_formatted_cmd(hex_string):
        """Decodes a hex-encoded command string and replaces null bytes with spaces."""
        try:
            decoded = binascii.unhexlify(hex_string).decode("utf-8")
            return decoded.replace("\x00", " ")
        except binascii.Error as e:
            logger.error(f"Hex decoding error: {e}")
            return hex_string

    def get_user_from_id(user_id):
        try:
            user_info = pwd.getpwuid(int(user_id))
            return user_info.pw_name
        except Exception as get_user_from_id_error:
            logger.error(f"Error in get_user_from_id: {get_user_from_id_error}")
            return f"userId-{user_id}"

    def converted_time_format(date_str):
        try:
            date_obj = datetime.strptime(date_str, "%a %b %d %H:%M:%S %Y")
            formatted_date = date_obj.strftime("%d/%m/%Y %H:%M:%S")
            return str(formatted_date)
        except Exception as convert_time_err:
            logger.error(f"Error converting time: {convert_time_err}")
            return str(date_str)

    def to_camel_case(snake_str):
        try:
            parts = snake_str.split('_')
            return parts[0] + ''.join(word.capitalize() for word in parts[1:])
        except Exception as camel_case_err:
            logger.error(f"Error converting to camelcase: {camel_case_err}")
            return snake_str

    def get_pids_of_agent_services():
        agent_pids = []
        try:
            services = [
                "cyberauditor-linux-agent-bluetooth-trigger.service",
                "cyberauditor-linux-agent-cleanup-trigger.service",
                "cyberauditor-linux-agent-cmd-history.service",
                "cyberauditor-linux-agent-daily-trigger.service",
                "cyberauditor-linux-agent-firewall-trigger.service",
                "cyberauditor-linux-agent-interval-trigger.service",
                "cyberauditor-linux-agent-logon-trigger.service",
                "cyberauditor-linux-agent-network-trigger.service",
                "cyberauditor-linux-agent-patch-update.service",
                "cyberauditor-linux-agent-usb-trigger.service",
                "cyberauditor-linux-agent-usb-watcher.service",
                "cyberauditor-linux-agent-watchdog-trigger.service",
            ]

            for service in services:
                try:
                    pid_output = subprocess.check_output(f"systemctl status {service} | grep 'Main PID'",
                                                         shell=True, universal_newlines=True)
                    pid = pid_output.strip().split()[2]
                    agent_pids.append(pid)
                except subprocess.CalledProcessError as get_pids_err:
                    logger.error(f"Error in get_pids_of_agent_dervices: {get_pids_err}")
            logger.info(f"PIDs of agent services: {agent_pids}")
        except Exception as get_pids_err:
            logger.error(f"Error in get_pids_of_agent_dervices: {get_pids_err}")
        return agent_pids

    def get_pids_from_file():
        try:
            file_path = PIDS_MAINTAIN_FILE_PATH
            with open(file_path, "r") as pid_file:
                pid = pid_file.read().strip()
                return pid.split("\n")
        except Exception as get_pids_from_file_err:
            print(f"Error in get_pids_from_file: {get_pids_from_file_err}")
            return []

    def get_final_filtered_data(results):
        final_results = []
        try:
            list_of_pids_to_exclude = set()
            services_pids = get_pids_of_agent_services()
            file_pids = get_pids_from_file()
            list_of_pids_to_exclude.update(services_pids)
            list_of_pids_to_exclude.update(file_pids)
            for result in results:
                if result is not None:
                    try:
                        cwd = result["basicDetails"].get("cwd")
                        user = result["basicDetails"].get("user")
                        command = result["basicDetails"].get("command")
                        pid = result["syscallDetails"].get("pid")
                        ppid = result["syscallDetails"].get("ppid")
                        if not result["syscallDetails"]:
                            continue
                        elif ((cwd == "/" or cwd == "/etc/cyberauditor_linux_agent") and user == "root" and pid and
                                ("/etc/cyberauditor_linux_agent/service_exe/service-agent" in command or
                                 "/etc/cyberauditor_linux_agent/audit_exe/audit-agent" in command or
                                 "/etc/cyberauditor_linux_agent/setup-agent" in command)):
                            list_of_pids_to_exclude.add(pid)
                            continue
                        elif ppid in list_of_pids_to_exclude:
                            list_of_pids_to_exclude.add(pid)
                            continue
                        else:
                            final_results.append(result)
                    except Exception as final_inner_filter_err:
                        logger.error(f"Error in filtering data: {result}, {final_inner_filter_err}")
            logger.info(f"list_of_pids_to_exclude(size) : {len(list_of_pids_to_exclude)}")
        except Exception as final_filter_err:
            logger.error(f"Error in final filtered data: {final_filter_err}")

        return final_results

    def process_chunk(chunk):
        try:
            result = {
                "basicDetails": {},
                "pathDetails": [],
                "execveDetails": {},
                "syscallDetails": {}
            }

            command = ""
            user = ""

            # Basic Details (time)
            time_match = re.search(r'time->(?P<datetime>[A-Za-z]{3} [A-Za-z]{3}  ?\d{1,2} \d{2}:\d{2}:\d{2} \d{4})',
                                   chunk)
            if time_match:
                time_str = time_match.group('datetime')
                result["basicDetails"]["originalTime"] = time_str
                result["basicDetails"]["timestamp"] = converted_time_format(time_str)

            # CWD
            cwd = re.search(r'type=CWD msg=.*?cwd="([^"]+)"', chunk)
            if cwd:
                cwd = cwd.group(1)
                result["basicDetails"]["cwd"] = cwd

            # Proctitle
            proctitle = re.search(r'type=PROCTITLE msg=.*?proctitle=([^\n]+)', chunk)
            if proctitle:
                result["basicDetails"]["proctitle"] = proctitle.group(1)
                proctitle = proctitle.group(1)
                command = get_formatted_cmd(proctitle)
                result["basicDetails"]["command"] = command

            # Paths
            for m in re.finditer(
                    r'type=PATH msg=.*?item=\d+ name="(?P<name>[^"]+)" .*?inode=(?P<inode>\d+).*?mode=(?P<mode>\d+).*?nametype=(?P<nametype>\w+)',
                    chunk):
                path_info = {to_camel_case(k): v for k, v in m.groupdict().items()}
                result["pathDetails"].append(path_info)

            # EXECVE
            execve_match = re.search(r'type=EXECVE msg=.*?argc=(\d+)(.*?)type=', chunk, re.DOTALL)
            if execve_match:
                argc = execve_match.group(1)
                result["execveDetails"]["argc"] = argc
                args = re.findall(r'\ba(\d+)=(".*?"|[^\s"]+)', execve_match.group(2))
                for idx, val in args:
                    result["execveDetails"][f"a{idx}"] = val.strip('"')

            # SYSCALL
            syscall = re.search(
                r'type=SYSCALL msg=.*?arch=(?P<arch>\w+)\s+syscall=(?P<syscall>\d+)\s+success=(?P<success>\w+)\s+exit=(?P<exit>-?\d+).*?ppid=(?P<ppid>\d+)\s+pid=(?P<pid>\d+)'
                r'.*?auid=(?P<auid>\d+)\s+uid=(?P<uid>\d+)\s+gid=(?P<gid>\d+)\s+euid=(?P<euid>\d+)\s+suid=(?P<suid>\d+)\s+fsuid=(?P<fsuid>\d+)\s+egid=(?P<egid>\d+)'
                r'\s+sgid=(?P<sgid>\d+)\s+fsgid=(?P<fsgid>\d+)\s+tty=(?P<tty>[^\s]+).*?comm="(?P<comm>[^"]+)"\s+exe="(?P<exe>[^"]+)"\s+subj=(?P<subj>[^\s]+)\s+key="(?P<key>[^"]+)"',
                chunk, re.DOTALL
            )
            if syscall:
                result["syscallDetails"] = {to_camel_case(k): v for k, v in syscall.groupdict().items()}
                if result["syscallDetails"].get("uid"):
                    user_id = result["syscallDetails"]["uid"]
                    user = get_user_from_id(user_id)
                    result["basicDetails"]["user"] = user

            if proctitle == "\"dir\"" and command == "\"dir\"" and cwd == "/" and user == "root":
                return None

            if not result["basicDetails"] and not result["execveDetails"] and not result["pathDetails"] and not result[
                "syscallDetails"]:
                return None

            return result

        except Exception as process_chunk_err:
            logger.warning(f"Error processing chunk: {process_chunk_err}")
            return None

    def extract_and_filter_auditd_log_entries(log_data):
        """Extracts audit log entries into a list of dictionaries."""
        try:
            total_cmd = re.split(r'(?=^time->)', log_data, flags=re.MULTILINE)
            logger.info(f"Total number of chunks: {len(total_cmd)}")

            with concurrent.futures.ThreadPoolExecutor() as executor:
                matches_list = list(executor.map(process_chunk, total_cmd))

            # Filter out None results and return the final list
            results = [result for result in matches_list if result is not None]
            logger.info(f"Number of matches: {len(matches_list)}")
            logger.info(f"Number of results: {len(results)}")
            final_results = get_final_filtered_data(results)
            logger.info(f"Number of final results: {len(final_results)}")
            return final_results

        except Exception as filter_cmd_err:
            logger.error(f"Error in filtering: {filter_cmd_err}")
            return []

    try:
        # Create necessary directories efficiently
        for directory in [LOGS_DESTINATION_DIRECTORY, ENCRYPTED_CMD_LOGS_DESTINATION_DIRECTORY]:
            os.makedirs(directory, exist_ok=True)
        if LOGS_NEEDED:
            os.makedirs(VISIBLE_CMD_LOGS_DESTINATION_DIRECTORY, exist_ok=True)

    except Exception as cmd_dir_exception:
        logger.error(f"Error creating log directories: {cmd_dir_exception}")

    try:
        get_hostname_from_env()
        audit_path = "/etc/audit/rules.d/audit.rules"
        rule_string = "-a always,exit -F arch=b64 -S execve -k cyberauditor_cmd_logging"

        try:
            check_rules_out = subprocess.run(
                "auditctl -l", shell=True, check=True, capture_output=True, text=True
            )
            logger.info(f"Audit rules result:{check_rules_out}")
            if rule_string in check_rules_out.stdout:
                logger.info("Command history rule already added")
            else:
                restart_result = subprocess.run(f"auditctl {rule_string}", shell=True, check=True)
                logger.info(f"Command history rule add result: {restart_result}")

            with open(audit_path, "r+") as audit_file:
                audit_rules = audit_file.read()
                if rule_string not in audit_rules:
                    audit_file.write(f"\n{rule_string}\n")
                    logger.info("Added command history rule.")
                else:
                    logger.info("Command history already added.")
        except FileNotFoundError:
            logger.info("Audit file not found, creating a new one.")
            with open(audit_path, "w") as audit_file:
                audit_file.write(f"{rule_string}")
                logger.info("Added command history")
            restart_result = subprocess.run(f"auditctl {rule_string}", shell=True, check=True)
            logger.info(f"Command history rule add result: {restart_result}")
        except Exception as audit_path_err:
            logger.error(f"Error setting up auditd: {audit_path_err}")

        file_path = CMD_TIMESTAMP_FILE_PATH
        previous_time = decrypt_string(file_path)
        logger.info(f"previous time: {previous_time}")
        cmd_ausearch = f"LC_TIME=en_US.UTF-8 ausearch -ts {previous_time} -k cyberauditor_cmd_logging"
        current_formatted_time = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
        if not previous_time:
            encrypt_string(file_path, current_formatted_time)
            logger.info("No previous time found, starting from now.")
            return

        # logger.info(f"command: {cmd_ausearch}")
        result_ausearch = subprocess.run(cmd_ausearch, capture_output=True,
                                         shell=True, text=True)
        # print(f"ausearch result total lines: {len(result_ausearch.stdout.splitlines())}")
        # print(f"ausearch result total chars: {len(result_ausearch.stdout)}")
        logger.info(f"ausearch result err: {result_ausearch.stderr}")

        encrypt_string(file_path, current_formatted_time)

        logged_events = extract_and_filter_auditd_log_entries(result_ausearch.stdout)
        if logged_events:
            if LOGS_NEEDED:
                generate_visible_agent_log_file(VISIBLE_CMD_LOGS_DESTINATION_DIRECTORY, logged_events, "ca-cmd")
            generate_encrypted_symmetric_log_file(ENCRYPTED_CMD_LOGS_DESTINATION_DIRECTORY, json.dumps(logged_events),
                                                  "ca-cmd")

        if TRIGGER_TYPE == 'LINUX_COMMAND_HISTORY':
            # Send remaining log files
            send_remaining_encrypted_log_files_to_backend(ENCRYPTED_CMD_LOGS_DESTINATION_DIRECTORY, CMD_API_URL)

    except Exception as command_history_error:
        print(f"Error in Command History block: {command_history_error}")


def call_audit_agent():
    subprocess.run(f"{AUDIT_EXE_DIRECTORY_NAME}{AGENT_FILE_NAME} {TRIGGER_TYPE}",
                   shell=True, text=True, stderr=subprocess.PIPE,
                   stdout=subprocess.PIPE)


if __name__ == "__main__":

    add_process_id_to_maintain()

    if TRIGGER_TYPE == 'LINUX_WATCHDOG_TRIGGER':
        OS_NAME, PACKAGE_NAME = get_os_distributor_name()
        SERVICE_EXE_DIRECTORY_NAME = "/etc/cyberauditor_linux_agent/service_exe/"
        SERVICE_FOLDER_NAME = "service_exe/"
        SERVICE_FILE_NAME = "service-agent"
        PC_ID = get_pc_id()
        try:
            logger = setup_logger("WATCHDOG_LOGGER", log_filename="/tmp/cyberauditor_agent_watchdog.log")
            logger.info("-------------------------------------------")
        except Exception as watchdog_logger_exception:
            print(f"Watchdog logger exception occurred: {watchdog_logger_exception}")


        def send_watchdog_alert(message):
            try:
                try_count = 0
                max_retry = 2
                retry_delay = 5

                while try_count < max_retry:
                    try:
                        alert_response = requests.post(WATCHDOG_ALERT_API_URL,
                                                       data={"alertType": message,
                                                             "pcId": PC_ID, "osType": "Linux"},
                                                       timeout=TIMEOUT_SUBPROCESS, verify=CA_FILE)

                        if alert_response.status_code == 201 or alert_response.status_code == 200:
                            logger.info(f"Sent watchdog alert: {message} to backend. Response: {alert_response.text}")
                            return
                        else:
                            logger.warning(f"Unexpected status code: {alert_response.status_code}")

                    except Exception as validation_error:
                        logger.warning(f"Attempt {try_count + 1} Unexpected error: {validation_error}")

                    try_count += 1
                    time.sleep(retry_delay)

                logger.warning(f"Validation failed after {max_retry} attempts.")

            except Exception as send_watchdog_alert_error:
                logger.error(f"An error occurred while sending watchdog alert: {send_watchdog_alert_error}")


        def download_package_file(url, dest):
            try:
                lickey = get_lickey_from_env()

                if not PC_ID or not lickey:
                    logger.warning("Error: Missing PC ID or License Key")
                    return False

                # Encrypt the data
                data = {'pcId': PC_ID, 'licenseKey': lickey}
                data_enc = encrypt_using_public_key(json.dumps(data))

                if not data_enc:
                    logger.warning("Error: Encryption failed")
                    return False

                # Send POST request
                response = requests.post(url, data={"encryptedData": data_enc}, stream=True, verify=CA_FILE)

                # Check HTTP status
                if response.status_code == 200:
                    with open(dest, 'wb') as file_to_write:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                file_to_write.write(chunk)

                    if os.path.exists(dest) and os.path.getsize(dest) > 0:
                        logger.info("Successfully downloaded file")
                        return True
                    else:
                        logger.warning("Error: File not downloaded correctly")
                        return False
                else:
                    logger.warning(f"Error: Failed to download file, HTTP status {response.status_code}")
                    return False

            except Exception as download_file_err:
                logger.warning(f"Download error: {download_file_err}")
                return False


        def download_config_file(url, dest):
            try:
                lic_key = get_lickey_from_env()
                response = requests.post(url, data={"licKey": lic_key}, timeout=TIMEOUT_SUBPROCESS, verify=CA_FILE)
                if response.status_code == 200:
                    with open(dest, 'wb') as file_to_write:
                        file_to_write.write(response.content)
                    if os.path.exists(dest) and os.path.getsize(dest) > 0:
                        return True
                    else:
                        logger.warning("Error: Config File not downloaded correctly")
                        return False
                else:
                    logger.warning(f"Failed to download {url}")
                    return False
            except Exception as download_file_err:
                logger.warning(f"download_file_err: {download_file_err}")
                return False


        def backup_and_restore_files(source_dir, target_dir):
            """Copy all files from source directory to target directory."""
            try:
                if not os.path.exists(source_dir):
                    logger.warning(f"Source directory '{source_dir}' does not exist.")
                    return False

                if not os.path.exists(target_dir):
                    os.makedirs(target_dir)

                for file_name in os.listdir(source_dir):
                    source_file = os.path.join(source_dir, file_name)
                    target_file = os.path.join(target_dir, file_name)

                    if os.path.isfile(source_file):
                        shutil.copy(source_file, target_file)
                    elif os.path.isdir(source_file):
                        # Recursively copy subdirectories
                        shutil.copytree(source_file, target_file)

                logger.info(f"All files from '{source_dir}' have been copied to '{target_dir}'.")
                return True
            except Exception as copy_err:
                logger.warning(f"copy_all_files error: {copy_err}")
                return False


        def cleanup_files_and_dirs(uninstall_flag_path, final_package_path):
            try:
                logger.info("Cleaning files...")
                os.remove(uninstall_flag_path)
                os.remove(final_package_path)
                shutil.rmtree(BACKUP_WORKING_DIRECTORY)
            except Exception as delete_backup_err:
                logger.warning(f"Error deleting backup directory: {delete_backup_err}")


        def reinstall_ca(package_url, package_name):
            uninstall_flag_path = "/tmp/uninstall_flag_cyberauditor"
            final_package_path = f"/tmp/{package_name}"
            try:
                logger.info("Reinstalling CA...")

                # Step 1: Download package
                if not download_package_file(package_url, final_package_path):
                    logger.warning("Error: Could not download package.")
                    cleanup_files_and_dirs(uninstall_flag_path, final_package_path)
                    return

                # Step 2: Create uninstall flag
                os.system(f"touch {uninstall_flag_path}")

                # Step 3: Backup critical files
                logger.info("Backing up critical files...")
                if not backup_and_restore_files(DESTINATION_WORKING_DIRECTORY, BACKUP_WORKING_DIRECTORY):
                    logger.warning("Error: Backup failed. Aborting reinstallation.")
                    cleanup_files_and_dirs(uninstall_flag_path, final_package_path)
                    return

                # Step 3: Uninstall the old package
                logger.info("Uninstalling old package...")
                try:
                    uninstall_command = (
                        ["rpm", "-e", "--allmatches", "cyberauditor-linux-agent"]
                        if package_name.endswith(".rpm")
                        else ["dpkg", "-r", "cyberauditor-linux-agent"]
                        if package_name.endswith(".deb")
                        else None
                    )
                    if uninstall_command is None:
                        raise ValueError("Unsupported package format.")
                    subprocess.run(uninstall_command, check=True)
                    logger.info("Uninstalled package successfully.")
                except Exception as uninstall_err:
                    logger.warning(f"Unable to install package: {uninstall_err}")

                # Step 4: Install the new package
                logger.info("Installing new package...")
                install_command = (
                    ["rpm", "-i", "--force", final_package_path]
                    if package_name.endswith(".rpm")
                    else ["dpkg", "-i", final_package_path]
                    if package_name.endswith(".deb")
                    else None
                )
                if install_command is None:
                    raise ValueError("Unsupported package format.")
                subprocess.run(install_command, check=True)
                logger.info("Reinstalled CA successfully.")
                cleanup_files_and_dirs(uninstall_flag_path, final_package_path)
                sys.exit(0)

            except Exception as reinstall_err:
                logger.warning(f"Error during reinstallation: {reinstall_err}")
                logger.info("Checking if restoration is required...")
                if len(os.listdir(DESTINATION_WORKING_DIRECTORY)) == 0:
                    logger(f"As {DESTINATION_WORKING_DIRECTORY} is empty, restoring the backup file...")
                    if backup_and_restore_files(BACKUP_WORKING_DIRECTORY, DESTINATION_WORKING_DIRECTORY):
                        logger.info("Backup restored successfully.")
                cleanup_files_and_dirs(uninstall_flag_path, final_package_path)
                sys.exit(0)


        def get_config_from_backend():
            try:
                config_url = f"{BACKEND_CONFIG_API}/{OS_NAME}"
                tmp_config_path = "/tmp/cyberauditor_global_config.txt.tmp"
                if download_config_file(config_url, tmp_config_path):
                    os.rename(tmp_config_path, "/tmp/cyberauditor_global_config.txt")
            except Exception as backend_conf_err:
                logger.warning(f"Error: {backend_conf_err}")


        def delete_cmd_service():
            try:
                subprocess.run(["systemctl", "stop", "cyberauditor-linux-agent-cmd-history.service"])
                subprocess.run(["systemctl", "disable", "cyberauditor-linux-agent-cmd-history.service"])
                subprocess.run(["systemctl", "daemon-reload"])
                subprocess.run("rm -rf /etc/systemd/system/cyberauditor-linux-agent-cmd-history.service", shell=True)
                subprocess.run(f"rm -rf {ENCRYPTED_CMD_LOGS_DESTINATION_DIRECTORY}", shell=True)
                subprocess.run(f"rm -rf {CMD_TIMESTAMP_FILE_PATH}", shell=True)
                return True
            except Exception as cmd_service_err:
                logger.error(f"Error: {cmd_service_err}")
                return False


        def maintain_ca_version():
            try:
                config_path = "/tmp/cyberauditor_global_config.txt"
                if os.path.isfile(config_path):
                    with open("/etc/environment") as file_to_read:
                        env_content = file_to_read.read()
                    local_agent_version = next(
                        (line.split('=')[1].strip('"') for line in env_content.splitlines()
                         if "CA_LATEST_VERSION=" in line), None)

                    with open(config_path) as global_config_file:
                        global_config = json.load(global_config_file)
                    global_agent_version = global_config.get("LATEST_VERSION")

                    logger.info(f"Local agent version: {local_agent_version},"
                                f"Global agent version: {global_agent_version}")
                    os.remove(config_path)

                    if not local_agent_version or global_agent_version != local_agent_version:
                        logger.info("CA version is not up-to-date.")
                        send_watchdog_alert("WATCHDOG_VERSION_ALERT")
                        reinstall_ca(f"{FETCH_API_PACKAGE}/{OS_NAME}",
                                     f"cyberauditor-linux-agent{PACKAGE_NAME}")
                    else:
                        global_features = global_config.get("features")
                        local_features = json.loads(decrypt_string(ORG_FEATURES_FILE_PATH) or "{}")
                        logger.info(f"Global features: {global_features}")
                        logger.info(f"Local features: {local_features}")

                        if global_features != local_features:
                            logger.info("CA features are not up-to-date.")
                            os.makedirs(os.path.dirname(ORG_FEATURES_FILE_PATH), exist_ok=True)
                            encrypt_string(ORG_FEATURES_FILE_PATH, json.dumps(global_features))
                            if local_features.get("CommandHistory") == False and \
                                global_features.get("CommandHistory") == True:
                                subprocess.run("/etc/cyberauditor_linux_agent/setup-agent CREATE_CMD_SERVICE",
                                               shell=True, text=True, stderr=subprocess.PIPE,
                                               stdout=subprocess.PIPE)
                            elif local_features.get("CommandHistory") == True and \
                                global_features.get("CommandHistory") == False:
                                if delete_cmd_service():
                                    logger.info("Command history service deleted successfully.")
                                else:
                                    logger.warning("Failed to delete command history service.")

            except Exception as maintain_ca_version_err:
                logger.warning(f"maintain_ca_version_err: {maintain_ca_version_err}")


        def maintain_ca_services():
            FEATURES = json.loads(decrypt_string(ORG_FEATURES_FILE_PATH) or "{}")
            services = [
                "cyberauditor-linux-agent-bluetooth-trigger.service",
                "cyberauditor-linux-agent-cleanup-trigger.service",
                "cyberauditor-linux-agent-daily-trigger.service",
                "cyberauditor-linux-agent-firewall-trigger.service",
                "cyberauditor-linux-agent-interval-trigger.service",
                "cyberauditor-linux-agent-logon-trigger.service",
                "cyberauditor-linux-agent-network-trigger.service",
                "cyberauditor-linux-agent-patch-update.service",
                "cyberauditor-linux-agent-usb-trigger.service",
                "cyberauditor-linux-agent-usb-watcher.service",
                "cyberauditor-linux-agent-watchdog-trigger.service",
            ]

            running_services = [
                "cyberauditor-linux-agent-bluetooth-trigger.service",
                "cyberauditor-linux-agent-firewall-trigger.service",
                "cyberauditor-linux-agent-logon-trigger.service",
                "cyberauditor-linux-agent-network-trigger.service",
                "cyberauditor-linux-agent-patch-update.service",
                "cyberauditor-linux-agent-usb-trigger.service",
                "cyberauditor-linux-agent-usb-watcher.service",
            ]

            hash_values = [
                "abc4e2d05f9641fadde0bba564c82db84ca1e1d8061fccdfcc09052d1ad2f4df",
                "3f228116df3f892be52bf57b3dbc82eec16fa290a16f9cb578e17b63560fd91c",
                "4b4d56d2b831d372f1ab75b1a888c0b8843db3d2970be2ad41352fe124a306ac",
                "b2a3206440d1b64fb34bcf37ee214f1bcc38f00d8c181a4ce60e20c635f3149a",
                "8161f5276bbfc7349c770aa982a0be4ed63638da6ee5288b8ac6526ea6128436",
                "0a5e020c4505733d2a0c9f389216088dadd735a8e3950091dee4066301d8f386",
                "0d12c8310cddd50cc586d06e5648dd6d667796e605ef824534c0e7ceed56e887",
                "c618cddfe69dc53e504005eb8560de67b3d26246c74e8e7ab8a484b39fbbc918",
                "cf64f3b43c3e5d9114f2c14386654e0cc3a552eec3a7e37233bd7a2255a0a86c",
                "7b654636faccd81a2d2baf1ebd51affc7cc52a2514ce4085ef039128cffdc0a3",
                "55a5fe3b555ce662ea11e76336b9e55ec104820f48f251075bbf39a6c8c4f2a0",
            ]

            if FEATURES.get("CommandHistory"):
                services.append("cyberauditor-linux-agent-cmd-history.service")
                hash_values.append("bbfa50211bea29c2cbe59b41be5166c08833d84b0b7c84cad0299f297a2cc5c1")

            try:
                for service, expected_hash in zip(services, hash_values):
                    service_path = f"/etc/systemd/system/{service}"
                    if not os.path.isfile(service_path):
                        send_watchdog_alert("WATCHDOG_SERVICE_ALERT")
                        reinstall_ca(f"{FETCH_API_PACKAGE}/{OS_NAME}", f"cyberauditor-linux-agent{PACKAGE_NAME}")
                        break
                    else:
                        with open(service_path, "rb") as file_to_check:
                            file_hash = hashlib.sha256(file_to_check.read()).hexdigest()
                        if file_hash != expected_hash:
                            send_watchdog_alert("WATCHDOG_SERVICE_ALERT")
                            reinstall_ca(f"{FETCH_API_PACKAGE}/{OS_NAME}", f"cyberauditor-linux-agent{PACKAGE_NAME}")
                            break
                        else:
                            is_changed = False
                            if service != "cyberauditor-linux-agent-daily-trigger.service":
                                is_enabled = subprocess.run(["systemctl", "is-enabled", service],
                                                            capture_output=True, text=True).stdout.strip()
                                if is_enabled != "enabled":
                                    is_changed = True
                                    subprocess.run(["systemctl", "enable", service], check=True)
                                is_active = subprocess.run(["systemctl", "is-active", service],
                                                           capture_output=True, text=True).stdout.strip()
                                if ((service in running_services and is_active != "active")
                                        or is_active == "inactive"):
                                    is_changed = True
                                    subprocess.run(["systemctl", "restart", service], check=True)

                            if is_changed:
                                send_watchdog_alert("WATCHDOG_SERVICE_ALERT")

                logger.info("CA services are present.")
            except Exception as service_check_err:
                logger.warning(f"Service check error: {service_check_err}")


        def maintain_ca_files():
            try:
                audit_exec_path = os.path.join(AUDIT_EXE_DIRECTORY_NAME, AGENT_FILE_NAME)
                audit_lib_dir = os.path.join(AUDIT_EXE_DIRECTORY_NAME, 'lib')
                avml_path = os.path.join(DESTINATION_WORKING_DIRECTORY, 'avml')
                fanotify_path = os.path.join(DESTINATION_WORKING_DIRECTORY, 'ca-fanotify')

                # Check required files and directories
                if not (os.path.isdir(DESTINATION_WORKING_DIRECTORY) and
                        os.path.isdir(audit_lib_dir) and
                        os.path.isfile(audit_exec_path) and
                        os.path.isfile(avml_path)):
                    logger.warning("Missing CA files or directories.")
                    send_watchdog_alert("WATCHDOG_FILES_ALERT")
                    reinstall_ca(f"{FETCH_API_PACKAGE}/{OS_NAME}",
                                 f"cyberauditor-linux-agent{PACKAGE_NAME}")

                # Ensure audit file is executable
                if not os.access(audit_exec_path, os.X_OK):
                    logger.info("Making the Audit file executable...")
                    os.chmod(audit_exec_path, 0o755)
                    return

                # Ensure avml is executable
                if not os.access(avml_path, os.X_OK):
                    logger.info("Making the avml executable...")
                    os.chmod(avml_path, 0o755)
                    return

                # Ensure avml is executable
                if not os.access(fanotify_path, os.X_OK):
                    logger.info("Making the avml executable...")
                    os.chmod(fanotify_path, 0o755)
                    return

                logger.info("All required CA files are present and properly configured.")

            except Exception as maintain_ca_files_err:
                logger.warning(f"Error maintaining CA files: {maintain_ca_files_err}")


        try:
            get_hostname_from_env()
            get_config_from_backend()
            maintain_ca_version()
            maintain_ca_services()
            maintain_ca_files()
        except Exception as watchdog_exception:
            print(f"Watchdog exception occurred: {watchdog_exception}")

    elif TRIGGER_TYPE == 'LINUX_INTERVAL_TRIGGER':

        try:
            file_path = "/tmp/cyberauditor_linux_interval_info.txt"
            if not os.path.exists(file_path):
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'w') as f:
                    f.write("y78yr82389urj0r9un09u")
            else:
                call_audit_agent()

        except Exception as interval_exception:
            print(f"Interval exception occurred: {interval_exception}")

    elif TRIGGER_TYPE == 'LINUX_BLUETOOTH_TRIGGER':
        while True:
            try:
                file_path = "/tmp/cyberauditor_bluetooth_info.txt"

                decrypted_content = decrypt_string(file_path)

                if not os.path.exists(file_path):
                    time.sleep(30)

                if get_current_loggedin_user() == "gdm":
                    break

                command_bluetooth_status = ["bluetoothctl", "show"]
                result_bluetooth_status = subprocess.run(command_bluetooth_status, text=True,
                                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                         timeout=TIMEOUT_SUBPROCESS)
                for line in result_bluetooth_status.stdout.splitlines():
                    if "Powered:" in line:
                        bluetooth_status = line.split(":")[1].strip().lower()
                        break

                output_file_temp = []
                paired_devices_cmd = ["bluetoothctl", "paired-devices"]
                paired_devices_result = subprocess.run(paired_devices_cmd, text=True,
                                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                       timeout=TIMEOUT_SUBPROCESS)
                if paired_devices_result.returncode != 0:
                    paired_devices_cmd = ["bluetoothctl", "devices"]
                    paired_devices_result = subprocess.run(paired_devices_cmd, text=True,
                                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                           timeout=TIMEOUT_SUBPROCESS)
                paired_devices = [line.split()[1] for line in paired_devices_result.stdout.strip().split("\n") if line]

                for device in paired_devices:
                    info_cmd = ["bluetoothctl", "info", device]
                    info_result = subprocess.run(info_cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                 timeout=TIMEOUT_SUBPROCESS)
                    info = info_result.stdout.strip().split("\n")
                    connected = None
                    ip_address = None
                    device_name = None

                    for line in info:
                        if "Connected" in line:
                            connected = line.split()[1]
                        if "Device" in line:
                            ip_address = line.split()[1]
                        if "Name" in line:
                            device_name = line.split()[1]

                    if connected == "yes":
                        output_file_temp.append(f"{ip_address} {device_name}")

                output = bluetooth_status + " ".join(output_file_temp)

                if not os.path.exists(file_path):
                    encrypt_string(file_path, output)

                elif output != decrypted_content:
                    encrypt_string(file_path, output)

                    print("Calling audit agent")
                    call_audit_agent()

            except Exception as bluetooth_exception:
                print(f"Bluetooth exception occurred: {bluetooth_exception}")

            time.sleep(10)

    elif TRIGGER_TYPE == 'LINUX_LOGON_TRIGGER':
        while True:
            try:
                file_path = "/tmp/cyberauditor_linux_logon_info.txt"

                decrypted_content = decrypt_string(file_path)

                current_loggedin_user = get_current_loggedin_user()

                output = current_loggedin_user

                if not os.path.exists(file_path):
                    encrypt_string(file_path, output)

                elif output != decrypted_content:
                    encrypt_string(file_path, output)
                    if output and output != "gdm":
                        print("Calling audit agent")
                        call_audit_agent()

            except Exception as logon_exception:
                print(f"Logon exception occurred: {logon_exception}")

            time.sleep(10)

    elif TRIGGER_TYPE == 'LINUX_NETWORK_TRIGGER':
        get_hostname_from_env()
        while True:
            try:
                file_path = "/tmp/cyberauditor_network_info.txt"

                decrypted_content = decrypt_string(file_path)

                if not os.path.exists(file_path):
                    time.sleep(30)

                nmcli_cmd = """nmcli connection show | awk '{if ($(NF) != "--" && ($(NF-1) == "wifi" || $(NF-1) == "ethernet")) print}'"""
                result = subprocess.run(nmcli_cmd, shell=True,
                                        text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        timeout=TIMEOUT_SUBPROCESS)

                result_lines = result.stdout.strip().split('\n')
                final_result = []
                for line in result_lines:
                    cleaned_line = " ".join(line.strip().split())
                    if cleaned_line != "":
                        final_result.append(cleaned_line)

                output = "\n".join(final_result)

                if not os.path.exists(file_path):
                    encrypt_string(file_path, output)

                elif decrypted_content != output:
                    if output != "":
                        encrypt_string(file_path, output)
                        previous_lines = decrypted_content.split('\n')
                        len_previous_lines = len(previous_lines)
                        current_lines = output.split('\n')
                        len_current_lines = len(current_lines)
                        if ((len_current_lines == len_previous_lines and previous_lines != current_lines)
                                or (len_current_lines > len_previous_lines)):
                            print("Calling audit agent")
                            call_audit_agent()
                        else:
                            send_remaining_encrypted_log_files_to_backend(ENCRYPTED_AUDIT_LOGS_DIRECTORY,
                                                                          BACKEND_API_URL)

            except Exception as network_exception:
                print(f"Network exception occurred: {network_exception}")

            time.sleep(10)

    elif TRIGGER_TYPE == 'LINUX_FIREWALL_TRIGGER':
        while True:
            try:
                file_path = "/tmp/cyberauditor_linux_firewall_info.txt"

                decrypted_content = decrypt_string(file_path)

                if not os.path.exists(file_path):
                    time.sleep(15)

                list_of_services = ["firewalld", "ufw", "nftables", "iptables"]

                count_of_active_services = 0
                for service in list_of_services:
                    try:
                        result = subprocess.run(["systemctl", "is-active", service],
                                                capture_output=True, text=True).stdout.strip()
                        if result == "active":
                            count_of_active_services += 1
                    except Exception as service_exception:
                        print(f"Service exception occurred: {service_exception}")

                output = str(count_of_active_services > 0)

                if not os.path.exists(file_path):
                    encrypt_string(file_path, output)

                elif decrypted_content != output:
                    encrypt_string(file_path, output)

                    print("Calling audit agent")
                    call_audit_agent()

            except Exception as firewall_exception:
                print(f"Firewall exception occurred: {firewall_exception}")

            time.sleep(5)

    elif TRIGGER_TYPE == 'LINUX_USB_TRIGGER':
        while True:
            try:
                file_path = "/tmp/cyberauditor_linux_usb_info.txt"

                decrypted_content = decrypt_string(file_path)

                # List directories matching mmc0:<digits> which is for SD cards.
                base_path = "/sys/class/mmc_host/mmc0"
                is_mmc_device = False
                mmc_output = ""
                try:
                    for entry in os.listdir(base_path):
                        full_path = os.path.join(base_path, entry)
                        if os.path.isdir(full_path) and entry.startswith("mmc0:"):
                            mmc_output += " " + full_path
                            if full_path not in decrypted_content:
                                is_mmc_device = True
                except Exception:
                    pass

                result = subprocess.run(["lsusb"], text=True,
                                        stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        timeout=TIMEOUT_SUBPROCESS)

                if result.returncode == 0:
                    output = " ".join(result.stdout.strip().split("\n"))
                    if mmc_output != "":
                        output += " " + mmc_output

                    if decrypted_content != output:
                        encrypt_string(file_path, output)

                        if is_mmc_device:
                            print("Calling audit agent")
                            call_audit_agent()
                            continue

                        current_devices = result.stdout.strip().split("\n")

                        for line in current_devices:
                            bus = line.split()[1].rstrip(':')
                            device = line.split()[3].rstrip(':')

                            if f"Bus {bus} Device {device}:" not in decrypted_content:
                                udevadm_cmd = ["udevadm", "info", "-q", "all", "-n", f"/dev/bus/usb/{bus}/{device}"]
                                udevadm_result = subprocess.run(udevadm_cmd, text=True, encoding='utf-8',
                                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                                timeout=TIMEOUT_SUBPROCESS)

                                id_interface = ""
                                for udev_line in udevadm_result.stdout.splitlines():
                                    if "ID_USB_INTERFACES" in udev_line:
                                        id_interface = udev_line.split('=')[1]

                                if re.search(r":080[0-9]*:|:080[0-9]*:080[0-9]*:|:060[0-9]*:|:ffff[0-9]*:|:060["
                                             r"0-9]*:.*:|:ffff[0-9]*:.*:", id_interface):
                                    print("Calling audit agent")
                                    call_audit_agent()
                                    break

                else:
                    devices = glob.glob('/dev/sd*')
                    filtered_devices = [device for device in devices if len(device) == 8]
                    output = " ".join(filtered_devices)
                    if mmc_output != "":
                        output += " " + mmc_output

                    if decrypted_content != output:
                        encrypt_string(file_path, output)

                        if is_mmc_device:
                            print("Calling audit agent")
                            call_audit_agent()
                            continue

                        for device in filtered_devices:

                            if device not in decrypted_content:
                                udevadm_cmd = ["udevadm", "info", "-q", "all", "-n", device]
                                udevadm_result = subprocess.run(udevadm_cmd, text=True, encoding='utf-8',
                                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                                timeout=TIMEOUT_SUBPROCESS)

                                id_interface = ""
                                for udev_line in udevadm_result.stdout.splitlines():
                                    if "ID_USB_INTERFACES" in udev_line:
                                        id_interface = udev_line.split('=')[1]

                                if re.search(r":080[0-9]*:|:080[0-9]*:080[0-9]*:|:060[0-9]*:|:ffff[0-9]*:|:060["
                                             r"0-9]*:.*:|:ffff[0-9]*:.*:", id_interface):
                                    print("Calling audit agent")
                                    call_audit_agent()
                                    break

            except Exception as usb_exception:
                print(f"USB exception occurred: {usb_exception}")

            time.sleep(2)

    elif TRIGGER_TYPE == 'LINUX_USB_WATCHER':

        LOGS_DESTINATION_DIRECTORY = '/var/log/cyberauditor_linux_agent_logs/'
        VISIBLE_WATCHER_LOGS_DESTINATION_DIRECTORY = LOGS_DESTINATION_DIRECTORY + 'ca-raw-watcher-logs'
        ENCRYPTED_WATCHER_LOGS_DESTINATION_DIRECTORY = LOGS_DESTINATION_DIRECTORY + 'ca-watcher-logs'
        WATCHER_MAINTAIN_FILE = LOGS_DESTINATION_DIRECTORY + 'ca-watcher-maintain.log'
        logged_events = []
        seen_paths = set()
        try:
            os.makedirs(LOGS_DESTINATION_DIRECTORY, exist_ok=True)
            os.makedirs(LOGS_DESTINATION_DIRECTORY, exist_ok=True)
            if LOGS_NEEDED:
                os.makedirs(VISIBLE_WATCHER_LOGS_DESTINATION_DIRECTORY, exist_ok=True)
            os.makedirs(ENCRYPTED_WATCHER_LOGS_DESTINATION_DIRECTORY, exist_ok=True)

        except Exception as watcher_dir_exception:
            print(f"Watcher exception occurred: {watcher_dir_exception}")

        try:
            get_hostname_from_env()

            def get_file_hash(file_path_source):
                try:
                    hash_sha256 = hashlib.sha256()
                    with open(file_path_source, "rb") as as_file:
                        # Read the file in chunks of 4096 bytes
                        for chunk in iter(lambda: as_file.read(4096), b""):
                            hash_sha256.update(chunk)
                    return hash_sha256.hexdigest()
                except Exception as file_hash_err:
                    print(f"An file_hash_err: {file_hash_err}")
                    return None

            def get_file_type(file_path_src):
                try:
                    # Check if file exists
                    if not os.path.exists(file_path_src):
                        raise FileNotFoundError(f"The file {file_path_src} was not found.")

                    # Use file command to get file type info
                    cmd = f"file -b --mime-type '{file_path_src}'"
                    cmd_result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                                timeout=TIMEOUT_SUBPROCESS, check=True)

                    # Extract mime type from the result
                    mime_type = cmd_result.stdout.strip()

                    return mime_type
                except Exception as file_type_err:
                    print(f"An file_type_err: {file_type_err}")
                    return None

            def get_file_size(file_path_src):
                try:
                    if not os.path.exists(file_path_src):
                        raise FileNotFoundError(f"The file {file_path_src} was not found.")

                    file_size_bytes = os.path.getsize(file_path_src)

                    # Convert to MB or GB
                    if file_size_bytes < 1024 ** 2:
                        size_str = f"{file_size_bytes / 1024:.2f} KB"
                    elif file_size_bytes < 1024 ** 3:
                        size_str = f"{file_size_bytes / (1024 ** 2):.2f} MB"
                    else:
                        size_str = f"{file_size_bytes / (1024 ** 3):.2f} GB"

                    return size_str
                except Exception as file_size_err:
                    print(f"An file_size_err: {file_size_err}")
                    return None

            def delete_watcher_list(current_drive):
                try:
                    if os.path.exists(WATCHER_MAINTAIN_FILE):
                        # Read the file and remove the current drive
                        with open(WATCHER_MAINTAIN_FILE, 'r') as file_to_read:
                            drives_present = file_to_read.readlines()
                        # Remove the current drive from the list
                        updated_drives = {curr_drive.strip() for curr_drive in drives_present if
                                          curr_drive.strip() != current_drive}
                        with open(WATCHER_MAINTAIN_FILE, 'w') as file_to_read:
                            for drives_to_write in updated_drives:
                                file_to_read.write(f"{drives_to_write}\n")
                        with open(WATCHER_MAINTAIN_FILE, 'r') as file_to_read:
                            latest_drives_present = file_to_read.readlines()
                        # If the file becomes empty, delete it
                        if not latest_drives_present:
                            os.remove(WATCHER_MAINTAIN_FILE)
                            print(f"File {WATCHER_MAINTAIN_FILE} deleted.")
                except Exception as delete_watcher_list_error:
                    print(f"File Delete Error: {delete_watcher_list_error}")

            def process_event(event_json):
                try:
                    data = json.loads(event_json)
                    data.pop("pid", None)
                    data.pop("mask", None)
                    data.pop("event", None)
                    path = data.get("path")

                    if path in seen_paths:
                        return
                    seen_paths.add(path)
                    if not os.path.exists(path):
                        return
                    data["eventType"] = "copied"
                    data["fileHash"] = get_file_hash(path)
                    data["fileType"] = get_file_type(path)
                    data["fileSize"] = get_file_size(path)
                    data["timeStamp"] = time.strftime('%d-%m-%Y %H:%M:%S')
                    logged_events.append(data)
                    # print(f"[+] Detected file copy: {path}")
                except Exception as e:
                    print(f"Error processing event: {e}")

            def setup_watcher(mount_point):
                proc = None
                try:
                    if not os.path.exists(FANOTIFY_BINARY):
                        raise FileNotFoundError("Fanotify binary not found")

                    cmd = [FANOTIFY_BINARY, mount_point]
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1
                    )

                    print(f"Watcher started. Watching drive {mount_point}")

                    while True:
                        # 1️⃣ Drive removed
                        if not any(mount_point == d.mountpoint for d in psutil.disk_partitions()):
                            print(f"Drive {mount_point} removed. Stopping fanotify...")
                            break

                        # 2️⃣ Read fanotify output
                        ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                        if ready:
                            line = proc.stdout.readline()
                            if not line:
                                break
                            try:
                                process_event(line.strip())
                            except Exception as parse_err:
                                # Never let bad event kill monitoring
                                print("Event parse error:", parse_err)

                        # 3️⃣ Fanotify crashed
                        if proc.poll() is not None:
                            print("Fanotify process exited unexpectedly")
                            break

                except Exception as setup_watcher_error:
                    # Catch ANY error (binary missing, select error, psutil error, etc.)
                    print("Error in setup watcher:", setup_watcher_error)

                finally:
                    # 🔥 CRITICAL: This ALWAYS runs
                    print(f"Finalizing watcher for drive {mount_point}")

                    # --- Stop fanotify process ---
                    try:
                        if proc and proc.poll() is None:
                            proc.terminate()
                            try:
                                proc.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                    except Exception as kill_err:
                        print("Failed to stop fanotify:", kill_err)

                    # --- ALWAYS write logs ---
                    try:
                        if logged_events:
                            if LOGS_NEEDED:
                                generate_visible_agent_log_file(
                                    VISIBLE_WATCHER_LOGS_DESTINATION_DIRECTORY,
                                    logged_events,
                                    "ca-watcher"
                                )

                            generate_encrypted_agent_log_file(
                                ENCRYPTED_WATCHER_LOGS_DESTINATION_DIRECTORY,
                                json.dumps(logged_events),
                                "ca-watcher"
                            )

                            send_remaining_encrypted_log_files_to_backend(
                                ENCRYPTED_WATCHER_LOGS_DESTINATION_DIRECTORY,
                                WATCHER_API_URL
                            )
                    except Exception as log_err:
                        # Last-resort safety: never crash here
                        print("FAILED TO WRITE LOGS (CRITICAL):", log_err)

                    # --- Cleanup ---
                    try:
                        delete_watcher_list(mount_point)
                    except Exception:
                        pass

                    logged_events.clear()
                    seen_paths.clear()
                    print(f"Watcher stopped for drive {mount_point}")

            def get_external_drives():
                external_drives = []
                try:
                    for partition in psutil.disk_partitions():
                        # print(partition)
                        # print(partition.mountpoint)
                        try:
                            if (partition.mountpoint.startswith('/run/media/') or
                                partition.mountpoint.startswith('/media/') or
                                    ('uid' in partition.opts and 'gid' in partition.opts)):
                                external_drives.append(partition.mountpoint)
                        except Exception as get_partition_error:
                            print(f"get_partition_error: {get_partition_error}")

                except Exception as get_external_drives_error:
                    print(f"get_external_drives_error: {get_external_drives_error}")
                return external_drives

            def check_drive_watcher(current_drive):
                try:
                    if not os.path.exists(WATCHER_MAINTAIN_FILE):
                        with open(WATCHER_MAINTAIN_FILE, 'w'):
                            pass

                    with open(WATCHER_MAINTAIN_FILE, 'r') as file_to_read:
                        drives_already_present = [line.strip() for line in file_to_read.readlines()]
                        if current_drive not in drives_already_present:
                            with open(WATCHER_MAINTAIN_FILE, 'a') as file_to_write:
                                file_to_write.write(current_drive + '\n')
                            return True
                        else:
                            return False

                except Exception as check_drive_watcher_error:
                    print(f"Error: {check_drive_watcher_error}")
                    return False

            threads = []

            while True:
                drives = get_external_drives()
                for drive in drives:
                    if check_drive_watcher(drive):
                        thread = threading.Thread(target=setup_watcher, args=(drive,))
                        thread.start()
                        threads.append(thread)
                time.sleep(2)

        except Exception as watcher_error_main:
            print(f"Error: {watcher_error_main}")

    elif TRIGGER_TYPE == 'LINUX_PATCH_UPDATE':
        logger = None
        try:
            logger = setup_logger("PATCH_LOGGER", log_filename="/tmp/cyberauditor_agent_patch_update.log")
            logger.info("-------------------------------------------")
        except Exception as patch_logger_exception:
            print(f"Patch logger exception occurred: {patch_logger_exception}")


        # Subscribe to Core NATS
        async def subscribe_to_core_nats():
            global core_subscription
            
            if core_subscription:
                try:
                    await core_subscription.unsubscribe()
                    logger.info("Unsubscribed old Core NATS subscription.")
                except Exception as e:
                    logger.warning(f"Error unsubscribing Core NATS: {e}")

            async def core_handler(msg):
                try:
                    data = json.loads(msg.data.decode())
                    logger.info(f"[Core NATS] Received:\n{json.dumps(data, indent=2)}")
                    msg_status = data.get("status")
                    if msg_status in ("open_ssh" ,"force_open_ssh"):
                        asyncio.create_task(handle_ssh_messages(data, msg_status))
                    else:
                        logger.info(f"[Core NATS] Ignored status: {msg_status}")
                except Exception as core_handler_err:
                    logger.error(f"[Core NATS] Error: {core_handler_err}")
            
            core_subscription = await nc.subscribe(CORE_SUBJECT, cb=core_handler)
            logger.info(f"Subscribed to {CORE_SUBJECT} via Core NATS")


        # Subscribe to JetStream subject
        async def subscribe_to_jetstream():
            global jetstream_subscription
            js = nc.jetstream()

            async def js_handler(msg):
                try:
                    data = json.loads(msg.data.decode())
                    logger.info(f"[JetStream] Received:\n{json.dumps(data, indent=2)}")
                    await msg.ack()
                    if data.get("status") == "ram_dump_available":
                        ram_dump_id = data.get("ramDumpId", None)
                        if ram_dump_id:
                            asyncio.create_task(take_current_ram_dump(ram_dump_id))
                        else:
                            logger.error("ramDumpId not found in ram_dump_available message")
                    else:
                        asyncio.create_task(handle_other_messages(data))
                except Exception as err:
                    logger.error(f"[JetStream] Error processing message: {err}")

            if jetstream_subscription and not jetstream_subscription._closed:
                logger.info(f"[JetStream] Already subscribed with durable {DURABLE_NAME}, skipping resubscribe.")
                return

            try:
                # Check if durable consumer exists (do NOT delete it)
                await js.consumer_info(STREAM_NAME, DURABLE_NAME)
                logger.info(f"[JetStream] Consumer exists, binding to it.")
                jetstream_subscription = await js.subscribe(
                    JETSTREAM_SUBJECT,
                    cb=js_handler,
                    durable=DURABLE_NAME,
                )
            except Exception as err:
                if "consumer not found" in str(err).lower():
                    logger.info(f"[JetStream] Creating new consumer {DURABLE_NAME}")
                    consumer_config = ConsumerConfig(
                        durable_name=DURABLE_NAME,
                        deliver_policy=DeliverPolicy.NEW,
                        ack_policy=AckPolicy.EXPLICIT
                    )
                    jetstream_subscription = await js.subscribe(
                        JETSTREAM_SUBJECT,
                        cb=js_handler,
                        durable=DURABLE_NAME,
                        config=consumer_config
                    )
                else:
                    logger.error(f"[JetStream] Subscribe failed: {err}")
                    raise


        # Handle reconnect
        # async def on_reconnect():
        #     logger.warning("Reconnecting to NATS server.")
        #     await subscribe_to_core_nats()
        #     await subscribe_to_jetstream()


        # Log disconnect and close
        async def on_disconnect():
            logger.warning("Disconnected from NATS.")


        async def on_close():
            logger.warning("Connection to NATS closed.")


        # Connect with reconnect logic
        async def connect_to_nats():
            await nc.connect(
                servers=[NATS_URL],
                tls=ssl_context_ws,
                user="agent",
                password="AGENT_PASSWORD",
                ping_interval=10,
                reconnect_time_wait=RECONNECT_DELAY,
                max_reconnect_attempts=-1,
                # reconnected_cb=on_reconnect,
                disconnected_cb=on_disconnect,
                closed_cb=on_close,
            )
            logger.info("Connected to NATS.")


        # Persistent listener
        async def listen_for_patches():
            global nc
            while True:
                try:
                    if not nc.is_connected:
                        await connect_to_nats()
                        await subscribe_to_core_nats()
                        await subscribe_to_jetstream()
                    while nc.is_connected:
                        await asyncio.sleep(10)
                except Exception as err:
                    logger.error(f"[listen_for_patches] Error: {err}")
                finally:
                    logger.warning("Cleaning up and retrying connection...")
                    try:
                        await nc.drain()
                        await nc.close()
                    except Exception as close_err:
                        logger.warning(f"Error closing NATS client: {close_err}")
                    nc = NATS()
                    await asyncio.sleep(RECONNECT_DELAY)


        # === SSH Handler ===
        async def handle_ssh_messages(patch_data, status):
            try:
                global connected_users
                user_id = patch_data.get("_id", "")
                user_name = patch_data.get("fname", "")
                ssh_code = patch_data.get("code", "")

                if not user_id:
                    logger.info("Invalid user data found in the message.")
                    return

                if status == "force_open_ssh":
                    if user_id in connected_users:
                        logger.info(f"User {user_id} already has an active session.")
                        os.write(connected_users[user_id].master_fd, "\r".encode())
                    else:
                        logger.info(f"Forcing SSH access for user {user_id}")
                        # Create a new session
                        session = SSHWebSocketSession(user_id=user_id)
                        connected_users[user_id] = session
                        asyncio.create_task(session.connect())

                else:
                    logger.info(f"Prompting user {user_id} for SSH access.")
                    access_code_json = {"user_id": user_id, "user_name": user_name, "code": ssh_code}
                    os.makedirs(LOGS_DESTINATION_DIRECTORY, exist_ok=True)

                    # Load existing access data
                    access_data = []
                    existing_entry = None
                    if os.path.exists(ACCESS_CODE_FILE):
                        try:
                            with open(ACCESS_CODE_FILE, "r") as acc_file:
                                access_data = json.load(acc_file)
                        except Exception as acc_file_error:
                            logger.warning(f"Could not read access code file: {acc_file_error}")

                    if not isinstance(access_data, list):
                        access_data = []

                    for entry in access_data:
                        if entry.get("user_id") == user_id:
                            existing_entry = entry
                            break

                    should_prompt_user = (
                        existing_entry is None or existing_entry.get("code") != ssh_code
                    )

                    # Replace old entry
                    access_data = [e for e in access_data if e.get("user_id") != user_id]
                    access_data.append(access_code_json)

                    try:
                        with open(ACCESS_CODE_FILE, "w") as f:
                            json.dump(access_data, f, indent=2)
                    except Exception as acc_update_error:
                        logger.error(f"Failed to write access code file: {acc_update_error}")

                    if should_prompt_user:
                        logger.info("Sending notification to user.")
                        notif_status = show_notification(
                            title=f"Access Code: {ssh_code}, Admin: {user_name}",
                            message=f"Stored at: {ACCESS_CODE_FILE}. Valid for 5 minutes."
                        )
                        if not notif_status:
                            return_code = show_user_for(f"{ssh_code} {user_name} ASK_FOR_SSH_ACCESS")
                            if return_code not in (42, 0):
                                logger.info("Unable to show GUI, Read SSH code from file.")
                    else:
                        logger.info("User was already prompted for SSH access. Skipping.")

            except Exception as ssh_handle_error:
                logger.error(f"Error in handle_ssh_messages: {ssh_handle_error}")

        class SSHWebSocketSession:
            def __init__(self, user_id):
                self.user_id = user_id
                self.ws = None
                self.loop = asyncio.get_event_loop()
                self.master_fd = None
                self.process = None
                self.force_disconnect = asyncio.Event()
                env = os.environ.copy()
                # Set default TERM for interactive programs
                env.setdefault("TERM", "xterm-256color")
                env.setdefault("LANG", "en_US.UTF-8")

            async def connect(self):
                try:
                    async with websockets.connect(WEBSOCKET_URL, ssl=ssl_context_ws) as ws:
                        self.ws = ws
                        logger.info(f"[WS] WebSocket connected for user {self.user_id}")

                        await self.ws.send(json.dumps({"type": "agent_init", "pcId": PC_ID}))
                        self._create_pty_shell()
                        await self._handle_messages()
                except Exception as e:
                    logger.error(f"[WS] Connection error for user {self.user_id}: {e}")
                finally:
                    logger.info(f"[WS] WebSocket closed for user {self.user_id}")
                    self.ws = None
                    self.force_disconnect.clear()
                    connected_users.pop(self.user_id, None)

            async def _handle_messages(self):
                try:
                    while not self.force_disconnect.is_set():
                        message = await self.ws.recv()
                        data = json.loads(message)

                        msg_type = data.get("type", "")
                        command = data.get("command", "")

                        if msg_type == "agent_ack":
                            os.write(self.master_fd, b"\n")
                            continue

                        if data.get("userId", "") != self.user_id:
                            continue

                        # logger.debug(f"[WS] Received message for user {self.user_id}: {data}")

                        if msg_type == "user_disconnected":
                            logger.info(f"[WS] User {self.user_id} disconnected")
                            connected_users.pop(self.user_id, None)

                            # Kill PTY process group
                            if self.process:
                                try:
                                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                                    logger.info(f"[WS] Killed PTY process for user {self.user_id}")
                                except Exception as e:
                                    logger.error(f"[WS] Failed to kill PTY process: {e}")

                            if not connected_users:
                                logger.info("[WS] No users remain, forcing disconnect")
                                self.force_disconnect.set()
                                break
                            else:
                                logger.info(f"[WS] Active users still present: {list(connected_users.keys())}")
                                continue

                        elif msg_type == "send_command":
                            if isinstance(command, str):
                                # Special handling for Ctrl+C (0x03)
                                if command == "\x03":
                                    self._send_ctrl_c()
                                else:
                                    os.write(self.master_fd, command.encode())
                            elif isinstance(command, list):
                                os.write(self.master_fd, bytes(command))

                        else:
                            logger.warning(f"[WS] Unknown message type {msg_type} for user {self.user_id}")

                except websockets.ConnectionClosed:
                    logger.warning(f"[WS] Connection closed for user {self.user_id}")
                except Exception as e:
                    logger.error(f"[WS] Error handling messages for user {self.user_id}: {e}")

            def _create_pty_shell(self):
                self.master_fd, slave_fd = pty.openpty()

                env = os.environ.copy()
                env.setdefault("TERM", "xterm-256color")
                env.setdefault("LANG", "en_US.UTF-8")

                def preexec():
                    os.setsid()  # new session
                    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)  # make controlling TTY

                self.process = subprocess.Popen(
                    ["/bin/bash"],
                    preexec_fn=preexec,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    close_fds=True,
                    env=env
                )
                os.close(slave_fd)

                output_thread = threading.Thread(target=self._read_output, daemon=True)
                output_thread.start()

            def _read_output(self):
                while not self.force_disconnect.is_set():
                    try:
                        output = os.read(self.master_fd, 1024).decode(errors="ignore")
                        if output and self.ws:
                            asyncio.run_coroutine_threadsafe(
                                self._send_output(output), self.loop
                            )
                    except OSError:
                        logger.warning(f"[WS] PTY session ended for user {self.user_id}")
                        break

            async def _send_output(self, output):
                try:
                    # logger.debug(f"[WS] Sending output for {self.user_id}: {output!r}")
                    await self.ws.send(json.dumps({
                        "userId": self.user_id,
                        "pcId": PC_ID,
                        "type": "agent_result",
                        "result": output
                    }))
                except Exception as e:
                    logger.error(f"[WS] Failed to send output for user {self.user_id}: {e}")

            def _send_ctrl_c(self):
                """Send SIGINT like a real Ctrl+C."""
                if self.master_fd:
                    try:
                        # Get foreground process group of the terminal
                        fg_pgid = os.tcgetpgrp(self.master_fd)
                        os.killpg(fg_pgid, signal.SIGINT)
                        logger.debug(f"[WS] Sent SIGINT to foreground PGID {fg_pgid}")
                    except Exception as e:
                        logger.error(f"[WS] Failed to send Ctrl+C: {e}")


        async def handle_other_messages(patch_data):
            """Handle messages received from the backend."""
            try:
                logger.info(f"Received PATCH data: {patch_data}")
                pc_id = patch_data.get("pcId")
                if not pc_id or pc_id != PC_ID:
                    logger.info(f"Received PATCH data with pcId: {pc_id}, expected: {PC_ID}")
                    return

                type_of_message = patch_data.get("status", "")
                list_of_patches = patch_data.get("patches", [])

                # Offload each command/patch to its own background task
                if type_of_message == "command_available":
                    asyncio.create_task(process_commands())
                elif type_of_message == "patch_available":
                    asyncio.create_task(process_patches(list_of_patches))
                else:
                    logger.info(f"Unknown message type: {type_of_message}")
            except Exception as handle_messages_error:
                logger.error(f"Error handling messages: {handle_messages_error}")


        async def process_commands():
            try:
                conn = aiohttp.TCPConnector(ssl=ssl_context_aiohttp)
                async with aiohttp.ClientSession(connector=conn) as session:
                    # Generate 32-byte AES key
                    key = get_random_bytes(32)
                    key_b64 = base64.b64encode(key).decode()

                    # Encrypt the data
                    data = {'pcId': PC_ID, 'osType': OS_TYPE, 'key': key_b64}
                    data_enc = encrypt_using_public_key(json.dumps(data)).decode('utf-8')

                    if not data_enc:
                        logger.warning("Error: Encryption failed")
                        return

                    # Send POST request
                    async with session.post(ASK_FOR_CAMMANDS_URL, data={"encryptedData": data_enc}) as resp:
                        response_text = await resp.text()
                        logger.info(f"Command API Response: {response_text}")
                        response = resp

                    if not response:
                        logger.warning("Error: Failed to ask for commands")
                        return

                    # Check HTTP status
                    if response.status == 200:
                        response_data = await response.json()
                        iv_b64, ciphertext_b64 = response_data.get("iv"), response_data.get("encryptedData")
                        # Decode
                        iv = base64.b64decode(iv_b64)
                        ciphertext = base64.b64decode(ciphertext_b64)

                        # Decrypt
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        decrypted_padded = cipher.decrypt(ciphertext)
                        plain_text = unpad(decrypted_padded, AES.block_size).decode()
                        data_in_json = json.loads(plain_text)
                        logger.info(f"Received json: {data_in_json}")
                        list_of_commands = list(data_in_json)

                    else:
                        logger.warning(f"Error: Failed to ask for commands, HTTP status {response.status}")
                        return

                    final_payload = {
                        "pcId": PC_ID,
                        "osType": OS_TYPE,
                        "listOfCommand": []
                    }
                    restart_needed = False
                    for command in list_of_commands:
                        os_command_id = command.get("osCommandId")
                        command_id = command.get("_id")
                        command_name = command.get("commandName")
                        command_type = command.get("commandType")

                        status, log = False, ""

                        if not command_name:
                            continue
                        elif command_type == "CUSTOM":
                            try:
                                status, log = await asyncio.wait_for(
                                    execute_command(command_name), timeout=120
                                )
                            except asyncio.TimeoutError:
                                status, log = False, "Command timed out"
                        elif command_name == "enable_wifi":
                            status, log, restart_needed = await enable_disable_wifi_driver(True)
                        elif command_name == "disable_wifi":
                            status, log, restart_needed = await enable_disable_wifi_driver(False)
                        elif command_name == "enable_bluetooth":
                            status, log, restart_needed = await enable_disable_bluetooth_driver(True)
                        elif command_name == "disable_bluetooth":
                            status, log, restart_needed = await enable_disable_bluetooth_driver(False)
                        elif command_name == "enable_usb":
                            status, log, restart_needed = await enable_disable_usb_ports(True)
                        elif command_name == "disable_usb":
                            status, log, restart_needed = await enable_disable_usb_ports(False)
                        elif command_name == "enable_rdp":
                            status, log = await enable_disable_rdp(True)
                        elif command_name == "disable_rdp":
                            status, log = await enable_disable_rdp(False)
                        elif command_name == "enable_ssh":
                            status, log = await enable_disable_ssh(True)
                        elif command_name == "disable_ssh":
                            status, log = await enable_disable_ssh(False)
                        elif command_name == "enable_firewall":
                            status, log = await enable_disable_firewall(True)
                        elif command_name == "disable_firewall":
                            status, log = await enable_disable_firewall(False)
                        else:
                            status = False
                            log = "Commnad not accepted by agent"

                        log_len = len(log)
                        if log_len > 4000000:
                            log = log[log_len-4000000:]
                        final_payload["listOfCommand"].append({
                            "commandId": command_id,
                            "osCommandId": os_command_id,
                            "status": status,
                            "log": log,
                            "timestamp": time.strftime("%d-%m-%Y %H:%M:%S"),
                        })

                        # logger.info(f"Sending API(Commands) Payload:\n {json.dumps(final_payload, indent=2)}")
                        # --- Hybrid Encryption for Sending Results ---
                        sym_key = get_random_bytes(32)   # AES-256
                        iv = get_random_bytes(16)

                        cipher_aes = AES.new(sym_key, AES.MODE_CBC, iv)
                        ciphertext = cipher_aes.encrypt(pad(json.dumps(final_payload).encode(), AES.block_size))
                        ciphertext_b64 = base64.b64encode(ciphertext).decode()

                        meta_dict = {"key": base64.b64encode(sym_key).decode(), "iv": base64.b64encode(iv).decode()}
                        meta_enc = encrypt_using_public_key(json.dumps(meta_dict)).decode('utf-8')

                        payload = {
                            "meta": meta_enc,
                            "encryptedData": ciphertext_b64
                        }

                        async with session.post(SEND_COMMANDS_URL, json=payload) as response:
                            text = await response.text()
                            data = await response.json()
                            if data.get("status") is True:
                                final_payload["listOfCommand"] = []
                            logger.info(f"API Response: {text}")

                    # Reboot the system
                    if restart_needed:
                        return_code = show_user_for("ASK_FOR_REBOOT")

                        if return_code == 42:
                            logger.info("User was prompted about the system reboot but rejected...")
                        else:
                            if return_code != 0:
                                logger.info("Something went wrong. Rebooting the system in 20 seconds...")
                                show_notification(
                                    title="Please save your work.",
                                    message="System will reboot in 20 seconds."
                                )
                                await asyncio.sleep(20)
                            else:
                                logger.info("User accepted the system reboot.")
                            
                            subprocess.run(["reboot"], check=True)

            except Exception as e:
                logger.error(f"[COMMANDS] Error: {e}")


        async def process_patches(list_of_patches):
            try:
                conn = aiohttp.TCPConnector(ssl=ssl_context_aiohttp)
                async with aiohttp.ClientSession(connector=conn) as session:
                    for patch in list_of_patches:
                        final_payload = {
                            "pcId": PC_ID,
                            "osType": OS_TYPE,
                            "patches": []
                        }

                        patch_id = patch.get("patchId")
                        patch_type = patch.get("patchType")
                        patch_info_id = patch.get("patchInfoId")
                        list_of_files = patch.get("listOfFiles", [])
                        processed_files = []

                        for file in list_of_files:
                            file_name = file.get("fileName")
                            file_hash = file.get("fileHash")
                            logger.info(f"Processing file: {file_name}")
                            if not file_name:
                                continue

                            encoded_file_name = urllib.parse.quote(file_name)
                            logger.info(f"Encoded file name: {encoded_file_name}")
                            download_url = f"{PATCH_DOWNLOAD_API}/{patch_id}/{encoded_file_name}"
                            logger.info(f"Downloading file from: {download_url}")

                            file_path = f"/tmp/{file_name}"
                            download_success = await download_update_package_file(download_url, file_path,
                                                                                  session)

                            if not download_success:
                                logger.warning(f"Failed to download {file_name}")
                                processed_files.append({
                                    "fileStatus": False,
                                    "fileName": file_name,
                                    "log": "Failed to download file"
                                })
                                continue

                            integrity_of_downloaded_file = await check_downloaded_file_integrity(file_path,
                                                                                                file_hash)
                            if not integrity_of_downloaded_file:
                                logger.warning(f"Failed to check Integrity of {file_name}")
                                processed_files.append({
                                    "fileStatus": False,
                                    "fileName": file_name,
                                    "log": "Failed to check integrity of downloaded file."
                                })
                                continue

                            if file_name.endswith(".rpm") or file_name.endswith(".deb"):
                                status, log = await install_update_package(file_name, file_path)
                            else:
                                status, log = await run_directly(file_name, file_path)

                            log_len = len(log)
                            if log_len > 4000000:
                                log = log[log_len-4000000:]
                            processed_files.append({
                                "fileStatus": status,
                                "fileName": file_name,
                                "log": log
                            })

                        final_payload["patches"].append({
                            "patchId": patch_id,
                            "patchType": patch_type,
                            "patchInfoId": patch_info_id,
                            "status": all(file["fileStatus"] for file in processed_files),
                            "files": processed_files
                        })

                        logger.info(f"Sending API Payload:\n {json.dumps(final_payload, indent=2)}")
                        async with session.post(STATUS_SEND_URL, json=final_payload) as response:
                            text = await response.text()
                            data = await response.json()
                            if data.get("status") == True:
                                final_payload["patches"] = []
                            logger.info(f"API Response: {text}")

            except Exception as e:
                logger.error(f"[PATCHES] Error: {e}")


        def show_notification(title, message, icon_name="ca-icon.ico"):
            logger.info("Sending the notification toast to the Linux user.")
            try:
                logger.info("Notification Section Starts")
                user = get_current_loggedin_user()
                logger.info(f"Notification Section - notify_current_loggedin_user: {user}")

                notify_userid = (
                    subprocess.run(['id', '-u', user], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=True, timeout=TIMEOUT_SUBPROCESS)
                    .stdout.decode('utf-8').strip()
                )

                logger.info(f"Notification Section - notify_userid: {notify_userid}")
                logger.info(f"Notification Section - DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{notify_userid}/bus")

                # Fallback to default icon if file doesn't exist
                icon_path = os.path.join(DESTINATION_WORKING_DIRECTORY, icon_name)
                if not os.path.exists(icon_path):
                    icon_path = "utilities-terminal"

                # Run notify-send using DBus of the logged-in user
                notify_cmd = [
                    'sudo', '-u', user,
                    f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{notify_userid}/bus',
                    'notify-send', '-i', icon_path, title, message
                ]

                notify_subprocess_result = subprocess.run(
                    notify_cmd,
                    env=os.environ,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    timeout=TIMEOUT_SUBPROCESS
                )

                logger.info(f"Notification Section - notify-send result: {notify_subprocess_result}")
                logger.info("Notification toast sent to the Linux user successfully.")
                return True
            except Exception as err:
                logger.warning(f"Notification toast not sent to the Linux user. Error: {err}")
                return False


        def show_user_for(arg):
            try:
                script = """#!/bin/bash
# Detect active session and user
active_user=""
for session in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
    is_active=$(loginctl show-session "$session" -p Active | awk -F= '{print $2}')
    if [ "$is_active" = "yes" ]; then
        active_user=$(loginctl show-session "$session" -p Name | awk -F= '{print $2}')
        if [ -n "$active_user" ]; then
            break
        fi
    fi
done

# Fallback if empty
if [ -z "$active_user" ]; then
    active_user=$(who | head -n1 | awk '{print $1}')
fi

# Still no user? Abort.
if [ -z "$active_user" ]; then
    echo "Could not detect any logged-in user"
    exit 1
fi

uid=$(id -u "$active_user")
user_home=$(getent passwd "$active_user" | cut -d: -f6)

display=$(loginctl show-session "$session" -p Display | awk -F= '{print $2}')
if [ -z "$display" ]; then
  display=":0"
fi

xauth="$user_home/.Xauthority"

export DISPLAY="$display"
export XAUTHORITY="$xauth"

su - "$active_user" -c "xhost +SI:localuser:root"
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus"

su - "$active_user" -c "DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY \
    DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS \
    /etc/cyberauditor_linux_agent/setup-agent """ + f'{arg}"'
                result_out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
                logger.info(result_out)
                return result_out.returncode
            except Exception as show_user_gui:
                logger.error(f"Error in show_user_gui: {show_user_gui}")
                return -1


        async def check_downloaded_file_integrity(file_path, signature_base64):
            try:
                public_key = RSA.import_key(CA_PUBLIC_KEY)

                # Load original file
                with open(file_path, 'rb') as f:
                    file_buffer = f.read()

                # Decode signature from base64
                signature = base64.b64decode(signature_base64)

                # Step 1: Compute hash of the file
                hash_obj = SHA256.new(file_buffer)

                # Step 2: Verify signature
                pkcs1_15.new(public_key).verify(hash_obj, signature)
                return True
            except (ValueError, TypeError):
                return False
            except Exception as integrity_check_err:
                logger.error(f"Error in integrity check of downloaded file: {integrity_check_err}")
                return False


        # === Security Settings Handler ===
        async def enable_disable_usb_ports(enable=True):
            status = False
            blacklist_file = "/etc/modprobe.d/disable-usb-storage.conf"
            udev_rule_file = "/etc/udev/rules.d/80-block-mtp-ptp.rules"
            restart_needed = False
            try:
                logger.info(f"{'Enabling' if enable else 'Disabling'} USB ports...")
                if not enable:
                    lines = [
                        "blacklist usb_storage\n",
                        "blacklist uas\n"
                    ]
                else:
                    lines = [
                        "# blacklist usb_storage\n",
                        "# blacklist uas\n"
                    ]

                with open(blacklist_file, "w") as f:
                    f.writelines(lines)

                # Regenerate initramfs
                logger.info("Regenerating initramfs...")
                if OS_NAME == "ubuntu":
                    subprocess.run(["update-initramfs", "-u"], check=True)
                else:
                    subprocess.run(["dracut", "-f"], check=True)

                if not enable:
                    rule_content = (
                        'SUBSYSTEM=="usb", ENV{ID_MTP_DEVICE}=="1", RUN+="/bin/sh -c \'echo 0 > /sys$devpath/authorized\'"\n'
                        'SUBSYSTEM=="usb", ENV{GPHOTO2_DRIVER}=="PTP", RUN+="/bin/sh -c \'echo 0 > /sys$devpath/authorized\'"\n'
                        'SUBSYSTEM=="usb", ENV{ID_GPHOTO2}=="1", RUN+="/bin/sh -c \'echo 0 > /sys$devpath/authorized\'"\n'
                    )

                    with open(udev_rule_file, "w") as f:
                        f.write(rule_content)

                    subprocess.run(["udevadm", "control", "--reload"], check=False)
                    subprocess.run(["udevadm", "trigger"], check=False)

                    logger.info("MTP/PTP devices blocked successfully.")
                else:
                    if os.path.exists(udev_rule_file):
                        os.remove(udev_rule_file)
                        logger.info("Removed MTP/PTP blocking udev rule")

                    subprocess.run(["udevadm", "control", "--reload"], check=False)
                    subprocess.run(["udevadm", "trigger"], check=False)
                    logger.info("MTP/PTP devices re-enabled successfully.")

                status = True
                log = "Successfully enabled USB storage devices." if enable else "Successfully disabled USB storage devices."
                restart_needed = True
            except Exception as usb_port_error:
                logger.error(f"Error in enabling/disabling USB port: {usb_port_error}")
                log = str(usb_port_error)
            return status, log, restart_needed


        async def enable_disable_bluetooth_driver(enable=True):
            status = False
            blacklist_file = "/etc/modprobe.d/disable-bluetooth.conf"
            restart_needed = False
            try:
                logger.info(f"{'Enabling' if enable else 'Disabling'} Bluetooth driver...")
                if not enable:
                    lines = [
                        "blacklist btusb\n"
                    ]
                else:
                    lines = [
                        "# blacklist btusb\n"
                    ]

                with open(blacklist_file, "w") as f:
                    f.writelines(lines)

                logger.info("Regenerating initramfs...")
                if OS_NAME == "ubuntu":
                    subprocess.run(["update-initramfs", "-u"], check=True)
                else:
                    subprocess.run(["dracut", "-f"], check=True)

                status = True
                log = "Successfully enabled Bluetooth devices." if enable else "Successfully disabled Bluetooth devices."
                restart_needed = True
            except Exception as bluetooth_error:
                logger.error(f"Error in enabling/disabling Bluetooth: {bluetooth_error}")
                log = str(bluetooth_error)
            return status, log, restart_needed


        async def enable_disable_wifi_driver(enable=True):
            status = False
            blacklist_file = "/etc/modprobe.d/disable-wifi.conf"
            restart_needed = False
            wifi_modules = [
                "iwlwifi", "iwlmvm", "iwldvm",
                "rtl8xxxu", "rtl8192cu", "rtl8192ce", "rtl8188eu",
                "rtl8821cu", "rtl8822bu", "rtl8812au", "rtl8814au",
                "ath9k_htc", "ath10k_pci", "ath10k_usb", "ath9k",
                "b43", "brcmfmac", "wl",
                "mt76x0u", "mt76x2u", "mt7610u",
                "rt2800usb", "rt2870sta", "rt61pci",
                "zd1211rw", "rtl8723bu",
            ]
            try:
                logger.info(f"{'Enabling' if enable else 'Disabling'} Wi-Fi drivers...")

                if not enable:
                    # Disable Wi-Fi: write blacklist entries
                    lines = [f"blacklist {mod}\n" for mod in wifi_modules]
                else:
                    # Enable Wi-Fi: comment out the blacklist lines
                    lines = [f"# blacklist {mod}\n" for mod in wifi_modules]

                with open(blacklist_file, "w") as f:
                    f.writelines(lines)

                logger.info("Regenerating initramfs...")
                if OS_NAME == "ubuntu":
                    subprocess.run(["update-initramfs", "-u"], check=True)
                else:
                    subprocess.run(["dracut", "-f"], check=True)

                status = True
                log = "Successfully enabled WiFi devices." if enable else "Successfully disabled WiFi devices."
                restart_needed = True
            except Exception as wifi_error:
                logger.error(f"Error in enabling/disabling WiFi: {wifi_error}")
                log = str(wifi_error)
            return status, log, restart_needed


        async def enable_disable_firewall(enable=True):
            status = False

            try:
                firewalls = ["ufw", "firewalld", "nftables", "iptables"]
                logger.info(f"{'Enabling' if enable else 'Disabling'} Firewall service...")
                if not enable:
                    for firewall in firewalls:
                        try:
                            subprocess.run(["systemctl", "disable", "--now", f"{firewall}.service"], check=True)
                        except subprocess.CalledProcessError:
                            pass
                    status = True
                    log = "Successfully disabled Firewall services."
                else:
                    for firewall in firewalls:
                        try:
                            result = subprocess.run(["systemctl", "enable", "--now", f"{firewall}.service"], check=True)
                            if result.returncode == 0:
                                status = True
                                log = f"Successfully enabled and started service: {firewall}."
                                logger.info(log)
                                return status, log
                        except subprocess.CalledProcessError:
                            pass
                    status = True
                    log = "Not able to enable Firewall services."
            except Exception as firewall_error:
                logger.error(f"Error in enabling/disabling WiFi: {firewall_error}")
                log = str(firewall_error)
            return status, log


        async def enable_disable_rdp(enable=True):
            status = False
            try:
                user_logged_in = get_current_loggedin_user()
                logger.info(f"{'Enabling' if enable else 'Disabling'} RDP service...")                
                if OS_NAME == "ubuntu":
                    cmd_arg = "true" if enable else "false"
                    cmd = f"su - '{user_logged_in}' -c 'gsettings set org.gnome.desktop.remote-desktop.rdp enable {cmd_arg}'"
                
                else:
                    user_id_cmd = f"id -u '{user_logged_in}'"
                    user_id_result = subprocess.run(user_id_cmd, shell=True, capture_output=True, text=True)
                    if user_id_result.returncode != 0:
                        raise RuntimeError("Failed to get user ID")
                    user_id = user_id_result.stdout.strip()
                    dbus_address = f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{user_id}/bus"

                    cmd_arg = "restart" if enable else "disable --now"
                    cmd = f"su - '{user_logged_in}' -c '{dbus_address} systemctl --user {cmd_arg} gnome-remote-desktop.service'"

                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                if result.returncode == 0:
                    status = True
                    log = f"Successfully {'enabled' if enable else 'disabled'} RDP service."
                    logger.info(log)
                else:
                    log = result.stderr.strip()
                    logger.warning(f"Failed to {'enable' if enable else 'disable'} RDP: {log}")

            except Exception as rdp_err:
                log = f"Error in enabling/disabling RDP: {str(rdp_err)}"
                logger.error(log)

            return status, log


        async def enable_disable_ssh(enable=True):
            status = False
            log = ""

            try:
                logger.info(f"{'Enabling' if enable else 'Disabling'} SSH service...")
                service_name = "ssh" if OS_NAME == "ubuntu" else "sshd"
                if enable:
                    try:
                        result_ssh = subprocess.run(["systemctl", "enable", "--now", service_name], check=True)
                        if result_ssh.returncode == 0:
                            status = True
                            log = "Successfully enabled SSH service."
                            logger.info(log)
                    except subprocess.CalledProcessError:
                        logger.warning(log)
                        status = False
                        log = "Unable to start SSH service."
                else:
                    try:
                        subprocess.run(["systemctl", "disable", "--now", service_name], check=True)
                        log = "Successfully disabled SSH service."
                    except subprocess.CalledProcessError:
                        logger.warning("Unable to stop SSH service.")
                        log = "SSH is already disabled/not running."
                    status = True

            except Exception as ssh_rdp_error:
                logger.error(f"Error in enabling/disabling SSH: {ssh_rdp_error}")

            return status, log


        # === Security Settings Handler ===

        async def execute_command(command):
            status = False
            log = ""
            try:
                logger.info(f"Running command: {command}")

                # Async subprocess
                process = await asyncio.create_subprocess_exec(
                    "bash", "-c", command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await process.communicate()

                status = process.returncode == 0
                log = stdout.decode().strip() if status else stderr.decode().strip()

            except Exception as execute_command_error:
                logger.error(f"Error: {execute_command_error}")
                log = str(execute_command_error)

            return status, log


        async def install_update_package(package_name, package_path):
            """Download and install an RPM package."""
            status = False
            log = ""
            try:
                if os.path.exists(package_path):
                    logger.info(f"Installing package: {package_name} from {package_path}")
                    if package_name.endswith(".rpm"):
                        result = subprocess.run(
                            ["rpm", "-Uvh", "--force", package_path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                    else:
                        result = subprocess.run(
                            ["dpkg", "-i", package_path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                    status = result.returncode == 0
                    log = result.stdout if status else result.stderr
                else:
                    log = "Package file not found after download."
            except Exception as install_update_package_error:
                logger.info(f"Error: {install_update_package_error}")
                log = str(install_update_package_error)
            finally:
                if package_path and os.path.exists(package_path):
                    os.remove(package_path)
                return status, log


        async def run_directly(package_name, package_path):
            status = False
            log = ""
            try:
                script_dir = os.path.dirname(os.path.abspath(package_path))
                if os.path.exists(package_path):
                    logger.info(f"Running package: {package_name} from {script_dir}")
                    result = subprocess.run(
                        [package_path],
                        cwd=script_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    status = result.returncode == 0
                    log = result.stdout if status else result.stderr
                else:
                    log = "Package file not found after download."
            except Exception as download_and_run_directly_error:
                logger.info(f"Error: {download_and_run_directly_error}")
                log = str(download_and_run_directly_error)
            finally:
                if package_path and os.path.exists(package_path):
                    os.remove(package_path)
                return status, log


        async def download_update_package_file(url, dest, session):
            """Asynchronously download a package file with retry on 502 errors."""
            max_retries = 3
            retry_delay = 5
            for attempt in range(1, max_retries + 1):
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            os.makedirs(os.path.dirname(dest), exist_ok=True)

                            with open(dest, 'wb') as file_to_write:
                                async for chunk in response.content.iter_chunked(8192):
                                    file_to_write.write(chunk)

                            if os.path.exists(dest) and os.path.getsize(dest) > 0:
                                logger.info("Successfully downloaded file")
                                return True
                            else:
                                logger.warning("File downloaded but is empty or invalid")
                                return False

                        elif response.status == 502:
                            logger.warning(
                                f"Received 502 Bad Gateway (attempt {attempt}/{max_retries}). "
                                f"Retrying in {retry_delay} seconds..."
                            )
                            if attempt < max_retries:
                                await asyncio.sleep(retry_delay)
                                continue
                            return False

                        else:
                            logger.warning(
                                f"Failed to download file, HTTP status {response.status}"
                            )
                            return False

                except aiohttp.ClientError as e:
                    logger.warning(
                        f"Client error during download (attempt {attempt}/{max_retries}): {e}"
                    )
                    if attempt < max_retries:
                        await asyncio.sleep(retry_delay)
                        continue
                    return False

                except Exception as e:
                    logger.exception(f"Unexpected error during download: {e}")
                    return False

            return False


        # === RAM Dump Handler ===
        async def take_current_ram_dump(ram_dump_id):
            async def get_sha_256(file_path_source):
                try:
                    hash_sha256 = hashlib.sha256()
                    with open(file_path_source, "rb") as as_file:
                        # Read the file in chunks of 4096 bytes
                        for chunk in iter(lambda: as_file.read(4096), b""):
                            hash_sha256.update(chunk)
                    return hash_sha256.hexdigest()
                except Exception as hash_error:
                    logger.error(f"An hash_error: {hash_error}")
                    return None

            async def initiate_upload(session, file_name, total_chunks, pc_id, key_b64, iv_b64, raw_hash):
                payload = {
                    "pcId": pc_id,
                    "osType": OS_TYPE,
                    "fileName": file_name,
                    "totalChunks": total_chunks,
                    "key": key_b64,
                    "iv": iv_b64,
                    "hash": raw_hash,
                    "ramDumpId": ram_dump_id
                }
                try:
                    encrypted_data = encrypt_using_public_key(json.dumps(payload)).decode('utf-8')
                    async with session.post(INIT_DUMP_URL, json={"encryptedData": encrypted_data}) as resp:
                        result = await resp.json()
                        logger.info(f"Init Dump Response: {result}")
                        return result.get("ramDumpId")
                except Exception as init_err:
                    logger.error(f"Failed to initiate upload: {init_err}")
                    return None

            async def upload_chunk(session, upload_id, chunk_data, chunk_index, chunk_hash, max_retries=2):
                """Upload a single chunk with retry logic."""
                headers = {
                    "ramdumpid": upload_id,
                    "chunkindex": str(chunk_index),
                    "chunkhash": chunk_hash,
                }
                for attempt in range(1, max_retries + 2):  # 1 + retries
                    try:
                        async with session.post(UPLOAD_CHUNK_URL, headers=headers, data=chunk_data) as resp:
                            result = await resp.json()
                            logger.info(f"Uploaded chunk {chunk_index}: {result}")
                            return True
                    except Exception as upload_err:
                        logger.warning(f"Attempt {attempt} failed for chunk {chunk_index}: {upload_err}")
                        if attempt <= max_retries:
                            await asyncio.sleep(2)
                        else:
                            logger.error(f"Failed to upload chunk {chunk_index} after {max_retries+1} attempts")
                            return False
                return False

            async def complete_upload(session, upload_id):
                try:
                    async with session.post(f"{COMPLETE_URL}/{upload_id}") as res:
                        result = await res.json()
                        logger.info(f"Dump Completion Result: {result}")
                except Exception as complete_err:
                    logger.error(f"Failed to complete upload: {complete_err}")

            async def upload_file_encrypted_chunked(file_path, pc_id, key, iv, key_b64, iv_b64, raw_hash):
                try:
                    file_size = os.path.getsize(file_path)
                    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
                    file_name = os.path.basename(file_path)
                    logger.info(f"Uploading encrypted file: {file_name}, size: {file_size} bytes, chunks: {total_chunks}")
                    BLOCK_SIZE = 16  # AES block size in bytes
                    initial_counter = int.from_bytes(iv, byteorder='big')
                    conn = aiohttp.TCPConnector(ssl=ssl_context_aiohttp)
                    async with aiohttp.ClientSession(connector=conn) as session:
                        upload_id = await initiate_upload(session, file_name, total_chunks, pc_id, key_b64, iv_b64, raw_hash)
                        if not upload_id:
                            return
                        with open(file_path, 'rb') as f:
                            for chunk_index in range(total_chunks):
                                chunk_data = f.read(CHUNK_SIZE)
                                if not chunk_data:
                                    break
                                # Calculate correct counter for this chunk:
                                blocks_so_far = (chunk_index * CHUNK_SIZE) // BLOCK_SIZE
                                counter_for_chunk = initial_counter + blocks_so_far
                                ctr = Counter.new(128, initial_value=counter_for_chunk)
                                cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
                                chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                                encrypted_chunk = cipher.encrypt(chunk_data)
                                success = await upload_chunk(session, upload_id, encrypted_chunk, chunk_index + 1, chunk_hash)
                                if not success:
                                    logger.error(f"Upload failed at chunk {chunk_index+1}, deleting file {file_path}")
                                    try:
                                        os.remove(file_path)
                                        logger.info(f"Deleted file {file_path}")
                                    except Exception as e:
                                        logger.error(f"Error deleting file {file_path}: {e}")
                                    return
                        await complete_upload(session, upload_id)
                except Exception as file_chunked_err:
                    logger.error(f"Error in upload_file_encrypted_chunked: {file_chunked_err}")


            """Take a RAM dump and upload it to the API."""
            raw_dump = ""
            try:

                key = get_random_bytes(32)
                key_b64 = base64.b64encode(key).decode()
                iv = get_random_bytes(16)
                iv_b64 = base64.b64encode(iv).decode()

                os.makedirs(RAM_DUMP_LOGS_FOLDER, exist_ok=True)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dump_filename = f"ramdump_{timestamp}.lime.zlib"
                raw_dump = os.path.join(RAM_DUMP_LOGS_FOLDER, dump_filename)

                process = await asyncio.create_subprocess_exec(
                    AVML_BINARY,
                    raw_dump,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                logger.info(f"avml stdout: {stdout}, stderr: {stderr}")
                if process.returncode != 0:
                    return

                raw_sha = await get_sha_256(raw_dump)
                logger.info(f"Raw SHA256: {raw_sha}")
                if not raw_sha:
                    logger.error("Hashing failed. Aborting.")
                    return

                logger.info(f"RAM dump created: {raw_dump}, size: {os.path.getsize(raw_dump)} bytes, ")

                # Remove encrypt_file_aes_ctr and encrypted_dump usage
                await upload_file_encrypted_chunked(raw_dump, PC_ID, key, iv, key_b64, iv_b64, raw_sha)
                os.remove(raw_dump)

            except Exception as ram_dump_error:
                logger.error(f"Error in take_current_ram_dump: {ram_dump_error}")
            finally:
                if os.path.exists(raw_dump):
                    os.remove(raw_dump)


        try:
            active_websocket = None
            master_fd = None
            event_loop = asyncio.get_event_loop()
            websocket_force_disconnect = asyncio.Event()
            last_command_user_id = None
            connected_users = {}
            CHUNK_SIZE = 500 * 1024 * 1024

            get_hostname_from_env()
            OS_NAME = get_os_distributor_name()[0]
            PC_ID = get_pc_id()
            PC_ID_FORMATTED = PC_ID.replace(" ", "_")
            STREAM_NAME = "PATCH_STREAM"
            DURABLE_NAME = f"durable-patch-{PC_ID_FORMATTED}"
            CORE_SUBJECT = f"agent.command.{PC_ID_FORMATTED}"
            JETSTREAM_SUBJECT = f"patch.status.{PC_ID_FORMATTED}"
            RECONNECT_DELAY = 10
            OS_TYPE = "Linux"
            nc = NATS()
            js = None
            subscription = None
            subscribed = False
            jetstream_subscription = None
            core_subscription = None 

            if OS_NAME == "ubuntu":
                if CA_FILE:
                    ssl_context_ws = ssl.create_default_context(cafile=CA_FILE)
                    ssl_context_aiohttp = ssl.create_default_context(cafile=CA_FILE)

                else:
                    ssl_context_ws = ssl.create_default_context(cafile=certifi.where())
                    ssl_context_aiohttp = ssl.create_default_context(cafile=certifi.where())
            else:
                ssl_context_ws = ssl.SSLContext()
                ssl_context_aiohttp = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

                if CA_FILE:
                    ssl_context_ws.load_verify_locations(cafile=CA_FILE)
                    ssl_context_aiohttp.load_verify_locations(cafile=CA_FILE)
                else:
                    ssl_context_ws.load_default_certs()
                    ssl_context_aiohttp.load_default_certs()

            logger.info(f"Connecting to NATS_URL: {NATS_URL}")
            asyncio.run(listen_for_patches())
        except Exception as patch_update_error:
            print(f"Error in Patch update block: {patch_update_error}")

    elif TRIGGER_TYPE == 'LINUX_COMMAND_HISTORY':
        FEATURES = json.loads(decrypt_string(ORG_FEATURES_FILE_PATH) or "{}")
        if not FEATURES.get("CommandHistory"):
            print("CommandHistory feature is disabled")
        else:
            if (not os.path.exists(PIDS_MAINTAIN_FILE_PATH) and
                    os.path.exists(CMD_TIMESTAMP_FILE_PATH)):
                time.sleep(30)
            main_logic_for_command_history()

    elif TRIGGER_TYPE == "LINUX_CLEANUP_SERVICE":
        def remove_temp_files():
            patterns = ["/tmp/cyberauditor_linux_*", "/tmp/cyberauditor_setup*", "/tmp/cyberauditor-setup*"]
            for pattern in patterns:
                for path in glob.glob(pattern):
                    try:
                        os.remove(path)
                        print(f"Deleted: {path}")
                    except Exception as delete_err:
                        print(f"Failed to delete {path}: {delete_err}")

        FEATURES = json.loads(decrypt_string(ORG_FEATURES_FILE_PATH) or "{}")
        try:
            if not os.path.exists("/tmp/cyberauditor_flag_for_cleanup"):
                if not FEATURES.get("CommandHistory"):
                    print("CommandHistory feature is disabled")
                else:
                    main_logic_for_command_history()
            remove_temp_files()
        except Exception as cleanup_error:
            print(f"Error in Cleanup block: {cleanup_error}")

    else:
        print(queue.__name__)
        sys.exit(0)
