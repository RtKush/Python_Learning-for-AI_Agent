import os #Used to interact with the operating system.
import sys #Used to interact with the Python runtime.
import subprocess #Run Linux commands / external programs from Python.
from datetime import time, datetime
from Crypto.Cipher import AES #encryption
from Crypto.Util.Padding import pad
import logging # professional way to print instead of print
import tkinter as tk # GUI
from tkinter import ttk # modern wedgets
from tkinter import messagebox # popup message 
import requests # used in rest API
import queue #thread safe communication
import threading # run task in parallel
import random # selection of random choice 
import shutil # file operations-> copy, rename, delete
import base64 #Encode binary data into readable text.
import json # handle the json data 
import time as time_lib
from PIL import Image, ImageTk #Image = load & process images, ImageTk = convert images so Tkinter can display them in GUI

# CHANGE THE FOLLOWING ENV_VARIABLE FROM DEV/TEST/PROD
# ----------------------------------------------------
ENVIRONMENT = "DEMO"
CERT_NEEDED = True
HOSTNAME_NEEDED = True
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
ADMIN_NAME = " ".join(sys.argv[2:-1]) if len(sys.argv) > 2 else ""
ADMIN_CODE = sys.argv[1] if len(sys.argv) > 1 else ""
CUSTODIAN_NAME = sys.argv[-3] if len(sys.argv) > 3 else ""
LICENSE_KEY = sys.argv[-2] if len(sys.argv) > 2 else ""
LICENSE_KEY_VALIDATE_API = f"{HOSTNAME}/api/v1/config/validate"
TRIGGER_INTERVAL_IN_HOUR = 24
CMD_HISTORY_INTERVAL_IN_HOUR = 4
WATCHDOG_INTERVAL_IN_MINUTES = 5
LOCAL_AGENT_VERSION = {
    "ubuntu": "26.1.1",
    "rhel": "26.1.1",
    "centos": "26.1.1",
}

# Initializing paths and script names
LOGS_DESTINATION_DIRECTORY = "/var/log/cyberauditor_linux_agent_logs/"
LOGGER_FILE_NAME = "cyberauditor-setup.log"
DESTINATION_WORKING_DIRECTORY = "/etc/cyberauditor_linux_agent/"
AUDIT_EXE_DIRECTORY_NAME = "/etc/cyberauditor_linux_agent/audit_exe/"
AGENT_FOLDER_NAME = "audit_exe/"
AGENT_FILE_NAME = "audit-agent"
SERVICE_EXE_DIRECTORY_NAME = "/etc/cyberauditor_linux_agent/service_exe/"
SERVICE_FOLDER_NAME = "service_exe/"
SERVICE_FILE_NAME = "service-agent"
SETUP_AGENT_FILE_NAME = "setup-agent"
WATCHDOG_INTERVAL_IN_SECONDS = WATCHDOG_INTERVAL_IN_MINUTES * 60
PIDS_MAINTAIN_FILE_PATH = "/tmp/cyberauditor_linux_pids.txt"
SYSTEMD_PATH = "/etc/systemd/system/"
ACCESS_CODE_FILE = LOGS_DESTINATION_DIRECTORY + "access_code.json"
ORG_FEATURES_FILE_PATH = "/var/lib/cyberauditor-linux-agent/org_features.txt"
TIMEOUT_SUBPROCESS = 10
COMMAND_HISTORY_STATUS = False
CA_FILE = os.path.join(DESTINATION_WORKING_DIRECTORY, "ca.crt") if CERT_NEEDED else None

# ===================KEYS===================
p_key = base64.urlsafe_b64decode('nAy7rLX4teIS2CR_2lpV8mt67VvTQT53o2D_-ErE6Ng=')
iv = b'1234567890123456'


# Function to setup the logger
def setup_logger_function():
    setup_logger_function_status = False

    def create_logger_file():
        is_logger_file_creation_successful = False
        var_log_file_path = ""
        try:

            # Define the path to the log file
            var_log_file_path = os.path.join("/tmp/", LOGGER_FILE_NAME)
            is_logger_file_creation_successful = True

        except Exception as setup_logger_err:
            print(f"Error creating logger file: {setup_logger_err}")

        return is_logger_file_creation_successful, var_log_file_path

    def setup_logger(log_file):
        setup_logger_status = False
        try:
            # Configure the logger
            logging.basicConfig(filename=log_file, level=logging.DEBUG,
                                format=f'%(asctime)s - %(levelname)s -> %(message)s')
            setup_logger_status = True
        except Exception as setup_logger_err:
            with open(log_file, 'w') as log_file_text:
                log_file_text.write(f"Error setting up logger_file: {setup_logger_err}")

        return setup_logger_status

    is_logger_file_creation_successful_status, logger_file = create_logger_file()

    if is_logger_file_creation_successful_status:
        setup_logger_creation_status = setup_logger(logger_file)
        if setup_logger_creation_status:
            setup_logger_function_status = True
    else:
        print(f"Error creating logger file at path: {logger_file}")

    return setup_logger_function_status


# Function to setup the logger function
def logger_function(func):
    """
    Decorator function that wraps another function and logs its name and current time.

    Parameters:
        func (function): The function to be wrapped.

    Returns:
        function: The wrapped function.
    """
    try:
        def wrapper(*args, **kwargs):
            """
            Logs the function name and current time, calls the wrapped function, and returns its result.

            Parameters:
                *args: The positional arguments passed to the wrapped function.
                **kwargs: The keyword arguments passed to the wrapped function.

            Returns:
                The result of calling the wrapped function.
            """
            # Log the function name and current time
            logging.info(f'Function <{func.__name__}> started at <{datetime.now()}>')
            result = func(*args, **kwargs)
            logging.info(f'Function <{func.__name__}> ends at <{datetime.now()}>')
            return result

        return wrapper
    except Exception as err:
        logging.error(f"Error setting up logger_function: {err}")
        return None


@logger_function
def get_lickey_from_env():
    try:
        global LICENSE_KEY
        logging.info("Getting License key fron env")
        if os.path.exists("/etc/environment"):
            with open("/etc/environment", "r") as f:
                for line in f.readlines():
                    if "CA_LICENSE_KEY" in line:
                        LICENSE_KEY = line.split("=")[1].strip()[1:-1]
                        logging.info(f"License key Found fron env: {LICENSE_KEY}")
    except Exception as lic_env_err:
        logging.error(f"Erron in get_lic_from_env: {lic_env_err}")


@logger_function
def get_hostname_from_env():
    try:
        global HOSTNAME
        global LICENSE_KEY_VALIDATE_API
        if os.path.exists("/etc/environment"):
            with open("/etc/environment", "r") as f:
                for line in f.readlines():
                    if "CA_HOST_NAME" in line:
                        HOSTNAME = line.split("=")[1].strip()[1:-1]
                        logging.info(f"Found hostname: {HOSTNAME}")
                        LICENSE_KEY_VALIDATE_API = f"{HOSTNAME}/api/v1/config/validate"
    except Exception as hostname_env_err:
        logging.error(f"Erron in get_hostname_from_env: {hostname_env_err}")


# Function to get linux os type
@logger_function
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

        logging.info(f"Extracted os-distributor name method 1: {os_distributor_output}")
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
            logging.info(f"Extracted os-distributor name method 2: {os_distributor_output}")
            if "ubuntu" in os_distributor_output or "kali" in os_distributor_output:
                return "ubuntu", ".deb"
            elif "red hat" in os_distributor_output or "almalinux" in os_distributor_output:
                return "rhel", ".rpm"
            elif "centos" in os_distributor_output:
                return "centos", ".rpm"
            else:
                return "ubuntu", ".deb"
    except Exception as err:
        logging.error(f"Error occurred while getting os-distributor name: {repr(err)}")
        return "ubuntu", ".deb"


@logger_function
def get_system_serial_from_file():
    try:
        logging.info("Reading system serial number from /sys/class/dmi/id/product_serial")
        with open('/sys/class/dmi/id/product_serial', 'r') as file:
            serial_number = file.read().strip()
            logging.info(f"System serial number found: {serial_number}")
            return serial_number if serial_number else ""
    except FileNotFoundError:
        logging.warning("Serial number file not found.")
        return ""
    except Exception as system_serial_from_file_error:
        logging.error(f"An error occurred while reading system serial number: "
                      f"{system_serial_from_file_error}")
        return ""


@logger_function
def get_motherboard_serial_from_file():
    try:
        logging.info("Reading motherboard serial number from /sys/class/dmi/id/board_serial")
        with open('/sys/class/dmi/id/board_serial', 'r') as file:
            motherboard_serial = file.read().strip()
            logging.info(f"Motherboard serial number found: {motherboard_serial}")
            return motherboard_serial if motherboard_serial else ""
    except FileNotFoundError:
        logging.warning("Motherboard serial file not found.")
        return ""
    except Exception as motherboard_serial_from_file_error:
        logging.error(f"An error occurred while reading motherboard serial number: "
                      f"{motherboard_serial_from_file_error}")
        return ""


@logger_function
def get_device_uuid_from_file():
    try:
        logging.info("Reading device UUID from /sys/class/dmi/id/product_uuid")
        with open('/sys/class/dmi/id/product_uuid', 'r') as file:
            uuid = file.read().strip()
            logging.info(f"Device UUID found: {uuid}")
            return uuid if uuid else ""
    except FileNotFoundError:
        logging.warning("UUID file not found.")
        return ""
    except Exception as device_uuid_from_file_error:
        logging.error(f"An error occurred while reading device UUID: "
                      f"{device_uuid_from_file_error}")
        return ""


@logger_function
def get_system_serial_number():
    try:
        logging.info("Getting system serial number")
        bios_serial_cmd = r"dmidecode -t system | grep 'Serial Number'"
        logging.info(f"bios_serial_cmd: {bios_serial_cmd}")
        subprocess_serial_output = subprocess.run(bios_serial_cmd, capture_output=True,
                                                  shell=True, timeout=TIMEOUT_SUBPROCESS, text=True)
        logging.info(f"subprocess_serial_output: {subprocess_serial_output}")
        system_serial_output = subprocess_serial_output.stdout.strip()
        logging.info(f"System Serial Subprocess output: {system_serial_output}")
        system_serial = system_serial_output.split(":")[1].strip()
        if system_serial is None or system_serial == "":
            logging.error("System Serial number could not be retrieved.")
            return ""
        else:
            logging.info(f"System Serial number retrieved: {system_serial}")
            return system_serial.replace("/", "")
    except Exception as system_serial_output_error:
        logging.error(f"An error occurred while getting system serial number: "
                      f"{system_serial_output_error}")
        return ""


@logger_function
def get_motherboard_serial_number():
    try:
        logging.info("Getting motherboard serial number")
        motherboard_serial_cmd = r"dmidecode -t baseboard | grep 'Serial Number'"
        logging.info(f"motherboard_serial_cmd: {motherboard_serial_cmd}")
        subprocess_motherboard_serial_output = subprocess.run(motherboard_serial_cmd, capture_output=True,
                                                              shell=True, timeout=TIMEOUT_SUBPROCESS, text=True)
        logging.info(f"subprocess_motherboard_serial_output: {subprocess_motherboard_serial_output}")
        motherboard_serial_output = subprocess_motherboard_serial_output.stdout.strip()
        logging.info(f"Motherboard Serial Subprocess output: {motherboard_serial_output}")
        motherboard_serial = motherboard_serial_output.split(":")[1].strip()
        if motherboard_serial is None or motherboard_serial == "":
            logging.error("Motherboard Serial number could not be retrieved.")
            return ""
        else:
            logging.info(f"Motherboard Serial number retrieved: {motherboard_serial}")
            return motherboard_serial.replace("/", "")
    except Exception as motherboard_serial_output_error:
        logging.error(f"An error occurred while getting motherboard serial number: "
                      f"{motherboard_serial_output_error}")
        return ""


@logger_function
def get_device_uuid():
    try:
        logging.info("Getting device uuid number")
        uuid_cmd = r"dmidecode -t system | grep 'UUID'"
        logging.info(f"uuid_cmd: {uuid_cmd}")
        uuid_serial_output = subprocess.run(uuid_cmd, capture_output=True, shell=True,
                                            timeout=TIMEOUT_SUBPROCESS, text=True)
        logging.info(f"uuid_serial_output: {uuid_serial_output}")
        uuid_serial_output = uuid_serial_output.stdout.strip()
        logging.info(f"uuid serial output: {uuid_serial_output}")
        uuid_serial = uuid_serial_output.split(":")[1].strip()
        if uuid_serial is None or uuid_serial == "":
            logging.error("UUID Serial number could not be retrieved.")
            return ""
        else:
            logging.info(f"UUID Serial number retrieved: {uuid_serial}")
            return uuid_serial.replace("/", "")
    except Exception as uuid_serial_output_error:
        logging.error(f"An error occurred while getting uuid serial number: "
                      f"{uuid_serial_output_error}")
        return ""


@logger_function
def get_pc_id():
    try:
        logging.info("Getting pc id")
        bios_serial = get_system_serial_number() or get_system_serial_from_file()
        motherb_serial = get_motherboard_serial_number() or get_motherboard_serial_from_file()
        if bios_serial == motherb_serial:
            device_uuid = get_device_uuid() or get_device_uuid_from_file()
            pc_id = device_uuid + '-' + LICENSE_KEY
        elif motherb_serial == "":
            pc_id = bios_serial + '-' + LICENSE_KEY
        elif bios_serial == "":
            pc_id = motherb_serial + '-' + LICENSE_KEY
        else:
            pc_id = motherb_serial + '-' + bios_serial + '-' + LICENSE_KEY
        logging.info(f"PC ID: {pc_id}")
        pc_id = pc_id.replace("/", "")
        return pc_id
    except Exception as pc_id_error:
        logging.error(f"An error occurred while getting pc id: {pc_id_error}")
        return ""


# Delete the old service
@logger_function
def delete_service_if_exists(service_name):
    try:
        service_path = f"/etc/systemd/system/{service_name}.service"
        if os.path.exists(service_path):
            subprocess.run(["sudo", "systemctl", "stop", f"{service_name}.service"])
            os.remove(service_path)
            logging.info(f"Deleted the old service <'{service_name}.service'>.")
    except Exception as delete_service_if_exists_err:
        logging.error(f"Error occurred while deleting the service: {delete_service_if_exists_err}")


# Delete the old timer
@logger_function
def delete_timer_if_exists(timer_name):
    try:
        timer_path = f"/etc/systemd/system/{timer_name}.timer"
        if os.path.exists(timer_path):
            subprocess.run(["sudo", "systemctl", "stop", f"{timer_name}.timer"])
            os.remove(timer_path)
            logging.info(f"Deleted the old timer <'{timer_name}.timer'>.")
    except Exception as delete_timer_if_exists_err:
        logging.error(f"Error occurred while deleting the timer: {delete_timer_if_exists_err}")


# Function to create environment variable
@logger_function
def create_env_variable():
    try:
        global LICENSE_KEY
        global HOSTNAME
        os_name = get_os_distributor_name()[0]
        if os_name == "ubuntu":
            agent_version = LOCAL_AGENT_VERSION["ubuntu"]
        elif os_name == "rhel":
            agent_version = LOCAL_AGENT_VERSION["rhel"]
        elif os_name == "centos":
            agent_version = LOCAL_AGENT_VERSION["centos"]
        else:
            agent_version = None
        if agent_version is not None:
            env_path = "/etc/environment"
            logging.info("Removing old version from environment variable file.")
            try:
                subprocess.run("sed -i '/^CA_LATEST_VERSION/d' /etc/environment > /dev/null", shell=True,
                               stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception as remove_old_version_err:
                logging.error(f"Error removing old version: {remove_old_version_err}")
            with open(env_path, 'a') as env_file:
                logging.info("Writing to environment variable file.")
                env_file.write(f'CA_LATEST_VERSION="{agent_version}"\n')
                env_file.flush()
                os.fsync(env_file.fileno())
            logging.info("Environment variable <CA_LATEST_VERSION> created successfully.")
        if LICENSE_KEY:
            env_path = "/etc/environment"
            logging.info("Removing old license key from environment variable file.")
            try:
                subprocess.run("sed -i '/^CA_LICENSE_KEY/d' /etc/environment > /dev/null", shell=True,
                               stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception as remove_old_license_key_err:
                logging.error(f"Error removing old license key: {remove_old_license_key_err}")
            with open(env_path, 'a') as env_file:
                logging.info("Writing to environment variable file.")
                env_file.write(f'CA_LICENSE_KEY="{LICENSE_KEY}"\n')
                env_file.flush()
                os.fsync(env_file.fileno())
            logging.info("Environment variable <CA_LICENSE_KEY> created successfully.")
        if HOSTNAME:
            env_path = "/etc/environment"
            logging.info("Removing old host from environment variable file.")
            try:
                subprocess.run("sed -i '/^CA_HOST_NAME/d' /etc/environment > /dev/null", shell=True,
                               stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception as remove_old_hostname:
                logging.error(f"Error removing old Hostname: {remove_old_hostname}")
            with open(env_path, 'a') as env_file:
                logging.info("Writing to environment variable file.")
                env_file.write(f'CA_HOST_NAME="{HOSTNAME}"\n')
                env_file.flush()
                os.fsync(env_file.fileno())
            logging.info("Environment variable <CA_HOST_NAME> created successfully.")
        if CUSTODIAN_NAME:
            env_path = "/etc/environment"
            logging.info("Removing old custodian name from environment variable file.")
            try:
                subprocess.run("sed -i '/^CA_CUSTODIAN_NAME/d' /etc/environment > /dev/null", shell=True,
                               stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception as remove_old_hostname:
                logging.error(f"Error removing old Hostname: {remove_old_hostname}")
            with open(env_path, 'a') as env_file:
                logging.info("Writing to environment variable file.")
                env_file.write(f'CA_CUSTODIAN_NAME="{CUSTODIAN_NAME}"\n')
                env_file.flush()
                os.fsync(env_file.fileno())
            logging.info("Environment variable <CA_CUSTODIAN_NAME> created successfully.")

    except Exception as create_env_variable_err:
        logging.error(f"Error creating environment variable file: {create_env_variable_err}")


# Function to create installation trigger service
@logger_function
def create_installation_trigger_service():
    try:
        exec_command = f"{AUDIT_EXE_DIRECTORY_NAME}{AGENT_FILE_NAME}"
        trigger_event_name = "LINUX_INSTALLATION_TRIGGER"

        # Enable the service
        enable_command = f"{exec_command} {trigger_event_name}"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    except Exception as create_installation_trigger_service_err:
        logging.error(f"Error occurred while creating installation trigger service: "
                      f"{create_installation_trigger_service_err}")


# Function to create daily trigger service
@logger_function
def create_daily_trigger_service():
    def generate_random_time():
        try:
            hour = random.randint(10, 16)
            minute = random.randint(1, 59)
            second = 0

            if hour == 16:
                minute = 0

            logging.info(f"Random time generated: {time(hour, minute, second)}")
            return str(time(hour, minute, second))
        except Exception as generate_random_time_err:
            logging.error(f"Error occurred while generating random time:{generate_random_time_err}")
            return "11:30:00"

    try:
        daily_trigger_time = generate_random_time()
        service_name = "cyberauditor-linux-agent-daily-trigger"
        timer_name = "cyberauditor-linux-agent-daily-trigger"
        description = "CA Linux Agent Service (Daily Trigger)"
        exec_command = f"{AUDIT_EXE_DIRECTORY_NAME}{AGENT_FILE_NAME}"
        trigger_event_name = "LINUX_DAILY_TRIGGER"
        service_file_content = rf"""
[Unit]
Description={description}

[Service]
Type=simple
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=no

[Install]
WantedBy=default.target
"""

        delete_service_if_exists(service_name)
        with open(f"{SYSTEMD_PATH}{service_name}.service", 'w') as service_file:
            service_file.write(service_file_content)

        timer_file_content = rf"""
[Unit]
Description={description}

[Timer]
Unit={service_name}.service
OnCalendar=*-*-* {daily_trigger_time}

[Install]
WantedBy=timers.target
"""

        delete_timer_if_exists(timer_name)
        with open(f"{SYSTEMD_PATH}{timer_name}.timer", "w") as file:
            file.write(timer_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.timer >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as create_daily_trigger_service_err:
        logging.error(f"Error occurred while creating daily trigger service: {create_daily_trigger_service_err}")


# Function to create interval trigger service
@logger_function
def create_interval_trigger_service():
    try:
        try:
            os.remove("/tmp/cyberauditor_linux_interval_info.txt")
        except FileNotFoundError:
            logging.info("Interval temp file does not exist, no action taken.")
        service_name = "cyberauditor-linux-agent-interval-trigger"
        description = "CA Linux Agent Service (Interval Trigger)"
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_INTERVAL_TRIGGER"

        service_file_content = rf"""
[Unit]
Description={description}

[Service]
Type=simple
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
RestartSec={TRIGGER_INTERVAL_IN_HOUR}h
Restart=always

[Install]
WantedBy=default.target
"""

        delete_service_if_exists(service_name)
        with open(f"{SYSTEMD_PATH}{service_name}.service", 'w') as service_file:
            service_file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as create_interval_trigger_service_err:
        logging.error(f"Error occurred while creating interval trigger service: {create_interval_trigger_service_err}")


# Function to create systemd service triggered by USB insertion
@logger_function
def create_usb_trigger_service():
    try:
        service_name = "cyberauditor-linux-agent-usb-trigger"
        description = "CA Linux Agent Service (USB Trigger)"
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_USB_TRIGGER"

        # Construct the complete service file content with the formatted ExecStart
        service_file_content = rf"""
[Unit]
Description={description}

[Service]
Type=simple
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=always

[Install]
WantedBy=default.target
"""

        # Delete the old service
        delete_service_if_exists(service_name)

        # Write the service file content to the file
        with open(f"{SYSTEMD_PATH}{service_name}.service", "w") as file:
            file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as create_usb_trigger_service_err:
        logging.error(f"Error occurred while creating usb trigger service: {create_usb_trigger_service_err}")


# Function to create logon trigger service
@logger_function
def create_logon_trigger_service():
    try:
        service_name = "cyberauditor-linux-agent-logon-trigger"
        description = "CA Linux Agent Service (Logon Trigger)"
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_LOGON_TRIGGER"

        service_file_content = rf"""
[Unit]
Description={description}
After=network.target

[Service]
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=always

[Install]
WantedBy=multi-user.target
"""

        delete_service_if_exists(service_name)
        with open(f"{SYSTEMD_PATH}{service_name}.service", 'w') as service_file:
            service_file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as create_logon_trigger_service_err:
        logging.error(f"Error occurred while creating logon trigger service: {create_logon_trigger_service_err}")


# Function to create network trigger service
@logger_function
def create_network_trigger_service():
    try:
        service_name = "cyberauditor-linux-agent-network-trigger"
        description = "CA Linux Agent Service (Network Trigger)"
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_NETWORK_TRIGGER"

        service_file_content = rf"""
[Unit]
Description={description}
After=network.target

[Service]
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=always

[Install]
WantedBy=multi-user.target
"""

        delete_service_if_exists(service_name)
        with open(f"{SYSTEMD_PATH}{service_name}.service", 'w') as service_file:
            service_file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as create_network_trigger_service_err:
        logging.error(f"Error occurred while creating network trigger service: {create_network_trigger_service_err}")


# Function to create bluetooth trigger service
@logger_function
def create_bluetooth_trigger_service():
    try:
        service_name = "cyberauditor-linux-agent-bluetooth-trigger"
        description = "CA Linux Agent Service (Bluetooth Trigger)"
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_BLUETOOTH_TRIGGER"

        service_file_content = rf"""
[Unit]
Description={description}
After=network.target

[Service]
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=always

[Install]
WantedBy=multi-user.target
"""

        delete_service_if_exists(service_name)
        with open(f"{SYSTEMD_PATH}{service_name}.service", 'w') as service_file:
            service_file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as create_bluetooth_trigger_service_err:
        logging.error(f"Error occurred while creating bluetooth trigger service: "
                      f"{create_bluetooth_trigger_service_err}")


# Function to create watchdog trigger service
@logger_function
def create_watchdog_service():
    try:
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_WATCHDOG_TRIGGER"
        service_name = "cyberauditor-linux-agent-watchdog-trigger"
        service_filename = f"{service_name}.service"
        description = "CA Linux Agent Service (Watchdog Trigger)"

        full_service_path = os.path.join(SYSTEMD_PATH, service_filename)

        if not os.path.exists(full_service_path):
            logging.info("Creating watchdog trigger service...")
            service_file_content = rf"""
[Unit]
Description={description}
After=network.target

[Service]
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=always
RestartSec={WATCHDOG_INTERVAL_IN_SECONDS}

[Install]
WantedBy=multi-user.target
"""
            with open(full_service_path, 'w') as service_file:
                service_file.write(service_file_content)

            # Reload the systemd daemon
            subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

            # Enable the service
            enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
            subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        else:
            logging.info("Watchdog trigger service already exists.")
            logging.info("Checking if it's running...")
            result = subprocess.run(["systemctl", "is-active", service_filename],
                                    capture_output=True, text=True)
            if result.stdout.strip() != "active":
                logging.info("Watchdog trigger service is not running.")
                subprocess.run(["systemctl", "restart", service_filename], check=True)
                logging.info("Watchdog trigger service restarted successfully.")
            else:
                logging.info("Watchdog trigger service is already running.")

    except Exception as watchdog_err:
        logging.error(f"Error managing watchdog service: {watchdog_err}")


# Function to create cleanup trigger service
@logger_function
def create_cleanup_service():
    try:
        service_name = "cyberauditor-linux-agent-cleanup-trigger"
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_CLEANUP_SERVICE"
        service_file_content = rf"""
[Unit]
Description=Cleanup temporary files on shutdown

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStop=/bin/bash -c "{exec_command} {trigger_event_name}"

[Install]
WantedBy=multi-user.target
"""

        with open(f"{SYSTEMD_PATH}{service_name}.service", 'w') as service_file:
            service_file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as cleanup_trigger_error:
        logging.error(f"Error occurred while creating logon trigger service: {cleanup_trigger_error}")


# Function to create USB watcher service
@logger_function
def create_usb_watcher_service():
    try:
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_USB_WATCHER"
        service_name = "cyberauditor-linux-agent-usb-watcher"
        description = "CA Linux Agent Service (USB Watcher)"

        service_file_content = rf"""
[Unit]
Description={description}
After=network.target

[Service]
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=always

[Install]
WantedBy=multi-user.target
"""

        with open(f"{SYSTEMD_PATH}{service_name}.service", 'w') as service_file:
            service_file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as watchdog_trigger_err:
        logging.error(f"Error occurred while creating logon trigger service: {watchdog_trigger_err}")


# Function to create cmd history service
@logger_function
def create_cmd_history_service():
    if not COMMAND_HISTORY_STATUS:
        logging.info("Command history service is disabled.")
        return
    try:
        service_name = "cyberauditor-linux-agent-cmd-history"
        description = "CA Linux Agent Service (CMD History)"
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_COMMAND_HISTORY"

        service_file_content = rf"""
[Unit]
Description={description}

[Service]
Type=simple
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=always
RestartSec={CMD_HISTORY_INTERVAL_IN_HOUR}h

[Install]
WantedBy=default.target
"""

        delete_service_if_exists(service_name)
        with open(f"{SYSTEMD_PATH}{service_name}.service", 'w') as service_file:
            service_file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as create_patch_update_service_err:
        logging.error(f"Error occurred while creating cmd history service: {create_patch_update_service_err}")


# Function to create patch update service
@logger_function
def create_patch_update_service():
    try:
        service_name = "cyberauditor-linux-agent-patch-update"
        description = "CA Linux Agent Service (Patch Update)"
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_PATCH_UPDATE"

        service_file_content = rf"""
[Unit]
Description={description}

[Service]
Type=simple
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=always

[Install]
WantedBy=default.target
"""

        delete_service_if_exists(service_name)
        with open(f"{SYSTEMD_PATH}{service_name}.service", 'w') as service_file:
            service_file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as create_patch_update_service_err:
        logging.error(f"Error occurred while creating patch update service: {create_patch_update_service_err}")


# Function to create firewall trigger service
@logger_function
def create_firewall_trigger_service():
    try:
        service_name = "cyberauditor-linux-agent-firewall-trigger"
        description = "CA Linux Agent Service (Firewall Trigger)"
        exec_command = f"{SERVICE_EXE_DIRECTORY_NAME}{SERVICE_FILE_NAME}"
        trigger_event_name = "LINUX_FIREWALL_TRIGGER"

        # Construct the complete service file content with the formatted ExecStart
        service_file_content = rf"""
[Unit]
Description={description}

[Service]
Type=simple
ExecStart=/bin/bash -c "{exec_command} {trigger_event_name}"
Restart=always

[Install]
WantedBy=default.target
"""

        # Delete the old service
        delete_service_if_exists(service_name)

        # Write the service file content to the file
        with open(f"{SYSTEMD_PATH}{service_name}.service", "w") as file:
            file.write(service_file_content)

        # Reload the systemd daemon
        subprocess.run("systemctl daemon-reload", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Enable the service
        enable_command = f"systemctl enable --now {service_name}.service >/dev/null 2>&1"
        subprocess.run(enable_command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    except Exception as firewall_trigger_err:
        logging.error(f"Error occurred while creating firewall service: {firewall_trigger_err}")


@logger_function
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
        logging.error(f"encrypt_string Error: {encrypted_content_err}")

    return b""


@logger_function
def validate_license_key():
    pc_id = get_pc_id()
    msg = "Invalid Endpoint ID or Server IP / Hostname"
    try:
        license_key_response = requests.post(LICENSE_KEY_VALIDATE_API, data={
                                                "licKey": LICENSE_KEY, "pcId": pc_id, "osType": "Linux"
                                                },
                                                timeout=TIMEOUT_SUBPROCESS, verify=CA_FILE)

        if license_key_response.status_code == 200:
            response_data = license_key_response.json()
            if response_data.get("message") == "valid":
                logging.info("License key is valid.")
                logging.info(f"Response data: {response_data}")
                if response_data.get("features") is not None:
                    global COMMAND_HISTORY_STATUS
                    COMMAND_HISTORY_STATUS = response_data.get("features").get("CommandHistory")
                    os.makedirs(os.path.dirname(ORG_FEATURES_FILE_PATH), exist_ok=True)
                    encrypt_string(ORG_FEATURES_FILE_PATH, json.dumps(response_data.get("features")))
                return True, "Endpoint ID key and Server IP / Hostname set successfully."
            else:
                logging.warning("License key is not valid, returning false.")
                return False, msg
        else:
            logging.warning(f"Unexpected status code: {license_key_response.status_code}")
            logging.warning(f"Response content: {license_key_response.text}")
            msg = json.loads(license_key_response.text).get("message") or msg

    except requests.exceptions.RequestException as req_error:
        logging.error(f"Request failed: {req_error}")
    except ValueError as json_error:
        logging.error(f"Invalid JSON response: {json_error}")
    except Exception as validation_error:
        logging.error(f"Unexpected error: {validation_error}")

    return False, msg


@logger_function
def install_custom_certificates():
    try:
        os_name = get_os_distributor_name()[0]
        cert_file = "ca.crt"
        if os_name == "rhel" or os_name == "centos":
            dest_dir = "/etc/pki/ca-trust/source/anchors/"
            update_cmd = ["update-ca-trust"]
        elif os_name == "ubuntu":
            dest_dir = "/usr/local/share/ca-certificates/"
            update_cmd = ["update-ca-certificates"]
        else:
            raise ValueError(f"Unsupported OS: {os_name}")

        src_path = os.path.join(DESTINATION_WORKING_DIRECTORY, cert_file)
        dest_path = os.path.join(dest_dir, cert_file)

        if not os.path.isfile(src_path):
            raise FileNotFoundError(f"Certificate file not found: {src_path}")

        shutil.copy2(src_path, dest_path)
        logging.info(f"Copied {src_path} to {dest_path}")

        # Update CA trust
        subprocess.run(update_cmd, check=True)
        logging.info(f"CA trust updated successfully for {os_name}")

    except Exception as install_cert_err:
        logging.error(f"An error occurred: {install_cert_err}")


@logger_function
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
        logging.info(f"pid: {pid}, ppid: {ppid}")
    except Exception as add_process_id_to_maintain_err:
        logging.error(f"Error in add_process_id_to_maintain: {add_process_id_to_maintain_err}")


# Function to call the CA installation
def call_ca_installation(logger_callback):
    try:
        logging.info("Initialization done for the setup.")
        logging.info(f"TRIGGER_INTERVAL_IN_HOUR={TRIGGER_INTERVAL_IN_HOUR}")
        logging.info(f"WATCHDOG_INTERVAL_IN_MINUTES={WATCHDOG_INTERVAL_IN_MINUTES}")
        logging.info("Setup of Linux Agent started.")
        logging.info(f"Created the log directory <'{LOGS_DESTINATION_DIRECTORY}'>.")
        logging.info(f"Created the setup log file <'{LOGGER_FILE_NAME}'>.")
        logging.info(f"Current Setup file name: <'{SETUP_AGENT_FILE_NAME}'>")

        if logger_callback:
            logger_callback("Setting up the Agent")

        if logger_callback:
            logger_callback("Performing the intial audit... Please Wait")

        # Add current process id to maintain
        add_process_id_to_maintain()

        # Create latest version env variable
        create_env_variable()

        # Create installation trigger service
        create_installation_trigger_service()

        # Create cmd history service
        create_cmd_history_service()

        # Create daily trigger service
        create_daily_trigger_service()

        # Create interval trigger service
        create_interval_trigger_service()

        # Create patch update service
        create_patch_update_service()

        # Create logon trigger service
        create_logon_trigger_service()

        # Create USB trigger service
        create_usb_trigger_service()

        # Create network trigger service
        create_network_trigger_service()

        # Create bluetooth trigger service
        create_bluetooth_trigger_service()

        # Create firewall trigger service
        create_firewall_trigger_service()

        # Create watchdog service
        create_cleanup_service()

        # Create usb watcher service
        create_usb_watcher_service()

        # Create watchdog service
        create_watchdog_service()

    except Exception as ca_installation_err:
        logging.error(f"Error while installing Cyberauditor-Linux Agent: {ca_installation_err}")


class InstallationSetup(tk.Tk):
    def __init__(self):
        super().__init__()
        self.install_button = None
        self.progress_bar = None
        self.installation_page = None
        self.license_entry = None
        self.hostname_entry = None
        self.text_box = None
        self.welcome_img = None
        self.image_path = DESTINATION_WORKING_DIRECTORY + "ca-icon.ico"
        self.title("CyberAuditor Installation Setup")
        self.resizable(False, False)

        window_width = 800
        window_height = 400
        self.geometry(f"{window_width}x{window_height}")

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x_cordinate = (screen_width // 2) - (window_width // 2)
        y_cordinate = (screen_height // 2) - (window_height // 2)
        self.geometry(f"{window_width}x{window_height}+{x_cordinate}+{y_cordinate}")

        self.current_page = 0
        self.pages = []

        self.create_pages()
        self.show_page(0)

        style = ttk.Style()
        style.configure(
            "Custom.TButton",
            background="#4A90E2",
            foreground="white",
            font=("Helvetica", 13, "bold"),
            padding=12
        )
        style.map("Custom.TButton", background=[("active", "#357ABD")])

    def create_pages(self):
        welcome_page = tk.Frame(self, bg="#FFFFFF")
        heading_label = tk.Label(
            welcome_page, text="Welcome to CyberAuditor!", font=("Helvetica", 26, "bold"),
            bg="#FFFFFF", fg="#333333"
        )
        heading_label.pack(pady=(30, 10) if os.path.exists(self.image_path) else (60, 10))
        if os.path.exists(self.image_path):
            try:
                if self.image_path.endswith(".ico"):
                    img = Image.open(self.image_path)
                    img = img.resize((128, 128), Image.LANCZOS)
                    img = img.convert("RGBA")
                    self.welcome_img = ImageTk.PhotoImage(img)
                else:
                    self.welcome_img = tk.PhotoImage(file=self.image_path)

                img_label = tk.Label(
                    welcome_page, image=self.welcome_img, bg="#FFFFFF")
                img_label.pack(pady=(10, 10))
            except Exception as img_path_err:
                logging.error(f"Error in adding icon: {img_path_err}")
        subheading_label = tk.Label(
            welcome_page, text="Cyber Security Audit Tool", font=("Helvetica", 18),
            bg="#FFFFFF", fg="#555555"
        )
        subheading_label.pack(pady=(0, 30))
        ttk.Button(
            welcome_page, text="Next", command=lambda: self.show_page(1),
            style="Custom.TButton"
        ).pack(pady=(20, 0))
        self.pages.append(welcome_page)

        # License Page with Modern Design
        license_page = tk.Frame(self, bg="#FFFFFF")
        tk.Label(license_page, text="Please enter Endpoint Identifier Key", bg="#FFFFFF",
                 font=("Helvetica", 15, "bold"), fg="#333333").pack(pady=(30, 5))
        self.license_entry = tk.Entry(license_page, width=40, font=("Helvetica", 14), highlightthickness=1,
                                      highlightbackground="#DDDDDD")
        self.license_entry.pack(pady=(10, 30), padx=30)
        self.license_entry.bind("<KeyRelease>", self.check_entry)

        if HOSTNAME_NEEDED:
            tk.Label(license_page, text="Please enter Server IP / Hostname", bg="#FFFFFF",
                     font=("Helvetica", 15, "bold"), fg="#333333").pack(pady=(30, 5))
            self.hostname_entry = tk.Entry(license_page, width=40, font=("Helvetica", 14), highlightthickness=1,
                                           highlightbackground="#DDDDDD")
            self.hostname_entry.pack(pady=(10, 60), padx=30)
            self.hostname_entry.insert(0, f"{HOSTNAME or 'https://dev.cyberauditor.in'}")
            self.hostname_entry.bind("<KeyRelease>", self.check_entry)

        # Navigation Buttons
        button_frame = tk.Frame(license_page, bg="#FFFFFF")
        button_frame.pack(fill="x", pady=(10, 10))
        ttk.Button(button_frame, text="Back", command=lambda: self.show_page(0), style="Custom.TButton").pack(
            side="left", padx=(20, 0))
        self.install_button = ttk.Button(button_frame, text="Install", command=lambda: self.on_install_clicked(),
                                         style="Custom.TButton", state=tk.DISABLED)
        self.install_button.pack(side="right", padx=(0, 20))
        self.pages.append(license_page)

        # Installation Page with Progress Bar
        self.installation_page = tk.Frame(self, bg="#FFFFFF")
        tk.Label(self.installation_page, text="Installation Progress", font=("Helvetica", 16, "bold"), bg="#FFFFFF",
                 fg="#333333").pack(pady=(50, 20))
        self.progress_bar = ttk.Progressbar(self.installation_page, orient="horizontal", length=400,
                                            mode="indeterminate")
        self.progress_bar.pack(pady=(10, 40))
        self.pages.append(self.installation_page)

    def check_entry(self, _):
        if self.license_entry.get() and (not HOSTNAME_NEEDED or self.hostname_entry.get()):
            self.install_button.config(state=tk.NORMAL)
        else:
            self.install_button.config(state=tk.DISABLED)

    def show_page(self, page_index):
        for page in self.pages:
            page.pack_forget()
        self.pages[page_index].pack(fill="both", expand=True)
        self.current_page = page_index

        if page_index == len(self.pages) - 1:
            self.protocol("WM_DELETE_WINDOW", self.disable_close_button)
        else:
            self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def disable_close_button(self):
        pass

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit? You will need to Uninstall and reinstall Again."):
            self.destroy()

    def on_install_clicked(self):
        lic_key = self.license_entry.get()
        global LICENSE_KEY
        LICENSE_KEY = lic_key.strip()

        if HOSTNAME_NEEDED:
            hostname = self.hostname_entry.get()
            global HOSTNAME, LICENSE_KEY_VALIDATE_API
            HOSTNAME = hostname.strip()
            LICENSE_KEY_VALIDATE_API = f"{HOSTNAME}/api/v1/config/validate"

        lic_key_valid, msg = validate_license_key()
        if lic_key_valid:
            messagebox.showinfo("Success", msg)
            self.show_page(2)
            self.run_installation()
        else:
            messagebox.showerror("Error", msg)

    def run_installation(self):
        def update_text_box(message):
            self.text_box.config(state='normal')
            self.text_box.insert(tk.END, message + "\n")
            self.text_box.see(tk.END)
            self.text_box.config(state='disabled')

        if self.text_box is None:
            self.text_box = tk.Text(self.installation_page, height=10, width=60)
            self.text_box.pack(pady=5)
            self.text_box.config(state='disabled')

        update_text_box("Initializing installation process...")

        def run_ca_installation():
            call_ca_installation(update_text_box)
            update_text_box("Installation complete!")
            update_text_box("Exiting the setup process...")
            time_lib.sleep(3)
            self.progress_bar.stop()
            self.quit()

        self.progress_bar.start()
        threading.Thread(target=run_ca_installation).start()


def run_ask_ui(messages=[], message_alt="", button_accept="Accept", button_reject="Reject", final_text_accept="Accepted", final_text_reject="Rejected",
               countdown_seconds=20, is_ssh_access=False):
    user_response = {'status': None}

    def on_close():
        root.destroy()
        sys.exit(42)

    def update_countdown():
        if user_response['status'] is not None:
            return
        elif countdown[0] > 0:
            if is_ssh_access:
                label.config(text=message_alt)
            else:
                label.config(text=f"{message_alt} in {countdown[0]} seconds...")
            countdown[0] -= 1
            root.after(1000, update_countdown)
        else:
            root.destroy()
            sys.exit(42)

    def accept_action():
        user_response['status'] = "accepted"
        label.config(text=final_text_accept, foreground="green")
        disable_buttons()
        root.after(1000, lambda: (root.destroy(), sys.exit(0)))

    def reject_action():
        user_response['status'] = "rejected"
        label.config(text=final_text_reject, foreground="red")
        disable_buttons()
        root.after(1000, lambda: (root.destroy(), sys.exit(42)))

    def disable_buttons():
        accept_button.config(state="disabled")
        reject_button.config(state="disabled")

    root = tk.Tk()
    root.title("!!! Message From CyberAuditor Agent !!!")
    window_width = 600
    window_height = 350
    x_cordinate = (root.winfo_screenwidth() // 2) - (window_width // 2)
    y_cordinate = (root.winfo_screenheight() // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{x_cordinate}+{y_cordinate}")
    root.resizable(False, False)

    style = ttk.Style()
    style.theme_use('clam')

    image_path = os.path.join(DESTINATION_WORKING_DIRECTORY, "ca-icon.ico")
    if os.path.exists(image_path):
        try:
            img = Image.open(image_path)
            img = img.resize((100, 100), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            img_label = tk.Label(root, image=photo)
            img_label.image = photo
            img_label.pack(pady=(10, 5))
        except Exception as img_path_err:
            print(f"Error loading icon: {img_path_err}")

    for msg in messages:
        lbl = ttk.Label(root, text=msg, font=("Arial", 12, "bold"), anchor="center", wraplength=500, justify="center")
        lbl.pack(padx=20, pady=5)

    # Countdown or alternative message label
    label_font = ("Arial", 10 if is_ssh_access else 12)
    label = ttk.Label(root, text="", font=label_font, foreground="#242629")
    label.pack(padx=20, pady=10)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    if not is_ssh_access:
        accept_button = tk.Button(button_frame, text=button_accept, width=15, bg="#27ae60", fg="white",
                                  font=("Arial", 11, "bold"), relief="raised", bd=3, command=accept_action)
        accept_button.pack(side="left", padx=10)

        reject_button = tk.Button(button_frame, text=button_reject, width=15, bg="#e74c3c", fg="white",
                                  font=("Arial", 11, "bold"), relief="raised", bd=3, command=reject_action)
        reject_button.pack(side="left", padx=10)

    countdown = [countdown_seconds]
    root.protocol("WM_DELETE_WINDOW", on_close)
    update_countdown()
    root.mainloop()


def run_ask_for_reboot():
    run_ask_ui(
        messages=["System needs to reboot to complete installation of updates."],
        message_alt="Automatically cancelling reboot",
        button_accept="Accept Reboot",
        button_reject="Cancel Reboot",
        final_text_accept="Reboot accepted.",
        final_text_reject="Reboot cancelled.",
        countdown_seconds=20
    )


def run_ask_for_ssh_access():
    run_ask_ui(
        messages=[
            f"{ADMIN_NAME} is requesting SSH access to this system.",
            f"Access Code: {ADMIN_CODE}",
            "Valid for 5 minutes."
        ],
        message_alt=f"(saved at: {ACCESS_CODE_FILE})",
        countdown_seconds=30,
        is_ssh_access=True
    )


if __name__ == "__main__":
    if TRIGGER_TYPE == 'ASK_FOR_REBOOT':
        run_ask_for_reboot()
    elif TRIGGER_TYPE == 'ASK_FOR_SSH_ACCESS':
        run_ask_for_ssh_access()
    try:
        setup_logger_successful_status = setup_logger_function()
        if setup_logger_successful_status:
            logging.info("-----------------------------------------------------------------------------------")
            logging.info(f"{queue.__name__}")
            if TRIGGER_TYPE == 'CREATE_CMD_SERVICE':
                logging.info(f"Triggered by: {TRIGGER_TYPE}")
                COMMAND_HISTORY_STATUS = True
                create_cmd_history_service()
                sys.exit(0)

            if CERT_NEEDED:
                logging.info(f"Installing custom certificates for demo environment...")
                install_custom_certificates()
            get_lickey_from_env()
            get_hostname_from_env()
            logging.info(f"LICENSE_KEY: {LICENSE_KEY}, HOSTNAME: {HOSTNAME}")
            if LICENSE_KEY and HOSTNAME:
                logging.info("Both Endpoint ID / Key and Server IP / Hostname are set.")
                logging.info("Validating license key...")
                valid_lic_key, msg = validate_license_key()
                logging.info(f"valid_lic_key: {valid_lic_key}, msg: {msg}")
                if valid_lic_key:
                    call_ca_installation(None)
                else:
                    logging.error("Invalid license key. Exiting the setup process.")

            else:
                if 'DISPLAY' in os.environ:
                    app = InstallationSetup()
                    app.mainloop()
                else:
                    max_attempts = 3
                    for attempt in range(max_attempts):
                        LICENSE_KEY = input("Please enter Endpoint ID / Key: ")
                        if HOSTNAME_NEEDED:
                            HOSTNAME = input("Please enter Server IP / Hostname: ")
                            LICENSE_KEY_VALIDATE_API = f"{HOSTNAME}/api/v1/config/validate"

                        valid_lic_key, msg = validate_license_key()
                        print(f"valid_lic_key: {valid_lic_key}, msg: {msg}")
                        if valid_lic_key:
                            logging.info("Endpoint ID / Key is valid.")
                            print("Endpoint ID / Key is valid.")
                            logging.info("Installation process started...")
                            print("Installation process started...")
                            call_ca_installation(None)
                            logging.info("Installation process completed...")
                            print("Installation process completed...")
                            break
                        else:
                            if attempt == max_attempts - 1:
                                logging.error("Exiting as maximum attempts reached. Please Reinstall the Agent.")
                                print("Exiting as maximum attempts reached. Please Reinstall the Agent.")
                                break
                            else:
                                logging.warning("Invalid Endpoint ID or Server IP. Try again.")
                                print("Invalid Endpoint ID or Server IP. Try again.")

            logging.info("-----------------------------------------------------------------------------------")
        else:
            print("Error setting up the logger. setup_logger_successful_status: False")

    except Exception as mainerror:
        print(f"Error occured in setup-cyberauditor-agent file: {mainerror}")

# Script completes here
