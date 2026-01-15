from datetime import datetime, timezone, timedelta, date
import platform
import subprocess
import os
import re
import sys
import requests
import logging
import hashlib
import json
import time
import base64
from io import StringIO
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import glob
from multiprocessing import Pool, Manager
from html import escape as html_escape
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# CHANGE THE FOLLOWING ENV_VARIABLE FROM DEV/TEST/PROD
# ----------------------------------------------------
ENVIRONMENT = "DEMO"
CERT_NEEDED = False
LOGS_NEEDED = True
# ----------------------------------------------------

if ENVIRONMENT == "PROD":
    HOSTNAME = "https://cyberauditor.in"
elif ENVIRONMENT == "TEST":
    HOSTNAME = "https://test.cyberauditor.in"
elif ENVIRONMENT == "DEV":
    HOSTNAME = "https://dev.cyberauditor.in"
else:
    HOSTNAME = "https://nishar.ca.in"

error = {
    "pcIdentityInfo": {},
    "accountInfo": {},
    "backendInfo": {},
    "cisInfo": {},
    "hardwareInfo": {},
    "networkInfo": {},
    "osInfo": {},
    "usbInfo": {},
    "miscellaneousInfo": {},
}

if sys.version_info[:2] < (2, 7):
    from ordereddict import OrderedDict
else:
    from collections import OrderedDict

# ===================CONSTANTS===================
BACKEND_API_URL = f"{HOSTNAME}/api/v1/linux/ingest/main"
SCAN_TYPE = sys.argv[1] if len(sys.argv) > 1 else "LINUX_DAILY_TRIGGER"
DESTINATION_WORKING_DIRECTORY = '/etc/cyberauditor_linux_agent/'
LOGS_DESTINATION_DIRECTORY = "/var/log/cyberauditor_linux_agent_logs"
PIDS_MAINTAIN_FILE_PATH = "/tmp/cyberauditor_linux_pids.txt"
ENCRYPTED_AUDIT_LOGS_DIRECTORY = LOGS_DESTINATION_DIRECTORY + '/ca-audit-logs'
VISIBLE_AUDIT_LOGS_DESTINATION_DIRECTORY = LOGS_DESTINATION_DIRECTORY + '/ca-raw-audit-logs'
ENCRYPTED_AGENT_LOGS_DIRECTORY = LOGS_DESTINATION_DIRECTORY + '/ca-agent-logs'
VISIBLE_AGENT_LOGS_DESTINATION_DIRECTORY = LOGS_DESTINATION_DIRECTORY + '/ca-raw-agent-logs'
AGENT_FILE_NAME = "audit-agent"
AGENT_EXE_FILE_PATH = DESTINATION_WORKING_DIRECTORY + "audit_exe/" + AGENT_FILE_NAME
TIMEOUT_SUBPROCESS = 10
CA_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtkqRhn4d0+v2OLBQuvP8
rWY7CM418Tu0UoS6LuRdGEEFt/AE4lMD+rXTzGYkvRIskGCZ+otnQt2hg8MO+qHC
upylXcHkNpKgCdkDn5D+hB71OcJQDnzTkTzBEJIymZyGIea4YBPIsqhjQyPxdYel
0HMmRYPz0/okwUyJIsmiVaG+U5FW1VeIdtFhf02qCdbIndiWFdIbkP3OG32EJIUY
YEdF3aT3qxDH49qiNTI6D/V526EJmTCqjcOeeAt4sxoUgVxgqyL6YvOyYgBmTgeV
iZKI8VZ8+uRCnkwDBDsDCk6e7xEd7mGOk11lMJiyMj7kmttvlRbFbvb6FbVYxX5j
mwIDAQAB
-----END PUBLIC KEY-----"""
LICENSE_KEY = ""
CA_FILE = os.path.join(DESTINATION_WORKING_DIRECTORY, "ca.crt") if CERT_NEEDED else None


# Utility functions --------------------------------------------------------------------
def setup_logger_function():
    setup_logger_function_status = False
    logger_holder = StringIO()

    def setup_logger():
        setup_logger_status = False
        try:
            # Create the log folder if it doesn't exist
            if not os.path.exists(LOGS_DESTINATION_DIRECTORY):
                os.mkdir(LOGS_DESTINATION_DIRECTORY)

            # Configure the logger
            logging.basicConfig(stream=logger_holder, level=logging.DEBUG,
                                format=f'%(asctime)s - %(levelname)s - {SCAN_TYPE} -> %(message)s')
            setup_logger_status = True
        except Exception as setup_logger_err:
            print(f"Error setting up logger: {setup_logger_err}")

        return setup_logger_status

    setup_logger_creation_status = setup_logger()
    if setup_logger_creation_status:
        setup_logger_function_status = True

    return setup_logger_function_status, logger_holder


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
def convert_date_to_formatted(date_str):
    """ Converts the date string to dd-mm-yy H-M-S format by trying multiple formats. """
    if not date_str:
        return None
    date_formats = [
        "%a %d %b %Y %I:%M:%S %p %Z",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y, %H:%M:%S",
        "%b %d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S %z",
        "%d-%m-%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%d-%b-%Y %H:%M:%S",
        "%a %d %b %Y %H:%M:%S %z",
        "%d/%m/%y, %I:%M %p",
        "%d/%m/%Y, %I:%M %p",
        "%d-%m-%Y, %I:%M %p",
        "%d/%m/%y, %H:%M",
        "%d-%m-%Y %I:%M %p",
        "%B %d, %Y %I:%M %p",
        "%d %B %Y, %H:%M",
        "%d %B %Y %I:%M %p",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%b-%d %H:%M:%S",
        "%d.%m.%Y %H:%M",
        "%I:%M %p, %d %b %Y",
        "%A, %d %B %Y %I:%M %p",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S %z",
        "%d-%b-%y %I:%M:%S %p",
        "%b %d %H:%M:%S"
    ]
    for fmt in date_formats:
        try:
            parsed_date = datetime.strptime(date_str, fmt)
            formatted_date = parsed_date.strftime("%d-%m-%Y %H:%M:%S")
            return str(formatted_date)
        except ValueError:
            continue
        except Exception as date_format_err:
            logging.warning(f"Error in format: {date_format_err}")
            continue

    # If none of the formats worked, log the error and return the original date string
    logging.warning(
        f"Error parsing date '{date_str}' with all provided formats.")
    return str(date_str)


@logger_function
def add_audit_info_to_log():
    script = f'''
        if [ ! -f "{LOGS_DESTINATION_DIRECTORY}/audit-instance.log" ]; then
            touch "{LOGS_DESTINATION_DIRECTORY}/audit-instance.log"
        fi
        echo "$(date +'%d-%m-%Y %H:%M:%S,%3N') - INFO - {SCAN_TYPE}" >> \
            "{LOGS_DESTINATION_DIRECTORY}/audit-instance.log"
    '''
    try:
        result = subprocess.run(script, shell=True, timeout=TIMEOUT_SUBPROCESS,
                                text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if result.returncode == 0:
            logging.info(f"Audit log instance created.")
        else:
            logging.error(f"Failed to create log instance.")
    except Exception as add_audit_info_error:
        logging.error(f"Failed to create log instance.{add_audit_info_error}")


@logger_function
def extract_shell_info(command_args, file_path=None, var_name="extract_shell_info"):
    try:
        logging.info(f"command_args: {command_args}")
        logging.info(f"file_path: {file_path}")
        logging.info(f"var_name: {var_name}")

        # Check if file exists and readable (if applicable)
        if file_path is not None:
            if not os.path.exists(file_path):
                logging.warning(f"File path does not exist: {file_path}")
                return ""
            if not os.access(file_path, os.R_OK):
                logging.warning(f"File path not readable: {file_path}")
                return ""

        # Determine shell mode
        use_shell = not isinstance(command_args, (list, tuple))
        logging.debug(f"Using shell: {use_shell}")

        # Run the command and capture output
        output = subprocess.check_output(
            command_args,
            shell=use_shell,
            universal_newlines=True,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT_SUBPROCESS
        )

        return output.strip()

    except Exception as err:
        error["miscellaneousInfo"][var_name] = repr(err)
        logging.error(f"{var_name} error: {error['miscellaneousInfo'][var_name]}")
        return ""


@logger_function
def extract_info(command_args):
    var_name = "extract_info"
    logging.info(f"{var_name} function command_args: {command_args}")

    try:
        # Determine shell mode
        use_shell = not isinstance(command_args, (list, tuple))
        logging.debug(f"Using shell: {use_shell}")

        # Run the command
        output = subprocess.check_output(
            command_args,
            shell=use_shell,
            universal_newlines=True,
            timeout=TIMEOUT_SUBPROCESS,
            stderr=subprocess.PIPE
        )

        logging.info(f"{var_name} output: {output.strip()}")
        return output.strip()

    except subprocess.CalledProcessError as err:
        error["miscellaneousInfo"][var_name] = repr(err)
        logging.error(f"{var_name} error: {error['miscellaneousInfo'][var_name]}")
        return ""
    except Exception as err:
        error["miscellaneousInfo"][var_name] = repr(err)
        logging.error(f"{var_name} error: {error['miscellaneousInfo'][var_name]}")
        return ""


@logger_function
def get_current_loggedin_user():
    current_loggedin_user = ""
    try:
        # Use `loginctl` to list user sessions
        result = subprocess.run(['loginctl', 'list-sessions', '--no-legend'], stdout=subprocess.PIPE,
                                timeout=TIMEOUT_SUBPROCESS, text=True)
        logging.info(f"current_loggedin_user output: {result}")
        if result.stdout:
            sessions = result.stdout.splitlines()
            for session in sessions:
                session_no = session.strip().split(" ")[0].strip()
                show_result = subprocess.run(['loginctl', 'show-session', session_no, '-p', 'Active'],
                                             timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, text=True)
                logging.info(f"current_loggedin_user output: {show_result}")
                if show_result.stdout:
                    active_line = show_result.stdout.strip()
                    if 'Active=yes' in active_line:
                        username = subprocess.run(['loginctl', 'show-session', session_no, '-p', 'Name'],
                                                  timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, text=True)
                        logging.info(f"current_loggedin_user output: {username}")
                        if username.stdout:
                            current_loggedin_user = username.stdout.split("=")[-1].strip()
                            break
    except Exception as err:
        error["miscellaneousInfo"]["get_current_loggedin_user"] = repr(err)
        logging.error(f"error['miscellaneousInfo']['get_current_loggedin_user']: {err}")
    logging.info(f"current_loggedin_user: {current_loggedin_user}")
    return current_loggedin_user


@logger_function
def fetch_current_time():
    """
    Fetches the current time in Indian Standard Time (IST) and returns it in ISO 8601 format.

    Returns:
        str: The current time in ISO 8601 format.

    Raises:
        Exception: If there is an error while fetching the current time.
    """
    try:
        ist_offset = timedelta(hours=5, minutes=30)  # IST (Indian Standard Time) UTC offset
        current_time = datetime.now(timezone.utc)
        current_time_with_tz = current_time.astimezone(timezone(ist_offset))
        current_time_iso = current_time_with_tz.isoformat()
        return current_time_iso
    except Exception as err:
        error['miscellaneousInfo']['fetch_current_time'] = repr(err)
        logging.error(f"error['miscellaneousInfo']['fetch_current_time']: {err}")
        return ""


@logger_function
def send_linux_notification(title, message, notification_icon):
    was_notification_sent = False
    logging.info("Sending the notification toast to the linux user.")

    try:
        logging.info(f"Notification Section Starts")
        notify_current_loggedin_user = get_current_loggedin_user()

        logging.info(f"Notification Section - notify_current_loggedin_user: {notify_current_loggedin_user}")

        def get_notification_text(notification_message, current_user):
            logging.info(f"Notification Section - get_notification_text - notification_message : "
                         f"{notification_message}")
            logging.info(f"Notification Section - get_notification_text - current_user: {current_user}")
            updated_notification_message = notification_message.replace("USER", current_user)
            logging.info(f"Notification Section - get_notification_text - updated_notification_message: "
                         f"{updated_notification_message}")

            return updated_notification_message

        updated_notification_message_string = get_notification_text(message, notify_current_loggedin_user)
        logging.info(f"Notification Section - updated_notification_message_string: "
                     f"{updated_notification_message_string}")

        user = notify_current_loggedin_user
        notify_userid = (subprocess.run(['id', '-u', user], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        check=True, timeout=TIMEOUT_SUBPROCESS)
                         .stdout.decode('utf-8').replace('\n', ''))

        logging.info(f"Notification Section - notify_userid: {notify_userid}")
        logging.info(f"Notification Section - DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{notify_userid}/bus")
        if not os.path.exists(notification_icon):
            notification_icon = "utilities-terminal"
        notify_subprocess_result = subprocess.run(['sudo', '-u', user,
                                                   'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{}/bus'.format(
                                                       notify_userid),
                                                   'notify-send', '-i', notification_icon,
                                                   updated_notification_message_string,
                                                   title],
                                                  env=os.environ,
                                                  stdout=subprocess.PIPE,
                                                  stderr=subprocess.PIPE,
                                                  check=True, timeout=TIMEOUT_SUBPROCESS)

        logging.info(f"Notification Section - notify-send result: {notify_subprocess_result}")
        was_notification_sent = True
        logging.info("Notification toast sent to the linux user successfully.")
    except Exception as err:
        error["miscellaneousInfo"]["send_linux_notification"] = repr(err)
        logging.error(f"Notification toast not sent to the linux user. Error: {err}")
    return was_notification_sent


def get_file_type(file_path_src):
    try:
        if not os.path.exists(file_path_src):
            raise FileNotFoundError(f"The file {file_path_src} was not found.")

        cmd = f"file -b --mime-type '{file_path_src}'"
        cmd_result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                    timeout=TIMEOUT_SUBPROCESS, check=True)

        mime_type = cmd_result.stdout.strip()
        return mime_type
    except subprocess.CalledProcessError as e:
        logging.warning(f"Error: {e}")
        return None
    except FileNotFoundError as e:
        logging.warning(f"Error: {e}")
        return None
    except Exception as e:
        logging.warning(f"An unexpected error occurred: {e}")
        return None


def get_file_hash(file_path_source):
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path_source, "rb") as as_file:
            for chunk in iter(lambda: as_file.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except FileNotFoundError:
        return None
    except IOError as e:
        logging.warning(f"IOError occurred: {e}")
        return None
    except Exception as e:
        logging.warning(f"An unexpected error occurred: {e}")
        return None


def get_file_details(file_path, hostname):
    try:
        file_hash = get_file_hash(file_path)
        mime_type = get_file_type(file_path)
        last_modified_time = os.path.getmtime(file_path)
        last_modified_datetime = datetime.fromtimestamp(last_modified_time).strftime('%d-%m-%Y %H:%M:%S')

        return {
            "hostType": hostname,
            "path": file_path,
            "fileHash": file_hash,
            "fileType": mime_type,
            "lastModified": last_modified_datetime
        }
    except Exception as get_file_details_error:
        logging.error(f"Error in 'get_file_details' for {file_path}:"
                      f"{get_file_details_error}")
        return None


def process_file(task):
    try:
        path, result, hostname = task
        if os.path.isfile(path):
            file_details = get_file_details(path, hostname)
            if file_details:
                result.append(file_details)
    except Exception as process_file_error:
        logging.error(f"Error in 'process_file': {process_file_error}")


def add_file_hash_to_log(path, result, hostname):
    try:
        tasks = []
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file_to_walk in files:
                    file_path_c = os.path.join(root, file_to_walk)
                    tasks.append((file_path_c, result, hostname))
        else:
            tasks.append((path, result, hostname))

        with Pool() as pool:
            pool.map(process_file, tasks)
    except Exception as add_file_hash_to_log_error:
        logging.error(f"Error in 'add_file_hash_to_log': {add_file_hash_to_log_error}")


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
            return "ubuntu"
        elif "red hat" in os_distributor_output or "almalinux" in os_distributor_output \
            or os_id_like_output == "fedora":
            return "rhel"
        elif "centos" in os_distributor_output:
            return "centos"
        else:
            os_distributor_command = 'hostnamectl | grep "Operating System:"'
            os_distributor_output = \
                subprocess.check_output(os_distributor_command, shell=True, universal_newlines=True,
                                        stderr=subprocess.PIPE,
                                        timeout=TIMEOUT_SUBPROCESS).strip().split(":")[1].strip().lower()
            logging.info(f"Extracted os-distributor name method 2: {os_distributor_output}")
            if "ubuntu" in os_distributor_output or "kali" in os_distributor_output:
                return "ubuntu"
            elif "red hat" in os_distributor_output or "almalinux" in os_distributor_output:
                return "rhel"
            elif "centos" in os_distributor_output:
                return "centos"
            else:
                return "ubuntu"
    except Exception as err:
        logging.error(f"Error occurred while getting os-distributor name: {repr(err)}")
        return "ubuntu"


@logger_function
def get_linux_os_version():
    try:
        file_path = '/etc/os-release'
        logging.info(f"file_path: {file_path}")
        if not os.path.exists(file_path):
            logging.warning(f"Error: File '{file_path}' not found.")
            return ""

        if not os.access(file_path, os.R_OK):
            logging.warning(f"Error: File '{file_path}' not accessable.")
            return ""

        # Read the contents of the /etc/os-release file
        with open('/etc/os-release', 'r') as f:
            os_release_info = f.read()

        # logging.info(f"os_release_info: {os_release_info}")
        # Parse the contents to extract the version information
        os_version = ""
        for line in os_release_info.split('\n'):
            if line.startswith('VERSION='):
                os_version = line.split('=')[1].strip('"\'')

        logging.info(f"os_version: {os_version}")
        return os_version if os_version else ""
    except Exception as err:
        error["osInfo"]["get_linux_os_version"] = repr(err)
        logging.error(f"Error occurred while getting linux os version: {repr(err)}")
        return ""


@logger_function
def get_os_name_info():
    """
    Retrieves the operating system name and information.

    This function runs the `lsb_release -d` command and captures the output.
    It then extracts the description part from the output and returns it.

    Returns:
        str: The description of the operating system name and information.

    Raises:
        Exception: If there is an error running the command or capturing the output.
    """
    try:
        # Run the lsb_release -d command and capture the output
        command = r"""cat /etc/os-release | grep '^NAME=' | awk -F= '{print $2}' | tr -d '"'"""
        logging.info(f"get_os_name_info command: '{command}'")
        if not os.path.isfile('/etc/os-release'):
            error["pcIdentityInfo"]["get_os_name_info"] = "File '/etc/os-release' not found"
            logging.error(f"File '/etc/os-release' not found")
            return ""
        output = subprocess.check_output(command, universal_newlines=True, shell=True,
                                         timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE).strip()
        logging.info(f"get_os_name_info output: {output}")
        # Return the description
        return output
    except Exception as err:
        error["pcIdentityInfo"]["get_os_name_info"] = repr(err)
        logging.error(f"Error running lsb_release -d: {err}")
        return ""


@logger_function
def get_os_release_name(os_name):
    try:
        os_name_lower = os_name.lower()
        if "ubuntu" in os_name_lower:
            return "ubuntu"
        elif "red hat" in os_name_lower or "almalinux" in os_name_lower:
            return "rhel"
        elif "centos" in os_name_lower:
            return "centos"
        else:
            return "other"
    except Exception as err:
        error["pcIdentityInfo"]["get_os_name_info"] = repr(err)
        logging.error(f"Error running lsb_release -d: {err}")
        return "other"


@logger_function
def generate_html(json_data="", table_attributes='border="1"', escape=True):
    """
    Convert JSON to HTML Table format
    """

    text = str
    text_types = (str,)

    def generate_css():
        """
        Generate CSS styles
        """
        css_styles = """
        <style>
        /* Table Styles */
        * {
            box-sizing: border-box;
        }
        body {
            background-image: linear-gradient( 184.1deg,  rgba(249,255,182,1) 44.7%, rgba(226,255,172,1) 67.2% );
        }
        table {
            border-collapse: collapse;
            width: 100%;
            color: #000000;
        }
        div#heading {
            text-align: center;
            font-weight: bold;
            font-size: 20px;
        }

        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: left;

        }

        /* List Styles */
        ul {
            list-style-type: none;
            padding: 0;
            margin: 0;
            overflow-y: scroll;
            height: 200px;
        }

        li {
            padding: 8px;
        }
        </style>

        """
        return css_styles

    css_styles_output = generate_css()
    header = "<h1 style='text-align: center;'>CA-Audit-Report</h1>"

    # table attributes such as class, id, data-attr-*, etc.
    # eg: table_attributes = 'class = "table table-bordered sortable"'
    table_init_markup = "<table %s>" % table_attributes

    def camel_case_to_title_case(camel_case_str):
        """Convert camel case string to title case."""
        return re.sub(r'(?<!^)(?=[A-Z])', ' ', camel_case_str).title()

    def convert_json_node(json_data_input):
        """
        Dispatch JSON input according to the outermost type and process it
        to generate the super awesome HTML format.
        We try to adhere to duck typing such that users can just pass all kinds
        of funky objects to json2html that *behave* like dicts and lists and other
        basic JSON types.
        """
        if type(json_data_input) in text_types:
            if escape:
                return html_escape(text(json_data_input))
            else:
                return text(json_data_input)
        if hasattr(json_data_input, 'items'):
            return convert_object(json_data_input)
        if hasattr(json_data_input, '__iter__') and hasattr(json_data_input, '__getitem__'):
            return convert_list(json_data_input)
        return text(json_data_input)

    def convert_list(list_input):
        """
        Iterate over the JSON list and process it
        to generate either an HTML table or an HTML list, depending on what's inside.
        If suppose some key has an array of objects and all the keys are the same,
        instead of creating a new row for each such entry,
        club such values, thus it makes more sense and more readable table.
        """
        nonlocal table_init_markup

        if not list_input:
            return ""

        # Check if all elements in the list are objects
        all_objects = all(isinstance(item, dict) for item in list_input)

        # If all elements are objects, collapse each object into a single HTML representation
        if all_objects:
            html_content = ''
            for obj in list_input:
                html_content += '<p>' + convert_json_node(obj) + '</p>'
            return '<div style="overflow-y: scroll; height: 200px;">' + html_content + '</div>'
        else:
            # Treat the list as a regular HTML list
            converted_output = '<ul style="overflow-y: scroll; height: 200px;">'
            for item in list_input:
                converted_output += '<li>' + convert_json_node(item) + '</li>'
            converted_output += '</ul>'
            return converted_output

    def convert_object(json_data_input):
        """
        Iterate over the JSON object and process it
        to generate the super awesome HTML Table format
        """
        if not json_data_input:
            return ""  # avoid empty tables
        converted_output = table_init_markup + "<tr>"
        converted_output += "</tr><tr>".join([
            "<th>%s</th><td>%s</td>" % (
                camel_case_to_title_case(convert_json_node(k)),
                convert_json_node(v)
            )
            for k, v in json_data_input.items()
        ])
        converted_output += '</tr></table>'
        return converted_output

    if not json_data:
        json_input = {}
    elif type(json_data) in text_types:
        try:
            json.loads(json_data, object_pairs_hook=OrderedDict)
        except ValueError as json_value_error:
            if u"Expecting property name" in text(json_value_error):
                raise json_value_error
            json_input = json_data
    else:
        json_input = json_data

    return f'<html><head>{header}{css_styles_output}</head><body>{convert_json_node(json_input)}</body></html>'


@logger_function
def get_custodian_name():
    try:
        logging.info("Started function: get_custodian_name()")
        if os.path.exists("/etc/environment"):
            with open("/etc/environment", "r") as f:
                for line in f:
                    if line.startswith("CA_CUSTODIAN_NAME"):
                        logging.info(f"Found custodian name: {line.split('=')[1].strip()}")
                        custodian_name = line.split("=")[1].strip()[1:-1]
                        return custodian_name
        else:
            logging.error("File /etc/environment not found.")
            return ""
    except Exception as custodian_env_err:
        logging.error(f"Error in get_custodian_name: {custodian_env_err}")
        return ""


@logger_function
def get_lic_key_from_env():
    try:
        logging.info("Started function: get_lic_key_from_env()")
        global LICENSE_KEY
        if os.path.exists("/etc/environment"):
            with open("/etc/environment", "r") as f:
                for line in f:
                    if line.startswith("CA_LICENSE_KEY"):
                        logging.info(f"Found license key: {line.split('=')[1].strip()}")
                        LICENSE_KEY = line.split("=")[1].strip()[1:-1]
        else:
            logging.error("File /etc/environment not found.")
    except Exception as lic_env_err:
        logging.error(f"Error in get_lic_key_from_env: {lic_env_err}")

    return LICENSE_KEY


@logger_function
def find_and_extract_current_setup_version():
    """
        Function to find and extract the current setup version from the setup file.
        Returns the extracted version as a string, or an empty string if no version is found.
        Logs the process and any errors encountered during the operation.
    """
    agent_version = ""
    try:
        logging.info("Finding and extracting setup_file_name from setup file")
        # Get the current working directory
        setup_file_name = "/etc/environment"
        if os.path.exists(setup_file_name):
            with open(setup_file_name, 'r') as file:
                for line in file:
                    if "CA_LATEST_VERSION" in line:
                        agent_version = line.split("=")[1].strip()[1:-1]
                        logging.info(f"Current agent version: {agent_version}")
        else:
            logging.error(f"Setup file {setup_file_name} not found")

    except Exception as err:
        error["pcIdentityInfo"]["find_and_extract_current_setup_version"] = repr(err)
        logging.error(f"Error finding and setting setup_file_name: {err}")

    return agent_version


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
        bios_serial_cmd = r"sudo dmidecode -t system | grep 'Serial Number'"
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
        motherboard_serial_cmd = r"sudo dmidecode -t baseboard | grep 'Serial Number'"
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
        uuid_cmd = r"sudo dmidecode -t system | grep 'UUID'"
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


@logger_function
def get_pc_id_without_lickey():
    try:
        logging.info("Getting pc id")
        bios_serial = get_system_serial_number()
        motherb_serial = get_motherboard_serial_number()
        if bios_serial == motherb_serial:
            device_uuid = get_device_uuid()
            pc_id = device_uuid
        elif motherb_serial == "":
            pc_id = bios_serial
        elif bios_serial == "":
            pc_id = motherb_serial
        else:
            pc_id = motherb_serial + '-' + bios_serial
        logging.info(f"PC ID: {pc_id}")
        pc_id = pc_id.replace("/", "")
        return pc_id
    except Exception as pc_id_error:
        error["pcIdentityInfo"]["get_pc_id"] = repr(pc_id_error)
        logging.error(f"An error occurred while getting pc id: {pc_id_error}")
        return ""


@logger_function
def get_hostname_from_env():
    try:
        global HOSTNAME
        global BACKEND_API_URL
        if os.path.exists("/etc/environment"):
            with open("/etc/environment", "r") as f:
                for line in f.readlines():
                    if "CA_HOST_NAME" in line:
                        HOSTNAME = line.split("=")[1].strip()[1:-1]
                        logging.info(f"Found hostname: {HOSTNAME}")
                        BACKEND_API_URL = f"{HOSTNAME}/api/v1/linux/ingest/main"
    except Exception as hostname_err:
        logging.error(f"An error occurred while getting hostname: {hostname_err}")


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


@logger_function
def get_audit_log_id_info():
    try:
        # Provided key and IV
        ca_private_key = base64.urlsafe_b64decode('nAy7rLX4teIS2CR_2lpV8mt67VvTQT53o2D_-ErE6Ng=')
        iv = b'1234567890123456'

        def encrypt_content(file_path, file_content_to_encrypt):
            encryption_status = False
            try:
                # Ensure the key is 32 bytes long for AES-256
                key = ca_private_key[:32]

                # Create cipher object and encrypt the data
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_content = cipher.encrypt(pad(file_content_to_encrypt.encode(), AES.block_size))

                # Encode the encrypted content to base64
                encoded_encrypted_content = base64.urlsafe_b64encode(encrypted_content)

                # Ensure subprocess runs correctly and deletes the line if present
                subprocess.run("sudo sed -i '/^CA_LOG_VALUE/d' /etc/environment > /dev/null", shell=True,
                               universal_newlines=True,
                               stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS)

                # Open the file in append binary mode and write the encrypted content
                with open(file_path, 'ab') as f:
                    f.write(b'CA_LOG_VALUE="' + encoded_encrypted_content + b'"\n')
                    f.flush()
                    os.fsync(f.fileno())

                encryption_status = True
            except Exception as encrypted_content_err:
                logging.error(f"encrypt_content Error: {encrypted_content_err}")

            return encryption_status

        def decrypt_content(encrypted_content_str):
            try:
                # Decode the base64 encoded string
                encrypted_content = base64.urlsafe_b64decode(encrypted_content_str)

                # Ensure the key is 32 bytes long for AES-256
                key = ca_private_key[:32]

                # Create cipher object and decrypt the data
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_content = unpad(cipher.decrypt(encrypted_content), AES.block_size).decode()
                return decrypted_content
            except Exception as decrypted_content_err:
                logging.error(f"decrypt_content Error: {decrypted_content_err}")
                return ""

        def get_file_value_from_env():
            try:
                if os.path.exists("/etc/environment"):
                    with open("/etc/environment", "r") as f:
                        for line in f:
                            if line.startswith("CA_LOG_VALUE="):
                                file_inc_value = line.split("CA_LOG_VALUE=")[1].strip().strip('"')
                                logging.info(f"Found File Value: {file_inc_value}")
                                return file_inc_value
                else:
                    logging.error("File /etc/environment not found.")
            except Exception as file_inc_err:
                logging.error(f"Error in getting file value: {file_inc_err}")
            return ""

        # logging.info(f"Since File exists, reading the audit log id.")
        file_inc_from_env = get_file_value_from_env()

        if file_inc_from_env != "":
            try:
                log_file_content = decrypt_content(file_inc_from_env)
                if log_file_content != "" and log_file_content.strip().isdigit():
                    logging.info(f"Current audit_log_id: {log_file_content}")
                    audit_log_id = int(log_file_content)
                    next_audit_log_id = audit_log_id + 1
                    encryption_successful = encrypt_content("/etc/environment", str(next_audit_log_id))
                    if encryption_successful:
                        logging.info(f"Updated audit_log_id: {next_audit_log_id}")
                        return next_audit_log_id
                else:
                    next_audit_log_id = 1
                    encryption_successful = encrypt_content("/etc/environment", str(next_audit_log_id))
                    if encryption_successful:
                        logging.info(f"Updated audit_log_id: {next_audit_log_id}")
                        return next_audit_log_id
            except Exception as err:
                logging.error(f"Error in decrypting audit log id: {err}")
        else:
            try:
                next_audit_log_id = 1
                encryption_successful = encrypt_content("/etc/environment", str(next_audit_log_id))
                if encryption_successful:
                    logging.info(f"Updated audit_log_id: {next_audit_log_id}")
                    return next_audit_log_id
            except Exception as err:
                logging.error(f"Error in encrypting audit log id: {err}")

    except Exception as err:
        logging.error(f"Error in get_audit_log_id_info: {err}")

    return -1


# System Info block------------------------------------------
@logger_function
def get_ubuntu_system_info():
    # misc_functions ---------------------------------------------------------------------------

    @logger_function
    def get_os_install_date():
        try:
            logging.info(f"os_installation_date_command: ['stat', '-c', '%w', '/']")
            timestamp_str = str(extract_info(['stat', '-c', '%w', '/']))
            logging.info(f"os_installation_date_output: {timestamp_str}")
            # "2024-01-04 10:55:57.460197000 +0530"
            timestamp_list = timestamp_str.split()
            logging.info(f"os_installation_date_list: {timestamp_list}")
            install_date = timestamp_list[0]
            logging.info(f"os_installation_date: {install_date}")
            install_time = timestamp_list[1].split('.')[0]
            logging.info(f"os_installation_time: {install_time}")
            install_zone_hour = timestamp_list[2][:3]
            logging.info(f"os_installation_zone_hour: {install_zone_hour}")
            install_zone_minute = timestamp_list[2][3:]
            logging.info(f"os_installation_zone_minute: {install_zone_minute}")
            formatted_timestamp = f"{install_date} {install_time} {install_zone_hour}:{install_zone_minute}"
            logging.info(f"os_installation_formatted_timestamp: {formatted_timestamp}")
            return formatted_timestamp
        except Exception as err:
            error["osInfo"]["os_installation_date"] = repr(err)
            logging.error(f"Error occurred while extracting os installation date: {repr(err)}")
            return ""

    # accountInfo functions --------------------------------------------------------------------

    @logger_function
    def get_user_account_details(username):
        """
        Get user's account details based on the given username.

        Parameters:
            username (str): The username for which to retrieve the account details.

        Returns:
            dict: A dictionary containing the user's account details. The dictionary has the following keys:
                - "accountType" (str): The type of the account (currently set to "Linux").
                - "caption" (str): The user's caption or display name.
                - "sID" (str): The user's security identifier.
                - "name" (str): The user's name.

            If the account details cannot be retrieved or an error occurs, None is returned.
        """
        logging.info("Started function: get_user_account_details()")
        try:
            # Get user's information from /etc/passwd
            logging.info(f"Searching for user '{username}' in /etc/passwd.")
            passwd_file = open('/etc/passwd', 'r')
            lines = passwd_file.readlines()
            for line in lines:
                if username in line:
                    parts = line.split(':')
                    user_details = {
                        "accountType": "Linux",  # You can customize this value
                        "caption": parts[0],
                        "sID": parts[2],
                        "name": parts[0]
                    }
                    logging.info(f"User details found in /etc/passwd for '{username}'.")
                    return user_details
            passwd_file.close()

            # If not found in /etc/passwd, try using 'id' command
            logging.info(f"User '{username}' not found in /etc/passwd. Trying 'id' command.")

            id_output = subprocess.check_output(['id', username], timeout=TIMEOUT_SUBPROCESS).decode('utf-8').strip()
            uid = id_output.split('(')[0].split('=')[1]
            user_details = {
                "accountType": "Linux",
                "caption": username,
                "sID": uid,
                "name": username
            }
            logging.info(f"User details retrieved using 'id' command for '{username}'.")

            return user_details
        except Exception as err:
            error["accountInfo"]["get_user_account_details"] = repr(err)
            logging.error(f"Error occurred while retrieving user details for '{username}': {repr(err)}")
            return {}

    @logger_function
    def get_admin_accounts():
        """
        Retrieves a list of admin accounts from the system.

        Returns:
            If there are no admin accounts available, returns the string "No Admin Account Available".
            If there are admin accounts available, returns a dictionary with the following keys:
                - 'multipleAdminCount': a boolean indicating whether there are multiple admin accounts
                - 'localAdminCount': an integer representing the number of admin accounts
                - 'adminAccountsName': a list of strings representing the names of the admin accounts

        Raises:
            Exception: If there was an error retrieving the admin accounts, an empty list is returned.
        """
        logging.info("started function: get_admin_accounts()")
        admin_accounts_details = {
            'multipleAdminCount': False,
            'localAdminCount': -1,
            'adminAccountsName': []
        }
        try:
            logging.info("Retrieving admin accounts using 'getent' command.")
            # Run 'getent' command to retrieve sudoers information
            sudoers_output_command = "getent group sudo"
            logging.info(f"get_admin_accounts_command: '{sudoers_output_command}'")
            sudoers_output = subprocess.check_output(sudoers_output_command, shell=True, universal_newlines=True,
                                                     stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS)
            lines = sudoers_output.strip().split('\n')
            logging.info(f"get_admin_accounts_output: {lines}")
            admin_accounts = []

            for line in lines:
                if line.startswith("sudo:") and len(line.split(":")) > 3:
                    members = line.split(":")[3].split(",")
                    admin_accounts.extend([member.strip() for member in members])

            if '' in admin_accounts:
                admin_count = 0
                admin_accounts = []
                multiple_admin_count = False

            else:
                admin_accounts = list(set(admin_accounts))  # Remove duplicates
                admin_count = len(admin_accounts)
                multiple_admin_count = admin_count > 1

            admin_accounts_details = {
                'multipleAdminCount': multiple_admin_count,
                'localAdminCount': admin_count,
                'adminAccountsName': admin_accounts
            }
            logging.info("Admin accounts retrieved successfully.")

        except Exception as err:
            error["accountInfo"]["get_admin_accounts"] = repr(err)
            logging.error(f"Error occurred while retrieving admin accounts: {repr(err)}")

        return admin_accounts_details

    @logger_function
    def get_users_password_age():
        """
        Calculates the number of days since the user's last password change.

        Returns:
            int: The number of days since the last password change. If the last password change
            date cannot be retrieved or if the current date is the same as the last password
            change date, returns -1. If an error occurs during the process, returns None.

        Raises:
            None
        """
        logging.info("Started function: get_users_password_age()")
        users_password_age = []
        try:
            all_user_command = r"""awk -F: '$3 >= 1000 && $3 <= 1100 && $6 ~ /^\/home/ {print $1}' /etc/passwd"""
            all_user_list = subprocess.run(all_user_command, shell=True, universal_newlines=True,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           timeout=TIMEOUT_SUBPROCESS).stdout.strip().split('\n')
            logging.info(f"all_user_list: {all_user_list}")
            for user in all_user_list:
                password_age = {
                    "userName": user,
                    "passwordAge": -1
                }
                logging.info("Executing 'chage' command to retrieve last password change date.")
                pwd_command = (f"sudo chage -l {user} "
                               r"| awk -F ':' '/Last password change/ {print $2}'")
                logging.info(f"pwd_command: {pwd_command}")
                last_change_match = subprocess.run(pwd_command, shell=True, universal_newlines=True,
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()
                logging.info(f"Subprocess Result of Last password change date: {last_change_match}")
                if last_change_match:
                    last_change_match = str(last_change_match)
                    logging.info(f"Last password change date: {last_change_match}")

                    # Adjust the format to include time information
                    if "never" in last_change_match:
                        try:
                            last_change_date_temp = str(get_os_install_date())
                            logging.info(f"last_change_date_temp: {last_change_date_temp}")

                            # Adjust the format to exclude time information
                            last_change_date = datetime.strptime(str(last_change_date_temp).split()[0],
                                                                 "%Y-%m-%d").date()
                            logging.info(f"last_change_date: {last_change_date}")
                            current_date = date.today()
                            logging.info(f"current_date: {current_date}")
                            days_since_change = (current_date - last_change_date).days

                            if days_since_change or days_since_change == 0:
                                logging.info(f"Days since last password change: {days_since_change}")
                                password_age["passwordAge"] = days_since_change
                            else:
                                logging.error("Last password change date could not be retrieved.")
                        except Exception as never_match_err:
                            logging.error(
                                f"error['accountInfo']['users_password_age']"
                                f"['get_users_password_age']:{never_match_err}")
                    else:
                        try:
                            last_change_date = datetime.strptime(last_change_match, "%b %d, %Y").date()
                            logging.info(f"last_change_date: {last_change_date}")
                            current_date = date.today()
                            logging.info(f"current_date: {current_date}")
                            days_since_change = (current_date - last_change_date).days
                            logging.info(f"days_since_change: {days_since_change}")
                            if days_since_change or days_since_change == 0:
                                logging.info(f"Days since last password change: {days_since_change}")
                                password_age["passwordAge"] = days_since_change
                            else:
                                logging.error("Last password change date could not be retrieved.")
                        except Exception as found_match_err:
                            logging.error(
                                f"error['accountInfo']['users_password_age']"
                                f"['get_users_password_age']:{found_match_err}")
                else:
                    logging.error("Last password change date could not be retrieved.")
                users_password_age.append(password_age)

        except Exception as err:
            error["accountInfo"]["users_password_age"] = repr(err)
            logging.error(f"Error occurred while calculating days since last password change: {repr(err)}")

        return users_password_age

    # backendInfo functions --------------------------------------------------------------------

    @logger_function
    def get_installed_programs():
        try:
            out = extract_shell_info("dpkg --get-selections | cut -f1")
            return list(out.split())
        except Exception as err:
            error["backendInfo"]["get_installed_programs"] = repr(err)
            logging.error(f"Error occurred while retrieving installed programs: {repr(err)}")
            return []

    @logger_function
    def get_os_patch_info():
        os_versions = []
        try:
            version = get_linux_os_version()
            only_version = ""
            if version:
                only_version = version.split(" ")[0]
            result = {
                "name": get_os_name_info(),
                "version": only_version,
                "date": get_os_install_date(),
                "versionName": get_linux_os_version()
            }
            os_versions.append(result)

        except Exception as os_patch_info_error:
            error["backendInfo"]["get_os_patch_info"] = repr(os_patch_info_error)
            logging.error(f"Error occurred while getting os patch info: "
                          f"{repr(os_patch_info_error)}")

        return os_versions

    @logger_function
    def get_application_patch_info():
        def convert_date(unix_timestamp):
            """ Converts a Unix timestamp to dd-mm-yy H-M-S format. """
            try:
                parsed_date_format = datetime.fromtimestamp(int(unix_timestamp))
                formatted_date = parsed_date_format.strftime("%d-%m-%Y %H:%M:%S")
                return formatted_date
            except ValueError as e:
                logging.error(f"Error parsing date '{unix_timestamp}': {e}")
                return ""

        def extract_real_version(version):
            """
            Removes epoch, ubuntu/debian revision, and distro suffixes.
            Returns only the upstream version.
            """
            try:
                # Remove epoch (anything before colon)
                if ":" in version:
                    version = version.split(":", 1)[1]

                # Remove everything after tilda (Debian revision)
                if "~" in version:
                    version = version.split("~", 1)[0]

                # Remove everything after hyphen (Debian revision)
                if "-" in version:
                    version = version.split("-", 1)[0]

                # Remove things after '+' (dfsg, build info, etc.)
                if "+" in version:
                    version = version.split("+", 1)[0]

                # Remove 0ubuntu0 types
                if "ubuntu" in version:
                    splitted = version.split(".")
                    for i in range(len(splitted)):
                        if "ubuntu" in splitted[i]:
                            small_version = splitted[i].split("ubuntu", 1)[0]
                            version = ".".join(splitted[:i]) + f".{small_version}"
                            break

                return version
            except Exception as extract_real_version_err:
                logging.warning(f"Error extracting real version: {extract_real_version_err}")
                return version

        applications_versions = []
        try:
            os_install_date = convert_date_to_formatted(get_os_install_date())
            dpkg_list_command = "dpkg -l | awk 'NR>=6 {print $2, $3}'"
            logging.info(f"dpkg list command: {dpkg_list_command}")
            result = subprocess.run(dpkg_list_command, shell=True, text=True,
                                    timeout=TIMEOUT_SUBPROCESS, capture_output=True)
            logging.info(f"Return code of dpkg list command: {result.returncode}")

            if result.returncode == 0:
                logging.info(f"dpkg list command executed successfully.")
                packages = result.stdout.strip().split('\n')
                for line in packages:
                    try:
                        package_name, package_version = line.split()
                        cleaned_version = extract_real_version(package_version)
                        doc_path = f"/usr/share/doc/{package_name}"
                        if os.path.exists(doc_path):
                            stat_command = f"stat -c %Y {doc_path}"
                            install_timestamp = extract_shell_info(stat_command).strip()
                            formatted_install_date = convert_date(install_timestamp)

                            package_info = {
                                "name": package_name,
                                "version": cleaned_version,
                                "date": formatted_install_date
                            }
                            applications_versions.append(package_info)
                        else:
                            package_info = {
                                "name": package_name,
                                "version": cleaned_version,
                                "date": os_install_date
                            }
                            applications_versions.append(package_info)
                    except ValueError as ve:
                        logging.error(f"Error parsing package line: {line}. Error: {ve}")
            else:
                logging.error(f"Error executing dpkg list command. Return code: {result.returncode}")
                logging.error(f"Error output: {result.stderr}")

        except Exception as application_patch_info_error:
            logging.error(f"Error occurred while getting application patch info: {repr(application_patch_info_error)}")
            return []

        return applications_versions

    @logger_function
    def get_filtered_hostname():
        try:
            hostname_temp = get_pretty_hostname()
            if hostname_temp != "":
                hostname = hostname_temp
            else:
                hostname = platform.node()
            host_i = hostname.split(".")[0]
            host_j = host_i.split("-")[-1]
            host = ""
            for i in host_j:
                if i.islower() or i.isdigit():
                    break
                host += i
            logging.info(f"hostname filtered: {host}")
            return host
        except Exception as filter_hostname_error:
            logging.error(f"Error occurred while filtering hostname:"
                          f"{repr(filter_hostname_error)}")
            return ""

    @logger_function
    def get_pretty_hostname():
        try:
            result = subprocess.run(['hostnamectl', 'status'], capture_output=True,
                                    timeout=TIMEOUT_SUBPROCESS, text=True)
            for line in result.stdout.splitlines():
                if "Pretty hostname:" in line:
                    logging.info(f"Found pretty hostname via hostnamectl: {line}")
                    return line.split(":", 1)[1].strip()
        except Exception as pretty_hostname_error:
            logging.error(f"Error occurred while getting pretty hostname via hostnamectl: "
                          f"{repr(pretty_hostname_error)}")
            try:
                with open('/etc/machine-info', 'r') as file:
                    for line in file:
                        if line.startswith("PRETTY_HOSTNAME="):
                            pretty_hostname = line.split("=", 1)[1].strip().strip('"')
                            logging.info(f"Found pretty hostname via /etc/machine-info: {pretty_hostname}")
                            return pretty_hostname
            except FileNotFoundError:
                logging.warning("/etc/machine-info file not found.")
            except Exception as file_error:
                logging.warning(f"Error occurred while reading /etc/machine-info: {repr(file_error)}")

        return ""

    @logger_function
    def get_file_integrity_info():
        try:
            manager = Manager()
            result = manager.list()

            json_file_path = '/etc/rati/integrityCheck.json'
            path_json = json.load(open(json_file_path, 'r'))

            hostname = get_filtered_hostname()

            if hostname:
                list_of_dirs = path_json[hostname]

                for path in list_of_dirs:
                    add_file_hash_to_log(path, result, hostname)

                return list(result)
            else:
                return []

        except Exception as file_integrity_info_error:
            logging.error(f"Error occurred while getting file integrity info: "
                          f"{repr(file_integrity_info_error)}")
            return []

    # hardwareInfo functions --------------------------------------------------------------------

    @logger_function
    def get_memory_information():
        """
        Retrieves memory information by running the 'free -h' command and parsing the output.

        Returns:
            A dictionary containing the following memory sizes in GB:
            - totalRAM: The total amount of RAM.
            - usedRAM: The amount of RAM being used.
            - freeRAM: The amount of free RAM.
            - sharedRAM: The amount of RAM being shared.
            - cacheRAM: The amount of RAM used for caching.
            - availableRAM: The amount of available RAM.

            If an error occurs while retrieving or parsing the memory information, returns a dictionary
            with an "error" key and an error message as the value.
        """
        try:
            # Run the 'free -h' command and capture the output
            output = subprocess.check_output(['free', '-h', '--giga'],
                                             universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"get_memory_information command output: {output}")
            # Split the output into lines
            lines = output.strip().split('\n')

            # Parse the first line of 'Mem:' data
            mem_data = re.match(r'^\s*Mem:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', lines[1])
            logging.info(f"mem_data: {mem_data}")
            if mem_data:
                total_ram, used_ram, free_ram, shared_ram, cache_ram, available_ram = mem_data.groups()

                # Convert sizes from human-readable format to GB
                sizes_gb = {
                    "totalRAM": total_ram,
                    "usedRAM": used_ram,
                    "freeRAM": free_ram,
                    "sharedRAM": shared_ram,
                    "cacheRAM": cache_ram,
                    "availableRAM": available_ram
                }
                logging.info(f"sizes_gb: {sizes_gb}")
                return sizes_gb
            else:
                logging.error("Unable to parse memory information from 'free -h' command output.")
                return {}
        except Exception as err:
            error["hardwareInfo"]["get_memory_information"] = repr(err)
            logging.error(f"Error occurred while getting memory information: {repr(err)}")
            return {}

    @logger_function
    def get_time_zone_info():
        """
        Retrieves the time zone information of the device.

        This function uses the 'date' command to get the time zone information and extracts the time zone from it.

        Returns:
            str: The time zone of the device.
        """
        try:
            # Run the 'date' command to get the time zone information
            output = subprocess.check_output(['date', '+%Z %z'], universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"date output: {output}")
            time_zone = output.strip().split()[0]
            hours = output.strip().split()[1][:3]
            minutes = output.strip().split()[1][3:]
            formatted_time_zone = f"{time_zone} {hours}:{minutes}"
            return formatted_time_zone
        except Exception as err:
            error["hardwareInfo"]["get_time_zone_info"] = repr(err)
            logging.error(f"Error occurred while getting time zone information: {repr(err)}")
            return ""

    @logger_function
    def get_bios_battery_serviceable():
        """
        Retrieves the status of the BIOS battery serviceability.
        """
        result = False
        try:
            # Run dmidecode command and capture the output
            biosbattery_command = r"cat /proc/driver/rtc | grep batt_status | awk '{print $3}'"
            logging.info(f"dmidecode command for bios battery: {biosbattery_command}")
            if not os.path.exists("/proc/driver/rtc"):
                logging.warning(f"FileNotFoundError: /proc/driver/rtc")
                return result
            result = subprocess.run(biosbattery_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=TIMEOUT_SUBPROCESS, check=True)
            logging.info(f"dmidecode output: {result}")
            # Check if the output contains information about the battery
            if result.returncode == 0 and 'okay' in result.stdout:
                logging.info("BIOS battery is present and serviceable.")
                return True
            else:
                logging.info("BIOS battery information not found.")
                return False

        except Exception as e:
            logging.error(f"Error in get_bios_battery_serviceable: {e}")
            error["hardwareInfo"]["get_bios_battery_serviceable"] = repr(e)
        return result

    @logger_function
    def get_harddrive_info():
        """
        Retrieves information about the hard drive.

        Returns:
            list: A list of dictionaries containing information about each filesystem entry.
            Each dictionary has the following keys:
                - Filesystem (str): The name of the filesystem.
                - Size (str): The total size of the filesystem.
                - Used (str): The amount of space used on the filesystem.
                - Avail (str): The amount of space available on the filesystem.
                - Use% (str): The percentage of space used on the filesystem.
                - Mounted (str): The mount point of the filesystem.

        Raises:
            Exception: If there is an error while retrieving the hard drive information.
        """

        def convert_to_gigabytes(size_str):
            size_mapping = {'K': 1024 * 1024, 'M': 1024, 'G': 1}
            logging.info(f"converting {size_str} to GB")
            try:
                if size_str == '0':
                    return '0'
                value = float(size_str[:-1])
                unit = size_str[-1].upper()

                if unit in size_mapping:
                    gigabytes = value / size_mapping[unit]
                    return str(gigabytes)
                else:
                    return ""
            except Exception as er:
                error["hardwareInfo"]["convert_to_gigabytes"] = repr(er)
                logging.error(f"Error occurred in convert_to_gigabytes: {repr(er)}")
                return ""

        try:
            # Run the 'df -h' command and capture its output
            logging.info("Calling extract_shell_info('df -h')")
            df_output = extract_shell_info('df -h')
            # logging.info(f"get_harddrive_info command output: {df_output}")
            # Split the output into lines and skip the header line
            df_lines = df_output.split('\n')[1:]

            # Initialize an empty list to store filesystem entries as dictionaries
            filesystems = []

            # Iterate over each line and parse it into a dictionary
            for line in df_lines:
                if line.strip():  # Skip empty lines
                    fields = line.split()
                    filesystem = {
                        "fileSystem": fields[0],
                        "size": convert_to_gigabytes(fields[1]),
                        "used": convert_to_gigabytes(fields[2]),
                        "available": convert_to_gigabytes(fields[3]),
                        "usedPercent": fields[4][0:-1],
                        "mounted": fields[5]
                    }
                    filesystems.append(filesystem)

            logging.info(f"filesystems: {filesystems}")
            # Return the list of filesystem entries as a dictionary
            return filesystems
        except Exception as err:
            error["hardwareInfo"]["get_harddrive_info"] = repr(err)
            logging.error(f"Error occurred while getting hard drive information: {repr(err)}")
            return []

    @logger_function
    def list_printer_names():
        """
        Retrieves a list of printer names.

        This function runs the 'lpstat -l' command to capture the output, splits it into lines,
        and extracts the first column of each line to obtain the printer names.

        Returns:
            A list of printer names.

        Raises:
            Exception: If an error occurs while executing the command.
        """
        printer_names = []
        try:
            # Run the 'lpstat -l' command and capture its output
            lpstat_output = subprocess.check_output(['lpstat', '-l'], stderr=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

            # Split the output into lines and extract the first column
            for line in lpstat_output.split('\n'):
                columns = line.strip().split()
                if columns:
                    printer_names.append(columns[0])
            logging.info(f"printer_names: {printer_names}")
            return printer_names

        except Exception as err:
            error["hardwareInfo"]["list_printer_names"] = repr(err)
            logging.error(f"Error occurred while listing printer names: {repr(err)}")
            return printer_names

    @logger_function
    def list_scanner_names():
        """
        Retrieve a list of scanner names.

        Returns:
            list: A list of scanner names.

        Raises:
            Exception: If there is an error while retrieving the scanner names.
        """
        scanner_list = []
        try:
            # Run the 'sane-find-scanner' command and capture its output
            # scanner_output = extract_shell_info(command_args='sane-find-scanner', var_name="scanners_names_list")
            # <TODO> scanner_output will be returned after testing of scanner's functionality.
            logging.info(f"list_scanner_names: {scanner_list}")
            return scanner_list
        except Exception as err:
            error["hardwareInfo"]["list_scanner_names"] = repr(err)
            logging.error(f"Error occurred while listing scanner names: {repr(err)}")
            return scanner_list

    @logger_function
    def get_bluetooth_info():
        """
        Retrieves Bluetooth information including the connected devices, status, and device serial numbers.

        Returns:
            dict: A dictionary containing the following keys:
                - 'connectedDevice' (list): A list of dictionaries representing the connected devices.
                    Each dictionary contains the 'name' and 'macAddress' of the device.
                - 'status' (str): The status of Bluetooth. It is initialized as 'Off' and will
                    be updated to 'On' if Bluetooth is turned on.
                - 'deviceSerial' (str): The device serial number.
                - 'pairedDevice' (list): List of all paired Bluetooth devices with their names and MAC addresses.
        """
        bluetooth_info = {
            'status': 'Off',
            'deviceSerial': "",
            'connectedDevice': [],
            'pairedDevice': [],
        }

        try:
            command_bluetooth_check = ["bluetoothctl", "show"]
            command_bluetooth_devices = ["bluetoothctl", "paired-devices"]
            command_bluetooth_devices_alt = ["bluetoothctl", "devices"]

            # Check Bluetooth availability
            logging.info(f"Executing bluetooth cmd: {command_bluetooth_check}")
            result_check = subprocess.run(
                command_bluetooth_check, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_SUBPROCESS
            )
            if result_check.returncode != 0 or 'No default controller available' in result_check.stdout:
                logging.error("No bluetooth controller found or command failed.")
                return bluetooth_info

            for line in result_check.stdout.splitlines():
                if "Controller" in line:
                    bluetooth_info['deviceSerial'] = line.split()[1].strip()
                    logging.info(f"Bluetooth serial: {bluetooth_info['deviceSerial']}")
                elif "Powered: yes" in line:
                    bluetooth_info['status'] = 'On'
                    logging.info(f"Bluetooth status: {bluetooth_info['status']}")

            # Get paired devices
            result_devices = subprocess.run(
                command_bluetooth_devices, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_SUBPROCESS
            )
            if result_devices.returncode != 0:
                result_devices = subprocess.run(
                    command_bluetooth_devices_alt, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_SUBPROCESS
                )

            paired_output = result_devices.stdout.strip().splitlines()
            paired_result = []
            for line in paired_output:
                parts = line.strip().split(' ', 2)
                if len(parts) >= 3:
                    mac_address = parts[1]
                    device_name = parts[2]
                    paired_result.append({
                        "name": device_name,
                        "macAddress": mac_address
                    })
            bluetooth_info["pairedDevice"] = paired_result
            logging.info(f"Paired devices: {paired_result}")

            # Get connected devices
            connected_devices = []
            for device in paired_result:
                mac = device.get('macAddress')
                check_connected_cmd = ["bluetoothctl", "info", mac]
                logging.info(f"Checking connection for {mac}")
                result_connected = subprocess.run(
                    check_connected_cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_SUBPROCESS
                )
                for line in result_connected.stdout.splitlines():
                    if "Connected: yes" in line:
                        logging.info(f"Device {mac} is connected")
                        connected_devices.append(device)
                        break
            bluetooth_info["connectedDevice"] = connected_devices
            logging.info(f"Connected devices: {connected_devices}")

        except Exception as err:
            logging.error(f"Error occurred while getting Bluetooth info: {repr(err)}")

        return bluetooth_info

    @logger_function
    def get_high_cpu_processes():
        """
        Retrieves a list of processes with high CPU usage.

        Returns: list: A list of dictionaries representing the high CPU processes. Each dictionary contains the
        following keys: - 'pid' (int): The process ID. - 'cpuPercent' (float): The CPU usage percentage of the
        process. - 'name' (str): The name of the process.

        Raises:
            Exception: If an error occurs while retrieving the high CPU processes.
        """
        cutoff_percent = 0.5
        logging.info(f"get_high_cpu_processes cutoff_percent: {cutoff_percent}")
        processes = []
        try:
            cpu_process_command = r"ps -e -o pid,%cpu,comm"
            cpu_process_result = subprocess.run(cpu_process_command, shell=True, universal_newlines=True,
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                timeout=TIMEOUT_SUBPROCESS)
            # logging.info(f"get_high_cpu_processes subprocess command [ps -e -o pid,%cpu,cmd] output: "
            #              f"{cpu_process_result}")

            lines = cpu_process_result.stdout.split('\n')[1:]  # Skip the header line
            # logging.info(f"lines: {lines}")
            for line in lines:
                parts = line.strip().split(None, 2)
                if len(parts) == 3:
                    pid, cpu_percent, name = parts
                    cpu_percent = float(cpu_percent)
                    if cpu_percent >= cutoff_percent:
                        processes.append({
                            'pid': int(pid),
                            'cpuPercent': cpu_percent,
                            'name': name
                        })

            # logging.info(f"get_high_cpu_processes processes: {processes}")
            return processes
        except Exception as err:
            error["hardwareInfo"]["get_high_cpu_processes"] = repr(err)
            logging.error(f"Error occurred while getting high CPU processes: {repr(err)}")

        return processes

    @logger_function
    def get_processes_with_memory_usage():
        """
        Retrieves a list of processes along with their memory usage percentage.

        Returns:
            A list of dictionaries, where each dictionary represents a process and contains the following keys:
                - 'pid' (int): The process ID.
                - 'memoryPercent' (float): The memory usage percentage of the process.
                - 'name' (str): The name of the process.

        Raises:
            Exception: If there is an error while retrieving the processes or calculating the memory usage.
        """

        cutoff_percent = 1
        logging.info(f"get_processes_with_memory_usage cutoff_percent: {cutoff_percent}")
        processes = []
        try:
            ram_process_command = r"ps -e -o pid,%mem,comm"
            ram_process_result = subprocess.run(ram_process_command, shell=True, universal_newlines=True,
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                timeout=TIMEOUT_SUBPROCESS)
            # logging.info(f"get_processes_with_memory_usage subprocess command [ps -e -o pid,%mem,comm] output: "
            #              f"{ram_process_result}")

            lines = ram_process_result.stdout.split('\n')[1:]  # Skip the header line
            # logging.info(f"lines: {lines}")
            for line in lines:
                parts = line.strip().split(None, 2)
                if len(parts) == 3:
                    pid, mem_percent, name = parts
                    mem_percent = float(mem_percent)
                    if mem_percent >= cutoff_percent:
                        processes.append({
                            'pid': int(pid),
                            'memoryPercent': mem_percent,
                            'name': name
                        })
            # logging.info(f"get_processes_with_memory_usage processes: {processes}")
            return processes
        except Exception as err:
            error["hardwareInfo"]["get_processes_with_memory_usage"] = repr(err)
            logging.error(f"Error occurred while getting processes with memory usage: {repr(err)}")

        return processes

    @logger_function
    def nic_info():
        """
        Retrieves information about network interfaces using the `lshw` command.

        Returns:
            list: A list of dictionaries containing information about each network interface.
        """
        # Run the lshw command and capture its output
        nic_details = {
            "nicCount": "",
            "nicInfo": []
        }

        def extract_ip_mac(data):
            interfaces_list = []

            try:
                ip_pattern = re.compile(r'inet (\d+\.\d+\.\d+\.\d+)')
                mac_pattern = re.compile(r'ether (\S+)')

                blocks = data.strip().split('\n\n')

                for block in blocks:
                    ip_match = ip_pattern.search(block)
                    mac_match = mac_pattern.search(block)

                    if ip_match and mac_match:
                        interface_info = {
                            "ip": ip_match.group(1),
                            "mac": mac_match.group(1)
                        }
                        interfaces_list.append(interface_info)
            except Exception as extract_ip_err:
                logging.error(f"error['hardwareInfo']['nic_info']['extract_ip_mac']: {extract_ip_err}")

            return interfaces_list

        try:
            network_info_list = []
            nic_cmd = r"lshw -class network | awk  '/\*-network|description:|product:|vendor:|serial:|physical id:/'"
            logging.info(f"nic_info nic_cmd: {nic_cmd}")
            nic_output = subprocess.run(nic_cmd, shell=True, stderr=subprocess.PIPE, universal_newlines=True,
                                        stdout=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).stdout

            ifconfig_cmd = r"ifconfig -a"
            logging.info(f"nic_info ifconfig_cmd: {ifconfig_cmd}")
            ifconfig_output = subprocess.run(ifconfig_cmd, shell=True, stderr=subprocess.PIPE, universal_newlines=True,
                                             stdout=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).stdout
            interfaces = extract_ip_mac(ifconfig_output)
            # logging.info(f"nic_info output: {nic_output}")
            # Split the output into individual device sections
            device_sections = re.split(r'\*-network', nic_output)[1:]
            logging.info(f"nic_info device_sections: {device_sections}")
            for section in device_sections:
                network_info = {}
                lines = section.strip().split('\n')

                for line in lines:
                    # Split each line into key and value
                    parts = line.strip().split(': ', 1)
                    if len(parts) == 2:
                        key, value = parts
                        if value and len(value.strip()) > 0:
                            if key == "physical id":
                                network_info["physicalId"] = value
                            elif key == "serial":
                                network_info["macAddress"] = value
                            else:
                                network_info[key] = value
                if len(network_info.keys()) == 5:
                    ip_of_card = ""
                    for interface in interfaces:
                        if interface["mac"] == network_info["macAddress"]:
                            ip_of_card = interface["ip"]
                            break
                    network_info["ipAddress"] = ip_of_card
                    network_info_list.append(network_info)
            logging.info(f"nic_info network_info_list: {network_info_list}")
            nic_details["nicInfo"] = network_info_list
            nic_details["nicCount"] = str(len(network_info_list))
        except Exception as err:
            error["hardwareInfo"]["nic_info"] = repr(err)
            logging.error(f"Error occurred while getting network info: {repr(err)}")

        return nic_details

    @logger_function
    def get_optical_drive_info():
        """
        Retrieves information about opticalDrive using the `lshw` command.

        Returns:
            list: A list of dictionaries containing information about optical Drive.
        """
        # Run the lshw command and capture its output
        od_details = {
            "drivePresent": False,
            "driveDetails": [],
        }

        try:
            od_info_list = []
            od_cmd = r"lshw -class disk | awk  '/\*-cdrom|description:|product:|vendor:|physical id:/'"
            logging.info(f"optical drive cmd: {od_cmd}")
            od_output = subprocess.run(od_cmd, shell=True, stderr=subprocess.PIPE, universal_newlines=True,
                                       stdout=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).stdout
            logging.info(f"optical drive output: {od_output}")
            # Split the output into individual device sections
            device_sections = re.split(r'\*-cdrom', od_output)[1:]
            logging.info(f"optical drive device_sections: {device_sections}")
            if len(device_sections) > 0:
                od_details["drivePresent"] = True
            else:
                return od_details
            for section in device_sections:
                network_info = {}
                lines = section.strip().split('\n')

                for line in lines:
                    # Split each line into key and value
                    parts = line.strip().split(': ', 1)
                    if len(parts) == 2:
                        key, value = parts
                        if key == "physical id":
                            network_info["physicalId"] = value
                            break
                        else:
                            network_info[key] = value
                if network_info.get("product") and "DVD+-" in network_info.get("product"):
                    od_info_list.append(network_info)
            logging.info(f"optical_drive info list: {od_info_list}")
            od_details["driveDetails"] = od_info_list

        except Exception as err:
            error["hardwareInfo"]["optical_drive_info"] = repr(err)
            logging.error(f"Error occurred while getting optical drive info: {repr(err)}")

        return od_details

    @logger_function
    def get_tpm_version():
        result = "NA"
        try:
            tpm_v_command = "sudo dmesg | grep tpm_tis"
            tpm_v_output = subprocess.check_output(tpm_v_command, shell=True, universal_newlines=True,
                                                   timeout=TIMEOUT_SUBPROCESS).strip()

            match = re.search(r"(\d+\.\d+)\s+TPM", tpm_v_output)
            if match:
                return match.group(1)
        except Exception as tpm_version_err:
            error["hardwareInfo"]["tmp_version"] = repr(tpm_version_err)
            logging.error(f"Error occurred while getting tmp version: {repr(tpm_version_err)}")
        return result

    # networkInfo functions --------------------------------------------------------------------

    @logger_function
    def check_firewall_status():
        """
        Check the status of the firewall.

        This function runs a command to check the status of the firewall on the system. It executes the
            command "systemctl list-units --type=service | grep firewall | awk '{print $1}'" using the subprocess module
            and captures the output. The output is then split into lines and stored in an array.
            If there are any output lines, the function returns "ON" along with the lines.
            Otherwise, it returns "OFF" and an empty array.

        Returns:
            - If the firewall is ON, returns a tuple with the value "ON" and an array of output lines.
            - If the firewall is OFF, returns a tuple with the value "OFF" and an empty array.
            - If there is an exception while running the command, returns a string with an error message.

        """
        firewall_status = "OFF"
        firewall_services = []
        try:
            list_of_services = ["firewalld", "ufw", "nftables", "iptables"]

            count_of_active_services = 0
            for service in list_of_services:
                try:
                    result = subprocess.run(["systemctl", "is-active", service],
                                            capture_output=True, text=True).stdout.strip()
                    result_present = subprocess.run(["systemctl", "status", service],
                                                    capture_output=True, text=True)
                    if result == "active":
                        count_of_active_services += 1
                    if result_present.stdout.strip() != "":
                        firewall_services.append(service)
                    logging.info(f"Service {service} is {result}")
                except Exception as service_exception:
                    logging.warning(f"Service exception occurred: {service_exception}")

            if count_of_active_services > 0:
                firewall_status = "ON"

        except Exception as err:
            error["networkInfo"]["check_firewall_status"] = repr(err)
            logging.error(f"Error occurred while checking firewall status: {repr(err)}")

        return firewall_status, firewall_services

    @logger_function
    def get_wifi_info():
        """
        Retrieves information about the wi-fi network connection.

        Returns:
            dict: A dictionary containing the following keys:
                - wifiConnectivityStatus (str): The status of the wi-fi connection.
                    It can be either "connected" or "disconnected".
                - ssid (str): The SSID (Service Set Identifier) of the wi-fi network, if connected.
                - wifiMacAddress (str): The MAC address of the wi-fi network, if connected.

        Raises:
            Exception: If an error occurs while retrieving the wi-fi information.

        """
        wifi_info_list = []
        try:
            # Get a list of network devices using ip a command
            cmd = r"""nmcli d | awk '$3=="connected" && $2=="wifi" && $4!="--" && NF>=4'|awk '{print $1}'"""
            logging.info(f"get_wifi_info_command: '{cmd}'")
            interface_list_output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                                   stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()
            logging.info(f'get_wifi_info_output: {interface_list_output}')

            if not interface_list_output:
                return wifi_info_list

            interface_list = interface_list_output.split('\n')
            for interface in interface_list:
                wifi_info = {'connectivityStatus': 'connected', 'interfaceName': interface,
                             'ssid': '', 'ipAddress': '', 'macAddress': '', 'authenticationType': ''}
                command = f"nmcli -t -f NAME,UUID,DEVICE connection show --active | grep '{interface}' | cut -d: -f1"
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_wifi_info_output: {output}")
                if output:
                    wifi_info['ssid'] = output
                else:
                    wifi_info['ssid'] = ""

                command = f"ip link show '{interface}' | awk '/ether/ {{print $2}}'"
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_wifi_info_output: {output}")
                if output:
                    wifi_info['macAddress'] = output
                else:
                    wifi_info['macAddress'] = ""

                command = (f"ip -4 addr show {interface} | "
                           r"grep -oP '(?<=inet\s)\d+(\.\d+){3}'")
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_wifi_info_output: {output}")
                if output:
                    wifi_info['ipAddress'] = output
                else:
                    wifi_info['ipAddress'] = ""

                command = (f"""nmcli dev wifi | awk '$1=="*" && $3=="{wifi_info['ssid']}"' | """
                           r"""awk '{ for(i=NF; i>0; i--) if($i ~ /WPA/) { printf "%s ", $i } }'""")
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_wifi_info_output: {output}")
                if output:
                    wifi_info['authenticationType'] = output
                else:
                    wifi_info['authenticationType'] = ""
                logging.info(f"get_wifi_info wifi_info: {wifi_info}")

                wifi_info_list.append(wifi_info)

        except Exception as err:
            error['networkInfo']['get_wifi_info'] = repr(err)
            logging.error(f"Error occurred while getting wifi info: {repr(err)}")

        return wifi_info_list

    @logger_function
    def is_ntp_server_enabled():
        ntp_result = {
            "isNtpEnabled": False,
            "ntpServer": "",
            "ntpSyncStatus": "",
            "ntpStratumLevel": ""
        }
        try:
            # Run the PowerShell command to query NTP peers
            ntp_subprocess_result = subprocess.run("systemctl status ntp | grep Active: | awk '{print $2}'",
                                                   shell=True, universal_newlines=True,
                                                   stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()

            logging.info(f"Subprocess output of ntp: {ntp_subprocess_result}")
            # Check if the output indicates that the service has not been started
            if ntp_subprocess_result == "active":
                logging.info("NTP server is configured.")
                ntp_result["isNtpEnabled"] = True

            npt_file_path = "/etc/ntp.conf"
            logging.info(f"reading ntp file path: {npt_file_path}")
            if os.path.exists(npt_file_path):
                ntp_server_result = subprocess.run("cat /etc/ntp.conf | grep ^pool", shell=True,
                                                   universal_newlines=True,
                                                   stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()

                logging.info(f"Subprocess output of ntp: {ntp_server_result}")
                # Check if the output indicates that the service has not been started
                ntp_line_list = ntp_server_result.split()
                ntp_result["ntpServer"] = ntp_line_list[1] if len(ntp_line_list) >= 3 else ""

            else:
                logging.info(f"{npt_file_path} not found.")
            ntp_stat_result = subprocess.run("ntpstat", shell=True, universal_newlines=True,
                                             stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                             timeout=20).stdout.strip()
            lines = ntp_stat_result.split("\n")
            for line in lines:
                if line.startswith("synchronised to NTP server"):
                    ntp_result["ntpSyncStatus"] = "synchronised"
                    stratum = re.search(r"stratum (\d+)", line).group(1)
                    ntp_result["ntpStratumLevel"] = stratum
                    break
        except Exception as ntp_error:
            logging.error(f"NTP server error: {ntp_error}")

        return ntp_result

    @logger_function
    def get_ethernet_info():
        """
        Retrieves information about the wi-fi network connection.

        Returns:
            dict: A dictionary containing the following keys:
                - ethernetConnectivityStatus (str): The status of the wi-fi connection.
                    It can be either "connected" or "disconnected".
                - ssid (str): The SSID (Service Set Identifier) of the wi-fi network, if connected.
                - ethernetMacAddress (str): The MAC address of the wi-fi network, if connected.

        Raises:
            Exception: If an error occurs while retrieving the wi-fi information.

        """
        ethernet_info_list = []
        try:
            # Get a list of network devices using ip a command
            cmd = r"""nmcli d | awk '$3=="connected" && $2=="ethernet" && $4!="--" && NF>=4'|awk '{print $1}'"""
            logging.info(f"get_ethernet_info_command: '{cmd}'")
            interface_list_output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                                   stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()
            logging.info(f'get_ethernet_info_output: {interface_list_output}')
            if not interface_list_output:
                return ethernet_info_list

            interface_list = interface_list_output.split('\n')
            for interface in interface_list:
                ethernet_info = {'connectivityStatus': 'connected', 'interfaceName': interface,
                                 'macAddress': '', 'ipAddress': ''}
                command = f"ip link show '{interface}' | awk '/ether/ {{print $2}}'"
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_ethernet_info_output: {output}")
                if output:
                    ethernet_info['macAddress'] = output
                else:
                    ethernet_info['macAddress'] = ""
                logging.info(f"get_ethernet_info ethernet_info: {ethernet_info}")

                command = (f"ip -4 addr show {interface} | "
                           r"grep -oP '(?<=inet\s)\d+(\.\d+){3}'")
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_ethernet_info_output: {output}")
                if output:
                    ethernet_info['ipAddress'] = output
                else:
                    ethernet_info['ipAddress'] = ""

                ethernet_info_list.append(ethernet_info)

        except Exception as err:
            error['networkInfo']['get_ethernet_info'] = repr(err)
            logging.error(f"Error occurred while getting ethernet info: {repr(err)}")

        return ethernet_info_list

    @logger_function
    def get_established_connections():
        """
        Retrieves a list of established TCP/UDP network connections with process details.

        Returns:
            A list of dictionaries, each representing an established connection.
            Each dictionary contains:
            - 'localAddress': The local IP address.
            - 'localPort': The local port number.
            - 'foreignAddress': The remote IP address.
            - 'foreignPort': The remote port number.
            - 'processName': Name of the associated process (if any).
            - 'pid': PID of the associated process (if any).
        """

        established_connections = []
        try:
            logging.info("get_established_connections_command: ss -tup | grep 'ESTAB'")
            ss_output = subprocess.check_output(
                "ss -tup | grep 'ESTAB'",
                shell=True,
                universal_newlines=True,
                timeout=TIMEOUT_SUBPROCESS
            )

            for line in ss_output.strip().splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue

                local_addr_port = parts[4]
                remote_addr_port = parts[5]
                users_field = ' '.join(parts[6:]) if len(parts) > 6 else ''

                local_match = re.match(r'(?:\[?([^\]]+)\]?):(\S+)', local_addr_port)
                remote_match = re.match(r'(?:\[?([^\]]+)\]?):(\S+)', remote_addr_port)

                if not local_match or not remote_match:
                    continue

                local_ip, local_port = local_match.group(1), local_match.group(2)
                remote_ip, remote_port = remote_match.group(1), remote_match.group(2)

                proc_name = pid = exe_path = ""

                proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+),fd=(\d+)', users_field)
                if proc_match:
                    proc_name = proc_match.group(1)
                    pid = proc_match.group(2)

                    try:
                        exe_path = os.readlink(f"/proc/{pid}/exe")
                    except Exception:
                        exe_path = ""

                established_connections.append({
                    'localAddress': local_ip,
                    'localPort': local_port,
                    'foreignAddress': remote_ip,
                    'foreignPort': remote_port,
                    'processName': proc_name,
                    'pid': pid,
                    'exePath': exe_path,
                })

        except Exception as err:
            logging.error(f"Error occurred while getting established connections: {repr(err)}")
        return established_connections

    @logger_function
    def get_tcp_info():
        """
        Retrieves the TCP ports that are currently in the LISTEN state on the local machine.

        Returns:
            list: A list of integers representing the TCP ports that are currently in the LISTEN state.

        Raises:
            Exception: If there is an error while retrieving the TCP ports.

        """
        try:
            command = r"ss -tln | awk '/^LISTEN/ {print $4}' | awk -F '[:\\[\\]]' '{print $NF}'"
            out = subprocess.check_output(command, shell=True, universal_newlines=True,
                                          timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
            # logging.info(f"get_tcp_info out: {out}")
            tcp_ports_set = set(out.strip().split('\n'))
            tcp_ports = list(tcp_ports_set)
            tcp_ports = [int(x) for x in tcp_ports]
            tcp_ports_result_list = sorted(tcp_ports)
            return tcp_ports_result_list
        except Exception as err:
            error["networkInfo"]["get_tcp_info"] = repr(err)
            logging.error(f"Error occurred while getting tcp info: {repr(err)}")
            return []

    @logger_function
    def get_dns_info():
        """
        Retrieves the DNS information of the system.

        Returns:
            - If successful, a list containing the DNS server information.
            - If unsuccessful, an empty list.

        Raises:
            - Exception: If an error occurs while retrieving the DNS information.

        """
        dns_info = []
        try:
            cmd_dns = "nmcli dev show | grep 'IP4.DNS' | awk '{print $2}'"
            logging.info(f"get_dns_info_command: '{cmd_dns}'")
            result = subprocess.check_output(cmd_dns, shell=True, universal_newlines=True, stderr=subprocess.PIPE,
                                             timeout=TIMEOUT_SUBPROCESS).split()
            logging.info(f"get_dns_info result: {result}")
            if result:
                dns_info = result
            else:
                dns_info = []
            logging.info(f"get_dns_info dns_info: {dns_info}")
        except Exception as err:
            error['networkInfo']['get_dns_info'] = repr(err)
            logging.error(f"Error occurred while getting dns info: {repr(err)}")

        return list(set(dns_info))

    @logger_function
    def get_nac_info(installed_programs):
        """
        Returns a dictionary containing the NAC information.
        """
        nac_software = ["no data"]
        # nac_services_mandatory = ["ser_1", "ser_2"]
        try:
            nac_keywords = [prog.split() for prog in nac_software]
            for ins_prog in installed_programs:
                for keywords in nac_keywords:
                    if all(key in ins_prog for key in keywords):
                        # nac_services = get_service_status(nac_services_mandatory)
                        # nac_details[" ALL NAC Services Running"] = nac_services
                        logging.info("NAC is installed")
                    else:
                        return False
                        # logging.info("NAC is not installed")
            logging.info("returning from nac installation function")

        except Exception as err:
            error["networkInfo"]["get_nac_info"] = repr(err)
            logging.error(f"Error occurred while retrieving NAC info: {repr(err)}")
            return False

        return True

    # osInfo functions --------------------------------------------------------------------

    @logger_function
    def get_user_profile_directory(current_loggedin_user):
        """
        Retrieves the user's profile directory.

        This function uses the `getent passwd` command to retrieve the information about all users on the system.
        It then searches for the entry corresponding to the current user by comparing the usernames.
        Once the entry is found, the function extracts the home directory (the 6th field) and returns it.

        Returns:
            str: The user's profile directory.

        Raises:
            Exception: If an error occurs while executing the `getent` or `whoami` commands.

        """
        try:
            # Run the `getent passwd` command and capture the output
            output = subprocess.check_output(['getent', 'passwd'], universal_newlines=True,
                                             timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
            # logging.info(f"get_user_profile_directory output: {output}")
            # Split the output into lines
            lines = output.strip().split('\n')

            # Find the entry for the current user (based on the username)
            logging.info(f"get_user_profile_directory current_user: {current_loggedin_user}")
            for line in lines:
                if line.startswith(current_loggedin_user + ':'):
                    # Split the line by colons and get the home directory (the 6th field)
                    parts = line.split(':')
                    if len(parts) >= 6:
                        return parts[5]
            logging.info(f"get_user_profile_directory result: {output}")
            return ""
        except Exception as err:
            error["osInfo"]["get_user_profile_directory"] = repr(err)
            logging.error(f"Error occurred while getting user profile directory: {repr(err)}")
            return ""

    @logger_function
    def get_list_of_startup_programs():
        """
        Retrieves a list of startup programs.

        Returns:
            list: A list of startup programs.
        """
        startup_programs = []
        try:
            # Check user-specific autostart directory
            user_autostart_dir = os.path.expanduser("~/.config/autostart")
            logging.info(f"user_autostart_dir: {user_autostart_dir}")
            if os.path.exists(user_autostart_dir):
                user_autostart_files = os.listdir(user_autostart_dir)
                user_startup_programs = [file[:-8] for file in user_autostart_files if file.endswith(".desktop")]
                startup_programs.extend(user_startup_programs)
                logging.info(f"user_startup_programs: {user_startup_programs}")
            # Check system-wide autostart directory
            system_autostart_dir = "/etc/xdg/autostart"
            if os.path.exists(system_autostart_dir):
                system_autostart_files = os.listdir(system_autostart_dir)
                system_startup_programs = [file[:-8] for file in system_autostart_files if file.endswith(".desktop")]
                startup_programs.extend(system_startup_programs)
                # logging.info(f"system_startup_programs: {system_startup_programs}")
        except Exception as err:
            error["osInfo"]["get_list_of_startup_programs"] = repr(err)
            logging.error(f"Error occurred while getting list of startup programs: {repr(err)}")

        return startup_programs

    @logger_function
    def get_boot_device_info():
        """
        Retrieves the device path of the boot device.

        Returns:
            str: The device path of the boot device, or None if it cannot be determined.

        Raises:
            Exception: If an error occurs while retrieving the device path.
        """
        try:
            # Use dmidecode to get information about the system
            bootdevice_command = r"df -h"
            logging.info(f"get_boot_device_command: '{bootdevice_command}'")
            bootdevice_output = subprocess.check_output(bootdevice_command, shell=True, universal_newlines=True,
                                                        timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
            # logging.info(f"get_boot_device_output: {bootdevice_output}")
            bootdevice_list = bootdevice_output.split("\n")
            for line in bootdevice_list:
                line_list = line.split()
                if line_list[-1] == "/":
                    return line_list[0]
            return ""

        except Exception as err:
            error["osInfo"]["get_boot_device_info"] = repr(err)
            logging.error(f"Error occurred while getting boot device: {repr(err)}")
            return ""

    @logger_function
    def list_shared_directories():
        """
        Retrieves a list of shared directories.

        Returns:
            - If the usershares directory does not exist, returns False.
            - If there are no shared directories found, returns False.
            - If shared directories are found, returns a list of directory names.
        """

        def check_permission(file_path):
            permission = {
                "owner": "",
                "group": "",
                "other": ""
            }
            try:
                if not os.path.exists(file_path):
                    return permission
                else:
                    out = subprocess.check_output(f'ls -ld "{file_path}"', shell=True,
                                                  timeout=TIMEOUT_SUBPROCESS, universal_newlines=True)
                    owner_perm = out[1:4]
                    group_perm = out[4:7]
                    other_perm = out[7:10]
                    logging.info(f"owner_perm: {owner_perm}, group_perm: {group_perm}, other_perm: {other_perm}")
                    list_user = [{"owner": owner_perm}, {"group": group_perm}, {"other": other_perm}]
                    for ind in range(len(list_user)):
                        # Check permission
                        user = list_user[ind]
                        key = list(user.keys())[0]
                        value = list(user.values())[0]

                        if "r" in value and "w" in value and "x" in value:
                            res_perm = "READ/WRITE/EXECUTE"
                        elif "r" in value and "w" in value:
                            res_perm = "READ/WRITE"
                        elif "r" in value and "x" in value:
                            res_perm = "READ/EXECUTE"
                        elif "r" in value:
                            res_perm = "READ"
                        elif "w" in value and "x" in value:
                            res_perm = "WRITE/EXECUTE"
                        elif "w" in value:
                            res_perm = "WRITE"
                        elif "x" in value:
                            res_perm = "EXECUTE"
                        else:
                            res_perm = "NONE"

                        permission[key] = res_perm

            except Exception as perm_err:
                logging.error(f"Error occurred while checking permission: {repr(perm_err)}")

            return permission

        result = []
        try:
            list_shared_command = r"""cat /etc/samba/smb.conf | grep -E "[[]*]|path =" | awk '{for (i=1; i<NF; i++)
            printf $i; print $NF}'"""
            logging.info(f"list_shared_directories_command: {list_shared_command}")
            if not os.path.exists("/etc/samba/smb.conf"):
                logging.warning(f"Error: File '/etc/samba/smb.conf' does not exist.")
                return []
            list_shared_output = subprocess.check_output(list_shared_command, shell=True, universal_newlines=True,
                                                         timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
            sections = re.split(r'\[([^]]+)]', list_shared_output)[1:]
            logging.info(f"list_shared_directories_sections: {sections}")
            parsed_output = []

            for i in range(0, len(sections), 2):
                section_name = sections[i]
                section_content = sections[i + 1]
                path_match = re.search(r'path\s*=/\s*([^\n;]+)', section_content)
                if path_match:
                    parsed_output.append(f'{section_name} /{path_match.group(1).strip()}')

            logging.info(f"list_shared_directories_parsed_output: {parsed_output}")
            for line in parsed_output:
                result.append({"name": line.split()[0], "path": line.split()[1]})
            for res in result:
                path = res["path"]
                res["permission"] = check_permission(path)

        except Exception as err:
            error["osInfo"]["list_shared_directories"] = repr(err)
            logging.error(f"Error occurred while listing shared directories: {repr(err)}")

        return result

    @logger_function
    def get_services_info():
        """
        Retrieves information about services using systemctl.

        Returns:
            A list of dictionaries containing the service information. Each dictionary has the following keys:
                - "DisplayName" (str): The display name of the service.
                - "Status" (str): The status of the service.
                - "Description" (str): The description of the service.

            If an exception is encountered during the retrieval process, an empty list is returned.
        """
        try:
            # Get service information using systemctl
            systemctl_command = ['systemctl', '--quiet', '--all', '--no-pager', '--type=service', 'list-units',
                                 '--full']
            result = subprocess.run(systemctl_command, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                    universal_newlines=True, check=True,
                                    timeout=TIMEOUT_SUBPROCESS)
            # logging.info(f"result of systemctl command: {result}")
            # Parse and format the systemctl output
            services_info = []
            lines = result.stdout.strip().split('\n')
            for line in lines:
                columns = line.split()
                if len(columns) >= 6:
                    if columns[0] == '\u25cf':
                        service_name = columns[1]
                        result = ' '.join(columns[5:])
                        service_info = {
                            "displayName": service_name,
                            "status": columns[3],
                            "description": result
                        }
                    else:
                        service_name = columns[0]
                        result = ' '.join(columns[4:])
                        service_info = {
                            "displayName": service_name,
                            "status": columns[2],
                            "description": result
                        }
                    services_info.append(service_info)
            # logging.info(f"services_info: {services_info}")
            return services_info

        except Exception as err:
            error["osInfo"]["get_services_info"] = repr(err)
            logging.error(f"Error occurred while getting services info: {repr(err)}")
            return []

    @logger_function
    def get_rdp_status(current_loggedin_user):
        """
        Retrieves the status of the RDP (Remote Desktop Protocol) and SSH (Secure Shell) services.

        Returns:
            dict: A dictionary containing the status of the RDP and SSH services.
        """
        rdp_stat = {
            'rdpEnabled': "",
            'sshActive': "",
        }
        logging.info(f"current loggedin user: {current_loggedin_user}")
        try:
            # Check if RDP is enabled
            rdp_output = subprocess.run(
                ["sudo", "-u", current_loggedin_user, "gsettings", "get", "org.gnome.desktop.remote-desktop.rdp",
                 "enable"],
                capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"rdp_output: {rdp_output}")
            # Check if the gsettings command was successful
            if rdp_output.returncode == 0:
                rdp_stat['rdpEnabled'] = rdp_output.stdout.strip().capitalize()
            else:
                rdp_stat['rdpEnabled'] = ""

            # Check if the SSH service is enabled and active
            ssh_output = subprocess.run(["systemctl", "is-active", "ssh"], capture_output=True, text=True,
                                        timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"ssh_output: {ssh_output}")

            ssh_output_result = ssh_output.stdout.strip()
            if ssh_output.returncode == 0 and ssh_output_result == "active":
                rdp_stat['sshActive'] = "True"
            else:
                rdp_stat['sshActive'] = "False"

            logging.info(f"rdp_stat: {rdp_stat}")

        except Exception as err:
            error["osInfo"]["get_rdp_status"] = repr(err)
            logging.error(f"Error occurred while getting RDP status: {repr(err)}")

        return rdp_stat

    @logger_function
    def get_audit_logs():
        """
        Retrieves the audit logs from the system.

        Returns:
            str: The audit logs if the auditd service is active, otherwise an empty string.

        Raises:
            Exception: If an error occurs while retrieving the audit logs.
        """
        try:
            audit_output = subprocess.run(["systemctl", "is-active", "auditd"], stderr=subprocess.PIPE,
                                          stdout=subprocess.PIPE,
                                          universal_newlines=True, timeout=TIMEOUT_SUBPROCESS).stdout.strip()
            logging.info(f"audit_output: {audit_output}")
            if audit_output == "active":
                return audit_output
            elif audit_output == "inactive":
                return audit_output
            return ""

        except Exception as err:
            error["osInfo"]["get_audit_logs"] = repr(err)
            logging.error(f"Error occurred while getting audit logs: {repr(err)}")
            return ""

    @logger_function
    def get_edr_installed(installed_programs):
        """
        Checks if an EDR (Endpoint Detection and Response) software is installed on the system.

        Returns:
            bool: True if an EDR is installed, False otherwise.
        """
        edr = ["Microsoft Defender"]
        try:
            edr_keywords = [prog.split() for prog in edr]
            for ins_prog in installed_programs:
                for keywords in edr_keywords:
                    if all(key in ins_prog for key in keywords):
                        logging.info("EDR is installed")
                        return True
            logging.info("EDR is not installed")
            return False
        except subprocess.CalledProcessError as e:
            error["osInfo"]["is_edr_installed"] = repr(e)
            logging.error("Error occurred while checking EDR installation")
            return False

    @logger_function
    def get_antivirus_info(installed_progs, app_patch_info):
        def is_installed(package_name):
            """Check if a package is installed on a Debian-based system."""
            try:
                return package_name in installed_progs
            except Exception as installed_err:
                logging.error(f"Not Installed:{installed_err}")
                return False

        def get_service_status(service_name):
            """Get the status of a specific service."""
            try:
                result = subprocess.run(["systemctl", "is-active", service_name], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_SUBPROCESS)
                return result.stdout.strip() if result.returncode == 0 else "not found"
            except Exception as service_stat_err:
                logging.error(f"Not found:{service_stat_err}")
                return "not found"

        def get_app_version(app_name):
            """Get the version of the antivirus application."""
            try:
                for app_patch in app_patch_info:
                    if app_name == app_patch["name"]:
                        return app_patch["version"]
            except Exception as app_version_err:
                logging.error(f"app version error:{app_version_err}")
            return "not found"

        antivirus_result = []

        antivirus_info = {
            "Bitdefender GravityZone": {"name": "bdservice", "services": ["bdservice", "bdshield"]},
            "Kaspersky Endpoint Security": {"name": "kesl", "services": ["kesl-supervisor", "kesl"]},
            "Sophos Intercept X Endpoint": {"name": "sav", "services": ["sav-protect", "sav-rms"]},
            "Avast Business Security": {"name": "avast", "services": ["avast"]},
            "ClamAV": {"name": "clamav", "services": ["clamav-daemon", "clamav-freshclam"]},
            "Lynis": {"name": "lynis", "services": []},
            "Chkrootkit": {"name": "chkrootkit", "services": []},
            "RootKit Hunter": {"name": "rkhunter", "services": []},
            "Linux Malware Detect": {"name": "lmd", "services": []},
            "Trend Micro": {"name": "tmcmd", "services": ["trendmicro"]},
            "F-Secure": {"name": "fsav", "services": ["f-secure"]}
        }

        try:
            for name, info in antivirus_info.items():
                installed_antivirus = {"name": name,
                                       "installed": False, "version": "", "services": []}

                if is_installed(info["name"]):
                    installed_antivirus["installed"] = True
                    installed_antivirus["version"] = get_app_version(info["name"])
                    for service in info["services"]:
                        service_status = get_service_status(service)
                        installed_antivirus["services"].append({service: service_status})

                antivirus_result.append(installed_antivirus)
        except Exception as get_antivirus_info_err:
            logging.error(f"Error: {get_antivirus_info_err}")

        return antivirus_result

    # pcIdentityInfo functions --------------------------------------------------------------------
    @logger_function
    def get_system_security_status(user_logged_in):
        """
        Get the status of the system security settings.

        The function checks the following security settings and returns a dictionary
        with the status of each setting:

        - WiFi: enabled/disabled
        - Bluetooth: enabled/disabled
        - USB: enabled/disabled
        - Firewall: enabled/disabled
        - RDP (gnome-remote-desktop): enabled/disabled
        - SSH: enabled/disabled

        If there is an error in the command execution, the function logs a warning
        with the error message and sets the status of the setting to "enabled".

        Returns:
            dict: A dictionary with the status of each security setting.
        """
        status = {
            "wifi": "enabled",
            "bluetooth": "enabled",
            "usb": "enabled",
            "firewall": "disabled",
            "rdp": "disabled",
            "ssh": "disabled"
        }

        # Check WiFi
        try:
            with open("/etc/modprobe.d/disable-wifi.conf", "r") as f:
                for line in f:
                    if "blacklist iwlwifi" in line and not line.strip().startswith("#"):
                        status["wifi"] = "disabled"
                        break
        except Exception as wifi_err:
            logging.warning(f"WiFi status check failed: {wifi_err}")

        # Check Bluetooth
        try:
            with open("/etc/modprobe.d/disable-bluetooth.conf", "r") as f:
                for line in f:
                    if "blacklist btusb" in line and not line.strip().startswith("#"):
                        status["bluetooth"] = "disabled"
                        break
        except Exception as bluetooth_err:
            logging.warning(f"Bluetooth status check failed: {bluetooth_err}")

        # Check USB
        try:
            with open("/etc/modprobe.d/disable-usb-storage.conf", "r") as f:
                for line in f:
                    if ("blacklist usb_storage" in line or "blacklist uas" in line) and not line.strip().startswith(
                            "#"):
                        status["usb"] = "disabled"
                        break
        except Exception as usb_err:
            logging.warning(f"USB status check failed: {usb_err}")

        # Check Firewall
        firewall_services = ["ufw", "firewalld", "nftables", "iptables"]
        try:
            for firewall in firewall_services:
                try:
                    result = subprocess.run(["systemctl", "is-active", f"{firewall}.service"], capture_output=True,
                                            text=True)
                    if result.returncode == 0 and result.stdout.strip() == "active":
                        status["firewall"] = "enabled"
                        break
                except Exception as firewall_in_err:
                    logging.warning(f"Firewall status check failed: {firewall_in_err}")
        except Exception as firewall_err:
            logging.warning(f"Firewall status check failed: {firewall_err}")

        # Check RDP (gnome-remote-desktop)
        try:
            rdp_output = subprocess.run(f"su - '{user_logged_in}' -c 'gsettings get org.gnome.desktop.remote-desktop.rdp enable'",
                                        capture_output=True, text=True, shell=True, timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"rdp_output: {rdp_output}")
            # Check if the gsettings command was successful
            if rdp_output.returncode == 0 and rdp_output.stdout.strip() == "true":
                status["rdp"] = "enabled"
        except Exception as rdp_err:
            logging.warning(f"RDP status check failed: {rdp_err}")

        # Check SSH
        try:
            result = subprocess.run(["systemctl", "is-active", "ssh"], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == "active":
                status["ssh"] = "enabled"
        except Exception as ssh_err:
            logging.warning(f"SSH status check failed: {ssh_err}")

        return status

    @logger_function
    def check_pc_in_org_domain():
        """
        Checks if the computer is connected to an organization's domain
        by comparing the computer name with the DNS search domain name.

        :return: The domain name if connected to an organization's domain, "False" otherwise.
        :rtype: str
        """
        try:
            # Get the computer name from /etc/hostname
            with open('/etc/hostname', 'r') as hostname_file:
                computer_name = hostname_file.read().strip()
                logging.info(f"computer_name: {computer_name}")

            # Get the DNS search domain name from /etc/resolv.conf
            domain_name = ""
            with open('/etc/resolv.conf', 'r') as resolv_conf_file:
                for line in resolv_conf_file:
                    if line.startswith('search'):
                        domain_name = line.strip().split(' ')[1]
                        break
                logging.info(f"domain_name: {domain_name}")

            # Check if the computer name matches the domain name or is empty
            if domain_name and computer_name == domain_name:
                logging.info(f"Connected to an organization's domain: {domain_name}")
                logging.info(f"returning True")
                return "True"  # Connected to an organization's domain
            else:
                logging.info(f"Not connected to an organization's domain: {domain_name}")
                logging.info(f"returning False")
                return "False"  # Not connected to an organization's domain
        except Exception as err:
            error["pcIdentityInfo"]["check_pc_in_org_domain"] = repr(err)
            logging.error(f"Error checking pc in org domain: {err}")
            return ""

    # usbInfo functions --------------------------------------------------------------------

    @logger_function
    def get_usb_details():
        """
        Retrieves information about USB devices.
        This function reads the contents of the '/proc/mounts' file and extracts information about USB devices.
        It returns a dictionary containing the USB device information, including vendor, serial number, and USB name.
        If any errors occur during the process, the function returns an empty string or raises an exception.

        Returns:
            dict: A dictionary containing the USB device information.
        """

        def read_sysfs_value(path):
            try:
                with open(path, "r") as f:
                    return f.read().strip()
            except Exception as e:
                logging.debug(f"Unable to read {path}: {e}")
                return ""

        def hex_to_dec(value):
            try:
                if value.startswith("0x"):
                    return str(int(value, 16))
                return value
            except Exception:
                return value

        def normalize_manfid(manfid_hex):
            """
            Convert 0x00001b -> 1b
            """
            if not manfid_hex:
                return None

            try:
                value = manfid_hex.lower().replace("0x", "")
                return value[-2:]   # last byte only
            except Exception:
                return None

        def resolve_sd_manufacturer(manfid_hex):
            manfid = normalize_manfid(manfid_hex)
            return SD_MANUFACTURERS.get(manfid, f"Unknown ({manfid})")

        SD_MANUFACTURERS = {
            "01": "Panasonic",
            "02": "Toshiba",
            "03": "SanDisk",
            "1b": "Samsung",
            "27": "Phison",
            "28": "Lexar",
            "9f": "Kingston"
        }
        usb_info_list = []
        try:
            lsusb_result = subprocess.run("lsusb", shell=True,
                                          text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                          timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"lsusb_result: {lsusb_result}")

            device_details_list = []
            if lsusb_result.returncode == 0:
                lsusb_result_list = lsusb_result.stdout.split('\n')
                pattern = r'Bus (\d+) Device (\d+):'
                for line in lsusb_result_list:

                    match = re.search(pattern, line)
                    if match:
                        bus_number = match.group(1)
                        device_number = match.group(2)
                        logging.info(f"Bus:{bus_number} Device: {device_number}")

                        dev_detail_cmd = f"udevadm info -q all -n /dev/bus/usb/{bus_number}/{device_number}"
                        dev_detail_result = subprocess.check_output(dev_detail_cmd, shell=True, universal_newlines=True,
                                                                    stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS)
                        if dev_detail_result:
                            device_details_list.append(dev_detail_result.strip())
            else:
                devices = glob.glob('/dev/sd*')
                filtered_devices = [device for device in devices if len(device) == 8]

                for device in filtered_devices:
                    dev_detail_cmd = f"udevadm info -q all -n {device}"
                    dev_detail_result = subprocess.check_output(dev_detail_cmd, shell=True, universal_newlines=True,
                                                                stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS)
                    if dev_detail_result:
                        device_details_list.append(dev_detail_result.strip())

            for detail in device_details_list:
                usb = {'usbName': "", 'usbManufacturer': "", 'usbSerialNumber': "", "usbProductId": "",
                       "usbVendorId": "", "interfaceType": ""}
                int_pattern = r'ID_USB_INTERFACES=(.*)'
                name_pattern = r'ID_MODEL=(.*)'
                man_pattern = r'ID_VENDOR=(.*)'
                ser_pattern = r'ID_SERIAL_SHORT=(.*)'
                prod_id_pattern = r'ID_MODEL_ID=(.*)'
                vend_id_pattern = r'ID_VENDOR_ID=(.*)'
                mtp_id_pattern = r'ID_GPHOTO2=(.*)'

                int_match = re.search(int_pattern, detail)
                mtp_id_match = re.search(mtp_id_pattern, detail)

                # Detect MTP/PTP directly via ID_GPHOTO2=1
                if mtp_id_match and mtp_id_match.group(1).strip() == "1":
                    usb["interfaceType"] = "MTP/PTP"

                if int_match:
                    id_usb_interfaces = int_match.group(1)
                    logging.info(f"id_usb_interfaces: {id_usb_interfaces}")
                    usb_match_reg = r':080[0-9]*:'
                    hdd_match_reg = r':080[0-9]*:080[0-9]*:'
                    mtp_match_reg = r':ffff[0-9]*:(.*):'
                    ptp_match_reg = r':060[0-9]*:(.*):'
                    phn_match_reg = r':060[0-9]*:'
                    dvd_match_reg = r':0802[0-9]*:'
                    adp_match_reg = r':ffff[0-9]*:'

                    usb_match = re.search(usb_match_reg, id_usb_interfaces)
                    hdd_match = re.search(hdd_match_reg, id_usb_interfaces)
                    mtp_match = re.search(mtp_match_reg, id_usb_interfaces)
                    ptp_match = re.search(ptp_match_reg, id_usb_interfaces)
                    dvd_match = re.search(dvd_match_reg, id_usb_interfaces)
                    phn_match = re.search(phn_match_reg, id_usb_interfaces)
                    adp_match = re.search(adp_match_reg, id_usb_interfaces)

                    if usb_match or hdd_match or mtp_match or ptp_match or dvd_match or phn_match or adp_match or mtp_id_match:
                        logging.info("Match found")
                        usb_name = re.search(name_pattern, detail)
                        usb_manufacturer = re.search(man_pattern, detail)
                        usb_serial_number = re.search(ser_pattern, detail)
                        usb_product_id = re.search(prod_id_pattern, detail)
                        usb_vendor_id = re.search(vend_id_pattern, detail)

                        if usb_name: usb["usbName"] = usb_name.group(1)
                        if usb_manufacturer: usb["usbManufacturer"] = usb_manufacturer.group(1)
                        if usb_serial_number: usb["usbSerialNumber"] = usb_serial_number.group(1)
                        if usb_product_id: usb["usbProductId"] = usb_product_id.group(1)
                        if usb_vendor_id: usb["usbVendorId"] = usb_vendor_id.group(1)

                        if not usb["interfaceType"]:
                            if dvd_match:
                                logging.info("DVD match found")
                                usb["interfaceType"] = "CD/DVD"
                            elif hdd_match:
                                logging.info("HDD match found")
                                usb["interfaceType"] = "HDD/SSD"
                            elif usb_match:
                                logging.info("USB match found")
                                usb["interfaceType"] = "USB"
                            elif mtp_match or ptp_match or phn_match:
                                logging.info("MTP/PTP match found")
                                usb["interfaceType"] = "MTP/PTP"
                            elif adp_match:
                                logging.info("ADAPTER match found")
                                usb["interfaceType"] = "ADAPTER"
                            else:
                                logging.info("No match found")
                                usb["interfaceType"] = "Unknown"

                        usb_info_list.append(usb)
                    else:
                        logging.info("No match found")

            # List directories matching mmc0:<digits> which is for SD cards.
            base_path = "/sys/class/mmc_host/mmc0"

            if not os.path.exists(base_path):
                logging.info(f"base_path does not exist: {base_path}")
                return usb_info_list

            for entry in os.listdir(base_path):
                full_path = os.path.join(base_path, entry)

                if not (entry.startswith("mmc0:") and os.path.isdir(full_path)):
                    continue

                sd_name = read_sysfs_value(os.path.join(full_path, "name"))
                sd_manfid = read_sysfs_value(os.path.join(full_path, "manfid"))
                sd_serial = read_sysfs_value(os.path.join(full_path, "serial"))
                sd_oemid = read_sysfs_value(os.path.join(full_path, "oemid"))

                usb = {}
                if sd_name:
                    usb["usbName"] = sd_name.strip()
                if sd_manfid:
                    usb["usbManufacturer"] = resolve_sd_manufacturer(sd_manfid)
                if sd_serial:
                    usb["usbSerialNumber"] = hex_to_dec(sd_serial)
                if sd_oemid:
                    usb["usbProductId"] = hex_to_dec(sd_oemid)
                if sd_manfid:
                    usb["usbVendorId"] = hex_to_dec(sd_manfid)
                usb["interfaceType"] = "SD-Card"

                if len(usb) > 1:
                    usb_info_list.append(usb)

        except Exception as err:
            error["usbInfo"]["usb_info_details"] = repr(err)
            logging.error(f"Error usb_info_details: {err}")

        return usb_info_list

    @logger_function
    def get_usb_stored_history():
        """
        Extracts USB device information from the system log files and stores it in a list.

        Returns:
            usb_history (list): A list of dictionaries containing USB device information.
            Each dictionary represents a USB device and contains the following keys:
                - 'usbName' (str): The product name of the USB device.
                - 'manufacturer' (str): The manufacturer of the USB device.
                - 'serialNumber' (str): The serial number of the USB device.
                - 'time' (str): The timestamp when the USB device was detected.
        """
        usb_history = []
        try:
            def convert_timestamp(input_timestamp):
                try:
                    if input_timestamp == "":
                        return ""
                    current_year = datetime.now().year

                    # Parse the input timestamp
                    timestamp = datetime.strptime(input_timestamp, "%b %d %H:%M:%S")

                    # Assign the current year to the timestamp
                    timestamp = timestamp.replace(year=current_year)

                    # Check if the timestamp is in the future
                    if timestamp > datetime.now():
                        # If in the future, reduce the year by 1
                        timestamp = timestamp.replace(year=current_year - 1)

                    # Format the timestamp as dd-mm-yyyy hh:mm:ss
                    formatted_timestamp = timestamp.strftime("%d-%m-%Y %H:%M:%S")

                    return str(formatted_timestamp)

                except Exception as time_con_err:
                    logging.error(f"Error usb_info_details: {time_con_err}")
                    return ""

            usb = {'usbName': "", 'usbManufacturer': "", 'usbSerialNumber': "", 'time': ""}
            command_base = (
                r'sudo cat {file_path} | grep -i usb | grep -Ev '
                r'"cyberauditor-linux-agent|CA Linux Agent|Output before encryption|'
                r'seal-linux-agent|SEAL Linux Agent|nishar-linux-agent|NISHAR Linux Agent|'
                r'decrypt_string Error:|decrypted cont:"'
            )

            log_dir = '/var/log'
            file_pattern = "syslog*"
            files_to_read = glob.glob(os.path.join(log_dir, file_pattern))

            if not files_to_read:
                error["usbInfo"]["usb_store_history"] = "Error: No 'messages' files found."
                return []

            for file_path in files_to_read:
                if not os.path.exists(file_path):
                    logging.warning(f"File '{file_path}' not found, skipping.")
                    continue

                if not os.access(file_path, os.R_OK):
                    logging.warning(f"File '{file_path}' is not readable, skipping.")
                    continue

                if file_path.endswith(".gz"):
                    logging.warning(f"File '{file_path}' is not readable, skipping.")
                    continue

                command_usb = command_base.format(file_path=file_path)
                logging.info(f"usb_store_history command: '{command_usb}'")

                try:
                    log_text = subprocess.check_output(command_usb, shell=True, universal_newlines=True,
                                                       stderr=subprocess.PIPE, timeout=90)
                    log_lines = log_text.strip().split('\n')

                    # Regex patterns
                    line_match_regex = r"usb \d+-\d+(\.\d)?:"
                    usb_device_regex = r"usb \d+-\d+(\.\d)?: Product: (.+)"
                    usb_manufacturer_regex = r"usb \d+-\d+(\.\d)?: Manufacturer: (.+)"
                    usb_serial_number_regex = r"usb \d+-\d+(\.\d)?: SerialNumber: (.+)"
                    time_regex = r"(?P<date>[A-Za-z]{3}\s+\d+)\s+\d+:\d+:\d+"
                    connected_pattern = r'usb \d+-\d+(\.\d)?: new (\S+) USB device number (\d+) using (\S+)'

                    # Initialize variables to store device details
                    last_usb_type = ""
                    for line in log_lines:
                        if not re.search(line_match_regex, line):
                            continue

                        if re.search(connected_pattern, line):
                            usb = {'usbName': "", 'usbManufacturer': "", 'usbSerialNumber': "", 'time': ""}
                            last_usb_type = re.search(connected_pattern, line).group(2)
                            continue

                        product_match = re.search(usb_device_regex, line)
                        if product_match:
                            usb['usbName'] = product_match.group(2) if "Adapter" not in product_match.group(2) else ""
                        manufacturer_match = re.search(usb_manufacturer_regex, line)
                        if manufacturer_match:
                            usb['usbManufacturer'] = manufacturer_match.group(2)
                        serial_number_match = re.search(usb_serial_number_regex, line)
                        if serial_number_match:
                            usb['usbSerialNumber'] = serial_number_match.group(2)

                        if usb["usbName"] and usb["usbManufacturer"] and usb["usbSerialNumber"] and (
                                last_usb_type == "high-speed" or last_usb_type == "SuperSpeed"):
                            time_value = re.search(time_regex, line)
                            usb['time'] = convert_timestamp(time_value.group() if time_value else "")
                            usb_history.append(usb)
                            usb = {'usbName': "", 'usbManufacturer': "", 'usbSerialNumber': "", 'time': ""}

                except subprocess.CalledProcessError as e:
                    logging.error(f"Error processing file '{file_path}': {e}")

        except Exception as err:
            error["usbInfo"]["usb_store_history"] = repr(err)
            logging.error(f"Error storing usb history: {err}")

        return usb_history

    # CIS SECTION functions --------------------------------------------------------------------

    # base function to check if a package is installed or not
    @logger_function
    def check_if_installed(package_name, calling_function):
        check_installed_result = "Not Configured"
        try:
            # Check if the package is installed (Ubuntu/Debian)
            check_installed_command = f"dpkg -s {package_name}"

            logging.info(f"check_installed_command: {check_installed_command}")
            result = subprocess.run(check_installed_command, shell=True,
                                    stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

            logging.info(f"check_installed_command_result for {package_name}: {result}")

            if "is not installed" in result.stderr or "not installed" in result.stdout:
                check_installed_result = "False"
            elif "Status: install ok installed" in result.stdout:
                check_installed_result = "True"
            else:
                check_installed_result = "False"

            logging.info(f"check_installed_result: {check_installed_result}")
        except Exception as err:
            logging.error(f"Error {calling_function}, checking if {package_name} is installed: {err}")

        return check_installed_result

    @logger_function
    def check_if_not_installed(package_name, calling_function="cis_special_purpose_services"):
        check_installed_result = "Not Configured"
        try:
            check_installed_command = f"dpkg -s {package_name}"

            logging.info(f"check_installed_command: {check_installed_command}")
            result = subprocess.run(check_installed_command, shell=True,
                                    stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

            logging.info(f"check_installed_command_result for {package_name}: {result}")

            if "is not installed" in result.stderr or "not installed" in result.stdout:
                check_installed_result = "True"
            elif "Status: install ok installed" in result.stdout:
                check_installed_result = "False"
            else:
                check_installed_result = "True"

            logging.info(f"check_installed_result: {check_installed_result}")

        except Exception as err:
            logging.error(f"Error {calling_function}, checking if {package_name} is not installed: {err}")

        return check_installed_result

    # base function to run script
    @logger_function
    def run_script(script, calling_func):
        logging.info(f"running script... for {calling_func}")
        script_result = "Not Configured"
        try:
            script_command_result = subprocess.check_output(["bash", "-c", script], universal_newlines=True,
                                                            stderr=subprocess.STDOUT,
                                                            timeout=TIMEOUT_SUBPROCESS).strip()
            # logging.info(f"script_result: {script_command_result}")
            if "PASS" in script_command_result:
                script_result = "True"
            elif "FAIL" in script_command_result:
                script_result = "False"
            else:
                script_result = "Not Configured"

            logging.info(f"script_run_result: {script_result}")
        except Exception as err:
            error["cisInfo"][calling_func]["run_script"] = repr(err)
            logging.error(f"Error running script: {err}")
        return script_result

    @logger_function
    def run_script_for_output(script, calling_func):
        logging.info(f"running script... for {calling_func}")
        script_result = "Not Configured"
        try:
            script_command_result = subprocess.check_output(["bash", "-c", script], universal_newlines=True,
                                                            stderr=subprocess.STDOUT,
                                                            timeout=TIMEOUT_SUBPROCESS).strip()

            logging.info(f"script_run_result: {script_result}")
            return script_command_result

        except Exception as err:
            error["cisInfo"][calling_func]["run_script"] = repr(err)
            logging.error(f"Error running script: {err}")
        return script_result

    # CIS Section 1.1.1
    @logger_function
    def cis_file_system_configuration():
        result = []

        def check_mount_system(mnt_name):
            try:
                cmd_modprobe = f"modprobe -n -v {mnt_name}"
                cmd_result = subprocess.run(
                    cmd_modprobe,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=TIMEOUT_SUBPROCESS
                )
                output = cmd_result.stdout.strip()
                logging.info(f"[{mnt_name}] modprobe output: {output}")

                lsmod_result = subprocess.run(
                    f"lsmod | grep -w {mnt_name}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=TIMEOUT_SUBPROCESS
                )
                loaded = bool(lsmod_result.stdout.strip())
                logging.info(f"[{mnt_name}] loaded: {loaded}")

                is_configured = "True" if ("install /bin/false" in output or "install /bin/true" in output) else "False"
                is_disabled = "True" if not loaded else "False"

                return is_configured, is_disabled

            except Exception as e:
                logging.error(f"Error checking {mnt_name}: {e}")
                return "Not Configured", "Not Configured"

        mount_list = ["cramfs", "squashfs", "udf", "fat", "vfat", "msdos"]

        for name in mount_list:
            is_configured, is_disabled = check_mount_system(name)
            result.append({
                "mountName": name,
                "isConfigured": is_configured,
                "isDisabled": is_disabled
            })

        return result

    # CIS Section 1.1.2 - 1.1.8
    @logger_function
    def cis_audit_partitions():
        """
        A function that performs an audit of specified partitions.

        Returns:
            dict: A dictionary containing the audit results for the specified partition.
            The dictionary has the following keys:
                - mountPoint (str): The mount point of the partition.
                - isMounted (bool): Indicates whether the partition is mounted or not.
                - mountOptions (dict): A dictionary containing the mount options for the partition.
                The keys are the mount option names (str) and the values are booleans
                indicating whether the option is set or not.

        """
        audit_partitions_result = []

        try:
            def audit_partition(mount_point):
                """
                Audit a mount point to check if it is mounted and verify the mount options.

                Parameters:
                    mount_point (str): The path of the mount point to be audited.

                Returns: dict: A dictionary containing information about the mount point. - mountPoint (str): The
                path of the mount point. - isMounted (bool): True if the mount point is mounted, False otherwise. -
                mountOptions (dict): A dictionary containing the mount options as keys and their status as values. -
                option (str): The mount option. - True if the option is set for the mount point. - False if the
                option is not set for the mount point.
                """
                # Audit: Check if /tmp is mounted
                audit_command = fr"findmnt --kernel {mount_point}"
                result = subprocess.run(audit_command, shell=True, capture_output=True, text=True,
                                        timeout=TIMEOUT_SUBPROCESS)
                command_output = {"mountPoint": mount_point, "isMounted": "False", "mountOptions": {}}

                if mount_point in result.stdout:
                    logging.info(f"{mount_point} is mounted.")
                    command_output = {"mountPoint": mount_point, "isMounted": "True", "mountOptions": {}}

                    def verify_mount_option(options_list):
                        # Verify that the specified options are set for the mount point
                        for option in options_list:
                            verify_command = f"findmnt --kernel {mount_point} | grep {option}"
                            command_result = subprocess.run(verify_command, shell=True, capture_output=True, text=True,
                                                            timeout=TIMEOUT_SUBPROCESS)

                            if command_result.stdout:
                                logging.info(f"{option} option is set for {mount_point}.")
                                command_output["mountOptions"][option] = "True"
                            else:
                                logging.info(f"{option} option is not set for {mount_point}.")
                                command_output["mountOptions"][option] = "False"

                    # Additional checks
                    if "/tmp" in mount_point:
                        verify_mount_option(["nodev", "noexec", "nosuid"])
                    elif "/var" in mount_point:
                        verify_mount_option(["nodev", "nosuid"])
                    elif "/var/tmp" in mount_point:
                        verify_mount_option(["nodev", "noexec", "nosuid"])
                    elif "/var/log" in mount_point:
                        verify_mount_option(["nodev", "noexec", "nosuid"])
                    elif "/var/log/audit" in mount_point:
                        verify_mount_option(["nodev", "noexec", "nosuid"])
                    elif "/home" in mount_point:
                        verify_mount_option(["nodev", "nosuid"])
                    elif "/dev/shm" in mount_point:
                        verify_mount_option(["nodev", "nosuid", "noexec"])
                    else:
                        logging.warning(f"No specific options defined for {mount_point}.")

                    return command_output
                else:
                    logging.info(f"{mount_point} is not mounted.")
                    return command_output

            audit_partitions_list = ["/tmp", "/var", "/var/tmp", "/var/log", "/var/log/audit", "/home", "/dev/shm"]
            # Results for each partition
            results = [audit_partition(partition) for partition in audit_partitions_list]
            audit_partitions_result = results
        except Exception as err:
            error["cisInfo"]["cis_audit_partitions"] = repr(err)
            logging.error(f"error['cisInfo']['cis_audit_partitions']: {err}")

        return audit_partitions_result

    # CIS Section 1.3
    @logger_function
    def cis_check_aide_installed():
        """
        Check if AIDE is installed and get the status of AIDE services and timers.

        This function checks if the AIDE package and AIDE common package are installed using the `dpkg-query` command.
        It also checks the status of the AIDE services and timers using the `systemctl` command.
        The function returns a dictionary `command_output` containing the following information:

        - `check-aide-installed`:
            - `is-aide-installed`: Indicates whether AIDE is installed or not.
                Possible values are `"True"` if installed and `"False"` if not installed.
            - `is-aide-common-installed`: Indicates whether AIDE common is installed or not.
                Possible values are `"True"` if installed and `"False"` if not installed.
        - `check-aide-services`:
            - `aidecheck-service-status`: The status of the AIDE service.
                Possible values are `"enabled"` if enabled and `"disabled"` if disabled.
            - `aidecheck-timer-status`: The status of the AIDE timer.
                Possible values are `"enabled"` if enabled and `"disabled"` if disabled.
            - `aidecheck-timer-running-status`: The running status of the AIDE timer.
                Possible values are `"Active"` if active, `"Inactive"` if inactive, and `"Error"`
                    if there was an error in the command execution.

        Returns:
            command_output (dict): A dictionary containing the status of AIDE installation and AIDE services.
        """
        command_output = {
            "checkAideInstalled": {
                "isAideInstalled": "Not Configured",
                "isAideCommonInstalled": "Not Configured",
            },
            "checkAideServices": {
                "aidecheckServiceEnabled": "Not Configured",
                "aidecheckTimerEnabled": "Not Configured",
                "aidecheckTimerRunning": "Not Configured"
            }
        }

        try:
            def check_package_installed(package_name):
                # Command to check package status
                command = (f"dpkg-query -W -f='${{binary:Package}}\\t${{Status}}\\t${{db:Status-Status}}\\n' "
                           f"{package_name}")
                try:
                    logging.info(f"Running command: {command}")
                    result = subprocess.run(command, shell=True, capture_output=True, text=True,
                                            timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {result}")

                    words = package_name.split('-')
                    capitalized_words = [word.capitalize() for word in words]
                    camel_case_string = ''.join(capitalized_words)
                    # Check for errors in stderr
                    if result.stderr:
                        logging.info(f"Error in command execution: {result.stderr}")
                        command_output["checkAideInstalled"][f"is{camel_case_string}Installed"] = "False"
                    else:
                        # Use regex to check if "install ok installed" is present in the Status column
                        match = re.search(r"install\sok\sinstalled", result.stdout)
                        if match:
                            command_output["checkAideInstalled"][f"is{camel_case_string}Installed"] = "True"
                        else:
                            command_output["checkAideInstalled"][f"is{camel_case_string}Installed"] = "False"
                except Exception as cis_err:
                    error["cisInfo"]["cis_check_aide_installed"]["check_package_installed"] = repr(cis_err)
                    logging.error(f"Error occured in check_package_installed: {cis_err}")

            package_names = ["aide", "aide-common"]
            for package in package_names:
                check_package_installed(package)

            def check_aide_services_status():
                try:
                    # Commands to check the status of AIDE services and timers
                    service_status_command = "systemctl is-enabled aidecheck.service"
                    timer_status_command = "systemctl is-enabled aidecheck.timer"
                    timer_output_command = "systemctl status aidecheck.timer"

                    # Check AIDE service status
                    result_service = subprocess.run(service_status_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    if result_service.returncode == 0:
                        command_output["checkAideServices"]["aidecheckServiceEnabled"] = result_service.stdout.strip()

                    # Check AIDE timer status
                    result_timer = subprocess.run(timer_status_command, shell=True, capture_output=True, text=True,
                                                  timeout=TIMEOUT_SUBPROCESS)
                    if result_timer.returncode == 0:
                        command_output["checkAideServices"]["aidecheckTimerEnabled"] = result_timer.stdout.strip()

                    # Check AIDE timer output
                    result_timer_output = subprocess.run(timer_output_command, shell=True, capture_output=True,
                                                         text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Timer output return code: {result_timer_output.returncode}")
                    logging.info(f"Timer output: {result_timer_output}")
                    if result_timer_output.returncode == 0:
                        command_output["checkAideServices"]["aidecheckTimerRunning"] = "True"
                    elif result_timer_output.returncode == 3:
                        command_output["checkAideServices"]["aidecheckTimerRunning"] = "False"
                    else:
                        command_output["checkAideServices"]["aidecheckTimerRunning"] = "Not Configured"
                        logging.info(f"Error in command execution: {result_timer_output.stderr}")

                    logging.info(f"Command output: {command_output}")
                except Exception as cis_err:
                    error["cisInfo"]["cis_check_aide_installed"]["check_aide_services_status"] = repr(cis_err)
                    logging.error(f"Error occured in check_aide_services_status: {cis_err}")

            logging.info(f"Calling check_aide_services_status()")
            check_aide_services_status()
            logging.info(f"check_aide_services_status() execution completed.")

        except Exception as err:
            logging.error(f"Error occured in cis_check_aide_installed: {err}")
        return command_output

    # CIS Section 1.4
    @logger_function
    def cis_secure_boot_settings():
        """
        Generates a dictionary containing the secure boot settings.

        Returns:
            result (dict): A dictionary containing the secure boot settings. The dictionary has the following keys:
                - "is-bootloader-user-set" (str): Indicates whether superusers are set in the bootloader configuration.
                    Possible values are "True" or "False".
                - "is-bootloader-pwd-set" (str): Indicates whether a password is set in the bootloader configuration.
                    Possible values are "True" or "False".
                - "permission-on-bootloader-config" (str): Indicates whether the bootloader configuration file
                    has the correct permissions. Possible values are "True" or "False".
                - "is-password-set-for-single-user-mode" (str): Indicates whether authentication is required for
                    single user mode. Possible values are "True" or "False".
        """

        result = {
            "isSecureBootEnabled": "Not Configured",
            "isBootloaderUserSet": "Not Configured",
            "isBootloaderPwdSet": "Not Configured",
            "isPermissionOnBootloaderConfigured": "Not Configured",
            "isPasswordSetForSingleUserMode": "Not Configured"
        }

        try:
            def is_secure_boot_enabled():
                try:
                    # --- 1. Try mokutil ---
                    try:
                        result = subprocess.run(
                            ["mokutil", "--sb-state"],
                            capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS
                        )
                        logging.info(f"mokutil output: {result.stdout.strip()}")
                        if "secureboot enabled" in result.stdout.lower():
                            return "True"
                        elif "secureboot disabled" in result.stdout.lower():
                            return "False"
                    except Exception as e:
                        logging.warning(f"mokutil failed: {e}")

                    # --- 2. Try dmesg ---
                    try:
                        result = subprocess.run(
                            "dmesg | grep 'secureboot:'", capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS
                        )
                        for line in result.stdout.splitlines():
                            logging.info(f"dmesg line: {line}")
                            if "enabled" in line.lower():
                                return "True"
                            elif "disabled" in line.lower():
                                return "False"
                    except Exception as e:
                        logging.warning(f"dmesg check failed: {e}")

                    # --- 3. Try bootctl ---
                    try:
                        result = subprocess.run(
                            ["bootctl", "status"],
                            capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS
                        )
                        logging.info(f"bootctl output: {result.stdout.strip()}")
                        for line in result.stdout.splitlines():
                            if "secure boot:" in line.lower():
                                if "enabled" in line.lower():
                                    return "True"
                                elif "disabled" in line.lower():
                                    return "False"
                    except Exception as e:
                        logging.warning(f"bootctl failed: {e}")

                    # If none worked
                    return "False"

                except Exception as cis_err:
                    logging.error(f"Error in is_secure_boot_enabled: {cis_err}")
                    return "False"

            def bootloader_pwd_is_set():
                try:
                    user_set = "False"
                    password_set = "False"

                    # Check if superusers are set in the bootloader configuration
                    check_user_command = "grep '^set superusers' /boot/grub/grub.cfg"
                    check_user_command_result = subprocess.run(check_user_command, shell=True, capture_output=True,
                                                               text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_user_command output: {check_user_command_result}")

                    if check_user_command_result.returncode == 0:
                        user_set = "True"

                    # Check if a password is set in the bootloader configuration
                    check_pwd_command = "grep '^password' /boot/grub/grub.cfg"
                    check_pwd_command_result = subprocess.run(check_pwd_command, shell=True, capture_output=True,
                                                              text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_pwd_command output: {check_pwd_command_result}")

                    if check_pwd_command_result.returncode == 0:
                        password_set = "True"

                    logging.info(f"User set: {user_set}, Password set: {password_set}")
                    return user_set, password_set
                except Exception as cis_err:
                    error["cisInfo"]["cis_secure_boot_settings"]["bootloader_pwd_is_set"] = repr(cis_err)
                    logging.error(f"Error occured in bootloader_pwd_is_set: {cis_err}")
                    return "Not Configured", "Not Configured"

            def permission_on_bootloader_config():
                try:
                    # Check permissions on the bootloader configuration file
                    stat_command = "stat /boot/grub/grub.cfg"
                    stat_command_result = subprocess.run(stat_command, shell=True, capture_output=True, text=True,
                                                         timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"stat_command_result.stdout: {stat_command_result.stdout}")

                    stat_command_to_extract_permissions = "stat --format=%a /boot/grub/grub.cfg"
                    stat_command_permissions_result = subprocess.run(stat_command_to_extract_permissions, shell=True,
                                                                     capture_output=True, text=True,
                                                                     timeout=TIMEOUT_SUBPROCESS)

                    logging.info(f"stat_command output: {stat_command_permissions_result}")
                    logging.info(f"stat_command_permissions_result.returncode: "
                                 f"{stat_command_permissions_result.returncode}")
                    logging.info(f"stat_command_permissions_result.stdout: {stat_command_permissions_result.stdout}")

                    # Extract the permission number
                    permission_number = stat_command_permissions_result.stdout.strip()
                    logging.info(f"Permission number: {permission_number}")
                    if permission_number:
                        permission_number = int(permission_number)

                        # Extract Uid and Gid using regex
                        uid_match = re.search(r'Uid: \(\s*(\d+)/\s*([\w-]+)\)', stat_command_result.stdout)
                        gid_match = re.search(r'Gid: \(\s*(\d+)/\s*([\w-]+)\)', stat_command_result.stdout)

                        # Check if Uid and Gid are both 0/root
                        uid_condition = uid_match and uid_match.group(1) == '0' and uid_match.group(2) == 'root'
                        gid_condition = gid_match and gid_match.group(1) == '0' and gid_match.group(2) == 'root'

                        logging.info(f"Uid condition: {uid_condition}")
                        logging.info(f"Gid condition: {gid_condition}")

                        # Check if Uid and Gid are both 0/root and Access is 0400 or more restrictive
                        if uid_condition and gid_condition and permission_number <= 400:
                            return "True"
                        return "False"
                    return "Not Configured"
                except Exception as cis_err:
                    error["cisInfo"]["cis_secure_boot_settings"]["permission_on_bootloader_config"] = repr(cis_err)
                    logging.error(f"Error in permission_on_bootloader_config: {cis_err}")
                    return "Not Configured"

            def authentication_required_for_single_user_mode():
                try:
                    # Check if authentication is required for single user mode
                    check_auth_command = \
                        r"grep -Eq '^root:\$' /etc/shadow && echo 'Password is set' || echo 'No password set'"

                    check_auth_command_result = subprocess.run(check_auth_command, shell=True, capture_output=True,
                                                               text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(
                        f"check_auth_command_result.stdout.strip(): {check_auth_command_result.stdout.strip()}")

                    if check_auth_command_result.stdout.strip() == "Password is set":
                        return "True"
                    else:
                        return "False"
                except Exception as cis_err:
                    error["cisInfo"]["cis_secure_boot_settings"]["authentication_required_for_single_user_mode"] = (
                        repr(cis_err))
                    logging.error(f"Error in authentication_required_for_single_user_mode: {cis_err}")
                    return "Not Configured"

            is_user_set, is_password_set = bootloader_pwd_is_set()
            result["isBootloaderUserSet"] = is_user_set
            result["isBootloaderPwdSet"] = is_password_set
            result["isSecureBootEnabled"] = is_secure_boot_enabled()
            # Check permissions on bootloader configuration file
            result["isPermissionOnBootloaderConfigured"] = permission_on_bootloader_config()

            # Ensure authentication required for single user mode
            result["isPasswordSetForSingleUserMode"] = authentication_required_for_single_user_mode()

            logging.info(f"Result of secure_boot_settings(): {result}")

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_secure_boot_settings']: {err}")
        return result

    # CIS Section 1.5
    @logger_function
    def cis_additional_process_hardening():
        """
        Retrieves information about additional process hardening.

        This function checks various system configurations and returns a dictionary with the following keys:
        - "is-aslr-enabled": Indicates whether Address Space Layout Randomization (ASLR) is enabled or not.
        - "is-prelink-installed": Indicates whether the prelink package is installed or not.
        - "is-apport-enabled": Indicates whether the apport service is enabled or not.
        - "is-apport-active": Indicates whether the apport service is active or not.
        - "is-coredump-service-installed": Indicates whether the coredump service is installed or not.

        Returns:
            dict: A dictionary containing the status of additional process hardening configurations.

        Example usage:
            result = cis_additional_process_hardening()
        """
        result = {
            "isAslrEnabled": "Not Configured",
            "isPrelinkInstalled": "Not Configured",
            "isApportEnabled": "Not Configured",
            "isApportActive": "Not Configured",
            "isCoreDumpRestricted": "Not Configured",
        }

        try:
            # Check if the additional process hardening is enabled
            def audit_aslr():
                script = r"""krp="" pafile="" fafile="" kpname="kernel.randomize_va_space" kpvalue="2"
                searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf
                /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf"

                krp="$(sysctl "$kpname" | awk -F= '{print $2}' | xargs)" pafile="$(grep -Psl --
                "^\h*$kpname\h*=\h*$kpvalue\b\h*(#.*)?$" $searchloc)" fafile="$(grep -s -- "^\s*$kpname" $searchloc |
                grep -Pv -- "\h*=\h*$kpvalue\b\h*" | awk -F: '{print $1}')" if [ "$krp" = "$kpvalue" ] && [ -n
                "$pafile" ] && [ -z "$fafile" ]; then echo -e "\\nPASS:\\n\\"$kpname\\" is set to \\"$kpvalue\\" in
                the running config and in \\"$pafile\\"" else echo -e "\\nFAIL: " [ "$krp" != "$kpvalue" ] && echo -e
                "\\"$kpname\\" is set to \\"$krp\\" in the running configuration\\n" [ -n "$fafile" ] && echo -e
                "\\n\\"$kpname\\" is set incorrectly in \\"$fafile\\"" [ -z "$pafile" ] && echo -e "\\n\\"$kpname =
                $kpvalue\\" is not set in kernel parameter config file\\n" fi"""
                try:
                    try:
                        audit_result = subprocess.check_output(["bash", "-c", script], text=True,
                                                               stderr=subprocess.STDOUT,
                                                               timeout=TIMEOUT_SUBPROCESS).strip()
                        logging.info(f"audit_result: {audit_result}")
                    except subprocess.CalledProcessError as cis_additional_process_hardening_error:
                        audit_result = cis_additional_process_hardening_error.output.strip()

                    if "PASS" in audit_result:
                        audit_aslr_result = "True"
                    elif "FAIL" in audit_result:
                        audit_aslr_result = "False"
                    else:
                        audit_aslr_result = "Not Configured"

                    logging.info(f"audit_aslr_result: {audit_aslr_result}")
                    return audit_aslr_result
                except Exception as cis_additional_process_hardening_error:
                    error["cisInfo"]["cis_additional_process_hardening"]["audit_aslr"] = (
                        repr(cis_additional_process_hardening_error))
                    logging.error("Error in audit_aslr: " + repr(cis_additional_process_hardening_error))
                    return "Not Configured"

            def check_prelink_status():
                try:
                    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' prelink"
                    logging.info("Checking if prelink is installed or not")
                    command_result = subprocess.run(command, shell=True, text=True, capture_output=True, check=False,
                                                    timeout=TIMEOUT_SUBPROCESS)

                    logging.info(f"command_result : {command_result}")

                    if command_result.returncode == 0:
                        prelink_result = command_result.stdout
                        logging.info(f"prelink_result: {prelink_result}")

                        if "not-installed" in prelink_result or "no packages found matching prelink" in prelink_result:
                            logging.info("Prelink is not installed")
                            return "False"
                        else:
                            logging.info("Prelink is installed")
                            return "True"
                    elif command_result.returncode == 1:
                        logging.info("Prelink is not installed")
                        return "False"
                    else:
                        logging.error(f"Error executing command. Return code: {command_result.returncode}")
                        return "Not Configured"
                except Exception as cis_additional_process_hardening_error:
                    error["cisInfo"]["cis_additional_process_hardening"]["check_prelink_status"] = (
                        repr(cis_additional_process_hardening_error))
                    logging.error("Error in check_prelink_status: " + repr(cis_additional_process_hardening_error))
                    return "Not Configured"

            def check_apport_enabled_and_active():
                try:
                    # Check if apport is enabled
                    check_apport_command = (r"dpkg-query -s apport > /dev/null 2>&1 && grep -Psi -- "
                                            r"'^\h*enabled\h*=\h*[^0]\b' /etc/default/apport")
                    logging.info(f"check_apport_enabled command: {check_apport_command}")

                    check_apport_command_result = subprocess.run(check_apport_command, shell=True, capture_output=True,
                                                                 text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(
                        f"check_auth_command_result.stdout.strip(): {check_apport_command_result.stdout.strip()}")

                    if check_apport_command_result.stdout.strip() == "enabled=1":
                        is_apport_enabled_result = "True"
                    else:
                        is_apport_enabled_result = "False"

                    # Check if apport is active
                    check_apport_active_command = "systemctl is-active apport.service | grep '^active'"
                    logging.info(f"check_apport_active command: {check_apport_active_command}")

                    check_apport_active_result = subprocess.run(check_apport_active_command, shell=True,
                                                                capture_output=True,
                                                                text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(
                        f"check_apport_active_result.stdout.strip(): {check_apport_active_result.stdout.strip()}")

                    if check_apport_active_result.stdout.strip() == "active":
                        logging.info(f"Apport is active")
                        is_apport_active_result = "True"
                    else:
                        logging.info(f"Apport is not active")
                        is_apport_active_result = "False"

                    return is_apport_enabled_result, is_apport_active_result
                except Exception as cis_additional_process_hardening_error:
                    error["cisInfo"]["cis_additional_process_hardening"]["check_apport_enabled_and_active"] = (
                        repr(cis_additional_process_hardening_error))
                    logging.error("Error in check_apport_enabled_and_active: " +
                                  repr(cis_additional_process_hardening_error))
                    return "Not Configured"

            def check_core_dump_service():
                try:
                    limits_cmd = "grep -Ps -- '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/*"
                    limits_proc = subprocess.run(
                        limits_cmd, shell=True, capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS
                    )
                    sysctl_cmd = "sysctl fs.suid_dumpable"
                    sysctl_proc = subprocess.run(
                        sysctl_cmd, shell=True, capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS
                    )

                    result_limits = "* hard core 0" in limits_proc.stdout.strip()
                    result_sysctl = "fs.suid_dumpable = 0" == sysctl_proc.stdout.strip()

                    if result_limits and result_sysctl:
                        return "True"
                    else:
                        return "False"

                except Exception as err:
                    logging.error(f"Error in check_core_dump_service: {repr(err)}")
                    return "Not Configured"

            result["isAslrEnabled"] = audit_aslr()
            result["isPrelinkInstalled"] = check_prelink_status()

            is_apport_enabled, is_apport_active = check_apport_enabled_and_active()
            result["isApportEnabled"] = is_apport_enabled
            result["isApportActive"] = is_apport_active
            result["isCoreDumpRestricted"] = check_core_dump_service()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_additional_process_hardening']: {err}")
        return result

    # CIS Section 1.7
    @logger_function
    def cis_selinux_config_info():
        result = {
            "isSeLinuxInstalled": "Not Configured",
            "isSeLinuxNotDisabledInBootloader": "Not Configured",
            "isSeLinuxPolicyConfigured": "Not Configured",
            "isSeLinuxModeEnforcingOrPermissive": "Not Configured",
            "isSeTroubleshootNotInstalled": "Not Configured",
            "isMCSTranslationServiceInstalled": "Not Configured",
            "isSeLinuxEnabledInGrub": "Not Configured",
            "isSeLinuxStateEnforcing": "Not Configured",
            "isPeriodicFileIntegrityImplemented": "Not Configured",
            "isSeLinuxUserExecstackDisabled": "Not Configured",
            "isSeLinuxUserExecheapDisabled": "Not Configured",
            "isSeLinuxUserExecmodEnabled": "Not Configured",
            "isRhnsdDisabled": "Not Configured",
            "isGpgCheckInMainYumEnabled": "Not Configured",
            "isGpgCheckForLocalPackagesEnabled": "Not Configured",
        }
        try:
            def check_selinux_installed():
                try:
                    output = check_if_installed("selinux-basics", "cis_selinux_config_info")
                    result["isSeLinuxInstalled"] = output
                except Exception as selinux_in_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_selinux_installed']: {selinux_in_err}")

            def check_selinux_disabled_in_bootloader():
                try:
                    output = (
                        extract_shell_info(
                            r'''grep "^\s*linux" /boot/grub2/grub.cfg | grep -E "(selinux=0|enforcing=0)"'''))
                    if output:
                        result["isSeLinuxNotDisabledInBootloader"] = "True"
                    else:
                        result["isSeLinuxNotDisabledInBootloader"] = "False"
                except Exception as selinux_bootloader_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_selinux_disabled_in_bootloader']: {selinux_bootloader_err}")

            def check_selinux_policy_configured():
                try:
                    output = extract_shell_info('grep SELINUXTYPE= /etc/selinux/config')
                    if output == "SELINUXTYPE=targeted":
                        result["isSeLinuxPolicyConfigured"] = "True"
                    else:
                        result["isSeLinuxPolicyConfigured"] = "False"
                except Exception as selinux_policy_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_selinux_policy_configured']: {selinux_policy_err}")

            def check_se_linux_mode_enforcing_or_permissive():
                try:
                    output = extract_info('getenforce')
                    if output == "Enforcing" or output == "Permissive":
                        result["isSeLinuxModeEnforcingOrPermissive"] = "True"
                    else:
                        result["isSeLinuxModeEnforcingOrPermissive"] = "False"
                except Exception as selinux_enforce_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_se_linux_mode_enforcing_or_permissive']: {selinux_enforce_err}")

            def check_se_troubleshoot_installed():
                try:
                    output = check_if_not_installed("setroubleshoot", "cis_selinux_config_info")
                    result["isSeTroubleshootNotInstalled"] = output
                except Exception as setrouble_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_se_troubleshoot_installed']: {setrouble_err}")

            def check_mcs_translation_service_installed():
                try:
                    output = check_if_not_installed("mcstrans", "cis_selinux_config_info")
                    result["isMCSTranslationServiceInstalled"] = output
                except Exception as mcs_error:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_mcs_translation_service_installed']: {mcs_error}")

            def check_selinux_in_grub():
                try:
                    output = extract_shell_info(
                        r'''grep "^\s*linux" /boot/grub2/grub.cfg | grep -E "(selinux=0|enforcing=0)"''')
                    if "selinux=0" not in output and "enforcing=0" not in output:
                        result["isSeLinuxEnabledInGrub"] = "True"
                    else:
                        result["isSeLinuxEnabledInGrub"] = "False"
                except Exception as grub_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']['check_selinux_in_grub']: {grub_err}")

            def check_selinux_state_enforcing():
                try:
                    output = extract_shell_info(r'''grep -E '^\s*SELINUX=enforcing' /etc/selinux/config''')
                    if "SELINUX=enforcing" in output:
                        result["isSeLinuxStateEnforcing"] = "True"
                    else:
                        result["isSeLinuxStateEnforcing"] = "False"
                except Exception as grub_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']['check_selinux_state_enforcing']: {grub_err}")

            def check_periodic_file_integrity():
                try:
                    # Command to check if AIDE (Advanced Intrusion Detection Environment) is scheduled in cron
                    check_command = "crontab -l | grep aide"
                    output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE,
                                            stdout=subprocess.PIPE, universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    if output.stdout:
                        result["isPeriodicFileIntegrityImplemented"] = "True"
                    else:
                        result["isPeriodicFileIntegrityImplemented"] = "False"

                except Exception as er:
                    logging.error(f"error['cisInfo']['is_periodic_file_integrity_implemented']: {er}")

            def check_selinux_user_execstack_disabled():
                try:
                    output = extract_info(r'''semanage boolean -l | grep selinuxuser_execstack''')
                    if "off" in output:
                        result["isSeLinuxUserExecstackDisabled"] = "True"
                    else:
                        result["isSeLinuxUserExecstackDisabled"] = "False"
                except Exception as execstack_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']"
                        f"['check_selinux_user_execstack_disabled']: {execstack_err}")

            def check_selinux_user_execheap_disabled():
                try:
                    output = extract_info(r'''semanage boolean -l | grep selinuxuser_execheap''')
                    if "off" in output:
                        result["isSeLinuxUserExecheapDisabled"] = "True"
                    else:
                        result["isSeLinuxUserExecheapDisabled"] = "False"
                except Exception as execheap_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']"
                        f"['check_selinux_user_execheap_disabled']: {execheap_err}")

            def check_selinux_user_execmod_enabled():
                try:
                    output = extract_info(r'''semanage boolean -l | grep selinuxuser_execmod''')
                    if "off" not in output:
                        result["isSeLinuxUserExecmodEnabled"] = "True"
                    else:
                        result["isSeLinuxUserExecmodEnabled"] = "False"
                except Exception as execmod_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']"
                        f"['check_selinux_user_execmod_enabled']: {execmod_err}")

            def check_rhnsd_disabled():
                try:
                    output = extract_info(r'''systemctl is-enabled rhnsd''')
                    if "disabled" in output:
                        result["isRhnsdDisabled"] = "True"
                    else:
                        result["isRhnsdDisabled"] = "False"
                except Exception as rhsnd_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']['check_rhnsd_disabled']: {rhsnd_err}")

            def check_gpg_in_main_yum_enabled():
                try:
                    output = extract_shell_info(r'''grep -E '^gpgcheck' /etc/yum.conf''')
                    if "gpgcheck=1" in output:
                        result["isGpgCheckInMainYumEnabled"] = "True"
                    else:
                        result["isGpgCheckInMainYumEnabled"] = "False"
                except Exception as gpg_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']['check_gpg_in_main_yum_enabled']: {gpg_err}")

            def check_gpg_for_local_packages_enabled():
                try:
                    output = extract_shell_info(r'''grep -E '^\s*gpgcheck' /etc/yum.repos.d/*.repo''')
                    if output and "gpgcheck=1" in output:
                        result["isGpgCheckForLocalPackagesEnabled"] = "True"
                    else:
                        result["isGpgCheckForLocalPackagesEnabled"] = "False"
                except Exception as gpg_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']"
                        f"['check_gpg_for_local_packages_enabled']: {gpg_err}")

            check_selinux_installed()
            check_selinux_disabled_in_bootloader()
            check_selinux_policy_configured()
            check_se_linux_mode_enforcing_or_permissive()
            check_se_troubleshoot_installed()
            check_mcs_translation_service_installed()
            check_selinux_in_grub()
            check_selinux_state_enforcing()
            check_periodic_file_integrity()
            check_selinux_user_execstack_disabled()
            check_selinux_user_execheap_disabled()
            check_selinux_user_execmod_enabled()
            check_rhnsd_disabled()
            check_gpg_in_main_yum_enabled()
            check_gpg_for_local_packages_enabled()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_selinux_config_info']: {err}")

        return result

    # CIS Section 2.2
    @logger_function
    def cis_special_purpose_services():
        """
        Generate the dictionary `result` containing the status of various installed services.

        Returns:
            result (dict): A dictionary containing the status of various installed services.
                Each key represents a service name and the corresponding value represents
                whether the service is installed or not. The status can be one of the following:
                    - "True" if the service is installed
                    - "False" if the service is not installed
                    - "Not Configured" if the status is not determined
        """
        result = {
            "isXWindowsNotInstalled": "Not Configured",
            "isAvahiDaemonNotInstalled": "Not Configured",
            "isCupsNotInstalled": "Not Configured",
            "isDhcpServerNotInstalled": "Not Configured",
            "isSlapdNotInstalled": "Not Configured",
            "isNfsKernelServerNotInstalled": "Not Configured",
            "isBind9NotInstalled": "Not Configured",
            "isVsftpdNotInstalled": "Not Configured",
            "isApache2NotInstalled": "Not Configured",
            "isDovecotImapdNotInstalled": "Not Configured",
            "isDovecotPop3dNotInstalled": "Not Configured",
            "isSambaNotInstalled": "Not Configured",
            "isSquidNotInstalled": "Not Configured",
            "isSnmpNotInstalled": "Not Configured",
            "isNisNotInstalled": "Not Configured",
            "isRsyncNotInstalled": "Not Configured",
            "isMtaNotListening": "Not Configured",
        }

        try:
            def check_if_mta_configured():
                try:
                    # Check if mta is configured or not
                    check_mta_configured_command = r"ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'"

                    logging.info(f"check_installed_command: {check_mta_configured_command}")
                    check_mta_configured_command_result = subprocess.run(check_mta_configured_command, shell=True,
                                                                         capture_output=True, text=True,
                                                                         timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_configured_command_result: {check_mta_configured_command_result}")

                    if check_mta_configured_command_result.returncode == 0:
                        mta_configured_result = "True"
                    elif check_mta_configured_command_result.returncode == 1:
                        mta_configured_result = "False"
                    else:
                        mta_configured_result = "Not Configured"

                    logging.info(f"coredump_service_result: {mta_configured_result}")
                    return mta_configured_result
                except Exception as cis_special_purpose_services_error:
                    error["cisInfo"]["cis_special_purpose_services"]["check_if_mta_configured"] = (
                        repr(cis_special_purpose_services_error))
                    logging.error("Error in check_if_mta_configured: " + repr(cis_special_purpose_services_error))
                    return "Not Configured"

            result["isXWindowsNotInstalled"] = check_if_not_installed("xserver-common")
            result["isAvahiDaemonNotInstalled"] = check_if_not_installed("avahi-daemon")
            result["isCupsNotInstalled"] = check_if_not_installed("cups")
            result["isDhcpServerNotInstalled"] = check_if_not_installed("isc-dhcp-server")
            result["isSlapdNotInstalled"] = check_if_not_installed("slapd")
            result["isNfsKernelServerNotInstalled"] = check_if_not_installed("nfs-kernel-server")
            result["isBind9NotInstalled"] = check_if_not_installed("bind9")
            result["isVsftpdNotInstalled"] = check_if_not_installed("vsftpd")
            result["isApache2NotInstalled"] = check_if_not_installed("apache2")
            result["isDovecotImapdNotInstalled"] = check_if_not_installed("dovecot-imapd")
            result["isDovecotPop3dNotInstalled"] = check_if_not_installed("dovecot-pop3d")
            result["isSambaNotInstalled"] = check_if_not_installed("samba")
            result["isSquidNotInstalled"] = check_if_not_installed("squid")
            result["isSnmpNotInstalled"] = check_if_not_installed("snmp")
            result["isNisNotInstalled"] = check_if_not_installed("nis")
            result["isRsyncNotInstalled"] = check_if_not_installed("rsync")
            result["isMtaNotListening"] = check_if_mta_configured()
            result["isMailTransferLocalOnly"] = check_if_mta_configured()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_special_purpose_services']: {err}")
        return result

    # CIS Section 2.3
    @logger_function
    def cis_service_clients():
        """
        Generates the CIS service client's dictionary.

        Returns:
            dict: A dictionary containing the status of various CIS service clients.
                The keys are the names of the services, and the values are their installation status.
                The installation status can be one of the following:
                    - "True" if the service is installed
                    - "False" if the service is not installed
                    - "Not Configured" if the service's installation status is not determined
        """
        result = {
            "isNisInstalled": "Not Configured",
            "isRshInstalled": "Not Configured",
            "isTalkInstalled": "Not Configured",
            "isTelnetInstalled": "Not Configured",
            "isLdapNotInstalled": "Not Configured",
            "isRpcbindNotInstalled": "Not Configured"
        }

        try:
            def check_installed_or_not(service_name):
                try:
                    # Check if the service is installed
                    check_installed_command = (r"dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n'"
                                               fr" {service_name} | grep -Pi '\h+installed\b'")

                    logging.info(f"check_installed_command: {check_installed_command}")
                    check_installed_command_result = subprocess.run(check_installed_command, shell=True,
                                                                    capture_output=True, text=True,
                                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_installed_command_result for {service_name}: {check_installed_command_result}")

                    if check_installed_command_result.returncode == 0:
                        check_installed_result = "True"
                    elif check_installed_command_result.returncode == 1:
                        check_installed_result = "False"
                    else:
                        check_installed_result = "Not Configured"

                    logging.info(f"check_installed_result: {check_installed_result}")
                    return check_installed_result
                except Exception as cis_service_clients_error:
                    error["cisInfo"]["cis_service_clients"]["check_installed_or_not"] = (
                        repr(cis_service_clients_error))
                    logging.error(
                        f"error['cisInfo']['cis_service_clients']['check_installed_or_not']: "
                        f"{cis_service_clients_error}"
                    )
                    return "Not Configured"

            result["isNisInstalled"] = check_installed_or_not("nis")
            result["isRshInstalled"] = check_installed_or_not("rsh-client")
            result["isTalkInstalled"] = check_installed_or_not("talk")
            result["isTelnetInstalled"] = check_installed_or_not("telnet")
            result["isLdapNotInstalled"] = check_installed_or_not("ldap-utils")
            result["isRpcbindNotInstalled"] = check_installed_or_not("rpcbind")

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_service_clients']: {err}")
        return result

    # CIS Section - 3.2
    @logger_function
    def cis_network_configuration():
        result = {
            "isIpForwardingDisabled": "Not Configured",
            "isSendPcketRedirectsDisabled": "Not Configured",
            "isAcceptSourceRouteDisabled": "Not Configured",
            "isIcmpAcceptRedirectsDisabled": "Not Configured",
            "isSecureIcmpRedirectsDisabled": "Not Configured",
            "isLogSuspiciousPacketsEnabled": "Not Configured",
            "isBroadcastIcmpRequestIgnored": "Not Configured",
            "isBogusIcmpResponsesIgnored": "Not Configured",
            "isTcpSynCookiesEnabled": "Not Configured",
            "isIpv6RouterAdvertisementsDisabled": "Not Configured",
            "isIpv6Disabled": "Not Configured",
            "isDccpDisabled": "Not Configured",
            "isSctpDisabled": "Not Configured",
            "isReversePathFilteringEnabled": "Not Configured",
            "isRdsDisabled": "Not Configured",
            "isTipcDisabled": "Not Configured",
            "isWirelessInterfaceDeactivated": "Not Configured",
            "isSystemWideCryptoPolicyFIPS": "Not Configured",
            "isSshToUseSystemCryptoPolicy": "Not Configured",
        }

        def check_ip_forwarding_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.ip_forward")
                output_2 = extract_shell_info(
                    r'grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf '
                    r'/usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')

                output_3 = extract_info('sysctl net.ipv6.conf.all.forwarding')
                output_4 = extract_shell_info(
                    r'grep -E -s "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf '
                    r'/usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')

                if (output_1 == "net.ipv4.ip_forward = 0" or not output_2) \
                        and (output_3 == "net.ipv6.conf.all.forwarding = 0" or not output_4):
                    result["isIpForwardingDisabled"] = "True"
                else:
                    result["isIpForwardingDisabled"] = "False"
            except Exception as ip_forward_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']"
                              f"['check_ip_forwarding_disabled']: {ip_forward_err}")

        def check_send_packet_redirects_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.send_redirects")
                output_2 = extract_info("sysctl net.ipv4.conf.default.send_redirects")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.send_redirects = 0" \
                    or output_3 == "net.ipv4.conf.all.send_redirects = 0") \
                        and (output_2 == "net.ipv4.conf.default.send_redirects = 0" \
                            or output_4 == "net.ipv4.conf.default.send_redirects = 0"):
                    result["isSendPcketRedirectsDisabled"] = "True"
                else:
                    result["isSendPcketRedirectsDisabled"] = "False"
            except Exception as send_packet_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_send_packet_redirects_disabled']: {send_packet_err}")

        def check_accept_source_route_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.accept_source_route")
                output_2 = extract_info("sysctl net.ipv4.conf.default.accept_source_route")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.accept_source_route = 0" \
                    or output_3 == "net.ipv4.conf.all.accept_source_route = 0") \
                    and (output_2 == "net.ipv4.conf.default.accept_source_route = 0" \
                         or output_4 == "net.ipv4.conf.default.accept_source_route = 0"):
                    result["isAcceptSourceRouteDisabled"] = "True"
                else:
                    result["isAcceptSourceRouteDisabled"] = "False"
            except Exception as accept_source_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_accept_source_route_disabled']: {accept_source_err}")

        def check_icmp_accept_redirects_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.accept_redirects")
                output_2 = extract_info("sysctl net.ipv4.conf.default.accept_redirects")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')

                output_5 = extract_info("sysctl net.ipv6.conf.all.accept_redirects")
                output_6 = extract_info("sysctl net.ipv6.conf.default.accept_redirects")

                output_7 = extract_shell_info(
                    r'grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                output_8 = extract_shell_info(
                    r'grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.accept_redirects = 0" \
                    or output_3 == "net.ipv4.conf.all.accept_redirects = 0") \
                    and (output_2 == "net.ipv4.conf.default.accept_redirects = 0" \
                         or output_4 == "net.ipv4.conf.default.accept_redirects = 0") \
                    and (output_5 == "net.ipv6.conf.all.accept_redirects = 0" \
                         or output_7 == "net.ipv6.conf.all.accept_redirects = 0") \
                    and (output_6 == "net.ipv6.conf.default.accept_redirects = 0" \
                         or output_8 == "net.ipv6.conf.default.accept_redirects = 0"):
                    result["isIcmpAcceptRedirectsDisabled"] = "True"
                else:
                    result["isIcmpAcceptRedirectsDisabled"] = "False"
            except Exception as icmp_redirect_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_icmp_accept_redirects_disabled']: {icmp_redirect_err}")

        def check_secure_icmp_redirects_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.secure_redirects")
                output_2 = extract_info("sysctl net.ipv4.conf.default.secure_redirects")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.secure_redirects = 0" \
                    or output_3 == "net.ipv4.conf.all.secure_redirects= 0") \
                        and (output_2 == "net.ipv4.conf.default.secure_redirects = 0" \
                             or output_4 == "net.ipv4.conf.default.secure_redirects= 0"):
                    result["isSecureIcmpRedirectsDisabled"] = "True"
                else:
                    result["isSecureIcmpRedirectsDisabled"] = "False"
            except Exception as secure_icmp_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_secure_icmp_redirects_disabled']: {secure_icmp_err}")

        def check_log_suspicious_packets_enabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.log_martians")
                output_2 = extract_info("sysctl net.ipv4.conf.default.log_martians")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.log_martians = 1" \
                    or output_3 == "net.ipv4.conf.all.log_martians = 1") \
                    and (output_2 == "net.ipv4.conf.default.log_martians = 1" \
                         or output_4 == "net.ipv4.conf.default.log_martians = 1"):
                    result["isLogSuspiciousPacketsEnabled"] = "True"
                else:
                    result["isLogSuspiciousPacketsEnabled"] = "False"
            except Exception as suspicious_log_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_log_suspicious_packets_enabled']: {suspicious_log_err}")

        def check_broadcast_icmp_ignored():
            try:
                output_1 = extract_info("sysctl net.ipv4.icmp_echo_ignore_broadcasts")

                output_2 = extract_shell_info(
                    r'grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.icmp_echo_ignore_broadcasts = 1" or
                        output_2 == "net.ipv4.icmp_echo_ignore_broadcasts = 1"):
                    result["isBroadcastIcmpRequestIgnored"] = "True"
                else:
                    result["isBroadcastIcmpRequestIgnored"] = "False"
            except Exception as broadcast_icmp_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']"
                              f"['check_broadcast_icmp_ignored']: {broadcast_icmp_err}")

        def check_bogus_icmp_ignored():
            try:
                output_1 = extract_info("sysctl net.ipv4.icmp_ignore_bogus_error_responses")

                output_2 = extract_shell_info(
                    'grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.icmp_ignore_bogus_error_responses = 1"
                        or output_2 == "net.ipv4.icmp_ignore_bogus_error_responses = 1"):
                    result["isBogusIcmpResponsesIgnored"] = "True"
                else:
                    result["isBogusIcmpResponsesIgnored"] = "False"
            except Exception as bogus_icmp_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']"
                              f"['check_bogus_icmp_ignored']: {bogus_icmp_err}")

        def check_tcp_syn_cookies_enabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.tcp_syncookies")

                output_2 = extract_shell_info(r'grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*')

                if output_1 == "net.ipv4.tcp_syncookies = 1" or output_2 == "net.ipv4.tcp_syncookies = 1":
                    result["isTcpSynCookiesEnabled"] = "True"
                else:
                    result["isTcpSynCookiesEnabled"] = "False"
            except Exception as tcp_syn_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']"
                              f"['check_tcp_syn_cookies_enabled']: {tcp_syn_err}")

        def check_ipv6_router_advertisements_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv6.conf.all.accept_ra")
                output_2 = extract_info("sysctl net.ipv6.conf.default.accept_ra")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv6.conf.all.accept_ra = 0" \
                    or output_3 == "net.ipv6.conf.all.accept_ra = 0") \
                        and (output_2 == "net.ipv6.conf.default.accept_ra = 0" \
                            or output_4 == "net.ipv6.conf.default.accept_ra = 0"):
                    result["isIpv6RouterAdvertisementsDisabled"] = "True"
                else:
                    result["isIpv6RouterAdvertisementsDisabled"] = "False"
            except Exception as ip_adv_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_ipv6_router_advertisements_disabled']: {ip_adv_err}")

        def check_ipv6_disabled():
            try:
                srcipt = r'''
                    #!/bin/bash
                    [ -n "$passing" ] && passing=""
                    [ -z "$(grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disable=1)" ] &&
                    passing="true"
                    grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$"
                    /etc/sysctl.conf
                    /etc/sysctl.d/*.conf && grep -Eq
                    "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$"
                    /etc/sysctl.conf /etc/sysctl.d/*.conf && sysctl
                    net.ipv6.conf.all.disable_ipv6 |
                    grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" &&
                    sysctl net.ipv6.conf.default.disable_ipv6 |
                    grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" &&
                    passing="true"
                    if [ "$passing" = true ] ; then
                    echo "PASS"
                    else
                    echo "FAIL"
                    fi
                '''
                result["isIpv6Disabled"] = run_script(srcipt, "cis_network_configuration")

            except Exception as ipv6_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']['check_ipv6_disabled']: {ipv6_err}")

        def check_dccp_disabled():
            try:
                cmd = f"modprobe -n -v dccp"
                output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                logging.info(f"check_mount_system_command_result: {output}")
                cmd2 = f"lsmod | grep dccp"
                output2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True,
                                                  timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE).strip()

                if output.returncode == 0 and output.stdout == "install /bin/true":
                    if not output2:
                        result["isDccpDisabled"] = "True"
                    else:
                        result["isDccpDisabled"] = "False"

            except Exception as dccp_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']['check_dccp_disabled']: {dccp_err}")

        def check_sctp_disabled():
            try:
                cmd = f"modprobe -n -v sctp"
                output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                logging.info(f"check_mount_system_command_result: {output}")
                cmd2 = f"lsmod | grep sctp"
                output2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True,
                                                  timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE).strip()

                logging.info(f"check_sctp_disabled_command_result: {output2}")

                if output.returncode == 0 and output.stdout == "install /bin/true":
                    if not output2:
                        result["isSctpDisabled"] = "True"
                    else:
                        result["isSctpDisabled"] = "False"

            except Exception as sctp_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']['check_sctp_disabled']: {sctp_err}")

        def check_reverse_path_filtering_enabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.rp_filter")
                output_2 = extract_info("sysctl net.ipv4.conf.default.rp_filter")

                output_3 = extract_shell_info(
                    r'grep -E -s "^\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*0" /etc/sysctl.conf '
                    r'/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')
                output_4 = extract_shell_info(
                    r'grep -E -s "^\s*net\.ipv4\.conf\.default\.rp_filter\s*=\s*1" /etc/sysctl.conf '
                    r'/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')

                if (output_1 == "net.ipv4.conf.all.rp_filter = 1" or not output_3) \
                    and (output_2 == "net.ipv4.conf.default.rp_filter = 1" or not output_4):
                    result["isReversePathFilteringEnabled"] = "True"
                else:
                    result["isReversePathFilteringEnabled"] = "False"
            except Exception as secure_icmp_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_reverse_path_filtering_enabled']: {secure_icmp_err}")

        def check_rds_disabled():
            try:
                cmd = f"modprobe -n -v rds"
                output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                logging.info(f"check_mount_system_command_result: {output}")
                cmd2 = f"lsmod | grep rds"
                output2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True,
                                                  timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE).strip()

                logging.info(f"check_sctp_disabled_command_result: {output2}")

                if output.returncode == 0 and output.stdout == "install /bin/true":
                    if not output2:
                        result["isRdsDisabled"] = "True"
                    else:
                        result["isRdsDisabled"] = "False"

            except Exception as secure_icmp_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_rds_disabled']: {secure_icmp_err}")

        def check_tipc_disabled():
            try:
                cmd = f"modprobe -n -v tipc"
                output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                logging.info(f"check_mount_system_command_result: {output}")
                cmd2 = f"lsmod | grep tipc"
                output2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True,
                                                  timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE).strip()

                logging.info(f"check_sctp_disabled_command_result: {output2}")

                if output.returncode == 0 and output.stdout == "install /bin/true":
                    if not output2:
                        result["isTipcDisabled"] = "True"
                    else:
                        result["isTipcDisabled"] = "False"

            except Exception as secure_icmp_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_tipc_disabled']: {secure_icmp_err}")

        def check_wireless_disabled():
            try:
                output = extract_info("nmcli radio all")
                lines_out = output.split('\n')[-1].split()
                if len(lines_out) == 4:
                    if lines_out[0] == lines_out[2] == "enabled" and lines_out[1] == lines_out[3] == "disabled":
                        result["isWirelessInterfaceDeactivated"] = "True"
                    else:
                        result["isWirelessInterfaceDeactivated"] = "False"
                else:
                    result["isWirelessInterfaceDeactivated"] = "False"
            except Exception as wireless_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']['check_wireless_disabled']: {wireless_err}")

        def check_system_wide_crypto_policy_fips():
            try:
                output = extract_shell_info(r"grep -E -i '^\s*(FUTURE|FIPS)\s*(\s+#.*)?$' /etc/crypto-policies/config")
                if "Future" in output or "FIPS" in output:
                    result["isSystemWideCryptoPolicyFIPS"] = "True"
                else:
                    result["isSystemWideCryptoPolicyFIPS"] = "False"

            except Exception as fips_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_system_wide_crypto_policy_fips']: {fips_err}")

        def check_ssh_to_use_system_crypto_policy():
            try:
                output = extract_shell_info(r"grep -E '^\s*CRYPTO_POLICY\s*=\s*' /etc/sysconfig/sshd")
                if "CRYPTO_POLICY=" in output:
                    result["isSshToUseSystemCryptoPolicy"] = "True"
                else:
                    result["isSshToUseSystemCryptoPolicy"] = "False"

            except Exception as fips_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_ssh_to_use_system_crypto_policy']: {fips_err}")

        try:
            check_ip_forwarding_disabled()
            check_send_packet_redirects_disabled()
            check_accept_source_route_disabled()
            check_icmp_accept_redirects_disabled()
            check_secure_icmp_redirects_disabled()
            check_log_suspicious_packets_enabled()
            check_broadcast_icmp_ignored()
            check_bogus_icmp_ignored()
            check_tcp_syn_cookies_enabled()
            check_ipv6_router_advertisements_disabled()
            check_ipv6_disabled()
            check_dccp_disabled()
            check_sctp_disabled()
            check_reverse_path_filtering_enabled()
            check_rds_disabled()
            check_tipc_disabled()
            check_wireless_disabled()
            check_system_wide_crypto_policy_fips()
            check_ssh_to_use_system_crypto_policy()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_network_configuration']: {err}")

        return result

    # CIS Section - 3.4.1
    @logger_function
    def cis_configure_firewall_utility():
        result = {
            "isNftablesNotInstalled": "Not Configured",
            "isSingleFirewallConfInUse": "Not Configured"
        }
        try:
            firewall_script = r"""l_output=""
            l_output2=""
            l_fwd_status=""
            l_nft_status=""
            l_fwutil_status=""

            if rpm -q firewalld >/dev/null 2>&1; then
                l_fwd_status="$(systemctl is-enabled firewalld.service):$(systemctl is-active firewalld.service)"
            fi

            if rpm -q nftables >/dev/null 2>&1; then
                l_nft_status="$(systemctl is-enabled nftables.service):$(systemctl is-active nftables.service)"
            fi

            l_fwutil_status="$l_fwd_status:$l_nft_status"

            case $l_fwutil_status in enabled:active:masked:inactive | enabled:active:disabled:inactive) l_output="\n
            - FirewallD utility is in use, enabled and active\n - NFTables utility is correctly disabled or masked
            and inactive" ;; masked:inactive:enabled:active | disabled:inactive:enabled:active) l_output="\n -
            NFTables utility is in use, enabled and active\n - FirewallD utility is correctly disabled or masked and
            inactive" ;; enabled:active:enabled:active) l_output2="\n - Both FirewallD and NFTables utilities are
            enabled and active" ;; enabled:*:enabled:*) l_output2="\n - Both FirewallD and NFTables utilities are
            enabled" ;; *:active:*:active) l_output2="\n - Both FirewallD and NFTables utilities are enabled" ;;
            :enabled:active) l_output="\n - NFTables utility is in use, enabled, and active\n - FirewallD package is
            not installed" ;; :) l_output2="\n - Neither FirewallD nor NFTables is installed." ;; *:*:) l_output2="\n
            - NFTables package is not installed on the system" ;; *) l_output2="\n - Unable to determine firewall
            state" ;; esac

            if [ -z "$l_output2" ]; then
                echo -e "\n- Audit Results:\n ** PASS **$l_output\n"
            else
                echo -e "\n- Audit Results:\n ** FAIL **$l_output2\n"
            fi"""

            logging.info(f"check_single_firewall_conf_in_use with script")

            result["isNftablesNotInstalled"] = check_if_not_installed("nftables", "cis_configure_firewall_utility")
            result["isSingleFirewallConfInUse"] = run_script(firewall_script, "cis_configure_firewall_utility")
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_firewall_utility']: {err}")
        return result

    # CIS Section - 3.4.2
    @logger_function
    def cis_configure_firewall_rules():
        result = {
            "isFirewallDefaultZoneSet": "Not Configured",
            "atleastOneNftableExists": "Not Configured",
            "nftableBaseChainsExist": "Not Configured",
            "isFirewallLoopbackConfigured": "Not Configured",
        }
        try:
            # cis subsection 3.4.2.1
            def check_firewall_default_zone_set():
                try:
                    logging.info("Running check_single_firewall_conf_in_use()")
                    firewall_script = r"""l_output="" l_output2="" l_zone=""
                if systemctl is-enabled firewalld.service | grep -q 'enabled'; then
                    l_zone="$(firewall-cmd --get-default-zone)"
                    if [ -n "$l_zone" ]; then
                        l_output=" - The default zone is set to: \"$l_zone\""
                    else
                        l_output2=" - The default zone is not set"
                    fi
                else
                    l_output=" - FirewallD is not in use on the system"
                fi
                if [ -z "$l_output2" ]; then
                    echo -e "\n- Audit Results:\n ** PASS **\n$l_output\n"
                else
                    echo -e "\n- Audit Results:\n ** FAIL **\n$l_output2\n"
                fi"""
                    logging.info(f"check_firewall_default_zone_set with script")
                    return run_script(firewall_script, "cis_configure_firewall_rules")
                except Exception as er:
                    error["cisInfo"]["cis_configure_firewall_rules"]["check_firewall_default_zone_set"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_firewall_rules']['check_firewall_default_zone_set']: {er}")
                    return "Not Configured"

            # cis subsection 3.4.2.2
            def check_atleast_one_nftable_exists():
                try:
                    check_nftable_command = "nft list tables"
                    logging.info(f"check_nftable_command: '{check_nftable_command}'")
                    check_nftable_command_result = subprocess.run(check_nftable_command, shell=True,
                                                                  stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                                  universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_nftable_command_result : {check_nftable_command_result}")

                    if check_nftable_command_result.returncode == 0:
                        check_nftable_result = "True"
                    elif check_nftable_command_result.returncode == 1:
                        check_nftable_result = "False"
                    else:
                        check_nftable_result = "Not Configured"

                    logging.info(f"check_nftable_result: {check_nftable_result}")
                    return check_nftable_result
                except Exception as er:
                    error["cisInfo"]['cis_configure_firewall_rules']["check_atleast_one_nftable_exists"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_firewall_rules']['check_atleast_one_nftable_exists']: {er}")
                    return "Not Configured"

            # cis subsection 3.4.2.3
            def check_nftable_base_chains_exist():
                base_chain_result = {
                    "inputChain": "Not Configured",
                    "forwardChain": "Not Configured",
                    "outputChain": "Not Configured",
                }
                try:
                    base_chain_list = ["input", "forward", "output"]
                    for value in base_chain_list:
                        check_nftable_base_chains_command = f"nft list ruleset | grep 'hook {value}'"
                        logging.info(f"check_nftable_base_chains_command: '{check_nftable_base_chains_command}'")
                        check_nftable_base_chains_command_result = subprocess.run(check_nftable_base_chains_command,
                                                                                  shell=True,
                                                                                  stderr=subprocess.PIPE,
                                                                                  stdout=subprocess.PIPE,
                                                                                  universal_newlines=True,
                                                                                  timeout=TIMEOUT_SUBPROCESS)
                        logging.info(
                            f"check_nftable_base_chains_command_result : {check_nftable_base_chains_command_result}")

                        if check_nftable_base_chains_command_result.returncode == 0:
                            check_nftable_base_chains_result = "True"
                        elif check_nftable_base_chains_command_result.returncode == 1:
                            check_nftable_base_chains_result = "False"
                        else:
                            check_nftable_base_chains_result = "Not Configured"
                        base_chain_result[value + "Chain"] = check_nftable_base_chains_result

                    logging.info(f"check_nftable_base_chains_result: {base_chain_result}")
                except Exception as er:
                    error["cisInfo"]['cis_configure_firewall_rules']["check_nftable_base_chains_exist"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_firewall_rules']['check_nftable_base_chains_exist']: {er}")
                return base_chain_result

            # cis subsection 3.4.2.4
            def check_firewall_loopback():
                try:
                    script = r"""l_output="" l_output2="" if nft list ruleset | awk '/hook\s+input\s+/,
                    /\}\s*(#.*)?$/' | grep -Pq --'\H+\h+"lo"\h+accept'; then l_output="$l_output\n - Network traffic
                    to the loopback address is correctly set to accept" else l_output2="$l_output2\n - Network
                    traffic to the loopback address is not set to accept" fi l_ipsaddr="$(nft list ruleset | awk
                    '/filter_IN_public_deny|hook\s+input\s+/,/\}\s*(#.*)?$/' | grep -P --'ip\h+saddr')" if grep -Pq
                    --'ip\h+saddr\h+127\.0\.0\.0\/8\h+(counter\h+packets\h+\d+\h+bytes\h+\d+\h+)?drop' <<<
                    "$l_ipsaddr" || grep -Pq -- 'ip\h+daddr\h+\!\=\h+127\.0\.0\.1\h+ip\h+saddr\h+127\.0\.0\.1\h+drop'
                    <<< "$l_ipsaddr"; then l_output="$l_output\n - IPv4 network traffic from loopback address
                    correctly set to drop" else l_output2="$l_output2\n - IPv4 network traffic from loopback address
                    not set to drop" fi if grep -Pq -- '^\h*0\h*$' /sys/module/ipv6/parameters/disable; then
                    l_ip6saddr="$(nft list ruleset | awk '/filter_IN_public_deny|hook input/,/}/' | grep 'ip6
                    saddr')" if grep -Pq 'ip6\h+saddr\h+::1\h+(counter\h+packets\h+\d+\h+bytes\h+\d+\h+)?drop' <<<
                    "$l_ip6saddr" || grep -Pq --'ip6\h+daddr\h+\!=\h+::1\h+ip6\h+saddr\h+::1\h+drop' <<<
                    "$l_ip6saddr"; then l_output="$l_output\n - IPv6 network traffic from loopback address correctly
                    set to drop" else l_output2="$l_output2\n - IPv6 network traffic from loopback address not set to
                    drop" fi fi if [ -z "$l_output2" ]; then echo -e "\n- Audit Result:\n *** PASS ***\n$l_output"
                    else echo -e "\n- Audit Result:\n *** FAIL ***\n$l_output2\n\n - Correctly set:\n$l_output" fi"""
                    return run_script(script, "check_firewall_loopback")
                except Exception as er:
                    error["cisInfo"]['cis_configure_firewall_rules']["check_firewall_loopback"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_configure_firewall_rules']['check_firewall_loopback']: {er}")
                    return "Not Configured"

            result["isFirewallDefaultZoneSet"] = check_firewall_default_zone_set()
            result["atleastOneNftableExists"] = check_atleast_one_nftable_exists()
            result["nftableBaseChainsExist"] = check_nftable_base_chains_exist()
            result["isFirewallLoopbackConfigured"] = check_firewall_loopback()
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_firewall_rules']: {err}")
        return result

    # CIS Section - 3.5.1
    @logger_function
    def cis_configure_ufw():
        """
        Configures UFW firewall settings and retrieves the status of various UFW parameters.

        Returns: dict: A dictionary containing the following UFW parameters: - is_ufw_service_enabled (str): The
        status of the UFW service ("Enabled", "Disabled", or "Not Configured"). - is_ufw_service_active (str): The
        activity status of the UFW service ("Active", "Inactive", or "Not Configured"). - ufw_status (str): The
        status of the UFW firewall ("Active", "Inactive", or "Not Configured"). - ufw_default_deny (str): The default
        deny status of the UFW firewall ("True", "False", or "Not Configured").
        """
        result = {
            "isUfwInstalled": "Not Configured",
            "isUfwEnabled": "Not Configured",
            "isUfwDefaultDeny": "Not Configured",
        }

        try:
            # CIS Section - 3.5.1.3
            def check_ufw_installed_or_not():
                try:
                    ufw_command = ("dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' "
                                    "ufw")
                    logging.info(f"ufw_command: {ufw_command}")
                    check_ufw_installed_command_result = subprocess.run(ufw_command, shell=True,
                                                                        capture_output=True, text=True,
                                                                        timeout=TIMEOUT_SUBPROCESS)
                    logging.info(
                        f"check_ufw_installed_command_result : {check_ufw_installed_command_result}")
                    
                    if check_ufw_installed_command_result.returncode == 0:
                        if check_ufw_installed_command_result.stdout.lower().find("not-installed") >= 0:
                            configure_ufw_installed_result = "False"
                        elif check_ufw_installed_command_result.stdout.lower().find("installed") >= 0:
                            configure_ufw_installed_result = "True"
                        else:
                            configure_ufw_installed_result = "Not Configured"
                    else:
                        configure_ufw_installed_result =  "False"

                    logging.info(f"configure_ufw_installed_result: {configure_ufw_installed_result}")
                    return configure_ufw_installed_result
                except Exception as cis_configure_ufw_install:
                    error["cisInfo"]["cis_configure_ufw"]["check_ufw_uninstalled_or_not"] = (
                        repr(cis_configure_ufw_install))
                    logging.error(
                        f"error['cisInfo']['cis_configure_ufw']['check_ufw_uninstalled_or_not']: "
                        f"{cis_configure_ufw_install}"
                    )
                    return "Not Configured"

            def check_ufw_enabled_or_not():
                commands = [
                    {
                        "cmd": "systemctl is-enabled ufw.service",
                        "expected": "enabled"
                    },
                    {
                        "cmd": "systemctl is-active ufw.service",
                        "expected": "active"
                    },
                    {
                        "cmd": "ufw status",
                        "expected": "Status: active"
                    }
                ]

                try:
                    for entry in commands:
                        cmd = entry["cmd"]
                        expected = entry["expected"]

                        logging.info(f"Executing command: {cmd}")

                        result = subprocess.run(
                            cmd,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=TIMEOUT_SUBPROCESS
                        )

                        output = (result.stdout + result.stderr).strip()
                        logging.info(f"{cmd} Command output: {output}")

                        if expected not in output:
                            logging.info(f"Expected '{expected}' not found in output of '{cmd}'")
                            return "False"

                    return "True"

                except Exception as ufw_check_error:
                    logging.error(f"Error checking UFW configuration: {ufw_check_error}")
                    return "Not Configured"

            # 3.5.1.7
            def check_ufw_default_deny():
                try:
                    check_ufw_default_command = "ufw status verbose | grep Default:"
                    logging.info(f"check_ufw_default_command: {check_ufw_default_command}")
                    check_ufw_default_command_result = subprocess.run(check_ufw_default_command, shell=True,
                                                                      capture_output=True,
                                                                      text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_ufw_default_command_result : {check_ufw_default_command_result}")

                    logging.info(f"configure_ufw_loopback_result: {check_ufw_default_command_result.stdout}")

                    if check_ufw_default_command_result.stdout.lower().find("allow") >= 0:
                        configure_ufw_default_result = "False"
                    elif check_ufw_default_command_result.stdout.lower().find("deny") >= 0:
                        configure_ufw_default_result = "True"
                    else:
                        configure_ufw_default_result = "Not Configured"

                    return configure_ufw_default_result
                except Exception as cis_configure_ufw_error:
                    error["cisInfo"]["cis_configure_ufw"]["check_ufw_default_deny"] = (
                        repr(cis_configure_ufw_error))
                    logging.error(
                        f"error['cisInfo']['cis_configure_ufw']['check_ufw_default_deny']: "
                        f"{cis_configure_ufw_error}"
                    )
                    return "Not Configured"

            result["isUfwInstalled"] = check_ufw_installed_or_not()
            result["isUfwEnabled"] = check_ufw_enabled_or_not()
            result["isUfwDefaultDeny"] = check_ufw_default_deny()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_ufw']: {err}")
        return result

    # CIS Section - 3.5.3
    @logger_function
    def cis_configure_iptables_softwares():
        cis_configure_iptables_softwares_result = {
            "iptablesSoftwares": {
                "isIptableInstalled": "Not Configured",
                "isNftableUninstalled": "Not Configured",
                "isUfwUninstalledOrDisabled": "Not Configured"
            },
            "ipv4DefaultDeny": {
                "isChainInputDropped": "Not Configured",
                "isChainForwardDropped": "Not Configured",
                "isChainOutputDropped": "Not Configured"
            },
            "ipv6DefaultDeny": {
                "isChainInputDropped": "Not Configured",
                "isChainForwardDropped": "Not Configured",
                "isChainOutputDropped": "Not Configured"
            }
        }

        try:
            # 3.5.3.1
            def configure_iptables():
                result = {
                    "isIptableInstalled": "Not Configured",
                    "isNftableUninstalled": "Not Configured",
                    "isUfwUninstalledOrDisabled": "Not Configured"
                }

                try:
                    # 3.5.3.1.1
                    def check_iptable_installed_or_not():
                        try:
                            check_iptable_installed_command = "apt list iptables iptables-persistent | grep installed"
                            logging.info(f"check_iptable_installed_command: {check_iptable_installed_command}")
                            check_iptable_installed_command_result = subprocess.run(check_iptable_installed_command,
                                                                                    shell=True,
                                                                                    capture_output=True, text=True,
                                                                                    timeout=TIMEOUT_SUBPROCESS)
                            logging.info(
                                f"check_iptable_installed_command_result : {check_iptable_installed_command_result}")

                            if check_iptable_installed_command_result.returncode == 0:
                                if "not-installed" in check_iptable_installed_command_result.stdout.strip().lower():
                                    configure_iptable_installed_result = "False"
                                elif "installed" in check_iptable_installed_command_result.stdout.strip().lower():
                                    configure_iptable_installed_result = "True"
                                else:
                                    configure_iptable_installed_result = "Not Configured"
                            else:
                                configure_iptable_installed_result = "False"

                            logging.info(f"configure_iptable_installed_result: {configure_iptable_installed_result}")
                            return configure_iptable_installed_result
                        except Exception as cis_configure_iptables_installed_error:
                            error["cisInfo"]["cis_configure_iptables"]["check_iptable_installed_or_not"] = (
                                repr(cis_configure_iptables_installed_error))
                            logging.error(
                                f"error['cisInfo']['cis_configure_iptables']['check_iptable_installed_or_not']: "
                                f"{cis_configure_iptables_installed_error}"
                            )
                            return "Not Configured"

                    # 3.5.3.1.2
                    def check_nftable_uninstalled_or_not():
                        try:
                            nftable_command = ("dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' "
                                               "nftables")
                            logging.info(f"nftable_command: {nftable_command}")
                            check_nftable_installed_command_result = subprocess.run(nftable_command, shell=True,
                                                                                    capture_output=True, text=True,
                                                                                    timeout=TIMEOUT_SUBPROCESS)
                            logging.info(
                                f"check_ufw_installed_command_result : {check_nftable_installed_command_result}")
                            
                            if check_nftable_installed_command_result.returncode == 0:
                                if check_nftable_installed_command_result.stdout.lower().find("not-installed") >= 0:
                                    configure_nftable_installed_result = "True"
                                elif check_nftable_installed_command_result.stdout.lower().find("installed") >= 0:
                                    configure_nftable_installed_result = "False"
                                else:
                                    configure_nftable_installed_result = "Not Configured"
                            else:
                                configure_nftable_installed_result =  "True"

                            logging.info(f"configure_nftable_installed_result: {configure_nftable_installed_result}")
                            return configure_nftable_installed_result
                        except Exception as cis_configure_nftables_uninstall:
                            error["cisInfo"]["cis_configure_iptables"]["check_nftable_uninstalled_or_not"] = (
                                repr(cis_configure_nftables_uninstall))
                            logging.error(
                                f"error['cisInfo']['cis_configure_iptables']['check_nftable_uninstalled_or_not']: "
                                f"{cis_configure_nftables_uninstall}"
                            )
                            return "Not Configured"

                    # 3.5.3.1.3
                    def check_ufw_disabled_or_not():
                        try:
                            check_ufw_command = ("dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' "
                                                 "ufw")
                            logging.info(f"check_ufw_command: {check_ufw_command}")
                            check_ufw_installed_command_result = subprocess.run(check_ufw_command, shell=True,
                                                                                capture_output=True, text=True,
                                                                                timeout=TIMEOUT_SUBPROCESS)
                            logging.info(
                                f"check_ufw_installed_command_result : {check_ufw_installed_command_result}")

                            if check_ufw_installed_command_result.stdout.lower().find("not-installed") >= 0:
                                return "True"
                            elif check_ufw_installed_command_result.stdout.lower().find("installed") >= 0:
                                check_ufw_masked_command = "systemctl is-enabled ufw"
                                logging.info(f"check_ufw_masked_command: {check_ufw_masked_command}")
                                check_ufw_masked_command_result = subprocess.run(check_ufw_masked_command,
                                                                                    shell=True,
                                                                                    capture_output=True, text=True,
                                                                                    timeout=TIMEOUT_SUBPROCESS)
                                logging.info(f"check_ufw_masked_command_result : {check_ufw_masked_command_result}")

                                if check_ufw_masked_command_result.stdout.lower().find("enabled") >= 0:
                                    return "False"
                                else:
                                    return "True"

                        except Exception as cis_configure_ufw_disabled_error:
                            logging.error(
                                f"error['cisInfo']['cis_configure_iptables']['check_ufw']: "
                                f"{cis_configure_ufw_disabled_error}"
                            )
                            return "Not Configured"

                    result["isIptableInstalled"] = check_iptable_installed_or_not()
                    result["isNftableUninstalled"] = check_nftable_uninstalled_or_not()
                    result["isUfwUninstalledOrDisabled"] = check_ufw_disabled_or_not()
                except Exception as cis_configure_iptables_error:
                    logging.error(
                        f"error['cisInfo']['cis_configure_iptables']: "
                        f"{cis_configure_iptables_error}"
                    )
                return result

            # 3.5.3.2.1
            def ipv4_default_deny():
                ipv4_chain_result = {
                    "isChainInputDropped": "Not Configured",
                    "isChainForwardDropped": "Not Configured",
                    "isChainOutputDropped": "Not Configured",
                }
                try:
                    ipv4_default_deny_input_command = "iptables -L | grep INPUT | awk '{print $4}' | tr -d ')'"
                    ipv4_default_deny_output_command = "iptables -L | grep OUTPUT | awk '{print $4}' | tr -d ')'"
                    ipv4_default_deny_forward_command = "iptables -L | grep FORWARD | awk '{print $4}' | tr -d ')'"
                    logging.info(f"ipv4_default_deny_command: 'iptables -L | grep policy'")
                    ipv4_default_deny_input_command_result = subprocess.run(ipv4_default_deny_input_command, shell=True,
                                                                            capture_output=True, text=True,
                                                                            timeout=TIMEOUT_SUBPROCESS)
                    ipv4_default_deny_output_command_result = subprocess.run(ipv4_default_deny_output_command,
                                                                             shell=True,
                                                                             capture_output=True, text=True,
                                                                             timeout=TIMEOUT_SUBPROCESS)
                    ipv4_default_deny_forward_command_result = subprocess.run(ipv4_default_deny_forward_command,
                                                                              shell=True,
                                                                              capture_output=True, text=True,
                                                                              timeout=TIMEOUT_SUBPROCESS)

                    if "drop" in ipv4_default_deny_input_command_result.stdout.lower():
                        config_ipv4_deny_input_result = "True"
                    elif "reject" in ipv4_default_deny_input_command_result.stdout.lower():
                        config_ipv4_deny_input_result = "True"
                    else:
                        config_ipv4_deny_input_result = "False"
                    ipv4_chain_result["isChainInputDropped"] = config_ipv4_deny_input_result

                    if "drop" in ipv4_default_deny_output_command_result.stdout.lower():
                        config_ipv4_deny_output_result = "True"
                    elif "reject" in ipv4_default_deny_output_command_result.stdout.lower():
                        config_ipv4_deny_output_result = "True"
                    else:
                        config_ipv4_deny_output_result = "False"
                    ipv4_chain_result["isChainOutputDropped"] = config_ipv4_deny_output_result

                    if "drop" in ipv4_default_deny_forward_command_result.stdout.lower():
                        config_ipv4_deny_forward_result = "True"
                    elif "reject" in ipv4_default_deny_forward_command_result.stdout.lower():
                        config_ipv4_deny_forward_result = "True"
                    else:
                        config_ipv4_deny_forward_result = "False"
                    ipv4_chain_result["isChainForwardDropped"] = config_ipv4_deny_forward_result

                except Exception as ipv4_default_deny_error:
                    error["cisInfo"]["cis_configure_iptables"]["ipv4_default_deny"] = (
                        repr(ipv4_default_deny_error))
                    logging.error(f"error['cisInfo']['cis_configure_iptables']['ipv4_default_deny']: "
                                  f"{ipv4_default_deny_error}")
                return ipv4_chain_result

            # 3.5.3.2.1
            def ipv6_default_deny():
                ipv6_chain_result = {
                    "isChainInputDropped": "Not Configured",
                    "isChainForwardDropped": "Not Configured",
                    "isChainOutputDropped": "Not Configured",
                }
                try:
                    ipv6_default_deny_input_command = "ip6tables -L | grep INPUT | awk '{print $4}' | tr -d ')'"
                    ipv6_default_deny_output_command = "ip6tables -L | grep OUTPUT | awk '{print $4}' | tr -d ')'"
                    ipv6_default_deny_forward_command = "ip6tables -L | grep FORWARD | awk '{print $4}' | tr -d ')'"
                    logging.info(f"ipv6_default_deny_command: 'ip6tables -L | grep policy'")
                    ipv6_default_deny_input_command_result = subprocess.run(ipv6_default_deny_input_command, shell=True,
                                                                            capture_output=True, text=True,
                                                                            timeout=TIMEOUT_SUBPROCESS)
                    ipv6_default_deny_output_command_result = subprocess.run(ipv6_default_deny_output_command,
                                                                             shell=True,
                                                                             capture_output=True, text=True,
                                                                             timeout=TIMEOUT_SUBPROCESS)
                    ipv6_default_deny_forward_command_result = subprocess.run(ipv6_default_deny_forward_command,
                                                                              shell=True,
                                                                              capture_output=True, text=True,
                                                                              timeout=TIMEOUT_SUBPROCESS)

                    if "drop" in ipv6_default_deny_input_command_result.stdout.lower():
                        config_ipv6_deny_input_result = "True"
                    elif "reject" in ipv6_default_deny_input_command_result.stdout.lower():
                        config_ipv6_deny_input_result = "True"
                    else:
                        config_ipv6_deny_input_result = "False"
                    ipv6_chain_result["isChainInputDropped"] = config_ipv6_deny_input_result

                    if "drop" in ipv6_default_deny_output_command_result.stdout.lower():
                        config_ipv6_deny_output_result = "True"
                    elif "reject" in ipv6_default_deny_output_command_result.stdout.lower():
                        config_ipv6_deny_output_result = "True"
                    else:
                        config_ipv6_deny_output_result = "False"
                    ipv6_chain_result["isChainOutputDropped"] = config_ipv6_deny_output_result

                    if "drop" in ipv6_default_deny_forward_command_result.stdout.lower():
                        config_ipv6_deny_forward_result = "True"
                    elif "reject" in ipv6_default_deny_forward_command_result.stdout.lower():
                        config_ipv6_deny_forward_result = "True"
                    else:
                        config_ipv6_deny_forward_result = "False"
                    ipv6_chain_result["isChainForwardDropped"] = config_ipv6_deny_forward_result

                except Exception as ipv6_default_deny_error:
                    error["cisInfo"]["cis_configure_iptables"]["ipv6_default_deny"] = (
                        repr(ipv6_default_deny_error))
                    logging.error(f"error['cisInfo']['cis_configure_iptables']['ipv6_default_deny']: "
                                  f"{ipv6_default_deny_error}")
                return ipv6_chain_result

            cis_configure_iptables_softwares_result["iptablesSoftwares"] = configure_iptables()
            cis_configure_iptables_softwares_result["ipv4DefaultDeny"] = ipv4_default_deny()
            cis_configure_iptables_softwares_result["ipv6DefaultDeny"] = ipv6_default_deny()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_iptables_softwares']: {err}")
        return cis_configure_iptables_softwares_result

    # CIS Section 4.1.1
    @logger_function
    def cis_configure_system_auditing():
        """
        Configure system auditing.

        This function configures system auditing and returns a dictionary with the following keys:
        - "isAudispdPluginsInstalled": indicates whether the audispd-plugins package is installed.
        - "isAuditdInstalled": indicates whether the auditd package is installed.
        - "isAuditdServiceEnabled": indicates whether the auditd service is enabled.
        - "isAuditdServiceActive": indicates whether the auditd service is active.
        - "isAuditingPriorToAuditdEnabled": indicates whether auditing prior to auditd is enabled.
        - "isAuditBacklogLimitSufficient": indicates whether the audit backlog limit is sufficient.

        :return: a dictionary containing the audit configuration status.
        """
        # Configure system auditing
        result = {
            "isAudispdPluginsInstalled": "Not Configured",
            "isAuditdInstalled": "Not Configured",
            "isAuditdServiceEnabled": "Not Configured",
            "isAuditdServiceActive": "Not Configured",
            "isAuditingPriorToAuditdEnabled": "Not Configured",
            "isAuditBacklogLimitSufficient": "Not Configured",
        }

        try:
            def check_installed_or_not(service_name):
                try:
                    # Check if the service is installed
                    check_installed_command = (r"dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n'"
                                               fr" {service_name} | grep -Pi '\h+installed\b'")

                    logging.info(f"check_installed_command: {check_installed_command}")
                    check_installed_command_result = subprocess.run(check_installed_command, shell=True,
                                                                    capture_output=True, text=True,
                                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_installed_command_result for {service_name}: {check_installed_command_result}")

                    if check_installed_command_result.returncode == 0:
                        check_installed_result = "True"
                    elif check_installed_command_result.returncode == 1:
                        check_installed_result = "False"
                    else:
                        check_installed_result = "Not Configured"

                    logging.info(f"check_installed_result: {check_installed_result}")
                    return check_installed_result
                except Exception as check_installed_error:
                    error["cisInfo"]["cis_configure_system_auditing"]["check_installed_or_not"] = (
                        repr(check_installed_error))
                    logging.error(f"error['cisInfo']['cis_configure_system_auditing']['check_installed_or_not']: "
                                  f"{check_installed_error}")
                    return "Not Configured"

            def check_auditd_service_enabled_and_active():
                try:
                    # Check if auditd_service is enabled
                    check_auditd_service_enabled_command = r"systemctl is-enabled auditd"
                    logging.info(f"check_auditd_service_enabled command: {check_auditd_service_enabled_command}")

                    check_auditd_service_enabled_command_result = subprocess.run(check_auditd_service_enabled_command,
                                                                                 shell=True, capture_output=True,
                                                                                 text=True,
                                                                                 timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_auth_command_result: {check_auditd_service_enabled_command_result}")
                    logging.info(
                        f"check_auth_command_result.stdout.strip(): "
                        f"{check_auditd_service_enabled_command_result.stdout.strip()}")

                    if check_auditd_service_enabled_command_result.returncode == 0:
                        if check_auditd_service_enabled_command_result.stdout.strip() == "enabled":
                            is_auditd_service_enabled_result = "True"
                        else:
                            is_auditd_service_enabled_result = "False"
                    elif check_auditd_service_enabled_command_result.returncode == 1:
                        is_auditd_service_enabled_result = "Not Configured"
                    else:
                        is_auditd_service_enabled_result = "Not Configured"

                    logging.info(f"is_auditd_service_enabled_result: {is_auditd_service_enabled_result}")

                    # Check if auditd_service is active
                    check_auditd_service_active_command = "systemctl is-active auditd"
                    logging.info(f"check_auditd_service_active command: {check_auditd_service_active_command}")

                    check_auditd_service_active_result = subprocess.run(check_auditd_service_active_command, shell=True,
                                                                        capture_output=True,
                                                                        text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(
                        f"check_auditd_service_active_result.stdout.strip(): "
                        f"{check_auditd_service_active_result.stdout.strip()}")

                    if check_auditd_service_active_result.stdout.strip() == "active":
                        logging.info(f"auditd_service is active")
                        is_auditd_service_active_result = "True"
                    elif check_auditd_service_active_result.stdout.strip() == "inactive":
                        logging.info(f"auditd_service is not active")
                        is_auditd_service_active_result = "False"
                    else:
                        logging.info(f"auditd_service is not configured")
                        is_auditd_service_active_result = "Not Configured"

                    logging.info(f"is_auditd_service_active_result: {is_auditd_service_active_result}")

                    return is_auditd_service_enabled_result, is_auditd_service_active_result
                except Exception as check_auditd_service_enabled_and_active_error:
                    error["cisInfo"]["cis_configure_system_auditing"]["check_auditd_service_enabled_and_active"] = (
                        repr(check_auditd_service_enabled_and_active_error))
                    logging.error(
                        f"error['cisInfo']['cis_configure_system_auditing']"
                        f"['check_auditd_service_enabled_and_active']: "
                        f"{check_auditd_service_enabled_and_active_error}")
                    return "Not Configured", "Not Configured"

            def check_if_auditing_prior_to_auditd_enabled():
                try:
                    # Check if mta is configured or not
                    check_auditing_prior_to_auditd_enabled_command = \
                        r"find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -v 'audit=1'"

                    logging.info(
                        f"check_auditing_prior_to_auditd_enabled_command: "
                        f"{check_auditing_prior_to_auditd_enabled_command}")
                    check_auditing_prior_to_auditd_enabled_command_result = subprocess.run(
                        check_auditing_prior_to_auditd_enabled_command, shell=True,
                        capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(
                        f"check_auditing_prior_to_auditd_enabled_command_result: "
                        f"{check_auditing_prior_to_auditd_enabled_command_result}")

                    if check_auditing_prior_to_auditd_enabled_command_result.stdout.strip() == "":
                        auditing_prior_to_auditd_enabled_result = "True"
                    else:
                        auditing_prior_to_auditd_enabled_result = "Not Configured"

                    logging.info(f"auditing_prior_to_auditd_enabled_result: {auditing_prior_to_auditd_enabled_result}")

                    return auditing_prior_to_auditd_enabled_result
                except Exception as check_if_auditing_prior_to_auditd_enabled_error:
                    error["cisInfo"]["cis_configure_system_auditing"]["check_if_auditing_prior_to_auditd_enabled"] = (
                        repr(check_if_auditing_prior_to_auditd_enabled_error))
                    logging.error(
                        f"error['cisInfo']['cis_configure_system_auditing']"
                        f"['check_if_auditing_prior_to_auditd_enabled']: "
                        f"{check_if_auditing_prior_to_auditd_enabled_error}")
                    return "Not Configured"

            def check_if_audit_backlog_limit_sufficient():
                try:
                    # Check if mta is configured or not
                    check_audit_backlog_limit_sufficient_command = \
                        (r"find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | "
                         r"grep -Pv 'audit_backlog_limit=\d+\b'")

                    logging.info(
                        f"check_audit_backlog_limit_sufficient_command: {check_audit_backlog_limit_sufficient_command}")
                    check_audit_backlog_limit_sufficient_command_result = subprocess.run(
                        check_audit_backlog_limit_sufficient_command, shell=True,
                        capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(
                        f"check_audit_backlog_limit_sufficient_command_result: "
                        f"{check_audit_backlog_limit_sufficient_command_result}")

                    if check_audit_backlog_limit_sufficient_command_result.stdout.strip() == "":
                        audit_backlog_limit_sufficient_result = "True"
                    else:
                        audit_backlog_limit_sufficient_result = "Not Configured"

                    logging.info(f"audit_backlog_limit_sufficient_result: {audit_backlog_limit_sufficient_result}")

                    return audit_backlog_limit_sufficient_result
                except Exception as check_if_audit_backlog_limit_sufficient_error:
                    error["cisInfo"]["cis_configure_system_auditing"]["check_if_audit_backlog_limit_sufficient"] = (
                        repr(check_if_audit_backlog_limit_sufficient_error))
                    logging.error(
                        f"error['cisInfo']['cis_configure_system_auditing']"
                        f"['check_if_audit_backlog_limit_sufficient']: "
                        f"{check_if_audit_backlog_limit_sufficient_error}")
                    return "Not Configured"

            result["isAudispdPluginsInstalled"] = check_installed_or_not("audispd-plugins")
            result["isAuditdInstalled"] = check_installed_or_not("auditd")
            result["isAuditdServiceEnabled"], result["isAuditdServiceActive"] = (
                check_auditd_service_enabled_and_active())
            result["isAuditingPriorToAuditdEnabled"] = check_if_auditing_prior_to_auditd_enabled()
            result["isAuditBacklogLimitSufficient"] = check_if_audit_backlog_limit_sufficient()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_system_auditing']: {err}")
        return result

    # CIS Section - 4.1.2
    @logger_function
    def cis_logging_and_auditing():
        result = {
            "isAuditLogStorageSizeConfigured": "Not Configured",
            "recordEventsThatModifyDateAndTimeAreCollected": "Not Configured",
            "recordEventsThatModifyUserOrGroupAreCollected": "Not Configured",
            "recordEventsThatModifyNetworkAreCollected": "Not Configured",
            "recordEventsThatModifyMandatoryAccessAreCollected": "Not Configured",
            "isSessionIniationCollected": "Not Configured",
            "isDiscretionaryAccessEventsCollected": "Not Configured",
            "isUnsuccessfulUnauthorizedAccessCollected": "Not Configured",
            "isSuccessfulFilesystemCollected": "Not Configured",
            "isChangeToSystemAdministrativeScopeCollected": "Not Configured",
            "isKernelModuleLoadingAndUnloadingCollected": "Not Configured",
            "isAuditConfigurationImmutable": "Not Configured",
            "isAuditLogsAreNotAutomaticallyDeleted": "Not Configured",
            "isLoginAndLogoutEventsCollected": "Not Configured",
            "isFileDeletionEventsByUserCollected": "Not Configured",
            "isAnyAttemptsToRunChconRecorded": "Not Configured",
            "isWriteLogFilesToPersistentDisk": "Not Configured",
            "isDisableSystemOnAuditLogFull": "Not Configured",
            "isJournaldConfiguredToCompressLargeLogFiles": "Not Configured",
            "isUseOfPrivilegedCommandsCollected": "Not Configured",
        }
        try:
            def check_if_audit_log_storage_size_configured():

                try:
                    # Check if mta is configured or not
                    output = extract_shell_info(r"grep -E '^max_log_file =' /etc/audit/auditd.conf")

                    if "max_log_file" in output:
                        result["isAuditLogStorageSizeConfigured"] = "True"
                    else:
                        result["isAuditLogStorageSizeConfigured"] = "False"

                    logging.info(f"audit_log_storage_size_configured_result: "
                                 f"{result['isAuditLogStorageSizeConfigured']}")
                except Exception as audit_store_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['check_if_audit_log_storage_size_configured']: {audit_store_err}")

            def check_record_events_that_modify_date_and_time_are_collected():
                try:
                    output1 = extract_shell_info(r"grep time-change /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep time-change")

                    match1 = '''\
                        -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
                        -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
                        -a always,exit -F arch=b64 -S clock_settime -k time-change
                        -a always,exit -F arch=b32 -S clock_settime -k time-change
                        -w /etc/localtime -p wa -k time-change\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["recordEventsThatModifyDateAndTimeAreCollected"] = "True"
                    else:
                        result["recordEventsThatModifyDateAndTimeAreCollected"] = "False"
                    logging.info(f"record_events_that_modify_date_and_time_are_collected_result: "
                                 f"{result['recordEventsThatModifyDateAndTimeAreCollected']}")
                except Exception as modify_dt_time_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['check_record_events_that_modify_date_and_time_are_collected']: "
                                  f"{modify_dt_time_err}")

            def check_record_events_that_modify_user_or_group_are_collected():
                try:
                    output1 = extract_shell_info(r"grep identity /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep identity")

                    match1 = '''\
                        -w /etc/group -p wa -k identity
                        -w /etc/passwd -p wa -k identity
                        -w /etc/gshadow -p wa -k identity
                        -w /etc/shadow -p wa -k identity
                        -w /etc/security/opasswd -p wa -k identity\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["recordEventsThatModifyUserOrGroupAreCollected"] = "True"
                    else:
                        result["recordEventsThatModifyUserOrGroupAreCollected"] = "False"
                    logging.info(f"record_events_that_modify_user_or_group_are_collected_result: "
                                 f"{result['recordEventsThatModifyUserOrGroupAreCollected']}")
                except Exception as user_grp_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['check_record_events_that_modify_user_or_group_are_collected']: {user_grp_err}")

            def check_record_events_that_modify_network_are_collected():
                try:
                    output1 = extract_shell_info(r"grep system-locale /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep system-locale")

                    match1 = '''\
                        -w /etc/issue -p wa -k system-locale
                        -w /etc/issue.net -p wa -k system-locale
                        -w /etc/hosts -p wa -k system-locale
                        -w /etc/network -p wa -k system-locale\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["recordEventsThatModifyNetworkAreCollected"] = "True"
                    else:
                        result["recordEventsThatModifyNetworkAreCollected"] = "False"
                    logging.info(f"record_events_that_modify_network_are_collected_result: "
                                 f"{result['recordEventsThatModifyNetworkAreCollected']}")
                except Exception as modify_net_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['check_record_events_that_modify_network_are_collected']: {modify_net_err}")

            def check_record_events_that_modify_the_systems_mandatory_access_controls_are_collected():
                try:
                    output1 = extract_shell_info(r"grep MAC-policy /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep MAC-policy")

                    match1 = '''\
                        -w /etc/apparmor/ -p wa -k MAC-policy
                        -w /etc/apparmor.d/ -p wa -k MAC-policy\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["recordEventsThatModifyMandatoryAccessAreCollected"] = "True"
                    else:
                        result["recordEventsThatModifyMandatoryAccessAreCollected"] = "False"
                    logging.info(f"record_events_that_modify_the_systems_mandatory_access_"
                                 f"controls_are_collected_result: "
                                 f"{result['recordEventsThatModifyMandatoryAccessAreCollected']}")
                except Exception as system_mac_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['recordEventsThatModifyMandatoryAccessAreCollected']: "
                                  f"{system_mac_err}")

            def check_if_session_information_is_collected():
                try:
                    output1 = extract_shell_info(r"grep -E '(session|logins)' /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep '(session|logins)'")

                    match1 = '''\
                        -w /var/run/utmp -p wa -k session
                        -w /var/log/wtmp -p wa -k logins
                        -w /var/log/btmp -p wa -k logins\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["isSessionIniationCollected"] = "True"
                    else:
                        result["isSessionIniationCollected"] = "False"
                    logging.info(f"is_session_information_collected_result: {result['isSessionIniationCollected']}")
                except Exception as session_info_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isSessionIniationCollected']: {session_info_err}")

            def check_if_collect_discretionary_access_control_information_is_collected():
                try:
                    output1 = extract_shell_info(r"grep perm_mod /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'perm_mod'")

                    match1 = '''-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
                    auid!=4294967295 -k perm_mod -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F
                    auid>=1000 -F auid!=4294967295 -k perm_mod -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S
                    fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k
                    perm_mod'''
                    match2 = ''' -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F
                    key=perm_mod -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F
                    key=perm_mod -a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,
                    fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod'''
                    if output1 == match1 and output2 == match2:
                        result["isDiscretionaryAccessEventsCollected"] = "True"
                    else:
                        result["isDiscretionaryAccessEventsCollected"] = "False"
                    logging.info(f"isDiscretionaryAccessEventsCollected result: "
                                 f"{result['isDiscretionaryAccessEventsCollected']}")
                except Exception as access_control_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isDiscretionaryAccessEventsCollected']: "
                                  f"{access_control_err}")

            def check_if_unsuccessful_unauthorized_file_access_attempts_are_collected():
                try:
                    output1 = extract_shell_info(r"grep access /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'access'")

                    match1 = '''\
                        -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
                        ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
                        -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
                        ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
                        -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
                        ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
                        -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
                        ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\
                    '''
                    match2 = '''\
                        -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat
                        EACCES -F auid>=1000 -F auid!=-1 -F key=access
                        -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat
                        EACCES -F auid>=1000 -F auid!=-1 -F key=access
                        -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat
                        EPERM -F auid>=1000 -F auid!=-1 -F key=access
                        -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat
                        EPERM -F auid>=1000 -F auid!=-1 -F key=access\
                    '''
                    if output1 == match1 and output2 == match2:
                        result["isUnsuccessfulUnauthorizedAccessCollected"] = "True"
                    else:
                        result["isUnsuccessfulUnauthorizedAccessCollected"] = "False"
                    logging.info(f"isUnsuccessfulUnauthorizedAccessCollected result: "
                                 f"{result['isUnsuccessfulUnauthorizedAccessCollected']}")
                except Exception as unauth_file_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isUnsuccessfulUnauthorizedAccessCollected']: "
                                  f"{unauth_file_err}")

            def check_if_collect_successful_file_system_actions_are_collected():
                try:
                    output1 = extract_shell_info(r"grep mounts /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'mounts'")

                    match1 = '''\
                    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
                    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts\
                    '''

                    match2 = '''\
                    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts
                    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts\
                    '''
                    if output1 == match1 and output2 == match2:
                        result["isSuccessfulFilesystemCollected"] = "True"
                    else:
                        result["isSuccessfulFilesystemCollected"] = "False"
                    logging.info(f"isSuccessfulFilesystemCollected result: "
                                 f"{result['isSuccessfulFilesystemCollected']}")
                except Exception as file_system_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isSuccessfulFilesystemCollected']: "
                                  f"{file_system_err}")

            def check_if_collect_changes_to_system_administration_scope_are_collected():
                try:
                    output1 = extract_shell_info(r"grep scope /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'scope'")

                    match1 = '''\
                    -w /etc/sudoers -p wa -k scope
                    -w /etc/sudoers.d/ -p wa -k scope\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["isChangeToSystemAdministrativeScopeCollected"] = "True"
                    else:
                        result["isChangeToSystemAdministrativeScopeCollected"] = "False"
                    logging.info(f"isChangeToSystemAdministrativeScopeCollected result: "
                                 f"{result['isChangeToSystemAdministrativeScopeCollected']}")
                except Exception as admin_scope_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isChangeToSystemAdministrativeScopeCollected']: "
                                  f"{admin_scope_err}")

            def check_if_collect_kernel_module_loading_and_unloading_are_collected():
                try:
                    output1 = extract_shell_info(r"grep modules /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'modules'")

                    match1 = '''\
                    -w /sbin/insmod -p x -k modules
                    -w /sbin/rmmod -p x -k modules
                    -w /sbin/modprobe -p x -k modules
                    -a always,exit -F arch=b64 -S init_module -S delete_module -k modules\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["isKernelModuleLoadingAndUnloadingCollected"] = "True"
                    else:
                        result["isKernelModuleLoadingAndUnloadingCollected"] = "False"
                    logging.info(f"isKernelModuleLoadingAndUnloadingCollected result: "
                                 f"{result['isKernelModuleLoadingAndUnloadingCollected']}")

                except Exception as load_unload_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isKernelModuleLoadingAndUnloadingCollected']: "
                                  f"{load_unload_err}")

            def check_if_audit_configuration_is_immutable():
                try:
                    output1 = extract_shell_info(r'grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1')

                    if output1 == "-e 2":
                        result["isAuditConfigurationImmutable"] = "True"
                    else:
                        result["isAuditConfigurationImmutable"] = "False"
                    logging.info(f"is_audit_configuration_immutable_result: {result['isAuditConfigurationImmutable']}")
                except Exception as immutable_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"["f"'check_if_audit_configuration_is_immutable']: {immutable_err}")

            def check_audit_logs_not_automatically_deleted():
                try:
                    output = extract_shell_info("grep max_log_file_action /etc/audit/auditd.conf")
                    if "max_log_file_action = keep_logs" in output:
                        result["isAuditLogsAreNotAutomaticallyDeleted"] = "True"
                    else:
                        result["isAuditLogsAreNotAutomaticallyDeleted"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_audit_logs_not_automatically_deleted']: {e}")

            def check_login_and_logout_events_collected():
                try:
                    output1 = extract_shell_info("grep logins /etc/audit/rules.d/*.rules")
                    output2 = extract_info("auditctl -l | grep logins")
                    if ("-w /var/log/faillog -p wa -k logins" in output1 and
                            "-w /var/log/lastlog -p wa -k logins" in output2):
                        result["isLoginAndLogoutEventsCollected"] = "True"
                    else:
                        result["isLoginAndLogoutEventsCollected"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_login_and_logout_events_collected']: {e}")

            def check_file_deletion_events_by_user_collected():
                try:
                    output1 = extract_shell_info("grep delete /etc/audit/rules.d/*.rules")
                    output2 = extract_info("auditctl -l | grep delete")

                    if ("-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F" in output1
                            and "auid>=1000 -F auid!=4294967295 -k delete" in output1 and
                            "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F"
                            in output1 and "auid>=1000 -F auid!=4294967295 -k delete" in output1 and
                            "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F"
                            in output2 and "auid>=1000 -F auid!=4294967295 -k delete" in output2 and
                            "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F"
                            in output2 and "auid>=1000 -F auid!=4294967295 -k delete" in output2):
                        result["isFileDeletionEventsByUserCollected"] = "True"
                    else:
                        result["isFileDeletionEventsByUserCollected"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_file_deletion_events_by_user_collected']: {e}")

            def check_any_attempts_to_run_chcon_recorded():
                try:
                    output = extract_shell_info(
                        r"grep -E '^-a\s+always,exit\s+-F\s+path=/usr/bin/chcon\s+-F\s+perm=x' /etc/audit/audit.rules")
                    if output:
                        result["isAnyAttemptsToRunChconRecorded"] = "True"
                    else:
                        result["isAnyAttemptsToRunChconRecorded"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_any_attempts_to_run_chcon_recorded']: {e}")

            def check_write_log_files_to_persistent_disk():
                try:
                    output = extract_shell_info(r"grep -e ^\s*Storage /etc/systemd/journald.conf")
                    if "Storage=persistent" in output:
                        result["isWriteLogFilesToPersistentDisk"] = "True"
                    else:
                        result["isWriteLogFilesToPersistentDisk"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_write_log_files_to_persistent_disk']: {e}")

            def check_disable_system_on_audit_log_full():
                try:
                    output = extract_shell_info(
                        r"grep -E '^\s*admin_space_left_action\s*=\s*halt' /etc/audit/auditd.conf")
                    if "halt" in output:
                        result["isDisableSystemOnAuditLogFull"] = "True"
                    else:
                        result["isDisableSystemOnAuditLogFull"] = "False"
                except Exception as e:
                    logging.error(f"error['cisInfo']['is_disable_system_on_audit_log_full']: {e}")

            def check_journald_configured_to_compress_large_log_files():
                try:
                    output = extract_shell_info(r"grep -e ^\s*Compress /etc/systemd/journald.conf")
                    if "Compress=yes" in output:
                        result["isJournaldConfiguredToCompressLargeLogFiles"] = "True"
                    else:
                        result["isJournaldConfiguredToCompressLargeLogFiles"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_journald_configured_to_compress_large_log_files']: {e}")

            def check_use_of_privileged_commands_collected():
                try:
                    uid_min_command = "awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs"
                    uid_min_result = subprocess.run(uid_min_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)

                    if uid_min_result.returncode != 0:
                        result["isUseOfPrivilegedCommandsCollected"] = "False"
                        return

                    uid_min = uid_min_result.stdout.strip()

                    find_command = f"find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f"
                    find_result = subprocess.run(find_command, shell=True, stderr=subprocess.PIPE,
                                                 stdout=subprocess.PIPE, universal_newlines=True,
                                                 timeout=TIMEOUT_SUBPROCESS)

                    if find_result.returncode != 0:
                        result["isUseOfPrivilegedCommandsCollected"] = "False"
                        return

                    privileged_paths = find_result.stdout.splitlines()
                    audit_rules = []

                    for path in privileged_paths:
                        rule = (f"-a always,exit -F path={path} -F perm=x -F auid>={uid_min} "
                                f"-F auid!=4294967295 -k privileged")
                        audit_rules.append(rule)

                    # Check if all audit rules are present
                    for rule in audit_rules:
                        check_rule_command = f"grep -Fxq \"{rule}\" /etc/audit/rules.d/*.rules"
                        check_rule_result = subprocess.run(check_rule_command, shell=True, stderr=subprocess.PIPE,
                                                           stdout=subprocess.PIPE, universal_newlines=True,
                                                           timeout=TIMEOUT_SUBPROCESS)
                        if check_rule_result.returncode != 0:
                            result["isUseOfPrivilegedCommandsCollected"] = "False"
                            return

                    # Verify with auditctl
                    auditctl_command = "auditctl -l"
                    auditctl_result = subprocess.run(auditctl_command, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)

                    if auditctl_result.returncode != 0:
                        result["isUseOfPrivilegedCommandsCollected"] = "False"
                        return

                    auditctl_output = auditctl_result.stdout
                    for rule in audit_rules:
                        if rule not in auditctl_output:
                            result["isUseOfPrivilegedCommandsCollected"] = "False"
                            return

                    result["isUseOfPrivilegedCommandsCollected"] = "True"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_use_of_privileged_commands_collected']: {e}")

            check_if_audit_log_storage_size_configured()
            check_record_events_that_modify_date_and_time_are_collected()
            check_record_events_that_modify_user_or_group_are_collected()
            check_record_events_that_modify_network_are_collected()
            check_record_events_that_modify_the_systems_mandatory_access_controls_are_collected()
            check_if_session_information_is_collected()
            check_if_collect_discretionary_access_control_information_is_collected()
            check_if_unsuccessful_unauthorized_file_access_attempts_are_collected()
            check_if_collect_successful_file_system_actions_are_collected()
            check_if_collect_changes_to_system_administration_scope_are_collected()
            check_if_collect_kernel_module_loading_and_unloading_are_collected()
            check_if_audit_configuration_is_immutable()
            check_audit_logs_not_automatically_deleted()
            check_login_and_logout_events_collected()
            check_file_deletion_events_by_user_collected()
            check_any_attempts_to_run_chcon_recorded()
            check_write_log_files_to_persistent_disk()
            check_disable_system_on_audit_log_full()
            check_journald_configured_to_compress_large_log_files()
            check_use_of_privileged_commands_collected()

        except Exception as er:
            logging.error(f"error['cisInfo']['cis_logging_and_auditing']: {er}")

        return result

    # CIS Section 5.1
    @logger_function
    def cis_system_access_and_authentication():
        result = {
            "isCronDaemonEnabled": "Not Configured",
            "isPermissionsOnEtcCrontabSet": "Not Configured",
            "isPermissionsOnEtcCronHourlySet": "Not Configured",
            "isPermissionsOnEtcCronDailySet": "Not Configured",
            "isPermissionsOnEtcCronWeeklySet": "Not Configured",
            "isPermissionsOnEtcCronMonthlySet": "Not Configured",
            "isPermissionsOnEtcCronDSet": "Not Configured",
        }
        try:
            def check_if_cron_daemon_is_enabled():
                try:
                    output1 = extract_info(r"systemctl is-enabled crond")
                    output2 = extract_info(r"systemctl is-active crond")
                    if output1 == "enabled" and output2 == "active":
                        result["isCronDaemonEnabled"] = "True"
                    else:
                        result["isCronDaemonEnabled"] = "False"
                    logging.info(f"is_cron_daemon_enabled_result: {result['isCronDaemonEnabled']}")
                except Exception as cron_daemon_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_cron_daemon_is_enabled']: {cron_daemon_err}")

            def check_if_permissions_are_set_on_etc_crontab():
                try:
                    output = extract_shell_info(r"stat /etc/crontab | grep -E '^Access:'")
                    if "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCrontabSet"] = "True"
                    else:
                        result["isPermissionsOnEtcCrontabSet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_crontab_result: {result['isPermissionsOnEtcCrontabSet']}")
                except Exception as crontab_error:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_crontab']: {crontab_error}")

            def check_if_permissions_are_set_on_etc_cron_hourly():
                try:
                    output = extract_shell_info(r"stat /etc/cron.hourly | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronHourlySet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronHourlySet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_hourly_result: "
                                 f"{result['isPermissionsOnEtcCronHourlySet']}")
                except Exception as cron_hourly_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_hourly']: {cron_hourly_err}")

            def check_if_permissions_are_set_on_etc_cron_daily():
                try:
                    output = extract_shell_info(r"stat /etc/cron.daily | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronDailySet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronDailySet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_daily_result: "
                                 f"{result['isPermissionsOnEtcCronDailySet']}")
                except Exception as cron_daily_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_daily']: {cron_daily_err}")

            def check_if_permissions_are_set_on_etc_cron_weekly():
                try:
                    output = extract_shell_info(r"stat /etc/cron.weekly | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronWeeklySet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronWeeklySet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_weekly_result: "
                                 f"{result['isPermissionsOnEtcCronWeeklySet']}")
                except Exception as cron_weekly_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_weekly']: {cron_weekly_err}")

            def check_if_permissions_are_set_on_etc_cron_monthly():
                try:
                    output = extract_shell_info(r"stat /etc/cron.monthly | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronMonthlySet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronMonthlySet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_monthly_result: "
                                 f"{result['isPermissionsOnEtcCronMonthlySet']}")
                except Exception as cron_monthly_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_monthly']: {cron_monthly_err}")

            def check_if_permissions_are_set_on_etc_cron_d():
                try:
                    output = extract_shell_info(r"stat /etc/cron.d | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronDSet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronDSet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_d_result: {result['isPermissionsOnEtcCronDSet']}")
                except Exception as permission_on_ceond_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_d']: {permission_on_ceond_err}")

            check_if_cron_daemon_is_enabled()
            check_if_permissions_are_set_on_etc_crontab()
            check_if_permissions_are_set_on_etc_cron_hourly()
            check_if_permissions_are_set_on_etc_cron_daily()
            check_if_permissions_are_set_on_etc_cron_weekly()
            check_if_permissions_are_set_on_etc_cron_monthly()
            check_if_permissions_are_set_on_etc_cron_d()

        except Exception as er:
            logging.error(f"error['cisInfo']['cis_system_access_and_authentication']: {er}")

        return result

    # CIS Section 5.2
    @logger_function
    def cis_configure_ssh_server():
        result = {
            "arePermissionsOnEtcSshdSshdConfigRestrictive": "Not Configured",
            "isSSHPamEnabled": "Not Configured",
            "isSSHRootLoginDisabled": "Not Configured",
            "isSSHHostBasedAuthenticationDisabled": "Not Configured",
            "isSSHPermitEmptyPasswordsDisabled": "Not Configured",
            "isSSHPermitUserEnvironmentDisabled": "Not Configured",
            "isSSHIgnoreRhostsEnabled": "Not Configured",
            "isSSHX11ForwardingDisabled": "Not Configured",
            "isSSHAllowTcpForwardingDisabled": "Not Configured",
            "isSSHMaxAuthTriesSetTo4OrLess": "Not Configured",
            "isSSHMaxSessionSetTo10OrLess": "Not Configured",
            'isSSHLoginGraceTimeSetTo60SecondsOrLess': 'Not Configured',
        }

        try:
            def check_permissions_are_root_and_restrictive(base_command, permission_limit):
                try:
                    # Are permissions on /etc/passwd root and restrictive
                    logging.info("started function: check_permissions_are_root_and_restrictive()")
                    logging.info(f"base_command: {base_command}")
                    logging.info(f"permission_limit: {permission_limit}")

                    stat_command = f"{base_command} | grep Uid"
                    stat_command_result = subprocess.run(stat_command, shell=True, capture_output=True, text=True,
                                                         timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"stat_command_result: {stat_command_result}")
                    logging.info(f"stat_command_result.stdout: {stat_command_result.stdout}")

                    stat_command_to_extract_permissions = \
                        (f"{base_command} | grep Uid | "
                         r"awk '{print $2}' | awk -F/ '{print $1}' | tr -d '('")

                    logging.info(f"stat_command_to_extract_permissions: {stat_command_to_extract_permissions}")

                    stat_command_permissions_result = subprocess.run(stat_command_to_extract_permissions, shell=True,
                                                                     capture_output=True, text=True,
                                                                     timeout=TIMEOUT_SUBPROCESS)

                    logging.info(f"stat_command_permissions_result: {stat_command_permissions_result}")
                    logging.info(f"stat_command_permissions_result.returncode: "
                                 f"{stat_command_permissions_result.returncode}")
                    logging.info(f"stat_command_permissions_result.stdout: {stat_command_permissions_result.stdout}")

                    # Extract the permission number
                    permission_number = stat_command_permissions_result.stdout.strip()
                    logging.info(f"Permission number: {permission_number}")
                    if permission_number:
                        permission_number = int(permission_number)

                        # Extract Uid and Gid using regex
                        uid_match = re.search(r'Uid: \(\s*(\d+)/\s*([\w-]+)\)', stat_command_result.stdout)
                        gid_match = re.search(r'Gid: \(\s*(\d+)/\s*([\w-]+)\)', stat_command_result.stdout)

                        # Check if Uid and Gid are both 0/root
                        uid_condition = uid_match and uid_match.group(1) == '0' and uid_match.group(2) == 'root'
                        gid_condition = (gid_match and (gid_match.group(1) == '0' and gid_match.group(2) == 'root') or
                                         (gid_match.group(1) == '42' and gid_match.group(2) == 'shadow'))

                        logging.info(f"Uid condition: {uid_condition}")
                        logging.info(f"Gid condition: {gid_condition}")

                        # Check if Uid and Gid are both 0/root and Access is more restrictive
                        if uid_condition and gid_condition and permission_number <= permission_limit:
                            logging.info(
                                f"All permissions on /etc/ssh/sshd_config are set to "
                                f"{permission_limit} or more restrictive")
                            return "True"
                        logging.info(
                            f"Not all permissions on /etc/ssh/sshd_config are set to "
                            f"{permission_limit} or more restrictive")
                        return "False"
                    else:
                        logging.info("No permissions found on /etc/ssh/sshd_config")
                        return "Not Configured"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_permissions_are_root_and_restrictive"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_permissions_are_root_and_restrictive(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_pam():
                try:
                    logging.info("started function: check_ssh_pam()")
                    base_command = r"grep -Ei '^\s*UsePAM\s+no' /etc/ssh/sshd_config"

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 1:
                        logging.info("SSH PAM is enabled")
                        return "True"
                    else:
                        logging.info("SSH PAM is not enabled")
                        return "False"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_pam"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_pam(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_root_login_disabled():
                try:
                    logging.info("started function: check_ssh_root_login_disabled()")
                    base_command = r"grep -Ei '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config"

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 0:
                        logging.info("SSH root login is disabled")
                        return "True"
                    else:
                        logging.info("SSH root login is not enabled")
                        return "False"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_root_login_disabled"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_root_login_disabled(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_host_based_authentication_disabled():
                try:
                    logging.info("started function: check_ssh_host_based_authentication_disabled()")
                    base_command = r'''
                            sshd -T -C user=root -C host="$(hostname)" -C
                            addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" |
                            grep hostbasedauthentication
                            '''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")
                    logging.info(f"command_result.stdout.strip(): {command_result.stdout.strip()}")

                    if command_result.returncode == 0 and "hostbasedauthentication no" in command_result.stdout.strip():
                        logging.info("SSH host based authentication is disabled")
                        return "True"
                    else:
                        logging.info("SSH host based authentication is not enabled")
                        return "False"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_host_based_authentication_disabled"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_host_based_authentication_disabled(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_permit_empty_passwords_disabled():
                try:
                    logging.info("started function: check_ssh_permit_empty_passwords_disabled()")
                    base_command = r'''
                            sshd -T -C user=root -C host="$(hostname)" -C
                            addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" |
                            grep permitemptypasswords
                            '''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 0 and "permitemptypasswords no" in command_result.stdout.strip():
                        logging.info("SSH permit empty passwords is disabled")
                        return "True"
                    else:
                        logging.info("SSH permit empty passwords is not enabled")
                        return "False"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_permit_empty_passwords_disabled"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_permit_empty_passwords_disabled(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_permit_user_environment_disabled():
                try:
                    logging.info("started function: check_ssh_permit_user_environment_disabled()")
                    base_command = r'''
                            sshd -T -C user=root -C host="$(hostname)" -C
                            addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" |
                            grep permituserenvironment
                            '''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 0 and "permituserenvironment no" in command_result.stdout.strip():
                        logging.info("SSH permit user environment is disabled")
                        return "True"
                    else:
                        logging.info("SSH permit user environment is not enabled")
                        return "False"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_permit_user_environment_disabled"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_permit_user_environment_disabled(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_ignore_rhosts_enabled():
                try:
                    logging.info("started function: check_ssh_ignore_hosts_enabled()")
                    base_command = r'''
                                    sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts |
                                    awk '{print $1}')" | grep ignorerhosts
                                    '''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 0 and "ignorerhosts yes" in command_result.stdout.strip():
                        logging.info("SSH ignore hosts is enabled")
                        return "True"
                    else:
                        logging.info("SSH ignore hosts is not enabled")
                        return "False"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_ignore_hosts_enabled"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_ignore_hosts_enabled(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_x11_forwarding_disabled():
                try:
                    logging.info("started function: check_ssh_x11_forwarding_disabled()")
                    base_command = r'''
                                    sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts |
                                    awk '{print $1}')" | grep -i x11forwarding
                                    '''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 0 and "x11forwarding no" in command_result.stdout.strip():
                        logging.info("SSH X11 forwarding is disabled")
                        return "True"
                    else:
                        logging.info("SSH X11 forwarding is not enabled")
                        return "False"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_x11_forwarding_disabled"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_x11_forwarding_disabled(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_allow_tcp_forwarding_disabled():
                try:
                    logging.info("started function: check_ssh_allow_tcp_forwarding_disabled()")
                    base_command = r'''
                                    sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts |
                                    awk '{print $1}')" | grep -i allowtcpforwarding
                                    '''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 0 and "allowtcpforwarding no" in command_result.stdout.strip():
                        logging.info("SSH allow tcp forwarding is disabled")
                        return "True"
                    else:
                        logging.info("SSH allow tcp forwarding is not enabled")
                        return "False"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_allow_tcp_forwarding_disabled"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_allow_tcp_forwarding_disabled(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_max_auth_tries():
                try:
                    logging.info("started function: check_ssh_max_auth_tries()")
                    base_command = r'''
                                    sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts |
                                    awk '{print $1}')" | grep maxauthtries | awk '{print $2}'
                                    '''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    fetched_max_auth_tries = command_result.stdout.strip()
                    logging.info(f"fetched_max_auth_tries: {fetched_max_auth_tries}")
                    if fetched_max_auth_tries:
                        fetched_max_auth_tries = int(fetched_max_auth_tries)

                        if command_result.returncode == 0 and fetched_max_auth_tries <= 4:
                            logging.info("SSH max auth tries is set to 4 or less")
                            return "True"
                        else:
                            logging.info("SSH max auth tries is not set to 4 or less")
                            return "False"
                    else:
                        logging.info("SSH max auth tries is not configured")
                        return "Not Configured"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_max_auth_tries"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_max_auth_tries(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_max_sessions():
                try:
                    logging.info("started function: check_ssh_max_sessions()")
                    base_command = r'''
                                    sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts |
                                    awk '{print $1}')" | grep maxsessions | awk '{print $2}'
                                    '''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    fetched_max_sessions = command_result.stdout.strip()
                    logging.info(f"fetched_max_sessions: {fetched_max_sessions}")
                    if fetched_max_sessions:
                        fetched_max_sessions = int(fetched_max_sessions)

                        if command_result.returncode == 0 and fetched_max_sessions <= 10:
                            logging.info("SSH max sessions is set to 10 or less")
                            return "True"
                        else:
                            logging.info("SSH max sessions is not set to 10 or less")
                            return "False"
                    else:
                        logging.info("SSH max sessions is not configured")
                        return "Not Configured"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_max_sessions"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_max_sessions(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            def check_ssh_login_grace_time():
                try:
                    logging.info("started function: check_ssh_login_grace_time()")
                    base_command = r'''
                                    sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts |
                                    awk '{print $1}')" | grep logingracetime | awk '{print $2}'
                                    '''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    fetched_login_grace_time = command_result.stdout.strip()
                    logging.info(f"fetched_login_grace_time: {fetched_login_grace_time}")
                    if fetched_login_grace_time:
                        fetched_login_grace_time = int(fetched_login_grace_time)

                        if command_result.returncode == 0 and fetched_login_grace_time <= 60:
                            logging.info("SSH login grace time is set to 60 or less")
                            return "True"
                        else:
                            logging.info("SSH login grace time is not set to 60 or less")
                            return "False"
                    else:
                        logging.info("SSH login grace time is not configured")
                        return "Not Configured"
                except Exception as cis_configure_ssh_server_error:
                    error["cisInfo"]["cis_configure_ssh_server"]["check_ssh_login_grace_time"] = (
                        repr(cis_configure_ssh_server_error))
                    logging.error(f"Error in cis_configure_ssh_server->check_ssh_login_grace_time(): "
                                  f"{cis_configure_ssh_server_error}")
                    return "Not Configured"

            result["arePermissionsOnEtcSshdSshdConfigRestrictive"] = (
                check_permissions_are_root_and_restrictive("stat /etc/ssh/sshd_config", 600))

            result["isSSHPamEnabled"] = check_ssh_pam()
            result["isSSHRootLoginDisabled"] = check_ssh_root_login_disabled()
            result["isSSHHostBasedAuthenticationDisabled"] = check_ssh_host_based_authentication_disabled()
            result["isSSHPermitEmptyPasswordsDisabled"] = check_ssh_permit_empty_passwords_disabled()
            result["isSSHPermitUserEnvironmentDisabled"] = check_ssh_permit_user_environment_disabled()
            result["isSSHIgnoreRhostsEnabled"] = check_ssh_ignore_rhosts_enabled()
            result["isSSHX11ForwardingDisabled"] = check_ssh_x11_forwarding_disabled()
            result["isSSHAllowTcpForwardingDisabled"] = check_ssh_allow_tcp_forwarding_disabled()
            result["isSSHMaxAuthTriesSetTo4OrLess"] = check_ssh_max_auth_tries()
            result["isSSHMaxSessionSetTo10OrLess"] = check_ssh_max_sessions()
            result['isSSHLoginGraceTimeSetTo60SecondsOrLess'] = check_ssh_login_grace_time()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_ssh_server']: {err}")
        return result

    # CIS Section 5.3
    @logger_function
    def cis_configure_privilege_escalation():
        """
        Generates the configuration for privilege escalation.

        Returns:
            dict: A dictionary containing the configuration for privilege escalation. The keys
            of the dictionary are the different aspects of privilege escalation, and the values
            are the corresponding configuration status. The possible configuration status values
            are "True", "False", and "Not Configured".

            - "isSudoInstalled": Indicates whether the "sudo" package is installed.
            - "doSudoCommandsUsePty": Indicates whether sudo commands use pseudo-terminals (pty).
            - "doesSudoLogFileExist": Indicates whether the sudo log file exists.
            - "doUsersProvidePasswordForPrivilegeEscalation": Indicates whether users provide a password
                for privilege escalation.
            - "isReauthenticationForPrivilegeEscalationNotDisabledGlobally": Indicates whether reauthentication
                for privilege escalation is disabled globally.
            - "isSudoAuthenticationTimeoutConfigured": Indicates whether the sudo authentication timeout is configured.
            - "isAccessToSuCommandRestricted": Indicates whether access to the "su" command is restricted.
        """

        result = {
            "isSudoInstalled": "Not Configured",
            "doSudoCommandsUsePty": "Not Configured",
            "doesSudoLogFileExist": "Not Configured",
            "doUsersProvidePasswordForPrivilegeEscalation": "Not Configured",
            "isReauthenticationForPrivilegeEscalationNotDisabledGlobally": "Not Configured",
            "isSudoAuthenticationTimeoutConfigured": "Not Configured",
            "isAccessToSuCommandRestricted": "Not Configured",
        }

        try:
            def check_sudo_installed():
                try:
                    logging.info("started function: check_sudo_installed()")

                    base_command = (
                        "dpkg-query -W sudo sudo-ldap > /dev/null 2>&1 && "
                        "dpkg-query -W -f='${binary:Package}\\t${Status}\\t${db:Status-Status}\\n' "
                        "sudo sudo-ldap | awk '($4==\"installed\" && $NF==\"installed\") {"
                        "print \"\\nPASS:\\nPackage \\\"\"$1\"\\\" is installed\\n\"}' || "
                        "echo -e \"\\nFAIL:\\nneither \\\"sudo\\\" or \\\"sudo-ldap\\\" package is installed\\n\""
                    )

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 0:
                        if "PASS" in command_result.stdout:
                            logging.info("Sudo is installed")
                            return "True"
                        else:
                            logging.info("Sudo is not installed")
                            return "False"
                    else:
                        logging.error(f"Error executing command. Return code: {command_result.returncode}")
                        return "Not Configured"
                except Exception as cis_configure_privilege_escalation_error:
                    error["cisInfo"]["cis_configure_privilege_escalation"]["check_sudo_installed"] = (
                        repr(cis_configure_privilege_escalation_error))
                    logging.error(f"error['cisInfo']['cis_configure_privilege_escalation']: "
                                  f"{cis_configure_privilege_escalation_error}")
                    return "Not Configured"

            def check_sudo_command_use_pty():
                try:
                    logging.info("started function: check_sudo_command_use_pty()")

                    base_command = (r"grep -rPi '^\h*Defaults\h+([^#\n\r]+,)?use_pty(,\h*\h+\h*)*\h*(#.*)?$' "
                                    r"/etc/sudoers*")

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    expected_output = "/etc/sudoers:Defaults\tuse_pty"
                    logging.info(f"command_result.stdout.strip(): {command_result.stdout.strip()}")

                    if command_result.returncode == 0:
                        if expected_output in command_result.stdout.strip():
                            logging.info("Sudo commands use pty")
                            return "True"
                        else:
                            logging.info("Sudo commands does not use pty")
                            return "False"
                    else:
                        logging.error(f"Error executing command. Return code: {command_result.returncode}")
                        return "Not Configured"
                except Exception as cis_configure_privilege_escalation_error:
                    error["cisInfo"]["cis_configure_privilege_escalation"]["check_sudo_command_use_pty"] = (
                        repr(cis_configure_privilege_escalation_error))
                    logging.error(f"error['cisInfo']['cis_configure_privilege_escalation']: "
                                  f"{cis_configure_privilege_escalation_error}")
                    return "Not Configured"

            def check_sudo_log_file_exists():
                try:
                    pattern = (
                        r"^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$"
                    )

                    # Only check real sudoers files
                    sudoers_files = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")

                    if not sudoers_files:
                        logging.warning("No sudoers files found to check.")
                        return "Not Configured"

                    command = ["grep", "-Psi", pattern] + sudoers_files
                    logging.info("started function: check_sudo_log_file_exists()")
                    logging.info(f"Running command: {' '.join(command)}")

                    command_result = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=TIMEOUT_SUBPROCESS
                    )

                    logging.info(f"Command output: {command_result.stdout.strip()}")
                    logging.info(f"Command stderr: {command_result.stderr.strip()}")

                    if command_result.returncode == 0:
                        logging.info("Sudo log file exists")
                        return "True"
                    else:
                        logging.info("Sudo log file does not exist")
                        return "False"
                except Exception as cis_configure_privilege_escalation_error:
                    logging.error(f"Error in check_sudo_log_file_exists: "
                                  f"{cis_configure_privilege_escalation_error}")
                    return "Not Configured"

            def check_users_provide_pwd_for_privilege_escalation():
                try:
                    logging.info("started function: check_users_provide_pwd_for_privilege_escalation()")

                    base_command = 'grep -r "^[^#].*NOPASSWD" /etc/sudoers*'

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 1:
                        logging.info("Users provide password for privilege escalation")
                        return "True"
                    else:
                        logging.info("Users do not provide password for privilege escalation")
                        return "False"
                except Exception as cis_configure_privilege_escalation_error:
                    cis_function_name = "check_users_provide_pwd_for_privilege_escalation"
                    error["cisInfo"]["cis_configure_privilege_escalation"][cis_function_name]["def"] = (
                        repr(cis_configure_privilege_escalation_error))
                    logging.error(f"error['cisInfo']['cis_configure_privilege_escalation']: "
                                  f"{cis_configure_privilege_escalation_error}")
                    return "Not Configured"

            def check_reauthentication_disabled():
                try:
                    logging.info("started function: check_reauthentication_disabled()")

                    base_command = r'grep -r "^[^#].*\!authenticate" /etc/sudoers*'

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 1:
                        logging.info("Reauthentication for privilege escalation is not disabled")
                        return "True"
                    else:
                        logging.info("Reauthentication for privilege escalation is disabled")
                        return "False"
                except Exception as cis_configure_privilege_escalation_error:
                    error["cisInfo"]["cis_configure_privilege_escalation"]["check_reauthentication_disabled"] = (
                        repr(cis_configure_privilege_escalation_error))
                    logging.error(f"error['cisInfo']['cis_configure_privilege_escalation']: "
                                  f"{cis_configure_privilege_escalation_error}")
                    return "Not Configured"

            def check_sudo_authentication_timeout():
                try:
                    logging.info("started function: check_sudo_authentication_timeout()")

                    base_command = r'grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers*'

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 1:
                        logging.info("Sudo authentication timeout is not configured")
                        return "False"
                    else:
                        logging.info("Sudo authentication timeout is configured")
                        return "True"
                except Exception as cis_configure_privilege_escalation_error:
                    error["cisInfo"]["cis_configure_privilege_escalation"]["check_sudo_authentication_timeout"] = (
                        repr(cis_configure_privilege_escalation_error))
                    logging.error(f"error['cisInfo']['cis_configure_privilege_escalation']: "
                                  f"{cis_configure_privilege_escalation_error}")
                    return "Not Configured"

            def check_access_to_su_command_restricted():
                base_command = (
                    r"grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)"
                    r"(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$'"
                    r" /etc/pam.d/su"
                )
                try:
                    logging.info("started function: check_access_to_su_command_restricted()")
                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 1:
                        logging.info("Access to su command is not restricted")
                        return "False"
                    else:
                        logging.info("Access to su command is restricted")
                        return "True"
                except Exception as cis_configure_privilege_escalation_error:
                    error["cisInfo"]["cis_configure_privilege_escalation"]["check_access_to_su_command_restricted"] = (
                        repr(cis_configure_privilege_escalation_error))
                    logging.error(f"error['cisInfo']['cis_configure_privilege_escalation']: "
                                  f"{cis_configure_privilege_escalation_error}")
                    return "Not Configured"

            result["isSudoInstalled"] = check_sudo_installed()
            result["doSudoCommandsUsePty"] = check_sudo_command_use_pty()
            result["doesSudoLogFileExist"] = check_sudo_log_file_exists()
            result["doUsersProvidePasswordForPrivilegeEscalation"] = (
                check_users_provide_pwd_for_privilege_escalation())
            result["isReauthenticationForPrivilegeEscalationNotDisabledGlobally"] = check_reauthentication_disabled()
            result["isSudoAuthenticationTimeoutConfigured"] = check_sudo_authentication_timeout()
            result["isAccessToSuCommandRestricted"] = check_access_to_su_command_restricted()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_privilege_escalation']: {err}")
        return result

    # CIS Section 5.4
    @logger_function
    def cis_configure_pam():
        result = {
            "arePamCreationRequirementsConfigured": "Not Configured",
            "isLockoutForFailedPasswordsConfigured": "Not Configured",
            "isPasswordReuseLimited": "Not Configured",
            "isPasswordHashingAlgorithmLatest": "Not Configured",
            "doAllCurrentPasswordsUseConfiguredHashingAlgorithm": "Not Configured",
        }

        try:
            def check_requirements_configured(base_command):
                try:
                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 0:
                        logging.info("PAM creation requirements are configured")
                        return "True"
                    else:
                        logging.info("PAM creation requirements are not configured")
                        return "False"
                except Exception as cis_configure_pam_error:
                    error["cisInfo"]["cis_configure_pam"]["check_requirements_configured"] = (
                        repr(cis_configure_pam_error))
                    logging.error(f"error['cisInfo']['cis_configure_pam']: {cis_configure_pam_error}")
                    return "Not Configured"

            def check_password_hashing_algorithm():
                try:
                    logging.info("started function: check_password_hashing_algorithm()")

                    base_command_1 = \
                        (r'grep -v ^# /etc/pam.d/common-password | grep -E "('
                         r'yescrypt|md5|bigcrypt|sha256|sha512|blowfish)"')

                    logging.info(f"Running command: {base_command_1}")
                    command_result_1 = subprocess.run(base_command_1, shell=True, capture_output=True, text=True,
                                                      timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result_1}")

                    base_command_2 = r'grep -i "^\s*ENCRYPT_METHOD\s*yescrypt\s*$" /etc/login.defs'

                    logging.info(f"Running command: {base_command_2}")
                    command_result_2 = subprocess.run(base_command_2, shell=True, capture_output=True, text=True,
                                                      timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result_2}")

                    if (command_result_2.returncode == 0 and "ENCRYPT_METHOD yescrypt" in
                            command_result_2.stdout.strip() and command_result_1.stdout == ""):
                        return "True"
                    else:
                        return "False"

                except Exception as cis_configure_pam_error:
                    error["cisInfo"]["cis_configure_pam"]["check_password_hashing_algorithm"] = (
                        repr(cis_configure_pam_error))
                    logging.error(f"error['cisInfo']['cis_configure_pam']: {cis_configure_pam_error}")
                    return "Not Configured"

            def check_password_hashes():
                logging.info("started function: check_password_hashes()")

                bash_script = r"""
                declare -A HASH_MAP=( ["y"]="yescrypt" ["1"]="md5" ["2"]="blowfish"
                ["5"]="SHA256" ["6"]="SHA512" ["g"]="gost-yescrypt" )
                CONFIGURED_HASH=$(sed -n "s/^\s*ENCRYPT_METHOD\s*\(.*\)\s*$/\\1/p" /etc/login.defs)
                for MY_USER in $(sed -n "s/^\(.*\):\\$.*/\\1/p" /etc/shadow)
                do
                    CURRENT_HASH=$(sed -n "s/${MY_USER}:\\$\\(.\).*/\\1/p" /etc/shadow)
                    if [[ "${HASH_MAP["${CURRENT_HASH}"]^^}" != "${CONFIGURED_HASH^^}" ]];
                    then
                        echo "The password for '${MY_USER}' is using '${HASH_MAP["${CURRENT_HASH}"]}'
                        instead of the configured '${CONFIGURED_HASH}'."
                    fi
                done
                """

                try:
                    command_result = subprocess.run(['bash', '-c', bash_script], capture_output=True, text=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")
                    if command_result.returncode == 0:
                        logging.info(command_result.stdout)
                        return "False"
                    else:
                        logging.info(f"Error executing Bash script. Return code: {command_result.returncode}")
                        logging.info(command_result.stderr)
                        return "True"
                except Exception as cis_configure_pam_error:
                    error["cisInfo"]["cis_configure_pam"]["check_password_hashes"] = (
                        repr(cis_configure_pam_error))
                    logging.error(f"error['cisInfo']['cis_configure_pam']: {cis_configure_pam_error}")
                    return "Not Configured"

            result["arePamCreationRequirementsConfigured"] = (
                check_requirements_configured(r"grep '^\s*minlen\s*' /etc/security/pwquality.conf"))

            result["isLockoutForFailedPasswordsConfigured"] = (
                check_requirements_configured(r'grep "pam_faillock.so" /etc/pam.d/common-auth'))

            command_to_check_password_reuse_limited = (r"grep -P "
                                                       r"'^\h*password\h+([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?"
                                                       r"remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/common-password")

            result["isPasswordReuseLimited"] = (
                check_requirements_configured(command_to_check_password_reuse_limited))

            result["isPasswordHashingAlgorithmLatest"] = check_password_hashing_algorithm()

            result["doAllCurrentPasswordsUseConfiguredHashingAlgorithm"] = check_password_hashes()

        except Exception as cis_configure_pam_err:
            logging.error(f"error['cisInfo']['cis_configure_pam']: {cis_configure_pam_err}")
        return result

    # CIS Section 5.5
    @logger_function
    def cis_user_accounts_environment_details():
        logging.info("Starting function user_accounts_environment_details")
        result = {
            "isPassMinDaysGreaterThan0Days": "Not Configured",
            "isPassMaxDaysLessThan366Days": "Not Configured",
            "isPassWarnAgeGreaterThan6Days": "Not Configured",
            "isInactiveAccountsWithPasswordExpiredLessThan30Days": "Not Configured",
            "didAllUsersChangedPasswordsInPast": "Not Configured",
            "areSystemAccountsSecured": "Not Configured",
            "isDefaultGroupForRootAccountGid0": "Not Configured",
        }

        try:
            def retrieve_command_output(command_input):
                try:
                    base_command = (f"grep -v '^#' /etc/login.defs | grep {command_input} | "
                                    r"awk '{print $2}'")
                    logging.info(f"base_command: {base_command}")

                    subprocess_base_command_result = subprocess.run(base_command, shell=True, capture_output=True,
                                                                    text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {subprocess_base_command_result}")

                    if subprocess_base_command_result.returncode == 0:
                        command_output = subprocess_base_command_result.stdout.strip()
                        logging.info(f"command_output: {command_output}")
                    else:
                        command_output = "-999"
                        logging.info(f"command_output: {command_output}")

                    logging.info(f"type(command_output): {type(command_output)}")
                    return command_output
                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    error["cisInfo"]["cis_user_accounts_environment_details"]["retrieve_command_output"] \
                        = repr(cis_err)
                    return "-999"

            def check_pass_min_days_greater_than_0():
                check_pass_min_days_result = "Not Configured"
                try:
                    pass_min_days = int(retrieve_command_output("PASS_MIN_DAYS"))
                    logging.info(f"pass_min_days: {pass_min_days} and type(pass_min_days): {type(pass_min_days)}")
                    if pass_min_days:
                        if pass_min_days != -999:
                            if pass_min_days > 0:
                                check_pass_min_days_result = "True"
                            else:
                                check_pass_min_days_result = "False"
                        else:
                            check_pass_min_days_result = "Not Configured"
                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    error["cisInfo"]["cis_user_accounts_environment_details"]["check_pass_min_days_greater_than_0"] \
                        = repr(cis_err)
                return check_pass_min_days_result

            def check_pass_max_days_less_than_366():
                check_pass_max_days_result = "Not Configured"
                try:
                    pass_max_days = int(retrieve_command_output("PASS_MAX_DAYS"))
                    logging.info(f"pass_max_days: {pass_max_days} and type(pass_max_days): {type(pass_max_days)}")
                    if pass_max_days:
                        if pass_max_days != -999:
                            if pass_max_days < 366:
                                check_pass_max_days_result = "True"
                            else:
                                check_pass_max_days_result = "False"
                        else:
                            check_pass_max_days_result = "Not Configured"
                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    error["cisInfo"]["cis_user_accounts_environment_details"]["check_pass_max_days_less_than_366"] \
                        = repr(cis_err)
                return check_pass_max_days_result

            def check_pass_warn_age_greater_than_6():
                check_pass_warn_age_result = "Not Configured"
                try:
                    pass_warn_age = int(retrieve_command_output("PASS_WARN_AGE"))
                    logging.info(f"pass_warn_age: {pass_warn_age} and type(pass_warn_age): {type(pass_warn_age)}")
                    if pass_warn_age:
                        if pass_warn_age != -999:
                            if pass_warn_age > 6:
                                return "True"
                            else:
                                return "False"
                        else:
                            return "Not Configured"

                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    error["cisInfo"]["cis_user_accounts_environment_details"]["check_pass_warn_age_greater_than_6"] \
                        = repr(cis_err)
                return check_pass_warn_age_result

            def check_inactive_accounts_with_password_expired_less_than_30():
                try:
                    base_command = "useradd -D | grep INACTIVE | awk -F= '{print $2}'"
                    logging.info(f"base_command: {base_command}")

                    subprocess_base_command_result = subprocess.run(base_command, shell=True, capture_output=True,
                                                                    text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {subprocess_base_command_result}")

                    if subprocess_base_command_result.returncode == 0:
                        command_output = subprocess_base_command_result.stdout.strip()
                        logging.info(f"command_output: {command_output}")
                        if int(command_output) < 31:
                            command_result = "True"
                        else:
                            command_result = "False"
                    else:
                        command_output = "-999"
                        logging.info(f"command_output: {command_output}")
                        command_result = "Not Configured"

                    logging.info(f"command_result: {command_result}")
                    return command_result
                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    cis_function_name = "check_inactive_accounts_with_password_expired_less_than_30"
                    error["cisInfo"]["cis_user_accounts_environment_details"][cis_function_name] = repr(cis_err)
                    return "Not Configured"

            def check_commands_results(base_command):
                try:
                    logging.info(f"base_command: {base_command}")

                    subprocess_base_command_result = subprocess.run(base_command, shell=True, capture_output=True,
                                                                    text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {subprocess_base_command_result}")

                    if subprocess_base_command_result.returncode == 0:
                        command_output = subprocess_base_command_result.stdout.strip()
                        logging.info(f"command_output: {command_output}")
                        if command_output == "":
                            command_result = "True"
                        else:
                            command_result = "False"
                    else:
                        command_result = "Not Configured"

                    logging.info(f"command_result: {command_result}")
                    return command_result
                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    cis_function_name = "check_commands_results"
                    error["cisInfo"]["cis_user_accounts_environment_details"][cis_function_name] = repr(cis_err)
                    return "Not Configured"

            def check_all_users_changed_passwords_in_past():
                logging.info("started function: check_all_users_changed_passwords_in_past()")
                # All users should have a password change date in the past
                base_command = r'''awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; \
                                            do change=$(date -d "$(chage --list $usr | grep '^Last password change' \
                                            | cut -d: -f2 | grep -v 'never$')" +%s 2>/dev/null); \
                                            if [ -n "$change" ] && [ "$change" -gt "$(date +%s 2>/dev/null)" ]; then \
                                            echo "User: $usr last password change was $(chage --list $usr | \
                                            grep '^Last password change' | cut -d: -f2)"; fi; done'''

                try:
                    logging.info(f"base_command: {base_command}")
                    logging.info("calling function check_commands_results() from function : "
                                 "check_all_users_changed_passwords_in_past()")
                    return check_commands_results(base_command)
                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    error["cisInfo"]["cis_user_accounts_environment_details"][
                        "check_all_users_changed_passwords_in_past"] \
                        = repr(cis_err)
                    return "Not Configured"

            def are_system_accounts_secured():
                try:
                    # Are system accounts secured
                    base_command = (
                        r'''awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && '''
                        r'''$3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && '''
                        r'''$7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print}' /etc/passwd'''
                    )

                    logging.info(f"base_command: {base_command}")

                    logging.info(
                        "calling function check_commands_results() from function : are_system_accounts_secured")
                    return check_commands_results(base_command)
                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    error["cisInfo"]["cis_user_accounts_environment_details"]["are_system_accounts_secured"] = repr(
                        cis_err)
                    return "Not Configured"

            def check_default_group_for_root_account_gid_0():
                try:
                    logging.info("started function: check_default_group_for_root_account_gid_0()")

                    base_command = r"grep '^root:' /etc/passwd | cut -f4 -d:"

                    logging.info(f"base_command: {base_command}")

                    subprocess_base_command_result = subprocess.run(base_command, shell=True, capture_output=True,
                                                                    text=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {subprocess_base_command_result}")

                    if subprocess_base_command_result.returncode == 0:
                        command_output = subprocess_base_command_result.stdout.strip()
                        logging.info(f"command_output: {command_output}")
                        if command_output == "0":
                            command_result = "True"
                        else:
                            command_result = "False"
                    else:
                        command_output = "-999"
                        logging.info(f"command_output: {command_output}")
                        command_result = "Not Configured"

                    logging.info(f"command_result: {command_result}")
                    return command_result
                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    cis_function_name = "check_default_group_for_root_account_gid_0"
                    error["cisInfo"]["cis_user_accounts_environment_details"][cis_function_name] = repr(cis_err)
                    return "Not Configured"

            result["isPassMinDaysGreaterThan0Days"] = check_pass_min_days_greater_than_0()
            result["isPassMaxDaysLessThan366Days"] = check_pass_max_days_less_than_366()
            result["isPassWarnAgeGreaterThan6Days"] = check_pass_warn_age_greater_than_6()
            result["isInactiveAccountsWithPasswordExpiredLessThan30Days"] = (
                check_inactive_accounts_with_password_expired_less_than_30())
            result["didAllUsersChangedPasswordsInPast"] = check_all_users_changed_passwords_in_past()
            result["areSystemAccountsSecured"] = are_system_accounts_secured()
            result["isDefaultGroupForRootAccountGid0"] = check_default_group_for_root_account_gid_0()

            logging.info(f"user_accounts_environment_details result: {result}")

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_user_accounts_environment_details']: {err}")
        return result

    # CIS Section 6.1
    @logger_function
    def cis_system_file_permissions():
        result = {
            "arePermissionsOnEtcPasswdRestrictive": "Not Configured",
            "arePermissionsOnEtcPasswdDashRestrictive": "Not Configured",
            "arePermissionsOnEtcGroupRestrictive": "Not Configured",
            "arePermissionsOnEtcGroupDashRestrictive": "Not Configured",
            "arePermissionsOnEtcShadowRestrictive": "Not Configured",
            "arePermissionsOnEtcShadowDashRestrictive": "Not Configured",
            "arePermissionsOnEtcGshadowRestrictive": "Not Configured",
            "arePermissionsOnEtcGshadowDashRestrictive": "Not Configured",
        }

        try:
            def check_permissions_are_root_and_restrictive(base_command, permission_limit):
                try:
                    # Are permissions on /etc/passwd root and restrictive
                    logging.info("started function: check_permissions_are_root_and_restrictive()")
                    logging.info(f"base_command: {base_command}")
                    logging.info(f"permission_limit: {permission_limit}")

                    stat_command = f"{base_command} | grep Uid"
                    stat_command_result = subprocess.run(stat_command, shell=True, capture_output=True, text=True,
                                                         timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"stat_command_result: {stat_command_result}")
                    logging.info(f"stat_command_result.stdout: {stat_command_result.stdout}")

                    stat_command_to_extract_permissions = \
                        (f"{base_command} | grep Uid | "
                         r"awk '{print $2}' | awk -F/ '{print $1}' | tr -d '('")

                    logging.info(f"stat_command_to_extract_permissions: {stat_command_to_extract_permissions}")

                    stat_command_permissions_result = subprocess.run(stat_command_to_extract_permissions, shell=True,
                                                                     capture_output=True, text=True,
                                                                     timeout=TIMEOUT_SUBPROCESS)

                    logging.info(f"stat_command_permissions_result: {stat_command_permissions_result}")
                    logging.info(f"stat_command_permissions_result.returncode: "
                                 f"{stat_command_permissions_result.returncode}")
                    logging.info(f"stat_command_permissions_result.stdout: {stat_command_permissions_result.stdout}")

                    # Extract the permission number
                    permission_number = stat_command_permissions_result.stdout.strip()
                    logging.info(f"Permission number: {permission_number}")
                    if permission_number:
                        permission_number = int(permission_number)
                        # Extract Uid and Gid using regex
                        uid_match = re.search(r'Uid: \(\s*(\d+)/\s*([\w-]+)\)', stat_command_result.stdout)
                        gid_match = re.search(r'Gid: \(\s*(\d+)/\s*([\w-]+)\)', stat_command_result.stdout)

                        # Check if Uid and Gid are both 0/root
                        uid_condition = uid_match and uid_match.group(1) == '0' and uid_match.group(2) == 'root'
                        gid_condition = (gid_match and (gid_match.group(1) == '0' and gid_match.group(2) == 'root') or
                                         (gid_match.group(1) == '42' and gid_match.group(2) == 'shadow'))

                        logging.info(f"Uid condition: {uid_condition}")
                        logging.info(f"Gid condition: {gid_condition}")

                        # Check if Uid and Gid are both 0/root and Access is more restrictive
                        if uid_condition and gid_condition and permission_number <= permission_limit:
                            logging.info(f"All permissions on /etc/passwd are set to "
                                         f"{permission_limit} or more restrictive")
                            return "True"
                        logging.info(f"Not all permissions on /etc/passwd are set to "
                                     f"{permission_limit} or more restrictive")
                        return "False"
                    return "Not Configured"
                except Exception as cis_err:
                    logging.error(f"An error occurred: {cis_err}")
                    cis_function_name = "arePermissionsOnEtcPasswdRestrictive"
                    error["cisInfo"]["cis_system_file_permissions"][cis_function_name] = repr(cis_err)
                    return "Not Configured"

            result["arePermissionsOnEtcPasswdRestrictive"] = (
                check_permissions_are_root_and_restrictive("stat /etc/passwd", 644))

            result["arePermissionsOnEtcPasswdDashRestrictive"] = (
                check_permissions_are_root_and_restrictive("stat /etc/passwd-", 644))

            result["arePermissionsOnEtcGroupRestrictive"] = (
                check_permissions_are_root_and_restrictive("stat /etc/group", 644))

            result["arePermissionsOnEtcGroupDashRestrictive"] = (
                check_permissions_are_root_and_restrictive("stat /etc/group-", 644))

            result["arePermissionsOnEtcShadowRestrictive"] = (
                check_permissions_are_root_and_restrictive("stat /etc/shadow", 640))

            result["arePermissionsOnEtcShadowDashRestrictive"] = (
                check_permissions_are_root_and_restrictive("stat /etc/shadow-", 640))

            result["arePermissionsOnEtcGshadowRestrictive"] = (
                check_permissions_are_root_and_restrictive("stat /etc/gshadow", 640))

            result["arePermissionsOnEtcGshadowDashRestrictive"] = (
                check_permissions_are_root_and_restrictive("stat /etc/gshadow-", 640))

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_system_file_permissions']: {err}")
        return result

    # CIS Section 6.2
    @logger_function
    def get_user_and_group_info():
        result = {
            "noUid0OtherThanRoot": "Not Configured",
            "rootPathIntegrityMaintained": "Not Configured",
            "dotFilesAreNotGlobalWritable": "Not Configured",
            "netrcFilesAreNotAcessible": "Not Configured",
            "rhostsFilesAreNotAvailable": "Not Configured",
            "allUsersHaveValidHomeDirectories": "Not Configured",
            "isShadowGroupEmpty": "Not Configured",
        }
        try:
            def root_uid_0():
                try:
                    uid0_output = extract_info("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
                    if uid0_output == "root":
                        result["noUid0OtherThanRoot"] = "True"
                    else:
                        result["noUid0OtherThanRoot"] = "False"
                except Exception as root_uid_0_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['root_uid_0']: {root_uid_0_err}")

            def root_path_integrity():
                try:
                    rootpath_script = '''
                        #!/bin/bash
                        if echo "$PATH" | grep -q "::" ; then
                            echo "Empty Directory in PATH (::)"
                        fi
                        if echo "$PATH" | grep -q ":$" ; then
                            echo "Trailing : in PATH"
                        fi
                        for x in $(echo "$PATH" | tr ":" " ") ; do
                            if [ -d "$x" ] ; then
                                ls -ldH "$x" | awk '\
                                $9 == "." {print "PATH contains current working directory (.)"} \
                                $3 != "root" {print $9, "is not owned by root"} \
                                substr($1,6,1) != "-" {print $9, "is group writable"} \
                                substr($1,9,1) != "-" {print $9, "is world writable"}'
                            else
                                echo "$x is not a directory"
                            fi
                        done
                    '''
                    rootpath_output = run_script_for_output(rootpath_script, "root_path_integrity")
                    if rootpath_output == "root":
                        result["rootPathIntegrityMaintained"] = "True"
                    else:
                        result["rootPathIntegrityMaintained"] = "False"
                except Exception as root_path_integrity_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']"
                        f"['root_path_integrity']: {root_path_integrity_err}")

            def dot_files_writable():
                try:
                    dotfiles_script = r'''
                        #!/bin/bash
                        awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/
                        && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while
                        read -r user dir; do
                            if [ -d "$dir" ]; then
                                for file in "$dir"/.*; do
                                    if [ ! -h "$file" ] && [ -f "$file" ]; then
                                        fileperm=$(stat -L -c "%A" "$file")
                                        if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo
                                            "$fileperm" | cut -c9)" != "-" ]; then
                                            echo "User: \"$user\" file: \"$file\" has permissions:
                                            \"$fileperm\""
                                        fi
                                    fi
                                done
                            fi
                        done
                    '''
                    dotfiles_result = run_script_for_output(dotfiles_script, "dot_files_writable")
                    if dotfiles_result == "Not Configured":
                        result["dotFilesIntegrityMaintained"] = "Not Configured"
                    elif dotfiles_result:
                        result["dotFilesIntegrityMaintained"] = "False"
                    else:
                        result["dotFilesIntegrityMaintained"] = "True"
                except Exception as dot_files_writable_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['dot_files_writable']: {dot_files_writable_err}")

            def netrc_permission():
                try:
                    netrc_script = '''
                        #!/bin/bash
                        grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 !=
                        "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while \
                        read user dir; do
                        if [ ! -d "$dir" ]; then
                        echo "The home directory ($dir) of user $user does not exist."
                        else
                        for file in $dir/.netrc; do
                        if [ ! -h "$file" -a -f "$file" ]; then
                        fileperm=$(ls -ld $file | cut -f1 -d" ")
                        if [ $(echo $fileperm | cut -c5) != "-" ]; then
                        echo "Group Read set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c6) != "-" ]; then
                        echo "Group Write set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c7) != "-" ]; then
                        echo "Group Execute set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c8) != "-" ]; then
                        echo "Other Read set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c9) != "-" ]; then
                        echo "Other Write set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c10) != "-" ]; then
                        echo "Other Execute set on $file"
                        fi
                        fi
                        done
                        fi
                        done
                    '''
                    netrc_result = run_script_for_output(netrc_script, "netrc_permission")
                    if netrc_result == "Not Configured":
                        result["dotFilesIntegrityMaintained"] = "Not Configured"
                    elif netrc_result:
                        result["dotFilesIntegrityMaintained"] = "False"
                    else:
                        result["dotFilesIntegrityMaintained"] = "True"
                except Exception as netrc_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['netrc_permission']: {netrc_err}")

            def rhosts_available():
                try:
                    rhosts_script = r'''
                        #!/bin/bash
                        awk -F: '($1!~/(root|halt|sync|shutdown)/ &&
                        $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {
                        print $1 " " $6 }' /etc/passwd | while read -r user dir; do
                        if [ -d "$dir" ]; then
                        file="$dir/.rhosts"
                        if [ ! -h "$file" ] && [ -f "$file" ]; then
                        echo "User: \"$user\" file: \"$file\" exists"
                        fi
                        fi
                        done
                    '''
                    rhosts_result = run_script_for_output(rhosts_script, "rhosts_available")
                    if rhosts_result == "Not Configured":
                        result["rhostsFilesAreNotAvailable"] = "Not Configured"
                    elif rhosts_result:
                        result["rhostsFilesAreNotAvailable"] = "False"
                    else:
                        result["rhostsFilesAreNotAvailable"] = "True"

                except Exception as rhosts_available_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['rhosts_available']: {rhosts_available_err}")

            def check_users_have_valid_home_dirs():
                try:
                    usr_dir_script = '''
                        #!/bin/bash
                        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which
                        nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user
                        dir; do
                        if [ ! -d "$dir" ]; then
                        echo "The home directory ($dir) of user $user does not exist."
                        fi
                        done
                    '''
                    usr_dir_result = run_script_for_output(usr_dir_script, "check_users_have_valid_home_dirs")
                    if usr_dir_result:
                        result["allUsersHaveValidHomeDirectories"] = "False"
                    else:
                        result["allUsersHaveValidHomeDirectories"] = "True"

                except Exception as check_users_have_valid_home_dirs_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['check_users_have_valid_home_dirs']: "
                        f"{check_users_have_valid_home_dirs_err}")

            def shadow_group():
                try:
                    shadow_output1 = extract_info("grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group")
                    shadow_output2 = extract_info('''awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd''')
                    if shadow_output1 == "Not Configured" or shadow_output2 == "Not Configured":
                        result["isShadowGroupEmpty"] = "Not Configured"
                    elif not shadow_output1 and not shadow_output2:
                        result["isShadowGroupEmpty"] = "True"
                    else:
                        result["isShadowGroupEmpty"] = "False"

                except Exception as shadow_group_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['shadow_group']: {shadow_group_err}")

            root_uid_0()
            root_path_integrity()
            dot_files_writable()
            netrc_permission()
            rhosts_available()
            shadow_group()
            check_users_have_valid_home_dirs()

        except Exception as err:
            logging.error(
                f"error['cisInfo']['get_user_and_group_info']: {err}")

        return result

    def get_cis_base_and_os_services_info():
        result = {
            "isSmartCardServiceDisabled": "Not Configured",
            "isSmartDiskServiceDisabled": "Not Configured",
            "isInstallHelperServiceDisabled": "Not Configured",
            "isKdumpKernelCrashDisabled": "Not Configured",
            "isBluetoothHostControllerDisabled": "Not Configured",
            "isXinetdServiceDisabled": "Not Configured",
            "isChargenServiceDisabled": "Not Configured",
            "isDaytimeServiceDisabled": "Not Configured",
            "isEchoServiceDisabled": "Not Configured",
            "isTimeServiceDisabled": "Not Configured",
            "isTalkClientServiceDisabled": "Not Configured",
            "isDiscardServiceDisabled": "Not Configured",
        }
        try:
            def smart_card_service_disabled():
                try:
                    cmd = 'systemctl is-enabled pcscd'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in smart_card_service_disabled: {e}")
                    return "Not Configured"

            def smart_disk_service_disabled():
                try:
                    cmd = 'systemctl is-enabled smartd'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in smart_disk_service_disabled: {e}")
                    return "Not Configured"

            def install_helper_service_disabled():
                try:
                    cmd = 'systemctl is-enabled install-helper'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in install_helper_service_disabled: {e}")
                    return "Not Configured"

            def kdump_kernel_crash_disabled():
                try:
                    cmd = 'systemctl is-enabled kdump'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in kdump_kernel_crash_disabled: {e}")
                    return "Not Configured"

            def bluetooth_host_controller_disabled():
                try:
                    cmd = 'systemctl is-enabled bluetooth'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in bluetooth_host_controller_disabled: {e}")
                    return "Not Configured"

            def xinetd_service_disabled():
                try:
                    cmd = 'systemctl is-enabled xinetd'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in xinetd_service_disabled: {e}")
                    return "Not Configured"

            def chargen_service_disabled():
                try:
                    cmd = 'systemctl is-enabled chargen'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in chargen_service_disabled: {e}")
                    return "Not Configured"

            def daytime_service_disabled():
                try:
                    cmd = 'systemctl is-enabled daytime'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in daytime_service_disabled: {e}")
                    return "Not Configured"

            def echo_service_disabled():
                try:
                    cmd = 'systemctl is-enabled echo'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in echo_service_disabled: {e}")
                    return "Not Configured"

            def time_service_disabled():
                try:
                    cmd = 'systemctl is-enabled time'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in time_service_disabled: {e}")
                    return "Not Configured"

            def talk_client_service_disabled():
                try:
                    cmd = 'systemctl is-enabled talk'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in talk_client_service_disabled: {e}")
                    return "Not Configured"

            def discard_service_disabled():
                try:
                    cmd = 'systemctl is-enabled discard'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in discard_service_disabled: {e}")
                    return "Not Configured"

            result["isSmartCardServiceDisabled"] = smart_card_service_disabled()
            result["isSmartDiskServiceDisabled"] = smart_disk_service_disabled()
            result["isInstallHelperServiceDisabled"] = install_helper_service_disabled()
            result["isKdumpKernelCrashDisabled"] = kdump_kernel_crash_disabled()
            result["isBluetoothHostControllerDisabled"] = bluetooth_host_controller_disabled()
            result["isXinetdServiceDisabled"] = xinetd_service_disabled()
            result["isChargenServiceDisabled"] = chargen_service_disabled()
            result["isDaytimeServiceDisabled"] = daytime_service_disabled()
            result["isEchoServiceDisabled"] = echo_service_disabled()
            result["isTimeServiceDisabled"] = time_service_disabled()
            result["isTalkClientServiceDisabled"] = talk_client_service_disabled()
            result["isDiscardServiceDisabled"] = discard_service_disabled()

        except Exception as base_service_info_err:
            logging.error(
                f"error['cisInfo']['get_user_and_group_info']['base_service_info']: {base_service_info_err}")

        return result

    def get_cis_process_hardening_info():
        result = {
            "isCoreDumpForAllUsersDisabled": "Not Configured",
            "isRandomVirtualMemoryRegionPlacementEnabled": "Not Configured",
            "isExecShieldInSysctlEnabled": "Not Configured",
            "isDacOnSymLinksEnforced": "Not Configured",
            "isDacOnHardLinksEnforced": "Not Configured",
            "isTpmModuleEnabled": "Not Configured",
        }
        try:
            def core_dump_for_all_users_disabled():
                try:
                    cmd = 'sysctl fs.suid_dumpable'
                    output = extract_info(cmd)
                    return "True" if output == "fs.suid_dumpable = 0" else "False"
                except Exception as e:
                    logging.error(f"Error in core_dump_for_all_users_disabled: {e}")
                    return "Not Configured"

            def random_virtual_memory_region_placement_enabled():
                try:
                    cmd = 'sysctl kernel.randomize_va_space'
                    output = extract_info(cmd)
                    return "True" if output == "kernel.randomize_va_space = 2" else "False"
                except Exception as e:
                    logging.error(f"Error in random_virtual_memory_region_placement_enabled: {e}")
                    return "Not Configured"

            def exec_shield_in_sysctl_enabled():
                try:
                    cmd = 'sysctl kernel.exec-shield'
                    output = extract_info(cmd)
                    return "True" if output == "kernel.exec-shield = 1" else "False"
                except Exception as e:
                    logging.error(f"Error in exec_shield_in_sysctl_enabled: {e}")
                    return "Not Configured"

            def dac_on_symlinks_enforced():
                try:
                    cmd = 'sysctl fs.protected_symlinks'
                    output = extract_info(cmd)
                    return "True" if output == "fs.protected_symlinks = 1" else "False"
                except Exception as e:
                    logging.error(f"Error in dac_on_symlinks_enforced: {e}")
                    return "Not Configured"

            def dac_on_hardlinks_enforced():
                try:
                    cmd = 'sysctl fs.protected_hardlinks'
                    output = extract_info(cmd)
                    return "True" if output == "fs.protected_hardlinks = 1" else "False"
                except Exception as e:
                    logging.error(f"Error in dac_on_hardlinks_enforced: {e}")
                    return "Not Configured"

            def tpm_module_enabled():
                try:
                    cmd = 'sudo dmesg | grep tpm'
                    output = extract_shell_info(cmd)
                    if "tpm_tis" in output:
                        return "True"
                    else:
                        return "False"
                except Exception as e:
                    logging.error(f"Error in tpm_module_enabled: {e}")
                    return "Not Configured"

            result["isCoreDumpForAllUsersDisabled"] = core_dump_for_all_users_disabled()
            result["isRandomVirtualMemoryRegionPlacementEnabled"] = random_virtual_memory_region_placement_enabled()
            result["isExecShieldInSysctlEnabled"] = exec_shield_in_sysctl_enabled()
            result["isDacOnSymLinksEnforced"] = dac_on_symlinks_enforced()
            result["isDacOnHardLinksEnforced"] = dac_on_hardlinks_enforced()
            result["isTpmModuleEnabled"] = tpm_module_enabled()
        except Exception as process_hardening_info_err:
            logging.error(
                f"error['cisInfo']['get_user_and_group_info']['process_hardening_info']: {process_hardening_info_err}")

        return result

    # cis-section 1.8 warning banners----------------------------------------------------
    def get_cis_warning_banners_info():
        result = {
            "isMessageOfTheDayConfigured": "Not Configured",
            "isLocalLoginWarningBannerConfigured": "Not Configured",
            "isRemoteLoginWarningBannerConfigured": "Not Configured",
            "isPermissionOnEtcMotdConfigured": "Not Configured",
            "isPermissionOnEtcIssueConfigured": "Not Configured",
            "isPermissionOnEtcIssueNetConfigured": "Not Configured",
            "isGDMLoginBannerConfigured": "Not Configured",
            "isOsInfoRemovedFromLoginBanner": "Not Configured",
            "isUpdatesPatchesAdditionalSecurityPackagesInstalled": "Not Configured",
        }

        def is_message_of_the_day_configured():
            try:
                output = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/motd''')
                if output:
                    return "False"
                else:
                    return "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_message_of_the_day_configured']: {er}")
                return "Not Configured"

        def is_local_login_warning_banner_configured():
            try:
                output = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/issue''')
                if output:
                    return "False"
                else:
                    return "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_local_login_warning_banner_configured']: {er}")
                return "Not Configured"

        def is_remote_login_warning_banner_configured():
            try:
                output = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net''')
                if output:
                    return "False"
                else:
                    return "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_remote_login_warning_banner_configured']: {er}")
                return "Not Configured"

        def is_permission_on_etc_motd_configured():
            try:
                output = extract_shell_info("stat /etc/motd")
                if "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                    return "True"
                else:
                    return "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_etc_motd_configured']: {er}")
                return "Not Configured"

        def is_permission_on_etc_issue_configured():
            try:
                output = extract_shell_info("stat /etc/issue")
                if "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                    return "True"
                else:
                    return "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_etc_issue_configured']: {er}")
                return "Not Configured"

        def is_permission_on_etc_issue_net_configured():
            try:
                output = extract_shell_info("stat /etc/issue.net")
                if "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                    return "True"
                else:
                    return "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_etc_issue_net_configured']: {er}")
                return "Not Configured"

        def is_gdm_login_banner_configured():
            try:
                output = extract_shell_info("cat /etc/gdm3/greeter.dconf-defaults")

                # Split file into lines for safer parsing
                lines = output.splitlines()

                in_gnome_section = False
                banner_enable = False
                banner_text = False

                for line in lines:
                    stripped = line.strip()

                    # Detect start of the GDM login section
                    if stripped == "[org/gnome/login-screen]":
                        in_gnome_section = True
                        continue

                    # Stop checking when we leave the section (optional)
                    if in_gnome_section and stripped.startswith("[") and stripped.endswith("]"):
                        break

                    # Ignore comments and empty lines
                    if stripped.startswith("#") or not stripped:
                        continue

                    # Look for key/value pairs inside the section
                    if in_gnome_section:
                        if re.match(r"^banner-message-enable\s*=\s*true$", stripped):
                            banner_enable = True
                        elif re.match(r"^banner-message-text\s*=\s*['\"].+['\"]$", stripped):
                            banner_text = True

                if banner_enable and banner_text:
                    return "True"
                else:
                    return "False"

            except Exception as er:
                logging.error(f"error['cisInfo']['is_gdm_login_banner_configured']: {er}")
                return "Not Configured"

        def is_updates_patches_additional_security_packages_installed():
            try:
                output = extract_info("dnf check-update --security")
                if output:
                    return "False"
                else:
                    return "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_updates_patches_additional_security_packages_installed']: {er}")
                return "Not Configured"

        def is_os_info_removed_from_login_banner():
            try:
                output_issue = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/issue'''
                )
                output_issue_net = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net'''
                )

                # If the output is empty for both files, OS info is removed
                if not output_issue and not output_issue_net:
                    return "True"
                else:
                    return "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_os_info_removed_from_login_banner']: {er}")
                return "Not Configured"

        try:
            result["isMessageOfTheDayConfigured"] = is_message_of_the_day_configured()
            result["isLocalLoginWarningBannerConfigured"] = is_local_login_warning_banner_configured()
            result["isRemoteLoginWarningBannerConfigured"] = is_remote_login_warning_banner_configured()
            result["isPermissionOnEtcMotdConfigured"] = is_permission_on_etc_motd_configured()
            result["isPermissionOnEtcIssueConfigured"] = is_permission_on_etc_issue_configured()
            result["isPermissionOnEtcIssueNetConfigured"] = is_permission_on_etc_issue_net_configured()
            result["isGDMLoginBannerConfigured"] = is_gdm_login_banner_configured()
            result["isUpdatesPatchesAdditionalSecurityPackagesInstalled"] = \
                is_updates_patches_additional_security_packages_installed()
            result["isOsInfoRemovedFromLoginBanner"] = is_os_info_removed_from_login_banner()

        except Exception as warning_banners_err:
            logging.error(f"error['cisInfo']['cis_warning_banners_info']: {warning_banners_err}")
        return result

    def get_cis_desktop_conf_info():
        result = {
            "isPermissionOnFileBrowserConfigured": "Not Configured",
            "isFirefoxRemoved": "Not Configured",
            "isImageViewerRemoved": "Not Configured",
            "isPermissionOnGnomeTerminalConfigured": "Not Configured",
            "isPermissionOnGnomeDisksConfigured": "Not Configured",
            "isPermissionOnGnomeControlCenterConfigured": "Not Configured",
            "isTotemRemoved": "Not Configured",
            "isPermissionOnDiskImageMounterConfigured": "Not Configured",
            "isPermissionOnGnomeScreenshotConfigured": "Not Configured",
            "isCheeseRemoved": "Not Configured",
            "isCockpitRemoved": "Not Configured",
            "isTigerVNCRemoved": "Not Configured",
            "isWireSharkRemoved": "Not Configured",
            "isPermissionOnGnomeSoftwareConfigured": "Not Configured",
            "isFileRollerRemoved": "Not Configured",
            "isPermissionOnGnomeSystemMonitorConfigured": "Not Configured",
            "isPermissionOnGnomeLogsConfigured": "Not Configured",
            "isPanelRunDialogDisabled": "Not Configured",
            "isUSBDisabled": "Not Configured",
            "isMobilePhoneDisabled": "Not Configured",
            "isCdDvdDisabled": "Not Configured",
            "isBluetoothDisabled": "Not Configured",
            "isSerialPortDisabled": "Not Configured",
        }

        def is_permission_on_file_browser_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/nautilus"  # Adjust if different file browser is used
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_file_browser_configured']: {er}")
                return "Not Configured"

        def is_firefox_removed():
            try:
                check_command = "rpm -q firefox"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_firefox_removed']: {er}")
                return "Not Configured"

        def is_image_viewer_removed():
            try:
                check_command = "rpm -q eog"  # Assuming Eye of GNOME as image viewer
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_image_viewer_removed']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_terminal_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-terminal"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_terminal_configured']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_disks_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-disks"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_disks_configured']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_control_center_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-control-center"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_control_center_configured']: {er}")
                return "Not Configured"

        def is_totem_removed():
            try:
                check_command = "rpm -q totem"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_totem_removed']: {er}")
                return "Not Configured"

        def is_permission_on_disk_image_mounter_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-disk-utility"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_disk_image_mounter_configured']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_screenshot_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-screenshot"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_screenshot_configured']: {er}")
                return "Not Configured"

        def is_cheese_removed():
            try:
                check_command = "rpm -q cheese"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_cheese_removed']: {er}")
                return "Not Configured"

        def is_cockpit_removed():
            try:
                check_command = "rpm -q cockpit"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_cockpit_removed']: {er}")
                return "Not Configured"

        def is_tiger_vnc_removed():
            try:
                check_command = "rpm -q tigervnc-server"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_tiger_vnc_removed']: {er}")
                return "Not Configured"

        def is_wire_shark_removed():
            try:
                check_command = "rpm -q wireshark"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_wire_shark_removed']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_software_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-software"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_software_configured']: {er}")
                return "Not Configured"

        def is_file_roller_removed():
            try:
                check_command = "rpm -q file-roller"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_file_roller_removed']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_system_monitor_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-system-monitor"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_system_monitor_configured']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_logs_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-logs"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_logs_configured']: {er}")
                return "Not Configured"

        def is_panel_run_dialog_disabled():
            try:
                check_command = "gsettings get org.gnome.shell.extensions.dash-to-dock show-apps-at-top"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and output.stdout.strip() == "false" else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_panel_run_dialog_disabled']: {er}")
                return "Not Configured"

        def is_usb_disabled():
            try:
                check_command = "lsusb"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if not output.stdout else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_usb_disabled']: {er}")
                return "Not Configured"

        def is_mobile_phone_disabled():
            try:
                check_command = "lsusb | grep -i 'mobile'"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if not output.stdout else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_mobile_phone_disabled']: {er}")
                return "Not Configured"

        def is_cd_dvd_disabled():
            try:
                check_command = "lsblk | grep -i 'cdrom'"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if not output.stdout else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_cd_dvd_disabled']: {er}")
                return "Not Configured"

        def is_bluetooth_disabled():
            try:
                check_command = "rfkill list bluetooth"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if "yes" in output.stdout.lower() else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_bluetooth_disabled']: {er}")
                return "Not Configured"

        def is_serial_port_disabled():
            try:
                check_command = "dmesg | grep -i 'ttyS'"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if not output.stdout else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_serial_port_disabled']: {er}")
                return "Not Configured"

        try:
            result["isPermissionOnFileBrowserConfigured"] = is_permission_on_file_browser_configured()
            result["isFirefoxRemoved"] = is_firefox_removed()
            result["isImageViewerRemoved"] = is_image_viewer_removed()
            result["isPermissionOnGnomeTerminalConfigured"] = is_permission_on_gnome_terminal_configured()
            result["isPermissionOnGnomeDisksConfigured"] = is_permission_on_gnome_disks_configured()
            result["isPermissionOnGnomeControlCenterConfigured"] = is_permission_on_gnome_control_center_configured()
            result["isTotemRemoved"] = is_totem_removed()
            result["isPermissionOnDiskImageMounterConfigured"] = is_permission_on_disk_image_mounter_configured()
            result["isPermissionOnGnomeScreenshotConfigured"] = is_permission_on_gnome_screenshot_configured()
            result["isCheeseRemoved"] = is_cheese_removed()
            result["isCockpitRemoved"] = is_cockpit_removed()
            result["isTigerVNCRemoved"] = is_tiger_vnc_removed()
            result["isWireSharkRemoved"] = is_wire_shark_removed()
            result["isPermissionOnGnomeSoftwareConfigured"] = is_permission_on_gnome_software_configured()
            result["isFileRollerRemoved"] = is_file_roller_removed()
            result["isPermissionOnGnomeSystemMonitorConfigured"] = is_permission_on_gnome_system_monitor_configured()
            result["isPermissionOnGnomeLogsConfigured"] = is_permission_on_gnome_logs_configured()
            result["isPanelRunDialogDisabled"] = is_panel_run_dialog_disabled()
            result["isUSBDisabled"] = is_usb_disabled()
            result["isMobilePhoneDisabled"] = is_mobile_phone_disabled()
            result["isCdDvdDisabled"] = is_cd_dvd_disabled()
            result["isBluetoothDisabled"] = is_bluetooth_disabled()
            result["isSerialPortDisabled"] = is_serial_port_disabled()

        except Exception as desktop_conf_err:
            logging.error(f"error['cisInfo']: {desktop_conf_err}")

        return result

    @logger_function
    def get_system_info():
        """
        Generates a system information dictionary.

        Returns:
            dict: A dictionary containing various system information.
        """
        # Initialize the system_info dictionary
        system_info = {}
        html_report_info = {}
        try:
            # audit_log_id = get_audit_log_id_info()
            pc_id = get_pc_id()
            # host_name = platform.node()

            # ----------------------------------------------------------------
            # miscellaneousInfo
            # current_loggedin_user = get_current_loggedin_user()
            current_time = fetch_current_time()

            # ----------------------------------------------------------------
            # pcIdentityInfo
            # current_setup_file_version = find_and_extract_current_setup_version()
            # os_type = extract_info(['uname', '-s'])
            # os_name_info = get_os_name_info()
            # serial_number = get_system_serial_number() or get_system_serial_from_file()
            # uuid_number = get_device_uuid() or get_device_uuid_from_file()
            # motherboard_serial_number = get_motherboard_serial_number() or get_motherboard_serial_from_file()
            # is_pc_in_org_domain = check_pc_in_org_domain()
            # system_manufacturer_info = extract_shell_info('cat /sys/class/dmi/id/sys_vendor',
            #                                               '/sys/class/dmi/id/sys_vendor',
            #                                               "system_manufacturer_info")
            # system_model_info = extract_shell_info('cat /sys/class/dmi/id/product_name',
            #                                        '/sys/class/dmi/id/product_name',
            #                                        "system_model_info")
            # os_version = get_linux_os_version()
            # ip_address = extract_shell_info('hostname -I')

            # security_status_info = get_system_security_status(current_loggedin_user)

            if SCAN_TYPE == "LINUX_USB_TRIGGER":
                # ----------------------------------------------------------------
                # usbInfo
                usb_details_info = get_usb_details()

                system_info = {
                    # "currentTime": current_time,
                    # "pcId": pc_id,
                    # "eventTriggerType": SCAN_TYPE,
                    # "pcIdentityInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "auditLogId": audit_log_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "osType": os_type,
                    #     "osName": os_name_info,
                    #     "serialNumber": serial_number,
                    #     "motherboardSerialNumber": motherboard_serial_number,
                    #     "ipAddress": ip_address,
                    #     "hostname": host_name,
                    #     "connectedToDomainName": is_pc_in_org_domain,
                    #     "systemManufacturer": system_manufacturer_info,
                    #     "systemModel": system_model_info,
                    #     "currentUser": current_loggedin_user,
                    #     "currentAgentVersion": current_setup_file_version,
                    #     "osVersion": os_version,
                    #     "licenseKey": LICENSE_KEY,
                    #     "securityStatus": security_status_info
                    # },
                    # "usbInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "usbInfoDetails": usb_details_info,
                    # },
                    # "errorInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     **error
                    # }
                }
            elif (SCAN_TYPE == "LINUX_NETWORK_TRIGGER" or
                  SCAN_TYPE == "LINUX_FIREWALL_TRIGGER" or SCAN_TYPE == "LINUX_BLUETOOTH_TRIGGER"):
                # ----------------------------------------------------------------
                # miscellaneousInfo
                # installed_programs = get_installed_programs()

                # ----------------------------------------------------------------
                # networkInfo
                # firewall_status, firewall_service = check_firewall_status()
                # wifi_info = get_wifi_info()
                # ethernet_info = get_ethernet_info()
                # bluetooth_info = get_bluetooth_info()
                # established_connections_list = get_established_connections()
                # open_tcp_ports_list = get_tcp_info()
                # dns_info = get_dns_info()
                # nac_info = get_nac_info(installed_programs)
                # ntp_enabled = is_ntp_server_enabled()
                # ip_address = extract_shell_info('hostname -I')

                system_info = {
                    "currentTime": current_time,
                    "pcId": pc_id,
                    # "eventTriggerType": SCAN_TYPE,
                    # "pcIdentityInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "auditLogId": audit_log_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "osType": os_type,
                    #     "osName": os_name_info,
                    #     "serialNumber": serial_number,
                    #     "motherboardSerialNumber": motherboard_serial_number,
                    #     "ipAddress": ip_address,
                    #     "hostname": host_name,
                    #     "connectedToDomainName": is_pc_in_org_domain,
                    #     "systemManufacturer": system_manufacturer_info,
                    #     "systemModel": system_model_info,
                    #     "currentUser": current_loggedin_user,
                    #     "currentAgentVersion": current_setup_file_version,
                    #     "osVersion": os_version,
                    #     "licenseKey": LICENSE_KEY,
                    #     "securityStatus": security_status_info
                    # },
                    # "networkInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "firewallStatus": firewall_status,
                    #     "firewallService": firewall_service,
                    #     "wifiStatus": wifi_info,
                    #     "ethernetStatus": ethernet_info,
                    #     "bluetoothInfo": bluetooth_info,
                    #     "establishedNetworkConnections": established_connections_list,
                    #     "openTcpPorts": open_tcp_ports_list,
                    #     "dnsServer": dns_info,
                    #     "nacInstalled": nac_info,
                    #     "ntpDetails": ntp_enabled,
                    # },
                    # "errorInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     **error
                    # }
                }
            else:
                # ----------------------------------------------------------------
                usb_stored_history_info = []
                custodian_name = ""
                if SCAN_TYPE == "LINUX_INSTALLATION_TRIGGER":
                    usb_stored_history_info = get_usb_stored_history()
                    custodian_name = get_custodian_name()

                # ----------------------------------------------------------------
                # miscellaneousInfo
                # installed_programs = get_installed_programs()

                # ----------------------------------------------------------------
                # accountInfo
                # user_account_details = get_user_account_details(current_loggedin_user)
                # is_multiple_admin_acc = get_admin_accounts()
                # password_age_status = get_users_password_age()

                # ----------------------------------------------------------------
                # backendInfo
                # os_patch_info = get_os_patch_info()
                # app_patch_info = get_application_patch_info()
                # endpoint_type = get_filtered_hostname()
                filesystem_integrity_info = []
                if SCAN_TYPE == "LINUX_DAILY_TRIGGER" or SCAN_TYPE == "LINUX_INSTALLATION_TRIGGER":
                    filesystem_integrity_info = get_file_integrity_info()

                # ----------------------------------------------------------------
                # cis info
                # cis_file_system_configuration_info = cis_file_system_configuration()
                # cis_audit_partitions_info = cis_audit_partitions()
                # cis_filesystem_integrity_check = cis_check_aide_installed()
                # cis_secure_boot_settings_info = cis_secure_boot_settings()
                # cis_additional_process_hardening_info = cis_additional_process_hardening()
                # cis_selinux_info = cis_selinux_config_info()
                # cis_special_purpose_services_info = cis_special_purpose_services()
                # cis_service_clients_info = cis_service_clients()
                # cis_configure_firewall_info = cis_configure_firewall_utility()
                cis_configure_firewall_rules_info = cis_configure_firewall_rules()
                # cis_network_configuration_info = cis_network_configuration()
                # cis_system_auditing_info = cis_configure_system_auditing()
                # cis_system_access_and_authentication_info = cis_system_access_and_authentication()
                # cis_ssh_server_info = cis_configure_ssh_server()
                # cis_privilege_escalation_info = cis_configure_privilege_escalation()
                # cis_pam_info = cis_configure_pam()
                # cis_user_accounts_environment_info = cis_user_accounts_environment_details()
                # cis_system_file_permissions_info = cis_system_file_permissions()
                # cis_get_user_and_group_info = get_user_and_group_info()
                # cis_logging_and_auditing_info = cis_logging_and_auditing()
                # cis_base_and_os_services_info = get_cis_base_and_os_services_info()
                # cis_process_hardening_info = get_cis_process_hardening_info()
                # cis_warning_banners_info = get_cis_warning_banners_info()
                # cis_desktop_conf_info = get_cis_desktop_conf_info()
                # cis_configure_ufw_info = cis_configure_ufw()
                # cis_configure_iptables_softwares_info = cis_configure_iptables_softwares()

                # ----------------------------------------------------------------
                # hardwareInfo
                # processor_info = \
                #     extract_shell_info("lscpu | grep 'Model name:' | awk -F: '{print $2}' | awk '{$1=$1;print}'").split(
                #         "\n")[0]
                # machine_bit_type = platform.architecture()[0]
                # machine_type = platform.machine()
                # memory_info = get_memory_information()
                # bios_version_info = extract_shell_info('cat /sys/class/dmi/id/bios_version',
                #                                        '/sys/class/dmi/id/bios_version',
                #                                        "bios_version_info")
                # sys_time_zone_info = get_time_zone_info()
                # bios_battery_serviceable_info = get_bios_battery_serviceable()
                # internal_disks_info = get_harddrive_info()
                # printer_names_list = list_printer_names()
                # scanners_names_list = list_scanner_names()
                # high_cpu_usage = get_high_cpu_processes()
                # ram_use = get_processes_with_memory_usage()
                # nicinfo = nic_info()
                # optical_drive_info = get_optical_drive_info()
                # tmp_version = get_tpm_version()

                # ----------------------------------------------------------------
                # networkInfo
                # firewall_status, firewall_service = check_firewall_status()
                # wifi_info = get_wifi_info()
                # ethernet_info = get_ethernet_info()
                # bluetooth_info = get_bluetooth_info()
                # established_connections_list = get_established_connections()
                # open_tcp_ports_list = get_tcp_info()
                # dns_info = get_dns_info()
                # nac_info = get_nac_info(installed_programs)
                # ntp_enabled = is_ntp_server_enabled()
                # ip_address = extract_shell_info('hostname -I')

                # ----------------------------------------------------------------
                # osInfo
                # os_distributor = get_os_name_info()
                # os_release = extract_info(['uname', '-r'])
                # os_release_name = get_os_release_name(os_distributor)
                # os_config_info = extract_shell_info('cat /sys/class/dmi/id/product_name',
                #                                     '/sys/class/dmi/id/product_name',
                #                                     "os_config_info")
                # os_install_date_info = get_os_install_date()
                # user_home_dir = get_user_profile_directory(current_loggedin_user)
                # user_profile_dir = get_user_profile_directory(current_loggedin_user)
                # fetch_startup_programs = get_list_of_startup_programs()
                # system_boot_time_info = extract_shell_info("uptime -s")
                # boot_device_information = get_boot_device_info()
                # shared_dir = list_shared_directories()
                # services_info = get_services_info()
                # rdp_status = get_rdp_status(current_loggedin_user)
                # audit_logs = get_audit_logs()
                # av_info = get_antivirus_info(installed_programs, app_patch_info)
                # edr_installed = get_edr_installed(installed_programs)

                # ----------------------------------------------------------------
                # Below is the dictionary that will be returned
                system_info = {
                    "currentTime": current_time,
                    "pcId": pc_id,
                    "eventTriggerType": SCAN_TYPE,
                    # "pcIdentityInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "auditLogId": audit_log_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "osType": os_type,
                    #     "osName": os_name_info,
                    #     "serialNumber": serial_number,
                    #     "motherboardSerialNumber": motherboard_serial_number,
                    #     "ipAddress": ip_address,
                    #     "hostname": host_name,
                    #     "connectedToDomainName": is_pc_in_org_domain,
                    #     "systemManufacturer": system_manufacturer_info,
                    #     "systemModel": system_model_info,
                    #     "currentUser": current_loggedin_user,
                    #     "currentAgentVersion": current_setup_file_version,
                    #     "osVersion": os_version,
                    #     "licenseKey": LICENSE_KEY,
                    #     "securityStatus": security_status_info
                    # },
                    # "accountInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "additionalUserDetails": user_account_details,
                    #     "adminAccountsAreMultiple": is_multiple_admin_acc,
                    #     "usersPasswordAge": password_age_status,
                    # },
                    # "backendInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "endpointType": endpoint_type,
                    #     "installedPrograms": app_patch_info,
                    #     "osPatchInfo": os_patch_info,
                    # },
                    "cisInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        # "cisFilesystemConfigurationInfo": cis_file_system_configuration_info,
                        # "cisAuditPartitionsInfo": cis_audit_partitions_info,
                        # "cisFilesystemIntegrityInfo": cis_filesystem_integrity_check,
                        # "cisSecureBootSettingsInfo": cis_secure_boot_settings_info,
                        # "cisAdditionalProcessHardeningInfo": cis_additional_process_hardening_info,
                        # "cisSELinuxConfigureInfo": cis_selinux_info,
                        # "cisSpecialPurposeServicesInfo": cis_special_purpose_services_info,
                        # "cisServiceClientsInfo": cis_service_clients_info,
                        # "cisNetworkConfigurationInfo": cis_network_configuration_info,
                        # "cisConfigureFirewallInfo": cis_configure_firewall_info,
                        "cisConfigureFirewallRulesInfo": cis_configure_firewall_rules_info,
                        # "cisSystemAuditingInfo": cis_system_auditing_info,
                        # "cisLoggingAndAuditingInfo": cis_logging_and_auditing_info,
                        # "cisSystemAccessAuthInfo": cis_system_access_and_authentication_info,
                        # "cisConfigureSSHServerInfo": cis_ssh_server_info,
                        # "cisConfigurePrivilegeEscalationInfo": cis_privilege_escalation_info,
                        # "cisConfigurePamInfo": cis_pam_info,
                        # "cisUserAccountsEnvironmentInfo": cis_user_accounts_environment_info,
                        # "cisSystemFilePermissionsInfo": cis_system_file_permissions_info,
                        # "cisGetUserAndGroupInfo": cis_get_user_and_group_info,
                        # "cisBaseAndOsServicesInfo": cis_base_and_os_services_info,
                        # "cisProcessHardeningInfo": cis_process_hardening_info,
                        # "cisWarningBannersInfo": cis_warning_banners_info,
                        # "cisDesktopConfInfo": cis_desktop_conf_info,
                        # "cisConfigureUfwInfo": cis_configure_ufw_info,
                        # "cisConfigureIptablesSoftwaresInfo": cis_configure_iptables_softwares_info,
                    },
                    # "hardwareInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "processorInfo": processor_info,
                    #     "machineBitType": machine_bit_type,
                    #     "machineType": machine_type,
                    #     "memoryInformation": memory_info,
                    #     "biosVersion": bios_version_info,
                    #     "timeZone": sys_time_zone_info,
                    #     "biosBatteryServiceable": bios_battery_serviceable_info,
                    #     "internalHardDrivesInfo": internal_disks_info,
                    #     "printers": printer_names_list,
                    #     "scanners": scanners_names_list,
                    #     "highCpuUsage": high_cpu_usage,
                    #     "ramUsage": ram_use,
                    #     "nicDetails": nicinfo,
                    #     "opticalDriveInfo": optical_drive_info,
                    #     "deviceUUIDNumber": uuid_number,
                    #     "tpmVersion": tmp_version
                    # },
                    # "networkInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "firewallStatus": firewall_status,
                    #     "firewallService": firewall_service,
                    #     "wifiStatus": wifi_info,
                    #     "ethernetStatus": ethernet_info,
                    #     "bluetoothInfo": bluetooth_info,
                    #     "establishedNetworkConnections": established_connections_list,
                    #     "openTcpPorts": open_tcp_ports_list,
                    #     "dnsServer": dns_info,
                    #     "nacInstalled": nac_info,
                    #     "ntpDetails": ntp_enabled,
                    # },
                    # "osInfo": {
                    #     "currentTime": current_time,
                    #     "pcId": pc_id,
                    #     "eventTriggerType": SCAN_TYPE,
                    #     "osDistributor": os_distributor,
                    #     "osRelease": os_release,
                    #     "osReleaseName": os_release_name,
                    #     "osVersion": os_version,
                    #     "osConfiguration": os_config_info,
                    #     "osInstallationDate": os_install_date_info,
                    #     "userHomeDirectory": user_home_dir,
                    #     "userProfileDirectory": user_profile_dir,
                    #     "startupPrograms": fetch_startup_programs,
                    #     "systemBootTime": system_boot_time_info,
                    #     "bootDevice": boot_device_information,
                    #     "sharedDirectories": shared_dir,
                    #     "servicesInfo": services_info,
                    #     "rdpStatus": rdp_status,
                    #     "auditLogs": audit_logs,
                    #     "avInfo": av_info,
                    #     "edrInstalled": edr_installed,
                    # },
                    "errorInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        **error
                    }
                }
                html_report_info = {
                    # "currentTime": current_time,
                    # "pcId": pc_id,
                    # "eventTriggerType": SCAN_TYPE,
                    # "pcIdentityInfo": {
                    #     "osType": os_type,
                    #     "osName": os_name_info,
                    #     "serialNumber": serial_number,
                    #     "motherboardSerialNumber": motherboard_serial_number,
                    #     "ipAddress": ip_address,
                    #     "hostname": host_name,
                    #     "connectedToDomainName": is_pc_in_org_domain,
                    #     "systemManufacturer": system_manufacturer_info,
                    #     "systemModel": system_model_info,
                    #     "currentUser": current_loggedin_user,
                    #     "currentAgentVersion": current_setup_file_version,
                    #     "licenseKey": LICENSE_KEY,
                    #     "securityStatus": security_status_info
                    # },
                    # "accountInfo": {
                    #     "additionalUserDetails": user_account_details,
                    #     "adminAccountsAreMultiple": is_multiple_admin_acc,
                    #     "usersPasswordAge": password_age_status,
                    # },
                    # "backendInfo": {
                    #     "endpointType": endpoint_type,
                    #     "installedPrograms": app_patch_info,
                    #     "osPatchInfo": os_patch_info
                    # },
                    # "cisInfo": {
                    #     "cisFilesystemConfigurationInfo": cis_file_system_configuration_info,
                    #     "cisAuditPartitionsInfo": cis_audit_partitions_info,
                    #     "cisFilesystemIntegrityInfo": cis_filesystem_integrity_check,
                    #     "cisSecureBootSettingsInfo": cis_secure_boot_settings_info,
                    #     "cisAdditionalProcessHardeningInfo": cis_additional_process_hardening_info,
                    #     "cisSELinuxConfigureInfo": cis_selinux_info,
                    #     "cisSpecialPurposeServicesInfo": cis_special_purpose_services_info,
                    #     "cisServiceClientsInfo": cis_service_clients_info,
                    #     "cisNetworkConfigurationInfo": cis_network_configuration_info,
                    #     "cisConfigureFirewallInfo": cis_configure_firewall_info,
                    #     "cisConfigureFirewallRulesInfo": cis_configure_firewall_rules_info,
                    #     "cisSystemAuditingInfo": cis_system_auditing_info,
                    #     "cisLoggingAndAuditingInfo": cis_logging_and_auditing_info,
                    #     "cisSystemAccessAuthInfo": cis_system_access_and_authentication_info,
                    #     "cisConfigureSSHServerInfo": cis_ssh_server_info,
                    #     "cisConfigurePrivilegeEscalationInfo": cis_privilege_escalation_info,
                    #     "cisConfigurePamInfo": cis_pam_info,
                    #     "cisUserAccountsEnvironmentInfo": cis_user_accounts_environment_info,
                    #     "cisSystemFilePermissionsInfo": cis_system_file_permissions_info,
                    #     "cisGetUserAndGroupInfo": cis_get_user_and_group_info,
                    #     "cisBaseAndOsServicesInfo": cis_base_and_os_services_info,
                    #     "cisProcessHardeningInfo": cis_process_hardening_info,
                    #     "cisWarningBannersInfo": cis_warning_banners_info,
                    #     "cisDesktopConfInfo": cis_desktop_conf_info,
                    #     "cisConfigureUfwInfo": cis_configure_ufw_info,
                    #     "cisConfigureIptablesSoftwaresInfo": cis_configure_iptables_softwares_info,
                    # },
                    # "hardwareInfo": {
                    #     "processorInfo": processor_info,
                    #     "machineBitType": machine_bit_type,
                    #     "machineType": machine_type,
                    #     "memoryInformation": memory_info,
                    #     "biosVersion": bios_version_info,
                    #     "timeZone": sys_time_zone_info,
                    #     "biosBatteryServiceable": bios_battery_serviceable_info,
                    #     "internalHardDrivesInfo": internal_disks_info,
                    #     "printers": printer_names_list,
                    #     "scanners": scanners_names_list,
                    #     "highCpuUsage": high_cpu_usage,
                    #     "ramUsage": ram_use,
                    #     "nicDetails": nicinfo,
                    #     "opticalDriveInfo": optical_drive_info,
                    #     "deviceUUIDNumber": uuid_number,
                    # },
                    # "networkInfo": {
                    #     "firewallStatus": firewall_status,
                    #     "firewallService": firewall_service,
                    #     "wifiStatus": wifi_info,
                    #     "ethernetStatus": ethernet_info,
                    #     "bluetoothInfo": bluetooth_info,
                    #     "establishedNetworkConnections": established_connections_list,
                    #     "openTcpPorts": open_tcp_ports_list,
                    #     "dnsServer": dns_info,
                    #     "nacInstalled": nac_info,
                    #     "ntpDetails": ntp_enabled,
                    # },
                    # "osInfo": {
                    #     "osDistributor": os_distributor,
                    #     "osRelease": os_release,
                    #     "osReleaseName": os_release_name,
                    #     "osVersion": os_version,
                    #     "osConfiguration": os_config_info,
                    #     "osInstallationDate": os_install_date_info,
                    #     "userHomeDirectory": user_home_dir,
                    #     "userProfileDirectory": user_profile_dir,
                    #     "startupPrograms": fetch_startup_programs,
                    #     "systemBootTime": system_boot_time_info,
                    #     "bootDevice": boot_device_information,
                    #     "sharedDirectories": shared_dir,
                    #     "servicesInfo": services_info,
                    #     "rdpStatus": rdp_status,
                    #     "auditLogs": audit_logs,
                    #     "avInfo": av_info,
                    #     "edrInstalled": edr_installed,
                    # },
                    # "errorInfo": {
                    #     **error
                    # }
                }
                if SCAN_TYPE == "LINUX_INSTALLATION_TRIGGER":
                    usb_history_info = {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "usbStoredHistory": usb_stored_history_info,
                    }
                    system_info["usbInfo"] = usb_history_info
                    system_info["pcIdentityInfo"]["custodianName"] = custodian_name
                    html_report_info["usbInfo"] = usb_history_info
                    html_report_info["pcIdentityInfo"]["custodianName"] = custodian_name

                if SCAN_TYPE == "LINUX_DAILY_TRIGGER" or SCAN_TYPE == "LINUX_INSTALLATION_TRIGGER":
                    system_info["backendInfo"]["fileIntegrityInfo"] = filesystem_integrity_info
                    html_report_info["backendInfo"]["fileIntegrityInfo"] = filesystem_integrity_info

        except Exception as system_info_error:
            error["miscellaneousInfo"]["system_info"] = repr(system_info_error)
            logging.error(f"Error while generating json: {system_info_error}")

        return system_info, html_report_info

    # calling the get system info function
    return get_system_info()


@logger_function
def get_redhat_system_info():
    # accountInfo functions --------------------------------------------------------------------

    @logger_function
    def get_user_account_details(username):
        """
        Get user's account details based on the given username.

        Parameters:
            username (str): The username for which to retrieve the account details.

        Returns:
            dict: A dictionary containing the user's account details. The dictionary has the following keys:
                - "accountType" (str): The type of the account (currently set to "Linux").
                - "caption" (str): The user's caption or display name.
                - "sID" (str): The user's security identifier.
                - "name" (str): The user's name.

            If the account details cannot be retrieved or an error occurs, None is returned.
        """
        logging.info("Started function: get_user_account_details()")
        try:
            # Get user's information from /etc/passwd
            logging.info(f"Searching for user '{username}' in /etc/passwd.")
            passwd_file = open('/etc/passwd', 'r')
            lines = passwd_file.readlines()
            for line in lines:
                if username in line:
                    parts = line.split(':')
                    user_details = {
                        "accountType": "Linux",  # You can customize this value
                        "caption": parts[0],
                        "sID": parts[2],
                        "name": parts[0]
                    }
                    logging.info(f"User details found in /etc/passwd for '{username}'.")
                    return user_details
            passwd_file.close()

            # If not found in /etc/passwd, try using 'id' command
            logging.info(f"User '{username}' not found in /etc/passwd. Trying 'id' command.")

            id_output = subprocess.check_output(['id', username], timeout=TIMEOUT_SUBPROCESS,
                                                stderr=subprocess.PIPE).decode('utf-8').strip()
            uid = id_output.split('(')[0].split('=')[1]
            user_details = {
                "accountType": "Linux",
                "caption": username,
                "sID": uid,
                "name": username
            }
            logging.info(f"User details retrieved using 'id' command for '{username}'.")

            return user_details
        except Exception as err:
            error["accountInfo"]["get_user_account_details"] = repr(err)
            logging.error(f"Error occurred while retrieving user details for '{username}': {repr(err)}")
            return {}

    @logger_function
    def get_admin_accounts():
        """
        Retrieves a list of admin accounts from the system.

        Returns:
            If there are no admin accounts available, returns the string "No Admin Account Available".
            If there are admin accounts available, returns a dictionary with the following keys:
                - 'multipleAdminCount': a boolean indicating whether there are multiple admin accounts
                - 'localAdminCount': an integer representing the number of admin accounts
                - 'adminAccountsName': a list of strings representing the names of the admin accounts

        Raises:
            Exception: If there was an error retrieving the admin accounts, an empty list is returned.
        """
        logging.info("started function: get_admin_accounts()")
        admin_accounts_details = {
            'multipleAdminCount': False,
            'localAdminCount': -1,
            'adminAccountsName': []
        }
        try:
            logging.info("Retrieving admin accounts using 'getent' command.")
            # Run 'getent' command to retrieve sudoers information
            sudoers_output_command = "getent group wheel"
            logging.info(f"get_admin_accounts_command: '{sudoers_output_command}'")
            sudoers_output = subprocess.check_output(sudoers_output_command, shell=True, universal_newlines=True,
                                                     stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS)
            lines = sudoers_output.strip().split('\n')
            logging.info(f"get_admin_accounts_output: {lines}")
            admin_accounts = []

            for line in lines:
                if line.startswith("wheel:") and len(line.split(":")) > 3:
                    members = line.split(":")[3].split(",")
                    admin_accounts.extend([member.strip() for member in members])

            if '' in admin_accounts:
                admin_count = 0
                admin_accounts = []
                multiple_admin_count = False

            else:
                admin_accounts = list(set(admin_accounts))  # Remove duplicates
                admin_count = len(admin_accounts)
                multiple_admin_count = admin_count > 1

            admin_accounts_details = {
                'multipleAdminCount': multiple_admin_count,
                'localAdminCount': admin_count,
                'adminAccountsName': admin_accounts
            }
            logging.info("Admin accounts retrieved successfully.")

        except Exception as err:
            error["accountInfo"]["get_admin_accounts"] = repr(err)
            logging.error(f"Error occurred while retrieving admin accounts: {repr(err)}")

        return admin_accounts_details

    @logger_function
    def get_users_password_age():
        """
        Calculates the number of days since the user's last password change.

        Returns:
            int: The number of days since the last password change. If the last password change
            date cannot be retrieved or if the current date is the same as the last password
            change date, returns -1. If an error occurs during the process, returns None.

        Raises:
            None
        """
        logging.info("Started function: get_users_password_age()")
        users_password_age = []
        try:
            all_user_command = r"""awk -F: '$3 >= 1000 && $3 <= 1100 && $6 ~ /^\/home/ {print $1}' /etc/passwd"""
            all_user_list = subprocess.run(all_user_command, shell=True, universal_newlines=True,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           timeout=TIMEOUT_SUBPROCESS).stdout.strip().split('\n')
            logging.info(f"all_user_list: {all_user_list}")
            for user in all_user_list:
                password_age = {
                    "userName": user,
                    "passwordAge": -1
                }
                logging.info("Executing 'chage' command to retrieve last password change date.")
                pwd_command = (f"sudo chage -l {user} "
                               r"| awk -F ':' '/Last password change/ {print $2}'")
                logging.info(f"pwd_command: {pwd_command}")
                last_change_match = subprocess.run(pwd_command, shell=True, universal_newlines=True,
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()
                logging.info(f"Subprocess Result of Last password change date: {last_change_match}")
                if last_change_match:
                    last_change_match = str(last_change_match)
                    logging.info(f"Last password change date: {last_change_match}")

                    # Adjust the format to include time information
                    if "never" in last_change_match:
                        try:
                            last_change_date_temp = str(get_os_install_date())
                            logging.info(f"last_change_date_temp: {last_change_date_temp}")

                            # Adjust the format to exclude time information
                            last_change_date = datetime.strptime(str(last_change_date_temp).split()[0],
                                                                 "%Y-%m-%d").date()
                            logging.info(f"last_change_date: {last_change_date}")
                            current_date = date.today()
                            logging.info(f"current_date: {current_date}")
                            days_since_change = (current_date - last_change_date).days

                            if days_since_change or days_since_change == 0:
                                logging.info(f"Days since last password change: {days_since_change}")
                                password_age["passwordAge"] = days_since_change
                            else:
                                logging.error("Last password change date could not be retrieved.")
                        except Exception as never_match_err:
                            logging.error(
                                f"error['accountInfo']['users_password_age']"
                                f"['get_users_password_age']:{never_match_err}")
                    else:
                        try:
                            last_change_date = datetime.strptime(last_change_match, "%b %d, %Y").date()
                            logging.info(f"last_change_date: {last_change_date}")
                            current_date = date.today()
                            logging.info(f"current_date: {current_date}")
                            days_since_change = (current_date - last_change_date).days
                            logging.info(f"days_since_change: {days_since_change}")
                            if days_since_change or days_since_change == 0:
                                logging.info(f"Days since last password change: {days_since_change}")
                                password_age["passwordAge"] = days_since_change
                            else:
                                logging.error("Last password change date could not be retrieved.")
                        except Exception as found_match_err:
                            logging.error(
                                f"error['accountInfo']['users_password_age']"
                                f"['get_users_password_age']:{found_match_err}")
                else:
                    logging.error("Last password change date could not be retrieved.")
                users_password_age.append(password_age)

        except Exception as err:
            error["accountInfo"]["users_password_age"] = repr(err)
            logging.error(f"Error occurred while calculating days since last password change: {repr(err)}")

        return users_password_age

    # backendInfo functions --------------------------------------------------------------------

    @logger_function
    def get_installed_programs():
        try:
            out = extract_shell_info(r"rpm -qa --queryformat '%{NAME}\n' | sort")
            return list(out.split())
        except Exception as err:
            error["backendInfo"]["get_installed_programs"] = repr(err)
            logging.error(f"Error occurred while retrieving installed programs: {repr(err)}")
            return []

    @logger_function
    def get_os_patch_info():
        os_versions = []
        try:
            version = get_linux_os_version()
            only_version = ""
            if version:
                only_version = version.split(" ")[0]
            result = {
                "name": get_os_name_info(),
                "version": only_version,
                "date": get_os_install_date(),
                "versionName": get_linux_os_version()
            }
            os_versions.append(result)

        except Exception as os_patch_info_error:
            error["backendInfo"]["get_os_patch_info"] = repr(os_patch_info_error)
            logging.error(f"Error occurred while getting os patch info: "
                          f"{repr(os_patch_info_error)}")

        return os_versions

    @logger_function
    def get_application_patch_info():
        applications_versions = []
        try:
            pattern = r'([a-zA-Z0-9_\-]+)-(\d+\.\d+\.\d+)'
            install_date = get_os_install_date()
            # Compile the pattern
            regex = re.compile(pattern)

            # Get list of installed packages
            out = extract_shell_info("rpm -qa | sort")
            packages = list(out.split())

            for package in packages:
                match = regex.match(package)
                if match:
                    package_name, package_version = match.groups()
                else:
                    package_name = package
                    package_version = None
                # Get detailed information for the package
                detailed_info = extract_shell_info(f"rpm -qi {package}")
                # Extract the installation date
                package_name_pattern = r'Name\s*:\s*(.*)'
                package_version_pattern = r'Version\s*:\s*(.*)'
                install_date_pattern = r'Install Date\s*:\s*(.*)'

                package_name_match = re.search(package_name_pattern, detailed_info)
                if package_name_match:
                    package_name = package_name_match.group(1)

                package_version_match = re.search(package_version_pattern, detailed_info)
                if package_version_match:
                    package_version = package_version_match.group(1)

                install_date_match = re.search(install_date_pattern, detailed_info)
                if install_date_match:
                    install_date = install_date_match.group(1)

                # Collect package info
                package_info = {
                    "name": package_name,
                    "version": package_version,
                    "date": convert_date_to_formatted(install_date)
                }
                applications_versions.append(package_info)

        except Exception as application_patch_info_error:
            error["backendInfo"]["get_application_patch_info"] = repr(application_patch_info_error)
            logging.error(f"Error occurred while getting application patch info: "
                          f"{repr(application_patch_info_error)}")

        return applications_versions

    @logger_function
    def get_filtered_hostname():
        try:
            hostname_temp = get_pretty_hostname()
            if hostname_temp != "":
                hostname = hostname_temp
            else:
                hostname = platform.node()
            host_i = hostname.split(".")[0]
            host_j = host_i.split("-")[-1]
            host = ""
            for i in host_j:
                if i.islower() or i.isdigit():
                    break
                host += i
            logging.info(f"hostname filtered: {host}")
            return host
        except Exception as filter_hostname_error:
            logging.error(f"Error occurred while filtering hostname:"
                          f"{repr(filter_hostname_error)}")
            return ""

    @logger_function
    def get_pretty_hostname():
        try:
            result = subprocess.run(['hostnamectl', 'status'], capture_output=True,
                                    timeout=TIMEOUT_SUBPROCESS, text=True)
            for line in result.stdout.splitlines():
                if "Pretty hostname:" in line:
                    logging.info(f"Found pretty hostname via hostnamectl: {line}")
                    return line.split(":", 1)[1].strip()
        except Exception as pretty_hostname_error:
            logging.error(f"Error occurred while getting pretty hostname via hostnamectl: "
                          f"{repr(pretty_hostname_error)}")
            try:
                with open('/etc/machine-info', 'r') as file:
                    for line in file:
                        if line.startswith("PRETTY_HOSTNAME="):
                            pretty_hostname = line.split("=", 1)[1].strip().strip('"')
                            logging.info(f"Found pretty hostname via /etc/machine-info: {pretty_hostname}")
                            return pretty_hostname
            except FileNotFoundError:
                logging.warning("/etc/machine-info file not found.")
            except Exception as file_error:
                logging.warning(f"Error occurred while reading /etc/machine-info: {repr(file_error)}")

        return ""

    @logger_function
    def get_file_integrity_info():
        try:
            manager = Manager()
            result = manager.list()

            json_file_path = '/etc/rati/integrityCheck.json'
            path_json = json.load(open(json_file_path, 'r'))

            hostname = get_filtered_hostname()

            if hostname:
                list_of_dirs = path_json[hostname]

                for path in list_of_dirs:
                    add_file_hash_to_log(path, result, hostname)

                return list(result)
            else:
                return []

        except Exception as file_integrity_info_error:
            logging.error(f"Error occurred while getting file integrity info: "
                          f"{repr(file_integrity_info_error)}")
            return []

    # hardwareInfo functions --------------------------------------------------------------------

    @logger_function
    def get_memory_information():
        """
        Retrieves memory information by running the 'free -h' command and parsing the output.

        Returns:
            A dictionary containing the following memory sizes in GB:
            - totalRAM: The total amount of RAM.
            - usedRAM: The amount of RAM being used.
            - freeRAM: The amount of free RAM.
            - sharedRAM: The amount of RAM being shared.
            - cacheRAM: The amount of RAM used for caching.
            - availableRAM: The amount of available RAM.

            If an error occurs while retrieving or parsing the memory information, returns a dictionary
            with an "error" key and an error message as the value.
        """
        try:
            # Run the 'free -h' command and capture the output
            output = subprocess.check_output(['free', '-h', '--giga'],
                                             universal_newlines=True, timeout=TIMEOUT_SUBPROCESS,
                                             stderr=subprocess.PIPE)
            logging.info(f"get_memory_information command output: {output}")
            # Split the output into lines
            lines = output.strip().split('\n')

            # Parse the first line of 'Mem:' data
            mem_data = re.match(r'^\s*Mem:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', lines[1])
            logging.info(f"mem_data: {mem_data}")
            if mem_data:
                total_ram, used_ram, free_ram, shared_ram, cache_ram, available_ram = mem_data.groups()

                # Convert sizes from human-readable format to GB
                sizes_gb = {
                    "totalRAM": total_ram,
                    "usedRAM": used_ram,
                    "freeRAM": free_ram,
                    "sharedRAM": shared_ram,
                    "cacheRAM": cache_ram,
                    "availableRAM": available_ram
                }
                logging.info(f"sizes_gb: {sizes_gb}")
                return sizes_gb
            else:
                logging.error("Unable to parse memory information from 'free -h' command output.")
                return {}
        except Exception as err:
            error["hardwareInfo"]["get_memory_information"] = repr(err)
            logging.error(f"Error occurred while getting memory information: {repr(err)}")
            return {}

    @logger_function
    def get_time_zone_info():
        """
        Retrieves the time zone information of the device.

        This function uses the 'date' command to get the time zone information and extracts the time zone from it.

        Returns:
            str: The time zone of the device.
        """
        try:
            # Run the 'date' command to get the time zone information
            output = subprocess.check_output(['date', '+%Z %z'], universal_newlines=True,
                                             timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
            logging.info(f"date output: {output}")
            time_zone = output.strip().split()[0]
            hours = output.strip().split()[1][:3]
            minutes = output.strip().split()[1][3:]
            formatted_time_zone = f"{time_zone} {hours}:{minutes}"
            return formatted_time_zone
        except Exception as err:
            error["hardwareInfo"]["get_time_zone_info"] = repr(err)
            logging.error(f"Error occurred while getting time zone information: {repr(err)}")
            return ""

    @logger_function
    def get_bios_battery_serviceable():
        """
        Retrieves the status of the BIOS battery serviceability.
        """
        result = False
        try:
            # Run dmidecode command and capture the output
            biosbattery_command = r"cat /proc/driver/rtc | grep batt_status | awk '{print $3}'"
            logging.info(f"dmidecode command for bios battery: {biosbattery_command}")
            if not os.path.exists("/proc/driver/rtc"):
                logging.warning(f"FileNotFoundError: /proc/driver/rtc")
                return result
            result = subprocess.run(biosbattery_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS, check=True)
            logging.info(f"dmidecode output: {result}")
            # Check if the output contains information about the battery
            if result.returncode == 0 and 'okay' in result.stdout:
                logging.info("BIOS battery is present and serviceable.")
                return True
            else:
                logging.info("BIOS battery information not found.")
                return False

        except Exception as e:
            logging.error(f"Error in get_bios_battery_serviceable: {e}")
            error["hardwareInfo"]["get_bios_battery_serviceable"] = repr(e)
        return result

    @logger_function
    def get_harddrive_info():
        """
        Retrieves information about the hard drive.

        Returns:
            list: A list of dictionaries containing information about each filesystem entry.
            Each dictionary has the following keys:
                - Filesystem (str): The name of the filesystem.
                - Size (str): The total size of the filesystem.
                - Used (str): The amount of space used on the filesystem.
                - Avail (str): The amount of space available on the filesystem.
                - Use% (str): The percentage of space used on the filesystem.
                - Mounted (str): The mount point of the filesystem.

        Raises:
            Exception: If there is an error while retrieving the hard drive information.
        """

        def convert_to_gigabytes(size_str):
            size_mapping = {'K': 1024 * 1024, 'M': 1024, 'G': 1}
            logging.info(f"converting {size_str} to GB")
            try:
                if size_str == '0':
                    return '0'
                value = float(size_str[:-1])
                unit = size_str[-1].upper()

                if unit in size_mapping:
                    gigabytes = value / size_mapping[unit]
                    return str(gigabytes)
                else:
                    return ""
            except Exception as er:
                error["hardwareInfo"]["convert_to_gigabytes"] = repr(er)
                logging.error(f"Error occurred in convert_to_gigabytes: {repr(er)}")
                return ""

        try:
            # Run the 'df -h' command and capture its output
            logging.info("Calling extract_shell_info('df -h')")
            df_output = extract_shell_info('df -h')
            # logging.info(f"get_harddrive_info command output: {df_output}")
            # Split the output into lines and skip the header line
            df_lines = df_output.split('\n')[1:]

            # Initialize an empty list to store filesystem entries as dictionaries
            filesystems = []

            # Iterate over each line and parse it into a dictionary
            for line in df_lines:
                if line.strip():  # Skip empty lines
                    fields = line.split()
                    filesystem = {
                        "fileSystem": fields[0],
                        "size": convert_to_gigabytes(fields[1]),
                        "used": convert_to_gigabytes(fields[2]),
                        "available": convert_to_gigabytes(fields[3]),
                        "usedPercent": fields[4][0:-1],
                        "mounted": fields[5]
                    }
                    filesystems.append(filesystem)

            logging.info(f"filesystems: {filesystems}")
            # Return the list of filesystem entries as a dictionary
            return filesystems
        except Exception as err:
            error["hardwareInfo"]["get_harddrive_info"] = repr(err)
            logging.error(f"Error occurred while getting hard drive information: {repr(err)}")
            return []

    @logger_function
    def list_printer_names():
        """
        Retrieves a list of printer names.

        This function runs the 'lpstat -l' command to capture the output, splits it into lines,
        and extracts the first column of each line to obtain the printer names.

        Returns:
            A list of printer names.

        Raises:
            Exception: If an error occurs while executing the command.
        """
        printer_names = []
        try:
            # Run the 'lpstat -l' command and capture its output
            lpstat_output = subprocess.check_output(['lpstat', '-l'], stderr=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

            # Split the output into lines and extract the first column
            for line in lpstat_output.split('\n'):
                columns = line.strip().split()
                if columns:
                    printer_names.append(columns[0])
            logging.info(f"printer_names: {printer_names}")
            return printer_names

        except Exception as err:
            error["hardwareInfo"]["list_printer_names"] = repr(err)
            logging.error(f"Error occurred while listing printer names: {repr(err)}")
            return printer_names

    @logger_function
    def list_scanner_names():
        """
        Retrieve a list of scanner names.

        Returns:
            list: A list of scanner names.

        Raises:
            Exception: If there is an error while retrieving the scanner names.
        """
        scanner_list = []
        try:
            # Run the 'sane-find-scanner' command and capture its output
            # scanner_output = extract_shell_info(command_args='sane-find-scanner', var_name="scanners_names_list")
            # <TODO> scanner_output will be returned after testing of scanner's functionality.
            logging.info(f"list_scanner_names: {scanner_list}")
            return scanner_list
        except Exception as err:
            error["hardwareInfo"]["list_scanner_names"] = repr(err)
            logging.error(f"Error occurred while listing scanner names: {repr(err)}")
            return scanner_list

    @logger_function
    def get_bluetooth_info():
        """
        Retrieves Bluetooth information including the connected devices, status, and device serial numbers.

        Returns:
            dict: A dictionary containing the following keys:
                - 'connectedDevice' (list): A list of dictionaries representing the connected devices.
                    Each dictionary contains the 'name' and 'macAddress' of the device.
                - 'status' (str): The status of Bluetooth. It is initialized as 'Off' and will
                    be updated to 'On' if Bluetooth is turned on.
                - 'deviceSerial' (str): The device serial number.
                - 'pairedDevice' (list): List of all paired Bluetooth devices with their names and MAC addresses.
        """
        bluetooth_info = {
            'status': 'Off',
            'deviceSerial': "",
            'connectedDevice': [],
            'pairedDevice': [],
        }

        try:
            command_bluetooth_check = ["bluetoothctl", "show"]
            command_bluetooth_devices = ["bluetoothctl", "paired-devices"]
            command_bluetooth_devices_alt = ["bluetoothctl", "devices"]

            # Check Bluetooth availability
            logging.info(f"Executing bluetooth cmd: {command_bluetooth_check}")
            result_check = subprocess.run(
                command_bluetooth_check, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_SUBPROCESS
            )
            if result_check.returncode != 0 or 'No default controller available' in result_check.stdout:
                logging.error("No bluetooth controller found or command failed.")
                return bluetooth_info

            for line in result_check.stdout.splitlines():
                if "Controller" in line:
                    bluetooth_info['deviceSerial'] = line.split()[1].strip()
                    logging.info(f"Bluetooth serial: {bluetooth_info['deviceSerial']}")
                elif "Powered: yes" in line:
                    bluetooth_info['status'] = 'On'
                    logging.info(f"Bluetooth status: {bluetooth_info['status']}")

            # Get paired devices
            result_devices = subprocess.run(
                command_bluetooth_devices, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_SUBPROCESS
            )
            if result_devices.returncode != 0:
                result_devices = subprocess.run(
                    command_bluetooth_devices_alt, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_SUBPROCESS
                )

            paired_output = result_devices.stdout.strip().splitlines()
            paired_result = []
            for line in paired_output:
                parts = line.strip().split(' ', 2)
                if len(parts) >= 3:
                    mac_address = parts[1]
                    device_name = parts[2]
                    paired_result.append({
                        "name": device_name,
                        "macAddress": mac_address
                    })
            bluetooth_info["pairedDevice"] = paired_result
            logging.info(f"Paired devices: {paired_result}")

            # Get connected devices
            connected_devices = []
            for device in paired_result:
                mac = device.get('macAddress')
                check_connected_cmd = ["bluetoothctl", "info", mac]
                logging.info(f"Checking connection for {mac}")
                result_connected = subprocess.run(
                    check_connected_cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_SUBPROCESS
                )
                for line in result_connected.stdout.splitlines():
                    if "Connected: yes" in line:
                        logging.info(f"Device {mac} is connected")
                        connected_devices.append(device)
                        break
            bluetooth_info["connectedDevice"] = connected_devices
            logging.info(f"Connected devices: {connected_devices}")

        except Exception as err:
            logging.error(f"Error occurred while getting Bluetooth info: {repr(err)}")

        return bluetooth_info

    @logger_function
    def get_high_cpu_processes():
        """
        Retrieves a list of processes with high CPU usage.

        Returns: list: A list of dictionaries representing the high CPU processes. Each dictionary contains the
        following keys: - 'pid' (int): The process ID. - 'cpuPercent' (float): The CPU usage percentage of the
        process. - 'name' (str): The name of the process.

        Raises:
            Exception: If an error occurs while retrieving the high CPU processes.
        """
        cutoff_percent = 0.5
        logging.info(f"get_high_cpu_processes cutoff_percent: {cutoff_percent}")
        processes = []
        try:
            cpu_process_command = r"ps -e -o pid,%cpu,comm"
            cpu_process_result = subprocess.run(cpu_process_command, shell=True, universal_newlines=True,
                                                stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                timeout=TIMEOUT_SUBPROCESS)
            # logging.info(f"get_high_cpu_processes subprocess command [ps -e -o pid,%cpu,cmd] output: "
            #              f"{cpu_process_result}")

            lines = cpu_process_result.stdout.split('\n')[1:]  # Skip the header line
            # logging.info(f"lines: {lines}")
            for line in lines:
                parts = line.strip().split(None, 2)
                if len(parts) == 3:
                    pid, cpu_percent, name = parts
                    cpu_percent = float(cpu_percent)
                    if cpu_percent >= cutoff_percent:
                        processes.append({
                            'pid': int(pid),
                            'cpuPercent': cpu_percent,
                            'name': name
                        })

            # logging.info(f"get_high_cpu_processes processes: {processes}")
            return processes
        except Exception as err:
            error["hardwareInfo"]["get_high_cpu_processes"] = repr(err)
            logging.error(f"Error occurred while getting high CPU processes: {repr(err)}")

        return processes

    @logger_function
    def get_processes_with_memory_usage():
        """
        Retrieves a list of processes along with their memory usage percentage.

        Returns:
            A list of dictionaries, where each dictionary represents a process and contains the following keys:
                - 'pid' (int): The process ID.
                - 'memoryPercent' (float): The memory usage percentage of the process.
                - 'name' (str): The name of the process.

        Raises:
            Exception: If there is an error while retrieving the processes or calculating the memory usage.
        """

        cutoff_percent = 1
        logging.info(f"get_processes_with_memory_usage cutoff_percent: {cutoff_percent}")
        processes = []
        try:
            ram_process_command = r"ps -e -o pid,%mem,comm"
            ram_process_result = subprocess.run(ram_process_command, shell=True, universal_newlines=True,
                                                stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                timeout=TIMEOUT_SUBPROCESS)
            # logging.info(f"get_processes_with_memory_usage subprocess command [ps -e -o pid,%mem,comm] output: "
            #              f"{ram_process_result}")

            lines = ram_process_result.stdout.split('\n')[1:]  # Skip the header line
            # logging.info(f"lines: {lines}")
            for line in lines:
                parts = line.strip().split(None, 2)
                if len(parts) == 3:
                    pid, mem_percent, name = parts
                    mem_percent = float(mem_percent)
                    if mem_percent >= cutoff_percent:
                        processes.append({
                            'pid': int(pid),
                            'memoryPercent': mem_percent,
                            'name': name
                        })
            # logging.info(f"get_processes_with_memory_usage processes: {processes}")
            return processes
        except Exception as err:
            error["hardwareInfo"]["get_processes_with_memory_usage"] = repr(err)
            logging.error(f"Error occurred while getting processes with memory usage: {repr(err)}")

        return processes

    @logger_function
    def nic_info():
        """
        Retrieves information about network interfaces using the `lshw` command.

        Returns:
            list: A list of dictionaries containing information about each network interface.
        """
        # Run the lshw command and capture its output
        nic_details = {
            "nicCount": "",
            "nicInfo": []
        }

        def extract_ip_mac(data):
            interfaces_list = []

            try:
                ip_pattern = re.compile(r'inet (\d+\.\d+\.\d+\.\d+)')
                mac_pattern = re.compile(r'ether (\S+)')

                blocks = data.strip().split('\n\n')

                for block in blocks:
                    ip_match = ip_pattern.search(block)
                    mac_match = mac_pattern.search(block)

                    if ip_match and mac_match:
                        interface_info = {
                            "ip": ip_match.group(1),
                            "mac": mac_match.group(1)
                        }
                        interfaces_list.append(interface_info)
            except Exception as extract_ip_err:
                logging.error(f"error['hardwareInfo']['nic_info']['extract_ip_mac']: {extract_ip_err}")

            return interfaces_list

        try:
            network_info_list = []
            nic_cmd = r"lshw -class network | awk  '/\*-network|description:|product:|vendor:|serial:|physical id:/'"
            logging.info(f"nic_info nic_cmd: {nic_cmd}")
            nic_output = subprocess.run(nic_cmd, shell=True, stderr=subprocess.PIPE, universal_newlines=True,
                                        stdout=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).stdout

            ifconfig_cmd = r"ifconfig -a"
            logging.info(f"nic_info ifconfig_cmd: {ifconfig_cmd}")
            ifconfig_output = subprocess.run(ifconfig_cmd, shell=True, stderr=subprocess.PIPE, universal_newlines=True,
                                             stdout=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).stdout
            interfaces = extract_ip_mac(ifconfig_output)
            # logging.info(f"nic_info output: {nic_output}")
            # Split the output into individual device sections
            device_sections = re.split(r'\*-network', nic_output)[1:]
            logging.info(f"nic_info device_sections: {device_sections}")
            for section in device_sections:
                network_info = {}
                lines = section.strip().split('\n')

                for line in lines:
                    # Split each line into key and value
                    parts = line.strip().split(': ', 1)
                    if len(parts) == 2:
                        key, value = parts
                        if value and len(value.strip()) > 0:
                            if key == "physical id":
                                network_info["physicalId"] = value
                            elif key == "serial":
                                network_info["macAddress"] = value
                            else:
                                network_info[key] = value
                if len(network_info.keys()) == 5:
                    ip_of_card = ""
                    for interface in interfaces:
                        if interface["mac"] == network_info["macAddress"]:
                            ip_of_card = interface["ip"]
                            break
                    network_info["ipAddress"] = ip_of_card
                    network_info_list.append(network_info)
            logging.info(f"nic_info network_info_list: {network_info_list}")
            nic_details["nicInfo"] = network_info_list
            nic_details["nicCount"] = str(len(network_info_list))
        except Exception as err:
            error["hardwareInfo"]["nic_info"] = repr(err)
            logging.error(f"Error occurred while getting network info: {repr(err)}")

        return nic_details

    @logger_function
    def get_optical_drive_info():
        """
        Retrieves information about opticalDrive using the `lshw` command.

        Returns:
            list: A list of dictionaries containing information about optical Drive.
        """
        # Run the lshw command and capture its output
        od_details = {
            "drivePresent": False,
            "driveDetails": [],
        }

        try:
            od_info_list = []
            od_cmd = r"lshw -class disk | awk  '/\*-cdrom|description:|product:|vendor:|physical id:/'"
            logging.info(f"optical drive cmd: {od_cmd}")
            od_output = subprocess.run(od_cmd, shell=True, stderr=subprocess.PIPE, universal_newlines=True,
                                       stdout=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).stdout
            logging.info(f"optical drive output: {od_output}")
            # Split the output into individual device sections
            device_sections = re.split(r'\*-cdrom', od_output)[1:]
            logging.info(f"optical drive device_sections: {device_sections}")
            if len(device_sections) == 0:
                return od_details
            for section in device_sections:
                network_info = {}
                lines = section.strip().split('\n')

                for line in lines:
                    # Split each line into key and value
                    parts = line.strip().split(': ', 1)
                    if len(parts) == 2:
                        key, value = parts
                        if key == "physical id":
                            network_info["physicalId"] = value
                            break
                        else:
                            network_info[key] = value
                if network_info.get("product") and "DVD+-" in network_info.get("product"):
                    od_info_list.append(network_info)
            logging.info(f"optical_drive info list: {od_info_list}")
            if len(od_info_list) > 0:
                od_details["drivePresent"] = True
            od_details["driveDetails"] = od_info_list

        except Exception as err:
            error["hardwareInfo"]["optical_drive_info"] = repr(err)
            logging.error(f"Error occurred while getting optical drive info: {repr(err)}")

        return od_details

    @logger_function
    def get_tpm_version():
        result = "NA"
        try:
            tpm_v_command = "sudo dmesg | grep tpm_tis"
            tpm_v_output = subprocess.check_output(tpm_v_command, shell=True, universal_newlines=True,
                                                   timeout=TIMEOUT_SUBPROCESS).strip()

            match = re.search(r"(\d+\.\d+)\s+TPM", tpm_v_output)
            if match:
                return match.group(1)
        except Exception as tpm_version_err:
            error["hardwareInfo"]["tmp_version"] = repr(tpm_version_err)
            logging.error(f"Error occurred while getting tmp version: {repr(tpm_version_err)}")
        return result

    # networkInfo functions --------------------------------------------------------------------

    @logger_function
    def check_firewall_status():
        """
        Check the status of the firewall.

        This function runs a command to check the status of the firewall on the system. It executes the
            command "systemctl list-units --type=service | grep firewall | awk '{print $1}'" using the subprocess module
            and captures the output. The output is then split into lines and stored in an array.
            If there are any output lines, the function returns "ON" along with the lines.
            Otherwise, it returns "OFF" and an empty array.

        Returns:
            - If the firewall is ON, returns a tuple with the value "ON" and an array of output lines.
            - If the firewall is OFF, returns a tuple with the value "OFF" and an empty array.
            - If there is an exception while running the command, returns a string with an error message.

        """
        firewall_status = "OFF"
        firewall_services = []
        try:
            list_of_services = ["firewalld", "ufw", "nftables", "iptables"]

            count_of_active_services = 0
            for service in list_of_services:
                try:
                    result = subprocess.run(["systemctl", "is-active", service],
                                            capture_output=True, text=True).stdout.strip()
                    result_present = subprocess.run(["systemctl", "status", service],
                                                    capture_output=True, text=True)
                    if result == "active":
                        count_of_active_services += 1
                    if result_present.stdout.strip() != "":
                        firewall_services.append(service)
                    logging.info(f"Service {service} is {result}")
                except Exception as service_exception:
                    logging.warning(f"Service exception occurred: {service_exception}")

            if count_of_active_services > 0:
                firewall_status = "ON"

        except Exception as err:
            error["networkInfo"]["check_firewall_status"] = repr(err)
            logging.error(f"Error occurred while checking firewall status: {repr(err)}")

        return firewall_status, firewall_services

    @logger_function
    def get_wifi_info():
        """
        Retrieves information about the wi-fi network connection.

        Returns:
            dict: A dictionary containing the following keys:
                - wifiConnectivityStatus (str): The status of the wi-fi connection.
                    It can be either "connected" or "disconnected".
                - ssid (str): The SSID (Service Set Identifier) of the wi-fi network, if connected.
                - wifiMacAddress (str): The MAC address of the wi-fi network, if connected.

        Raises:
            Exception: If an error occurs while retrieving the wi-fi information.

        """
        wifi_info_list = []
        try:
            # Get a list of network devices using ip a command
            cmd = r"""nmcli d | awk '$3=="connected" && $2=="wifi" && $4!="--" && NF>=4'|awk '{print $1}'"""
            logging.info(f"get_wifi_info_command: '{cmd}'")
            interface_list_output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                                   stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()
            logging.info(f'get_wifi_info_output: {interface_list_output}')

            if not interface_list_output:
                return wifi_info_list

            interface_list = interface_list_output.split('\n')
            for interface in interface_list:
                wifi_info = {'connectivityStatus': 'connected', 'interfaceName': interface,
                             'ssid': '', 'ipAddress': '', 'macAddress': '', 'authenticationType': ''}
                command = f"nmcli -t -f NAME,UUID,DEVICE connection show --active | grep '{interface}' | cut -d: -f1"
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_wifi_info_output: {output}")
                if output:
                    wifi_info['ssid'] = output
                else:
                    wifi_info['ssid'] = ""

                command = f"ip link show '{interface}' | awk '/ether/ {{print $2}}'"
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_wifi_info_output: {output}")
                if output:
                    wifi_info['macAddress'] = output
                else:
                    wifi_info['macAddress'] = ""

                command = (f"ip -4 addr show {interface} | "
                           r"grep -oP '(?<=inet\s)\d+(\.\d+){3}'")
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_wifi_info_output: {output}")
                if output:
                    wifi_info['ipAddress'] = output
                else:
                    wifi_info['ipAddress'] = ""

                command = (f"""nmcli dev wifi | awk '$1=="*" && $3=="{wifi_info['ssid']}"' | """
                           r"""awk '{ for(i=NF; i>0; i--) if($i ~ /WPA/) { printf "%s ", $i } }'""")
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_wifi_info_output: {output}")
                if output:
                    wifi_info['authenticationType'] = output
                else:
                    wifi_info['authenticationType'] = ""
                logging.info(f"get_wifi_info wifi_info: {wifi_info}")

                wifi_info_list.append(wifi_info)

        except Exception as err:
            error['networkInfo']['get_wifi_info'] = repr(err)
            logging.error(f"Error occurred while getting wifi info: {repr(err)}")

        return wifi_info_list

    @logger_function
    def is_ntp_server_enabled():
        ntp_result = {
            "isNtpEnabled": False,
            "ntpServer": "",
            "ntpSyncStatus": "",
            "ntpStratumLevel": ""
        }
        try:
            # Run the PowerShell command to query NTP peers
            ntp_subprocess_result = subprocess.run("systemctl status chronyd | grep Active: | awk '{print $2}'",
                                                   shell=True, universal_newlines=True,
                                                   stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()

            logging.info(f"Subprocess output of ntp: {ntp_subprocess_result}")
            # Check if the output indicates that the service has not been started
            if ntp_subprocess_result == "active":
                logging.info("NTP server is configured.")
                ntp_result["isNtpEnabled"] = True

            npt_file_path = "/etc/chrony.conf"
            logging.info(f"reading ntp file path: {npt_file_path}")
            if os.path.exists(npt_file_path):
                ntp_server_result = subprocess.run("cat /etc/chrony.conf | grep -E '^(pool|server)'", shell=True,
                                                   universal_newlines=True,
                                                   stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()

                logging.info(f"Subprocess output of ntp: {ntp_server_result}")
                # Check if the output indicates that the service has not been started
                ntp_line_list = ntp_server_result.split("\n")[0].split()
                ntp_result["ntpServer"] = ntp_line_list[1] if len(ntp_line_list) >= 3 else ""

            else:
                logging.info(f"{npt_file_path} not found.")

            try:
                chrony_stat_result = subprocess.run("chronyc tracking", shell=True, universal_newlines=True,
                                                    stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                    timeout=TIMEOUT_SUBPROCESS).stdout.strip()

                lines = chrony_stat_result.split("\n")
                for line in lines:
                    if "Leap status" in line and "Normal" in line:
                        ntp_result["ntpSyncStatus"] = "synchronised"
                    if "Stratum" in line:
                        stratum = re.search(r"Stratum\s+:\s(\d+)", line).group(1)
                        ntp_result["ntpStratumLevel"] = stratum

            except subprocess.TimeoutExpired:
                ntp_result["ntpSyncStatus"] = "timeout"

            except Exception as sync_error:
                logging.error(f"NTP sync error: {sync_error}")
                ntp_result["ntpSyncStatus"] = "not synchronised"

        except Exception as ntp_error:
            logging.error(f"NTP server error: {ntp_error}")

        return ntp_result

    @logger_function
    def get_ethernet_info():
        """
        Retrieves information about the wi-fi network connection.

        Returns:
            dict: A dictionary containing the following keys:
                - ethernetConnectivityStatus (str): The status of the wi-fi connection.
                    It can be either "connected" or "disconnected".
                - ssid (str): The SSID (Service Set Identifier) of the wi-fi network, if connected.
                - ethernetMacAddress (str): The MAC address of the wi-fi network, if connected.

        Raises:
            Exception: If an error occurs while retrieving the wi-fi information.

        """
        ethernet_info_list = []
        try:
            # Get a list of network devices using ip a command
            cmd = r"""nmcli d | awk '$3=="connected" && $2=="ethernet" && $4!="--" && NF>=4'|awk '{print $1}'"""
            logging.info(f"get_ethernet_info_command: '{cmd}'")
            interface_list_output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                                   stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                   timeout=TIMEOUT_SUBPROCESS).stdout.strip()
            logging.info(f'get_ethernet_info_output: {interface_list_output}')
            if not interface_list_output:
                return ethernet_info_list

            interface_list = interface_list_output.split('\n')
            for interface in interface_list:
                ethernet_info = {'connectivityStatus': 'connected', 'interfaceName': interface,
                                 'macAddress': '', 'ipAddress': ''}
                command = f"ip link show '{interface}' | awk '/ether/ {{print $2}}'"
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_ethernet_info_output: {output}")
                if output:
                    ethernet_info['macAddress'] = output
                else:
                    ethernet_info['macAddress'] = ""
                logging.info(f"get_ethernet_info ethernet_info: {ethernet_info}")

                command = (f"ip -4 addr show {interface} | "
                           r"grep -oP '(?<=inet\s)\d+(\.\d+){3}'")
                output = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                 stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS).strip()
                logging.info(f"get_ethernet_info_output: {output}")
                if output:
                    ethernet_info['ipAddress'] = output
                else:
                    ethernet_info['ipAddress'] = ""

                ethernet_info_list.append(ethernet_info)

        except Exception as err:
            error['networkInfo']['get_ethernet_info'] = repr(err)
            logging.error(f"Error occurred while getting ethernet info: {repr(err)}")

        return ethernet_info_list

    @logger_function
    def get_established_connections():
        """
        Retrieves a list of established TCP/UDP network connections with process details.

        Returns:
            A list of dictionaries, each representing an established connection.
            Each dictionary contains:
            - 'localAddress': The local IP address.
            - 'localPort': The local port number.
            - 'foreignAddress': The remote IP address.
            - 'foreignPort': The remote port number.
            - 'processName': Name of the associated process (if any).
            - 'pid': PID of the associated process (if any).
        """

        established_connections = []
        try:
            logging.info("get_established_connections_command: ss -tup | grep 'ESTAB'")
            ss_output = subprocess.check_output(
                "ss -tup | grep 'ESTAB'",
                shell=True,
                universal_newlines=True,
                timeout=TIMEOUT_SUBPROCESS
            )

            for line in ss_output.strip().splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue

                local_addr_port = parts[4]
                remote_addr_port = parts[5]
                users_field = ' '.join(parts[6:]) if len(parts) > 6 else ''

                local_match = re.match(r'(?:\[?([^\]]+)\]?):(\S+)', local_addr_port)
                remote_match = re.match(r'(?:\[?([^\]]+)\]?):(\S+)', remote_addr_port)

                if not local_match or not remote_match:
                    continue

                local_ip, local_port = local_match.group(1), local_match.group(2)
                remote_ip, remote_port = remote_match.group(1), remote_match.group(2)

                proc_name = pid = exe_path = ""

                proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+),fd=(\d+)', users_field)
                if proc_match:
                    proc_name = proc_match.group(1)
                    pid = proc_match.group(2)

                    try:
                        exe_path = os.readlink(f"/proc/{pid}/exe")
                    except Exception:
                        exe_path = ""

                established_connections.append({
                    'localAddress': local_ip,
                    'localPort': local_port,
                    'foreignAddress': remote_ip,
                    'foreignPort': remote_port,
                    'processName': proc_name,
                    'pid': pid,
                    'exePath': exe_path,
                })

        except Exception as err:
            logging.error(f"Error occurred while getting established connections: {repr(err)}")
        return established_connections

    @logger_function
    def get_tcp_info():
        """
        Retrieves the TCP ports that are currently in the LISTEN state on the local machine.

        Returns:
            list: A list of integers representing the TCP ports that are currently in the LISTEN state.

        Raises:
            Exception: If there is an error while retrieving the TCP ports.

        """
        try:
            command = r"ss -tln | awk '/^LISTEN/ {print $4}' | awk -F '[:\\[\\]]' '{print $NF}'"
            out = subprocess.check_output(command, shell=True, universal_newlines=True,
                                          timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
            # logging.info(f"get_tcp_info out: {out}")
            tcp_ports_set = set(out.strip().split('\n'))
            tcp_ports = list(tcp_ports_set)
            tcp_ports = [int(x) for x in tcp_ports]
            tcp_ports_result_list = sorted(tcp_ports)
            return tcp_ports_result_list
        except Exception as err:
            error["networkInfo"]["get_tcp_info"] = repr(err)
            logging.error(f"Error occurred while getting tcp info: {repr(err)}")
            return []

    @logger_function
    def get_dns_info():
        """
        Retrieves the DNS information of the system.

        Returns:
            - If successful, a list containing the DNS server information.
            - If unsuccessful, an empty list.

        Raises:
            - Exception: If an error occurs while retrieving the DNS information.

        """
        dns_info = []
        try:
            cmd_dns = "nmcli dev show | grep 'IP4.DNS' | awk '{print $2}'"
            logging.info(f"get_dns_info_command: '{cmd_dns}'")
            result = subprocess.check_output(cmd_dns, shell=True, universal_newlines=True, stderr=subprocess.PIPE,
                                             timeout=TIMEOUT_SUBPROCESS).split()
            logging.info(f"get_dns_info result: {result}")
            if result:
                dns_info = result
            else:
                dns_info = []
            logging.info(f"get_dns_info dns_info: {dns_info}")
        except Exception as err:
            error['networkInfo']['get_dns_info'] = repr(err)
            logging.error(f"Error occurred while getting dns info: {repr(err)}")

        return list(set(dns_info))

    @logger_function
    def get_nac_info(installed_programs):
        """
        Returns a dictionary containing the NAC information.
        """
        nac_software = ["no data"]
        # nac_services_mandatory = ["ser_1", "ser_2"]
        try:
            nac_keywords = [prog.split() for prog in nac_software]
            for ins_prog in installed_programs:
                for keywords in nac_keywords:
                    if all(key in ins_prog for key in keywords):
                        # nac_services = get_service_status(nac_services_mandatory)
                        # nac_details[" ALL NAC Services Running"] = nac_services
                        logging.info("NAC is installed")
                    else:
                        return False
                        # logging.info("NAC is not installed")
            logging.info("returning from nac installation function")

        except Exception as err:
            error["networkInfo"]["get_nac_info"] = repr(err)
            logging.error(f"Error occurred while retrieving NAC info: {repr(err)}")
            return False

        return True

    # osInfo functions --------------------------------------------------------------------
    @logger_function
    def get_os_install_date():
        try:
            try:
                logging.info(f"os_installation_date_command: ['stat', '-c', '%w', '/']")
                timestamp_str = str(extract_info(['stat', '-c', '%w', '/']))
                logging.info(f"os_installation_date_output: {timestamp_str}")
                # "2024-01-04 10:55:57.460197000 +0530"
                timestamp_list = timestamp_str.split()
                logging.info(f"os_installation_date_list: {timestamp_list}")
                install_date = timestamp_list[0]
                logging.info(f"os_installation_date: {install_date}")
                install_time = timestamp_list[1].split('.')[0]
                logging.info(f"os_installation_time: {install_time}")
                install_zone_hour = timestamp_list[2][:3]
                logging.info(f"os_installation_zone_hour: {install_zone_hour}")
                install_zone_minute = timestamp_list[2][3:]
                logging.info(f"os_installation_zone_minute: {install_zone_minute}")
                formatted_timestamp = f"{install_date} {install_time} {install_zone_hour}:{install_zone_minute}"
                logging.info(f"os_installation_formatted_timestamp: {formatted_timestamp}")
                return formatted_timestamp
            except Exception as stat_one_err:
                logging.error(f"Error occurred while extracting os installation date: {repr(stat_one_err)}")
            try:
                logging.info(f"os_installation_date_command: 'sudo stat /root/anaconda-ks.cfg | grep Birth'")
                timestamp_str = \
                    subprocess.check_output("stat /root/anaconda-ks.cfg | grep Birth",
                                            shell=True, timeout=TIMEOUT_SUBPROCESS).decode('utf-8').split('Birth:')[
                        1].strip()
                if len(timestamp_str) < 30:
                    timestamp_str = \
                        subprocess.check_output("stat /root/anaconda-ks.cfg | grep Change",
                                                shell=True, timeout=TIMEOUT_SUBPROCESS).decode('utf-8').split(
                            'Change:')[-1].strip()
                logging.info(f"os_installation_date_output: {timestamp_str}")
                timestamp_list = timestamp_str.split()
                logging.info(f"os_installation_date_list: {timestamp_list}")
                install_date = timestamp_list[0]
                logging.info(f"os_installation_date: {install_date}")
                install_time = timestamp_list[1].split('.')[0]
                logging.info(f"os_installation_time: {install_time}")
                install_zone_hour = timestamp_list[2][:3]
                logging.info(f"os_installation_zone_hour: {install_zone_hour}")
                install_zone_minute = timestamp_list[2][3:]
                logging.info(f"os_installation_zone_minute: {install_zone_minute}")
                formatted_timestamp = f"{install_date} {install_time} {install_zone_hour}:{install_zone_minute}"
                logging.info(f"os_installation_formatted_timestamp: {formatted_timestamp}")
                return formatted_timestamp
            except Exception as stat_two_err:
                logging.error(f"Error occurred while extracting os installation date: {repr(stat_two_err)}")
                return ""
        except Exception as err:
            error["osInfo"]["os_installation_date"] = repr(err)
            logging.error(f"Error occurred while extracting os installation date: {repr(err)}")
            return ""

    @logger_function
    def get_user_profile_directory(current_loggedin_user):
        """
        Retrieves the user's profile directory.

        This function uses the `getent passwd` command to retrieve the information about all users on the system.
        It then searches for the entry corresponding to the current user by comparing the usernames.
        Once the entry is found, the function extracts the home directory (the 6th field) and returns it.

        Returns:
            str: The user's profile directory.

        Raises:
            Exception: If an error occurs while executing the `getent` or `whoami` commands.

        """
        try:
            # Run the `getent passwd` command and capture the output
            output = subprocess.check_output(['getent', 'passwd'], universal_newlines=True,
                                             timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
            # logging.info(f"get_user_profile_directory output: {output}")
            # Split the output into lines
            lines = output.strip().split('\n')

            # Find the entry for the current user (based on the username)
            logging.info(f"get_user_profile_directory current_user: {current_loggedin_user}")
            for line in lines:
                if line.startswith(current_loggedin_user + ':'):
                    # Split the line by colons and get the home directory (the 6th field)
                    parts = line.split(':')
                    if len(parts) >= 6:
                        return parts[5]
            logging.info(f"get_user_profile_directory result: {output}")
            return ""
        except Exception as err:
            error["osInfo"]["get_user_profile_directory"] = repr(err)
            logging.error(f"Error occurred while getting user profile directory: {repr(err)}")
            return ""

    @logger_function
    def get_list_of_startup_programs():
        """
        Retrieves a list of startup programs.

        Returns:
            list: A list of startup programs.
        """
        startup_programs = []
        try:
            # Check user-specific autostart directory
            user_autostart_dir = os.path.expanduser("~/.config/autostart")
            logging.info(f"user_autostart_dir: {user_autostart_dir}")
            if os.path.exists(user_autostart_dir):
                user_autostart_files = os.listdir(user_autostart_dir)
                user_startup_programs = [file[:-8] for file in user_autostart_files if file.endswith(".desktop")]
                startup_programs.extend(user_startup_programs)
                logging.info(f"user_startup_programs: {user_startup_programs}")
            # Check system-wide autostart directory
            system_autostart_dir = "/etc/xdg/autostart"
            if os.path.exists(system_autostart_dir):
                system_autostart_files = os.listdir(system_autostart_dir)
                system_startup_programs = [file[:-8] for file in system_autostart_files if file.endswith(".desktop")]
                startup_programs.extend(system_startup_programs)
                # logging.info(f"system_startup_programs: {system_startup_programs}")
        except Exception as err:
            error["osInfo"]["get_list_of_startup_programs"] = repr(err)
            logging.error(f"Error occurred while getting list of startup programs: {repr(err)}")

        return startup_programs

    @logger_function
    def get_boot_device_info():
        """
        Retrieves the device path of the boot device.

        Returns:
            str: The device path of the boot device, or None if it cannot be determined.

        Raises:
            Exception: If an error occurs while retrieving the device path.
        """
        try:
            # Use dmidecode to get information about the system
            bootdevice_command = r"df -h"
            logging.info(f"get_boot_device_command: '{bootdevice_command}'")
            bootdevice_output = subprocess.check_output(bootdevice_command, shell=True, universal_newlines=True,
                                                        timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
            # logging.info(f"get_boot_device_output: {bootdevice_output}")
            bootdevice_list = bootdevice_output.split("\n")
            for line in bootdevice_list:
                line_list = line.split()
                if line_list[-1] == "/":
                    return line_list[0]
            return ""

        except Exception as err:
            error["osInfo"]["get_boot_device_info"] = repr(err)
            logging.error(f"Error occurred while getting boot device: {repr(err)}")
            return ""

    @logger_function
    def list_shared_directories():
        """
        Retrieves a list of shared directories.

        Returns:
            - If the usershares directory does not exist, returns False.
            - If there are no shared directories found, returns False.
            - If shared directories are found, returns a list of directory names.
        """

        def check_permission(file_path):
            permission = {
                "owner": "",
                "group": "",
                "other": ""
            }
            try:
                if not os.path.exists(file_path):
                    return permission
                else:
                    out = subprocess.check_output(f'ls -ld "{file_path}"', shell=True,
                                                  timeout=TIMEOUT_SUBPROCESS, universal_newlines=True)
                    owner_perm = out[1:4]
                    group_perm = out[4:7]
                    other_perm = out[7:10]
                    logging.info(f"owner_perm: {owner_perm}, group_perm: {group_perm}, other_perm: {other_perm}")
                    list_user = [{"owner": owner_perm}, {"group": group_perm}, {"other": other_perm}]
                    for ind in range(len(list_user)):
                        # Check permission
                        user = list_user[ind]
                        key = list(user.keys())[0]
                        value = list(user.values())[0]

                        if "r" in value and "w" in value and "x" in value:
                            res_perm = "READ/WRITE/EXECUTE"
                        elif "r" in value and "w" in value:
                            res_perm = "READ/WRITE"
                        elif "r" in value and "x" in value:
                            res_perm = "READ/EXECUTE"
                        elif "r" in value:
                            res_perm = "READ"
                        elif "w" in value and "x" in value:
                            res_perm = "WRITE/EXECUTE"
                        elif "w" in value:
                            res_perm = "WRITE"
                        elif "x" in value:
                            res_perm = "EXECUTE"
                        else:
                            res_perm = "NONE"

                        permission[key] = res_perm

            except Exception as perm_err:
                logging.error(f"Error occurred while checking permission: {repr(perm_err)}")

            return permission

        result = []
        try:
            list_shared_command = r"""cat /etc/samba/smb.conf | grep -E "[[]*]|path =" | awk '{for (i=1; i<NF;
            i++) printf $i; print $NF}'"""
            logging.info(f"list_shared_directories_command: {list_shared_command}")
            if not os.path.exists("/etc/samba/smb.conf"):
                logging.warning(f"Error: File '/etc/samba/smb.conf.example' does not exist.")
                return []
            list_shared_output = subprocess.check_output(list_shared_command, shell=True, universal_newlines=True,
                                                         timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
            sections = re.split(r'\[([^]]+)]', list_shared_output)[1:]
            logging.info(f"list_shared_directories_sections: {sections}")
            parsed_output = []

            for i in range(0, len(sections), 2):
                section_name = sections[i]
                section_content = sections[i + 1]
                path_match = re.search(r'path\s*=/\s*([^\n;]+)', section_content)
                if path_match:
                    parsed_output.append(f'{section_name} /{path_match.group(1).strip()}')

            logging.info(f"list_shared_directories_parsed_output: {parsed_output}")
            for line in parsed_output:
                result.append({"name": line.split()[0], "path": line.split()[1]})
            for res in result:
                path = res["path"]
                res["permission"] = check_permission(path)

        except Exception as err:
            error["osInfo"]["list_shared_directories"] = repr(err)
            logging.error(f"Error occurred while listing shared directories: {repr(err)}")

        return result

    @logger_function
    def get_services_info():
        """
        Retrieves information about services using systemctl.    Returns:
            A list of dictionaries containing the service information. Each dictionary has the following keys:
                - "DisplayName" (str): The display name of the service.
                - "Status" (str): The status of the service.
                - "Description" (str): The description of the service.
            If an exception is encountered during the retrieval process, an empty list is returned.
        """
        try:
            # Get service information using systemctl
            systemctl_command = ['systemctl', '--quiet', '--all', '--no-pager', '--type=service', 'list-units',
                                 '--full']
            result = subprocess.run(systemctl_command, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                    universal_newlines=True, check=True,
                                    timeout=TIMEOUT_SUBPROCESS)
            # logging.info(f"result of systemctl command: {result}")
            # Parse and format the systemctl output
            services_info = []
            lines = result.stdout.strip().split('\n')
            for line in lines:
                columns = line.split()
                if len(columns) >= 6:
                    if columns[0] == '\u25cf':
                        service_name = columns[1]
                        result = ' '.join(columns[5:])
                        service_info = {
                            "displayName": service_name,
                            "status": columns[3],
                            "description": result
                        }
                    else:
                        service_name = columns[0]
                        result = ' '.join(columns[4:])
                        service_info = {
                            "displayName": service_name,
                            "status": columns[2],
                            "description": result
                        }
                    services_info.append(service_info)
            # logging.info(f"services_info: {services_info}")
            return services_info

        except Exception as err:
            error["osInfo"]["get_services_info"] = repr(err)
            logging.error(f"Error occurred while getting services info: {repr(err)}")
            return []

    @logger_function
    def get_rdp_status():
        """
        Retrieves the status of the RDP (Remote Desktop Protocol) and SSH (Secure Shell) services.

        Returns:
            dict: A dictionary containing the status of the RDP and SSH services.
        """
        rdp_stat = {
            'rdpEnabled': "",
            'sshActive': "",
        }
        try:
            logging.info(f"get_ssh_status_command: 'systemctl is-active sshd'")
            # Check if the SSH service is enabled and active
            ssh_output = subprocess.run(["systemctl", "is-active", "sshd"], stderr=subprocess.PIPE,
                                        stdout=subprocess.PIPE, universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"ssh_output, return code: {ssh_output.returncode}, stdout: {ssh_output.stdout}")

            ssh_output_result = ssh_output.stdout.strip()
            if ssh_output.returncode == 0 and ssh_output_result == "active":
                rdp_stat['sshActive'] = "True"
            else:
                rdp_stat['sshActive'] = "False"

            # Check if RDP is enabled
            rdp_command = r"ss -ltn | awk '$4 ~ /:5900/'"
            rdp_output = subprocess.run(rdp_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS, check=True)
            logging.info(f"rdp_output, return code: {rdp_output.returncode}, stdout: {rdp_output.stdout}")
            # Check if the gsettings command was successful
            if rdp_output.returncode == 0 and "LISTEN" in rdp_output.stdout.strip():
                rdp_stat['rdpEnabled'] = "True"
            else:
                rdp_stat['rdpEnabled'] = "False"

        except Exception as err:
            error["osInfo"]["get_rdp_status"] = repr(err)
            logging.error(f"Error occurred while getting RDP status: {repr(err)}")

        return rdp_stat

    @logger_function
    def get_audit_logs():
        """
        Retrieves the audit logs from the system.

        Returns:
            str: The audit logs if the auditd service is active, otherwise an empty string.

        Raises:
            Exception: If an error occurs while retrieving the audit logs.
        """
        try:
            audit_output = subprocess.run(["systemctl", "is-active", "auditd"], stderr=subprocess.PIPE,
                                          stdout=subprocess.PIPE,
                                          universal_newlines=True, timeout=TIMEOUT_SUBPROCESS).stdout.strip()
            logging.info(f"audit_output: {audit_output}")
            if audit_output == "active":
                return audit_output
            elif audit_output == "inactive":
                return audit_output
            return ""
        except Exception as err:
            error["osInfo"]["get_audit_logs"] = repr(err)
            logging.error(f"Error occurred while getting audit logs: {repr(err)}")
            return ""

    @logger_function
    def get_edr_installed(installed_programs):
        """
        Checks if an EDR (Endpoint Detection and Response) software is installed on the system.

        Returns:
            bool: True if an EDR is installed, False otherwise.
        """
        edr = ["Microsoft Defender"]
        try:
            edr_keywords = [prog.split() for prog in edr]
            for ins_prog in installed_programs:
                for keywords in edr_keywords:
                    if all(key in ins_prog for key in keywords):
                        logging.info("EDR is installed")
                        return True
            logging.info("EDR is not installed")
            return False
        except subprocess.CalledProcessError as e:
            error["osInfo"]["is_edr_installed"] = repr(e)
            logging.error("Error occurred while checking EDR installation")
            return False

    @logger_function
    def get_antivirus_info(installed_progs, app_patch_info):
        def is_installed(package_name):
            """Check if any installed package starts with the provided package_name."""
            try:
                return package_name in installed_progs
            except Exception as installed_err:
                logging.error(f"Not Installed: {installed_err}")
                return False

        def get_service_status(service_name):
            """Get the status of a specific service."""
            try:
                result = subprocess.run(["sudo", "systemctl", "is-enabled", service_name], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS, text=True)
                result_out = result.stdout.strip()
                if result_out == "enabled":
                    return "active"
                elif result_out == "disabled":
                    return "inactive"
                else:
                    return "not found"
            except Exception as service_stat_err:
                logging.error(f"Not found:{service_stat_err}")
                return "not found"

        def get_app_version(app_name):
            """Get the version of the antivirus application."""
            try:
                for app_patch in app_patch_info:
                    if app_name == app_patch["name"]:
                        return app_patch["version"]
            except Exception as app_version_err:
                logging.error(f"app version error:{app_version_err}")
            return "not found"

        antivirus_result = []

        antivirus_info = {
            "Bitdefender GravityZone": {"name": "bdservice", "services": ["bdservice", "bdshield"]},
            "Kaspersky Endpoint Security": {"name": "kesl", "services": ["kesl-supervisor", "kesl"]},
            "Sophos Intercept X Endpoint": {"name": "sav", "services": ["sav-protect", "sav-rms"]},
            "Avast Business Security": {"name": "avast", "services": ["avast"]},
            "ClamAV": {"name": "clamav", "services": ["clamav-daemon", "clamav-freshclam", "clamd@scan"]},
            "Lynis": {"name": "lynis", "services": []},
            "Chkrootkit": {"name": "chkrootkit", "services": []},
            "RootKit Hunter": {"name": "rkhunter", "services": []},
            "Linux Malware Detect": {"name": "lmd", "services": []},
            "Trend Micro": {"name": "tmcmd", "services": ["trendmicro"]},
            "F-Secure": {"name": "f-secure-linuxsecurity",
                         "services": ["fsbg-pmd", "fsbg-statusd", "fsbg-updated", "fsma2",
                                      "f-secure-baseguard-accd", "f-secure-baseguard-as",
                                      "f-secure-baseguard-authorize",
                                      "f-secure-baseguard-cleanup", "f-secure-baseguard-doormand",
                                      "f-secure-baseguard-icap",
                                      "f-secure-baseguard-sensor", "f-secure-baseguard-telemetry",
                                      "f-secure-baseguard-tokenverify",
                                      "f-secure-linuxsecurity-fsicd", "f-secure-linuxsecurity-lspmd",
                                      "f-secure-linuxsecurity-scand",
                                      "f-secure-linuxsecurity-statusd", "f-secure-linuxsecurity-webserver"]},
            "ESCAN": {"name": "escan-antivirus",
                      "services": ["epsdaemon", "mwagent", "nfdaemon", "mwconnect", "mwprintd", "rtscanner"]},
        }

        try:
            for name, info in antivirus_info.items():
                installed_antivirus = {"name": name,
                                       "installed": False, "version": "", "services": []}

                if is_installed(info["name"]):
                    installed_antivirus["installed"] = True
                    installed_antivirus["version"] = get_app_version(info["name"])
                    for service in info["services"]:
                        service_status = get_service_status(service)
                        installed_antivirus["services"].append({service: service_status})

                antivirus_result.append(installed_antivirus)
        except Exception as get_antivirus_info_err:
            logging.error(f"Error in get_antivirus_info: {get_antivirus_info_err}")

        return antivirus_result

    # pcIdentityInfo functions --------------------------------------------------------------------
    @logger_function
    def get_system_security_status(user_logged_in):
        """
        Get the status of the system security settings.

        The function checks the following security settings and returns a dictionary
        with the status of each setting:

        - WiFi: enabled/disabled
        - Bluetooth: enabled/disabled
        - USB: enabled/disabled
        - Firewall: enabled/disabled
        - RDP (gnome-remote-desktop): enabled/disabled
        - SSH: enabled/disabled

        If there is an error in the command execution, the function logs a warning
        with the error message and sets the status of the setting to "enabled".

        Returns:
            dict: A dictionary with the status of each security setting.
        """
        status = {
            "wifi": "enabled",
            "bluetooth": "enabled",
            "usb": "enabled",
            "firewall": "disabled",
            "rdp": "disabled",
            "ssh": "disabled"
        }

        # Check WiFi
        try:
            with open("/etc/modprobe.d/disable-wifi.conf", "r") as f:
                for line in f:
                    if "blacklist iwlwifi" in line and not line.strip().startswith("#"):
                        status["wifi"] = "disabled"
                        break
        except Exception as wifi_err:
            logging.warning(f"WiFi status check failed: {wifi_err}")

        # Check Bluetooth
        try:
            with open("/etc/modprobe.d/disable-bluetooth.conf", "r") as f:
                for line in f:
                    if "blacklist btusb" in line and not line.strip().startswith("#"):
                        status["bluetooth"] = "disabled"
                        break
        except Exception as bluetooth_err:
            logging.warning(f"Bluetooth status check failed: {bluetooth_err}")

        # Check USB
        try:
            with open("/etc/modprobe.d/disable-usb-storage.conf", "r") as f:
                for line in f:
                    if ("blacklist usb_storage" in line or "blacklist uas" in line) and not line.strip().startswith(
                            "#"):
                        status["usb"] = "disabled"
                        break
        except Exception as usb_err:
            logging.warning(f"USB status check failed: {usb_err}")

        # Check Firewall
        firewall_services = ["ufw", "firewalld", "nftables", "iptables"]
        try:
            for firewall in firewall_services:
                try:
                    result = subprocess.run(["systemctl", "is-active", f"{firewall}.service"], capture_output=True,
                                            text=True)
                    if result.returncode == 0 and result.stdout.strip() == "active":
                        status["firewall"] = "enabled"
                        break
                except Exception as firewall_in_err:
                    logging.warning(f"Firewall status check failed: {firewall_in_err}")
        except Exception as firewall_err:
            logging.warning(f"Firewall status check failed: {firewall_err}")

        # Check RDP (gnome-remote-desktop)
        try:
            cmd_rdp = (
                f"sudo -u '{user_logged_in}' DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u '{user_logged_in}')/bus "
                "systemctl --user is-active gnome-remote-desktop.service")
            result = subprocess.run(cmd_rdp, shell=True, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == "active":
                status["rdp"] = "enabled"
        except Exception as rdp_err:
            logging.warning(f"RDP status check failed: {rdp_err}")

        # Check SSH
        try:
            result = subprocess.run(["systemctl", "is-active", "sshd"], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == "active":
                status["ssh"] = "enabled"
        except Exception as ssh_err:
            logging.warning(f"SSH status check failed: {ssh_err}")

        return status

    @logger_function
    def check_pc_in_org_domain():
        """
        Checks if the computer is connected to an organization's domain
        by comparing the computer name with the DNS search domain name.

        :return: The domain name if connected to an organization's domain, "False" otherwise.
        :rtype: str
        """
        try:
            # Get the computer name from /etc/hostname
            with open('/etc/hostname', 'r') as hostname_file:
                computer_name = hostname_file.read().strip()
                logging.info(f"computer_name: {computer_name}")

            # Get the DNS search domain name from /etc/resolv.conf
            domain_name = ""
            with open('/etc/resolv.conf', 'r') as resolv_conf_file:
                for line in resolv_conf_file:
                    if line.startswith('search'):
                        domain_name = line.strip().split(' ')[1]
                        break
                logging.info(f"domain_name: {domain_name}")

            # Check if the computer name matches the domain name or is empty
            if domain_name and computer_name == domain_name:
                logging.info(f"Connected to an organization's domain: {domain_name}")
                logging.info(f"returning True")
                return "True"  # Connected to an organization's domain
            else:
                logging.info(f"Not connected to an organization's domain: {domain_name}")
                logging.info(f"returning False")
                return "False"  # Not connected to an organization's domain
        except Exception as err:
            error["pcIdentityInfo"]["check_pc_in_org_domain"] = repr(err)
            logging.error(f"Error checking pc in org domain: {err}")
            return ""

    # usbInfo functions --------------------------------------------------------------------

    @logger_function
    def get_usb_details():
        """
        Retrieves information about USB devices.
        This function reads the contents of the '/proc/mounts' file and extracts information about USB devices.
        It returns a dictionary containing the USB device information, including vendor, serial number, and USB name.
        If any errors occur during the process, the function returns an empty string or raises an exception.

        Returns:
            dict: A dictionary containing the USB device information.
        """

        def read_sysfs_value(path):
            try:
                with open(path, "r") as f:
                    return f.read().strip()
            except Exception as e:
                logging.debug(f"Unable to read {path}: {e}")
                return ""

        def hex_to_dec(value):
            try:
                if value.startswith("0x"):
                    return str(int(value, 16))
                return value
            except Exception:
                return value

        def normalize_manfid(manfid_hex):
            """
            Convert 0x00001b -> 1b
            """
            if not manfid_hex:
                return None

            try:
                value = manfid_hex.lower().replace("0x", "")
                return value[-2:]   # last byte only
            except Exception:
                return None

        def resolve_sd_manufacturer(manfid_hex):
            manfid = normalize_manfid(manfid_hex)
            return SD_MANUFACTURERS.get(manfid, f"Unknown ({manfid})")

        SD_MANUFACTURERS = {
            "01": "Panasonic",
            "02": "Toshiba",
            "03": "SanDisk",
            "1b": "Samsung",
            "27": "Phison",
            "28": "Lexar",
            "9f": "Kingston"
        }
        usb_info_list = []
        try:
            lsusb_result = subprocess.run("lsusb", shell=True,
                                          text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                          timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"lsusb_result: {lsusb_result}")

            device_details_list = []
            if lsusb_result.returncode == 0:
                lsusb_result_list = lsusb_result.stdout.split('\n')
                pattern = r'Bus (\d+) Device (\d+):'
                for line in lsusb_result_list:

                    match = re.search(pattern, line)
                    if match:
                        bus_number = match.group(1)
                        device_number = match.group(2)
                        logging.info(f"Bus:{bus_number} Device: {device_number}")

                        dev_detail_cmd = f"udevadm info -q all -n /dev/bus/usb/{bus_number}/{device_number}"
                        dev_detail_result = subprocess.check_output(dev_detail_cmd, shell=True, universal_newlines=True,
                                                                    stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS)
                        if dev_detail_result:
                            device_details_list.append(dev_detail_result.strip())
            else:
                devices = glob.glob('/dev/sd*')
                filtered_devices = [device for device in devices if len(device) == 8]

                for device in filtered_devices:
                    dev_detail_cmd = f"udevadm info -q all -n {device}"
                    dev_detail_result = subprocess.check_output(dev_detail_cmd, shell=True, universal_newlines=True,
                                                                stderr=subprocess.PIPE, timeout=TIMEOUT_SUBPROCESS)
                    if dev_detail_result:
                        device_details_list.append(dev_detail_result.strip())

            for detail in device_details_list:
                usb = {'usbName': "", 'usbManufacturer': "", 'usbSerialNumber': "", "usbProductId": "",
                       "usbVendorId": "", "interfaceType": ""}
                int_pattern = r'ID_USB_INTERFACES=(.*)'
                name_pattern = r'ID_MODEL=(.*)'
                man_pattern = r'ID_VENDOR=(.*)'
                ser_pattern = r'ID_SERIAL_SHORT=(.*)'
                prod_id_pattern = r'ID_MODEL_ID=(.*)'
                vend_id_pattern = r'ID_VENDOR_ID=(.*)'
                mtp_id_pattern = r'ID_GPHOTO2=(.*)'

                int_match = re.search(int_pattern, detail)
                mtp_id_match = re.search(mtp_id_pattern, detail)

                # Detect MTP/PTP directly via ID_GPHOTO2=1
                if mtp_id_match and mtp_id_match.group(1).strip() == "1":
                    usb["interfaceType"] = "MTP/PTP"

                if int_match:
                    id_usb_interfaces = int_match.group(1)
                    logging.info(f"id_usb_interfaces: {id_usb_interfaces}")
                    usb_match_reg = r':080[0-9]*:'
                    hdd_match_reg = r':080[0-9]*:080[0-9]*:'
                    mtp_match_reg = r':ffff[0-9]*:(.*):'
                    ptp_match_reg = r':060[0-9]*:(.*):'
                    phn_match_reg = r':060[0-9]*:'
                    dvd_match_reg = r':0802[0-9]*:'
                    adp_match_reg = r':ffff[0-9]*:'

                    usb_match = re.search(usb_match_reg, id_usb_interfaces)
                    hdd_match = re.search(hdd_match_reg, id_usb_interfaces)
                    mtp_match = re.search(mtp_match_reg, id_usb_interfaces)
                    ptp_match = re.search(ptp_match_reg, id_usb_interfaces)
                    dvd_match = re.search(dvd_match_reg, id_usb_interfaces)
                    phn_match = re.search(phn_match_reg, id_usb_interfaces)
                    adp_match = re.search(adp_match_reg, id_usb_interfaces)

                    if usb_match or hdd_match or mtp_match or ptp_match or dvd_match or phn_match or adp_match or mtp_id_match:
                        logging.info("Match found")
                        usb_name = re.search(name_pattern, detail)
                        usb_manufacturer = re.search(man_pattern, detail)
                        usb_serial_number = re.search(ser_pattern, detail)
                        usb_product_id = re.search(prod_id_pattern, detail)
                        usb_vendor_id = re.search(vend_id_pattern, detail)

                        if usb_name: usb["usbName"] = usb_name.group(1)
                        if usb_manufacturer: usb["usbManufacturer"] = usb_manufacturer.group(1)
                        if usb_serial_number: usb["usbSerialNumber"] = usb_serial_number.group(1)
                        if usb_product_id: usb["usbProductId"] = usb_product_id.group(1)
                        if usb_vendor_id: usb["usbVendorId"] = usb_vendor_id.group(1)

                        if not usb["interfaceType"]:
                            if dvd_match:
                                logging.info("DVD match found")
                                usb["interfaceType"] = "CD/DVD"
                            elif hdd_match:
                                logging.info("HDD match found")
                                usb["interfaceType"] = "HDD/SSD"
                            elif usb_match:
                                logging.info("USB match found")
                                usb["interfaceType"] = "USB"
                            elif mtp_match or ptp_match or phn_match:
                                logging.info("MTP/PTP match found")
                                usb["interfaceType"] = "MTP/PTP"
                            elif adp_match:
                                logging.info("ADAPTER match found")
                                usb["interfaceType"] = "ADAPTER"
                            else:
                                logging.info("No match found")
                                usb["interfaceType"] = "Unknown"

                        usb_info_list.append(usb)
                    else:
                        logging.info("No match found")

            # List directories matching mmc0:<digits> which is for SD cards.
            base_path = "/sys/class/mmc_host/mmc0"

            if not os.path.exists(base_path):
                logging.info(f"base_path does not exist: {base_path}")
                return usb_info_list

            for entry in os.listdir(base_path):
                full_path = os.path.join(base_path, entry)

                if not (entry.startswith("mmc0:") and os.path.isdir(full_path)):
                    continue

                sd_name = read_sysfs_value(os.path.join(full_path, "name"))
                sd_manfid = read_sysfs_value(os.path.join(full_path, "manfid"))
                sd_serial = read_sysfs_value(os.path.join(full_path, "serial"))
                sd_oemid = read_sysfs_value(os.path.join(full_path, "oemid"))

                usb = {}
                if sd_name:
                    usb["usbName"] = sd_name.strip()
                if sd_manfid:
                    usb["usbManufacturer"] = resolve_sd_manufacturer(sd_manfid)
                if sd_serial:
                    usb["usbSerialNumber"] = hex_to_dec(sd_serial)
                if sd_oemid:
                    usb["usbProductId"] = hex_to_dec(sd_oemid)
                if sd_manfid:
                    usb["usbVendorId"] = hex_to_dec(sd_manfid)
                usb["interfaceType"] = "SD-Card"

                if len(usb) > 1:
                    usb_info_list.append(usb)

        except Exception as err:
            error["usbInfo"]["usb_info_details"] = repr(err)
            logging.error(f"Error usb_info_details: {err}")

        return usb_info_list

    @logger_function
    def get_usb_stored_history():
        """
        Extracts USB device information from the system log files and stores it in a list.

        Returns:
            usb_history (list): A list of dictionaries containing USB device information.
            Each dictionary represents a USB device and contains the following keys:
                - 'usbName' (str): The product name of the USB device.
                - 'manufacturer' (str): The manufacturer of the USB device.
                - 'serialNumber' (str): The serial number of the USB device.
                - 'time' (str): The timestamp when the USB device was detected.
        """
        usb_history = []
        try:
            def convert_timestamp(input_timestamp):
                try:
                    if input_timestamp == "":
                        return ""
                    current_year = datetime.now().year

                    # Parse the input timestamp
                    timestamp = datetime.strptime(input_timestamp, "%b %d %H:%M:%S")

                    # Assign the current year to the timestamp
                    timestamp = timestamp.replace(year=current_year)

                    # Check if the timestamp is in the future
                    if timestamp > datetime.now():
                        # If in the future, reduce the year by 1
                        timestamp = timestamp.replace(year=current_year - 1)

                    # Format the timestamp as dd-mm-yyyy hh:mm:ss
                    formatted_timestamp = timestamp.strftime("%d-%m-%Y %H:%M:%S")

                    return str(formatted_timestamp)

                except Exception as time_con_err:
                    logging.error(f"Error usb_info_details: {time_con_err}")
                    return ""

            usb = {'usbName': "", 'usbManufacturer': "", 'usbSerialNumber': "", 'time': ""}
            command_base = (
                r'sudo cat {file_path} | grep -i usb | grep -Ev '
                r'"cyberauditor-linux-agent|CA Linux Agent|Output before encryption|'
                r'seal-linux-agent|SEAL Linux Agent|nishar-linux-agent|NISHAR Linux Agent|'
                r'decrypt_string Error:|decrypted cont:"'
            )

            log_dir = '/var/log'
            file_pattern = "messages*"
            files_to_read = glob.glob(os.path.join(log_dir, file_pattern))

            if not files_to_read:
                error["usbInfo"]["usb_store_history"] = "Error: No 'messages' files found."
                return []

            for file_path in files_to_read:
                if not os.path.exists(file_path):
                    logging.warning(f"File '{file_path}' not found, skipping.")
                    continue

                if not os.access(file_path, os.R_OK):
                    logging.warning(f"File '{file_path}' is not readable, skipping.")
                    continue

                if file_path.endswith(".gz"):
                    logging.warning(f"File '{file_path}' is not readable, skipping.")
                    continue

                command_usb = command_base.format(file_path=file_path)
                logging.info(f"usb_store_history command: '{command_usb}'")

                try:
                    log_text = subprocess.check_output(command_usb, shell=True, universal_newlines=True,
                                                       stderr=subprocess.PIPE, timeout=90)
                    log_lines = log_text.strip().split('\n')

                    # Regex patterns
                    line_match_regex = r"usb \d+-\d+(\.\d)?:"
                    usb_device_regex = r"usb \d+-\d+(\.\d)?: Product: (.+)"
                    usb_manufacturer_regex = r"usb \d+-\d+(\.\d)?: Manufacturer: (.+)"
                    usb_serial_number_regex = r"usb \d+-\d+(\.\d)?: SerialNumber: (.+)"
                    time_regex = r"(?P<date>[A-Za-z]{3}\s+\d+)\s+\d+:\d+:\d+"
                    connected_pattern = r'usb \d+-\d+(\.\d)?: new (\S+) USB device number (\d+) using (\S+)'

                    # Initialize variables to store device details
                    last_usb_type = ""
                    for line in log_lines:
                        if not re.search(line_match_regex, line):
                            continue

                        if re.search(connected_pattern, line):
                            usb = {'usbName': "", 'usbManufacturer': "", 'usbSerialNumber': "", 'time': ""}
                            last_usb_type = re.search(connected_pattern, line).group(2)
                            continue

                        product_match = re.search(usb_device_regex, line)
                        if product_match:
                            usb['usbName'] = product_match.group(2) if "Adapter" not in product_match.group(2) else ""
                        manufacturer_match = re.search(usb_manufacturer_regex, line)
                        if manufacturer_match:
                            usb['usbManufacturer'] = manufacturer_match.group(2)
                        serial_number_match = re.search(usb_serial_number_regex, line)
                        if serial_number_match:
                            usb['usbSerialNumber'] = serial_number_match.group(2)

                        if usb["usbName"] and usb["usbManufacturer"] and usb["usbSerialNumber"] and (
                                last_usb_type == "high-speed" or last_usb_type == "SuperSpeed"):
                            time_value = re.search(time_regex, line)
                            usb['time'] = convert_timestamp(time_value.group() if time_value else "")
                            usb_history.append(usb)
                            usb = {'usbName': "", 'usbManufacturer': "", 'usbSerialNumber': "", 'time': ""}

                except subprocess.CalledProcessError as e:
                    logging.error(f"Error processing file '{file_path}': {e}")

        except Exception as err:
            error["usbInfo"]["usb_store_history"] = repr(err)
            logging.error(f"Error storing usb history: {err}")

        return usb_history

    # CIS SECTION functions --------------------------------------------------------------------

    # base function to check if a package is installed or not
    @logger_function
    def check_if_installed(service_name, calling_function):
        check_installed_result = "Not Configured"
        try:
            # Check if the service is installed
            check_installed_command = f"rpm -q {service_name}"

            logging.info(f"check_installed_command: {check_installed_command}")
            check_installed_command_result = subprocess.run(check_installed_command, shell=True,
                                                            stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                            universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"check_installed_command_result for {service_name}: {check_installed_command_result}")

            if ('is not installed' in check_installed_command_result.stdout
                or 'is not installed' in check_installed_command_result.stderr):
                check_installed_result = "False"
            else:
                check_installed_result = "True"

            logging.info(f"check_installed_result: {check_installed_result}")
        except Exception as err:
            logging.error(f"Error {calling_function}, checking if {service_name} is installed: {err}")
        return check_installed_result

    @logger_function
    def check_if_not_installed(service_name, calling_function):
        check_installed_result = "Not Configured"
        try:
            # Check if the service is installed
            check_installed_command = f"rpm -q {service_name}"

            logging.info(f"check_installed_command: {check_installed_command}")
            check_installed_command_result = subprocess.run(check_installed_command, shell=True,
                                                            stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                            universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
            logging.info(f"check_installed_command_result for {service_name}: {check_installed_command_result}")

            if ('is not installed' in check_installed_command_result.stdout
                or 'is not installed' in check_installed_command_result.stderr):
                check_installed_result = "True"
            else:
                check_installed_result = "False"

            logging.info(f"check_installed_result: {check_installed_result}")
        except Exception as err:
            logging.error(f"Error {calling_function}, checking if {service_name} is installed: {err}")
        return check_installed_result

    # base function to run script
    @logger_function
    def run_script(script, calling_func):
        logging.info(f"running script... for {calling_func}")
        script_result = "Not Configured"
        try:
            script_command_result = subprocess.check_output(["bash", "-c", script], universal_newlines=True,
                                                            stderr=subprocess.STDOUT,
                                                            timeout=TIMEOUT_SUBPROCESS).strip()
            # logging.info(f"script_result: {script_command_result}")
            if "PASS" in script_command_result:
                script_result = "True"
            elif "FAIL" in script_command_result:
                script_result = "False"
            else:
                script_result = "Not Configured"

            logging.info(f"script_run_result: {script_result}")
        except Exception as err:
            error["cisInfo"][calling_func]["run_script"] = repr(err)
            logging.error(f"Error running script: {err}")
        return script_result

    @logger_function
    def run_script_for_output(script, calling_func):
        logging.info(f"running script... for {calling_func}")
        script_result = "Not Configured"
        try:
            script_command_result = subprocess.check_output(["bash", "-c", script], universal_newlines=True,
                                                            stderr=subprocess.STDOUT,
                                                            timeout=TIMEOUT_SUBPROCESS).strip()

            logging.info(f"script_run_result: {script_result}")
            return script_command_result

        except Exception as err:
            error["cisInfo"][calling_func]["run_script"] = repr(err)
            logging.error(f"Error running script: {err}")
        return script_result

    # CIS Section 1.1.1
    @logger_function
    def cis_file_system_configuration():
        result = []

        def check_mount_system(mnt_name):
            try:
                cmd_modprobe = f"modprobe -n -v {mnt_name}"
                cmd_result = subprocess.run(
                    cmd_modprobe,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=TIMEOUT_SUBPROCESS
                )
                output = cmd_result.stdout.strip()
                logging.info(f"[{mnt_name}] modprobe output: {output}")

                lsmod_result = subprocess.run(
                    f"lsmod | grep -w {mnt_name}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=TIMEOUT_SUBPROCESS
                )
                loaded = bool(lsmod_result.stdout.strip())
                logging.info(f"[{mnt_name}] loaded: {loaded}")

                is_configured = "True" if ("install /bin/false" in output or "install /bin/true" in output) else "False"
                is_disabled = "True" if not loaded else "False"

                return is_configured, is_disabled

            except Exception as e:
                logging.error(f"Error checking {mnt_name}: {e}")
                return "Not Configured", "Not Configured"

        mount_list = ["cramfs", "squashfs", "udf", "fat", "vfat", "msdos"]

        for name in mount_list:
            is_configured, is_disabled = check_mount_system(name)
            result.append({
                "mountName": name,
                "isConfigured": is_configured,
                "isDisabled": is_disabled
            })

        return result

    # CIS Section 1.1.2 - 1.1.8
    @logger_function
    def cis_audit_partitions():
        audit_partitions_result = []
        try:
            def audit_partition(mount_point):
                try:
                    # Audit: Check if /tmp is mounted
                    audit_command = fr"findmnt --kernel {mount_point}"
                    result = subprocess.run(audit_command, shell=True, stderr=subprocess.PIPE,
                                            stdout=subprocess.PIPE, universal_newlines=True,
                                            timeout=TIMEOUT_SUBPROCESS)
                    command_output = {"mountPoint": mount_point, "isMounted": "False", "mountOptions": {}}

                    if mount_point in result.stdout:
                        logging.info(f"{mount_point} is mounted.")
                        command_output = {"mountPoint": mount_point, "isMounted": "True", "mountOptions": {}}

                        def verify_mount_option(options_list):
                            # Verify that the specified options are set for the mount point
                            for option in options_list:
                                verify_command = f"findmnt --kernel {mount_point} | grep {option}"
                                command_result = subprocess.run(verify_command, shell=True, stderr=subprocess.PIPE,
                                                                stdout=subprocess.PIPE,
                                                                universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

                                if command_result.stdout:
                                    logging.info(f"{option} option is set for {mount_point}.")
                                    command_output["mountOptions"][option] = "True"
                                else:
                                    logging.info(f"{option} option is not set for {mount_point}.")
                                    command_output["mountOptions"][option] = "False"

                        # Additional checks
                        if "/tmp" in mount_point:
                            verify_mount_option(["nodev", "noexec", "nosuid"])
                        elif "/var" in mount_point:
                            verify_mount_option(["nodev", "nosuid"])
                        elif "/var/tmp" in mount_point:
                            verify_mount_option(["nodev", "noexec", "nosuid"])
                        elif "/var/log" in mount_point:
                            verify_mount_option(["nodev", "noexec", "nosuid"])
                        elif "/var/log/audit" in mount_point:
                            verify_mount_option(["nodev", "noexec", "nosuid"])
                        elif "/home" in mount_point:
                            verify_mount_option(["nodev", "nosuid"])
                        elif "/boot" in mount_point:
                            verify_mount_option(["nodev", "nosuid"])
                        elif "/boot/efi" in mount_point:
                            verify_mount_option(["nodev", "nosuid"])
                        elif "/dev/shm" in mount_point:
                            verify_mount_option(["nodev", "noexec", "nosuid"])
                        else:
                            logging.warning(f"No specific options defined for {mount_point}.")

                        return command_output
                    else:
                        logging.info(f"{mount_point} is not mounted.")
                        return command_output
                except Exception as er:
                    error["cisInfo"]['cis_audit_partitions']["audit_partition"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_audit_partitions']['audit_partition']: {err}")
                    return {"mountPoint": mount_point, "isMounted": "False", "mountOptions": {}}

            audit_partitions_list = ["/tmp", "/var", "/var/tmp", "/var/log", "/var/log/audit", "/home", "/dev/shm",
                                     "/boot", "/boot/efi"]
            # Results for each partition
            audit_partitions_result = [audit_partition(partition) for partition in audit_partitions_list]

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_audit_partitions']: {err}")
        return audit_partitions_result

    # CIS Section 1.3
    @logger_function
    def cis_check_aide_installed():
        command_output = {
            "checkAideInstalled": {
                "isAideInstalled": "Not Configured",
                "isAideCommonInstalled": "Not Configured",
            },
            "checkAideServices": {
                "aidecheckServiceEnabled": "Not Configured",
                "aidecheckTimerEnabled": "Not Configured",
                "aidecheckTimerRunning": "Not Configured"
            }
        }
        try:
            def check_package_installed(package_name):
                try:
                    # Command to check package status
                    command = f"rpm -q {package_name}"
                    logging.info(f"Running command: '{command}'")
                    result = subprocess.run(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                            universal_newlines=True,
                                            timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {result}")

                    words = package_name.split('-')
                    capitalized_words = [word.capitalize() for word in words]
                    camel_case_string = ''.join(capitalized_words)
                    # Check for errors in stderr
                    if result.stderr:
                        logging.info(f"Error in command execution: {result.stderr}")
                        command_output["checkAideInstalled"][f"is{camel_case_string}Installed"] = "False"
                    else:
                        # Use regex to check if "install ok installed" is present in the Status column
                        match = re.search(f"{package_name}-", result.stdout)
                        if match:
                            command_output["checkAideInstalled"][f"is{camel_case_string}Installed"] = "True"
                        else:
                            command_output["checkAideInstalled"][f"is{camel_case_string}Installed"] = "False"
                except Exception as er:
                    error["cisInfo"]['cis_check_aide_installed']["check_package_installed"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_check_aide_installed']['check_package_installed']: {err}")

            package_names = ["aide", "aide-common"]
            for package in package_names:
                check_package_installed(package)

            def check_aide_services_status():
                try:
                    # Commands to check the status of AIDE services and timers
                    service_status_command = "systemctl is-enabled aidecheck.service"
                    timer_status_command = "systemctl is-enabled aidecheck.timer"
                    timer_output_command = "systemctl status aidecheck.timer"

                    # Check AIDE service status
                    result_service = subprocess.run(service_status_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"result_service: {result_service}")
                    logging.info(f"result_service.returncode: {result_service.returncode}")
                    if result_service.returncode == 0:
                        command_output["checkAideServices"]["aidecheckServiceEnabled"] = result_service.stdout.strip()

                    # Check AIDE timer status
                    result_timer = subprocess.run(timer_status_command, shell=True, stderr=subprocess.PIPE,
                                                  stdout=subprocess.PIPE,
                                                  universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Timer return code: {result_timer.returncode}")
                    logging.info(f"Timer output: {result_timer}")

                    if result_timer.returncode == 0:
                        command_output["checkAideServices"]["aidecheckServiceEnabled"] = result_timer.stdout.strip()

                    # Check AIDE timer output
                    result_timer_output = subprocess.run(timer_output_command, shell=True, stderr=subprocess.PIPE,
                                                         stdout=subprocess.PIPE,
                                                         universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Timer output return code: {result_timer_output.returncode}")
                    logging.info(f"Timer output: {result_timer_output}")
                    if result_timer_output.returncode == 0:
                        command_output["checkAideServices"]["aidecheckServiceEnabled"] = "True"
                    elif result_timer_output.returncode == 3:
                        command_output["checkAideServices"]["aidecheckServiceEnabled"] = "False"
                    else:
                        command_output["checkAideServices"]["aidecheckTimerRunning"] = "Not Configured"
                        logging.info(f"Error in command execution: {result_timer_output.stderr}")
                except Exception as er:
                    error["cisInfo"]['cis_check_aide_installed']["check_aide_services_status"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_check_aide_installed']['check_aide_services_status']: {err}")

            logging.info(f"Calling check_aide_services_status()")
            check_aide_services_status()
            logging.info(f"check_aide_services_status() execution completed.")
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_check_aide_installed']: {err}")
        return command_output

    # CIS Section 1.4
    @logger_function
    def cis_secure_boot_settings():
        result = {
            "isSecureBootEnabled": "Not Configured",
            "isBootloaderPwdSet": "Not Configured",
            "isPermissionOnBootloaderConfigured": "Not Configured",
            "isBootloaderOwnerSet": "Not Configured",
            "isInteractiveBootDisabled": "Not Configured",
            "isAuthForSingleUserModeConfigured": "Not Configured",
            "isAuthForSystemdTargetConfigured": "Not Configured",
            "isKernelKexecLoadDisabled": "Not Configured",
            "isKernelCorePatternDisabled": "Not Configured",
            "isKernelPerfEventParanoidConfigured": "Not Configured",
            "isKernelUnprivilegedBpfDisabled": "Not Configured",
            "isKernelPageTableIsolationEnabled": "Not Configured",
            "isVsyscallDisabled": "Not Configured",
            "isAuditingForProcessBeforeAuditDaemonEnabled": "Not Configured",
            "isPageAllocatorPoisoningEnabled": "Not Configured",
            "isSlubAllocatorPoisoningEnabled": "Not Configured",
            "isAuditBacklogLimitSet": "Not Configured",
            "isBpfJitHardenConfigured": "Not Configured",
            "isKernelDmesgRestricted": "Not Configured",
            "isUsernamespacesConfigured": "Not Configured",
            "isDiskEncryptionEnabled": "Not Configured",
            "isDiskPartionsAsRecommended": "Not Configured",
        }
        try:

            def is_secure_boot_enabled():
                try:
                    # --- 1. Try mokutil ---
                    try:
                        result = subprocess.run(
                            ["mokutil", "--sb-state"],
                            capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS
                        )
                        logging.info(f"mokutil output: {result.stdout.strip()}")
                        if "secureboot enabled" in result.stdout.lower():
                            return "True"
                        elif "secureboot disabled" in result.stdout.lower():
                            return "False"
                    except Exception as e:
                        logging.warning(f"mokutil failed: {e}")

                    # --- 2. Try dmesg ---
                    try:
                        result = subprocess.run(
                            "dmesg | grep 'secureboot:'", capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS
                        )
                        for line in result.stdout.splitlines():
                            logging.info(f"dmesg line: {line}")
                            if "enabled" in line.lower():
                                return "True"
                            elif "disabled" in line.lower():
                                return "False"
                    except Exception as e:
                        logging.warning(f"dmesg check failed: {e}")

                    # --- 3. Try bootctl ---
                    try:
                        result = subprocess.run(
                            ["bootctl", "status"],
                            capture_output=True, text=True, timeout=TIMEOUT_SUBPROCESS
                        )
                        logging.info(f"bootctl output: {result.stdout.strip()}")
                        for line in result.stdout.splitlines():
                            if "secure boot:" in line.lower():
                                if "enabled" in line.lower():
                                    return "True"
                                elif "disabled" in line.lower():
                                    return "False"
                    except Exception as e:
                        logging.warning(f"bootctl failed: {e}")

                    # If none worked
                    return "False"

                except Exception as cis_err:
                    logging.error(f"Error in is_secure_boot_enabled: {cis_err}")
                    return "False"

            def bootloader_pwd_is_set():
                try:
                    check_pwd_command = r"""awk -F. '/^\s*GRUB2_PASSWORD/ {print $1"."$2"."$3}' /boot/grub2/user.cfg"""
                    output = extract_shell_info(check_pwd_command)
                    return "True" if output else "False"
                except Exception as e:
                    logging.error(f"Error in bootloader_pwd_is_set: {e}")
                    return "Not Configured"

            def permission_on_bootloader_config():
                try:
                    grub_list = ['grub.cfg', 'grubenv', 'user.cfg']
                    valid_permissions = 0
                    for grb in grub_list:
                        boot_permission_cmd = f'stat -Lc "%a" /boot/grub2/{grb}'
                        output = extract_shell_info(boot_permission_cmd)
                        if output and int(output) <= (700 if grb == 'grub.cfg' else 600):
                            valid_permissions += 1
                    return "True" if valid_permissions == 3 else "False"
                except Exception as e:
                    logging.error(f"Error in permission_on_bootloader_config: {e}")
                    return "Not Configured"

            def bootloader_owner_is_set():
                try:
                    owner_cmd = 'stat -c "%U %G" /boot/grub2/grub.cfg'
                    output = extract_shell_info(owner_cmd)
                    return "True" if "root root" in output else "False"
                except Exception as e:
                    logging.error(f"Error in bootloader_owner_is_set: {e}")
                    return "Not Configured"

            def interactive_boot_is_disabled():
                try:
                    cmd = r'grep "^\s*PROMPT" /etc/sysconfig/init'
                    output = extract_shell_info(cmd)
                    return "True" if "PROMPT=no" in output else "False"
                except Exception as e:
                    logging.error(f"Error in interactive_boot_is_disabled: {e}")
                    return "Not Configured"

            def auth_for_single_user_mode():
                try:
                    cmd = 'grep ^SINGLE=/sbin/sulogin /usr/lib/systemd/system/rescue.service'
                    output = extract_shell_info(cmd)
                    return "True" if output else "False"
                except Exception as e:
                    logging.error(f"Error in auth_for_single_user_mode: {e}")
                    return "Not Configured"

            def auth_for_systemd_target():
                try:
                    cmd = (r'grep ^ExecStart=-/usr/lib/systemd/systemd-sulogin-shell '
                           r'/usr/lib/systemd/system/rescue.service')
                    output = extract_shell_info(cmd)
                    return "True" if output else "False"
                except Exception as e:
                    logging.error(f"Error in auth_for_systemd_target: {e}")
                    return "Not Configured"

            def kernel_kexec_load_disabled():
                try:
                    cmd = 'sysctl kernel.kexec_load_disabled'
                    output = extract_info(cmd)
                    return "True" if "kernel.kexec_load_disabled = 1" in output else "False"
                except Exception as e:
                    logging.error(f"Error in kernel_kexec_load_disabled: {e}")
                    return "Not Configured"

            def kernel_core_pattern_disabled():
                try:
                    cmd = 'sysctl kernel.core_pattern'
                    output = extract_info(cmd)
                    return "True" if "|" not in output else "False"
                except Exception as e:
                    logging.error(f"Error in kernel_core_pattern_disabled: {e}")
                    return "Not Configured"

            def kernel_perf_event_paranoid():
                try:
                    cmd = 'sysctl kernel.perf_event_paranoid'
                    output = extract_info(cmd)
                    return "True" if int(output.split()[-1]) >= 2 else "False"
                except Exception as e:
                    logging.error(f"Error in kernel_perf_event_paranoid: {e}")
                    return "Not Configured"

            def kernel_unprivileged_bpf_disabled():
                try:
                    cmd = 'sysctl kernel.unprivileged_bpf_disabled'
                    output = extract_info(cmd)
                    return "True" if "kernel.unprivileged_bpf_disabled = 1" in output else "False"
                except Exception as e:
                    logging.error(f"Error in kernel_unprivileged_bpf_disabled: {e}")
                    return "Not Configured"

            def kernel_page_table_isolation_enabled():
                try:
                    cmd = 'dmesg | grep "Kernel/User page tables isolation: enabled"'
                    output = extract_info(cmd)
                    return "True" if output else "False"
                except Exception as e:
                    logging.error(f"Error in kernel_page_table_isolation_enabled: {e}")
                    return "Not Configured"

            def vsyscall_disabled():
                try:
                    cmd = 'grep vsyscall=none /proc/cmdline'
                    output = extract_shell_info(cmd)
                    return "True" if output else "False"
                except Exception as e:
                    logging.error(f"Error in vsyscall_disabled: {e}")
                    return "Not Configured"

            def auditing_for_process_before_audit_daemon_enabled():
                try:
                    cmd = 'grep audit=1 /proc/cmdline'
                    output = extract_shell_info(cmd)
                    return "True" if output else "False"
                except Exception as e:
                    logging.error(f"Error in auditing_for_process_before_audit_daemon_enabled: {e}")
                    return "Not Configured"

            def page_allocator_poisoning_enabled():
                try:
                    cmd = 'grep page_poison=1 /proc/cmdline'
                    output = extract_shell_info(cmd)
                    return "True" if output else "False"
                except Exception as e:
                    logging.error(f"Error in page_allocator_poisoning_enabled: {e}")
                    return "Not Configured"

            def slub_allocator_poisoning_enabled():
                try:
                    cmd = 'grep slub_debug=P /proc/cmdline'
                    output = extract_shell_info(cmd)
                    return "True" if output else "False"
                except Exception as e:
                    logging.error(f"Error in slub_allocator_poisoning_enabled: {e}")
                    return "Not Configured"

            def audit_backlog_limit_set():
                try:
                    cmd = 'grep audit_backlog_limit /proc/cmdline'
                    output = extract_shell_info(cmd)
                    return "True" if output else "False"
                except Exception as e:
                    logging.error(f"Error in audit_backlog_limit_set: {e}")
                    return "Not Configured"

            def bpf_jit_harden_configured():
                try:
                    cmd = 'sysctl net.core.bpf_jit_harden'
                    output = extract_info(cmd)
                    return "True" if "net.core.bpf_jit_harden = 2" in output else "False"
                except Exception as e:
                    logging.error(f"Error in bpf_jit_harden_configured: {e}")
                    return "Not Configured"

            def kernel_dmesg_restricted():
                try:
                    cmd = 'sysctl kernel.dmesg_restrict'
                    output = extract_info(cmd)
                    return "True" if "kernel.dmesg_restrict = 1" in output else "False"
                except Exception as e:
                    logging.error(f"Error in kernel_dmesg_restricted: {e}")
                    return "Not Configured"

            def usernamespaces_configured():
                try:
                    cmd = 'sysctl user.max_user_namespaces'
                    output = extract_info(cmd)
                    return "True" if int(output.split()[-1]) > 0 else "False"
                except Exception as e:
                    logging.error(f"Error in usernamespaces_configured: {e}")
                    return "Not Configured"

            def is_disk_encryption_enabled():
                try:
                    check_command = "lsblk -o NAME,TYPE,MOUNTPOINT,UUID,PARTUUID | grep 'luks'"
                    output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                            universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

                    if output.stdout:
                        return "True"
                    else:
                        return "False"

                except Exception as er:
                    logging.error(f"error['cisInfo']['is_disk_encryption_enabled']: {er}")
                    return "Not Configured"

            def is_disk_partions_as_recommended():
                try:
                    check_command = "df -h | awk '{print $NF}'"
                    output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                            universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    output_list = output.stdout.strip().split("\n")
                    input_list = ["/", "/dev", "/boot", "/boot/efi", "/home", "/tmp", "/var/tmp",
                                  "/var", "/var/log", "/var/log/audit"]
                    for item in input_list:
                        if item not in output_list:
                            return "False"
                    return "True"

                except Exception as er:
                    logging.error(f"error['cisInfo']['is_disk_partions_as_recommended']: {er}")
                    return "Not Configured"

            result["isSecureBootEnabled"] = is_secure_boot_enabled()
            result["isBootloaderPwdSet"] = bootloader_pwd_is_set()
            result["isPermissionOnBootloaderConfigured"] = permission_on_bootloader_config()
            result["isBootloaderOwnerSet"] = bootloader_owner_is_set()
            result["isInteractiveBootDisabled"] = interactive_boot_is_disabled()
            result["isAuthForSingleUserModeConfigured"] = auth_for_single_user_mode()
            result["isAuthForSystemdTargetConfigured"] = auth_for_systemd_target()
            result["isKernelKexecLoadDisabled"] = kernel_kexec_load_disabled()
            result["isKernelCorePatternDisabled"] = kernel_core_pattern_disabled()
            result["isKernelPerfEventParanoidConfigured"] = kernel_perf_event_paranoid()
            result["isKernelUnprivilegedBpfDisabled"] = kernel_unprivileged_bpf_disabled()
            result["isKernelPageTableIsolationEnabled"] = kernel_page_table_isolation_enabled()
            result["isVsyscallDisabled"] = vsyscall_disabled()
            result["isAuditingForProcessBeforeAuditDaemonEnabled"] = auditing_for_process_before_audit_daemon_enabled()
            result["isPageAllocatorPoisoningEnabled"] = page_allocator_poisoning_enabled()
            result["isSlubAllocatorPoisoningEnabled"] = slub_allocator_poisoning_enabled()
            result["isAuditBacklogLimitSet"] = audit_backlog_limit_set()
            result["isBpfJitHardenConfigured"] = bpf_jit_harden_configured()
            result["isKernelDmesgRestricted"] = kernel_dmesg_restricted()
            result["isUsernamespacesConfigured"] = usernamespaces_configured()
            result["isDiskEncryptionEnabled"] = is_disk_encryption_enabled()
            result["isDiskPartionsAsRecommended"] = is_disk_partions_as_recommended()
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_secure_boot_settings']: {err}")
        return result

    # CIS Section 1.5
    @logger_function
    def cis_additional_process_hardening():
        result = {
            "isAutomountingDisabled": "Not Configured",
            "isAslrEnabled": "Not Configured",
            "isCoredumpStorageDisabled": "Not Configured",
            "isCoredumpBacktraceDisabled": "Not Configured",
            "isPrelinkDisabled": "Not Configured",
        }

        # Check if the additional process hardening is enabled
        try:

            def check_automounting_disabled():
                try:
                    # Check if automounting is disabled
                    automounting_disabled_command = "systemctl is-enabled autofs"
                    logging.info(f"automounting_disabled_command: '{automounting_disabled_command}'")
                    automounting_disabled_command_result = subprocess.run(automounting_disabled_command, shell=True,
                                                                          stderr=subprocess.PIPE,
                                                                          stdout=subprocess.PIPE,
                                                                          universal_newlines=True,
                                                                          timeout=TIMEOUT_SUBPROCESS)

                    logging.info(f"automounting_disabled_command_result: {automounting_disabled_command_result}")
                    if automounting_disabled_command_result.stdout.strip() != "enabled":
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    logging.error(
                        f"error['cisInfo']['cis_additional_process_hardening']['check_automounting_disabled']: {er}")
                    return "Not Configured"

            def check_coredump_service_disabled():
                try:
                    # Check limits.conf for hard core limits
                    coredump_storage_command = (
                        r"grep -E -i 'storage|processsizemax' /etc/systemd/coredump.conf | awk -F '=' "
                        r"'{print $2}'")
                    coredump_storage_command_result = subprocess.run(coredump_storage_command, shell=True,
                                                                     stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                                     universal_newlines=True,
                                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"coredump_storage_check_command_result: {coredump_storage_command_result}")
                    input_string = coredump_storage_command_result.stdout.strip().split("\n")

                    # Filter out empty strings
                    storage_value = input_string[0]
                    process_size_value = input_string[1]
                    logging.info(f"storage_value: {storage_value}")
                    logging.info(f"process_size_value: {process_size_value}")
                    if storage_value == "none":
                        coredump_storage_result = "True"
                    else:
                        coredump_storage_result = "False"

                    if process_size_value == "0":
                        coredump_backtrace_result = "True"
                    else:
                        coredump_backtrace_result = "False"

                    logging.info(f"coredump_storage_result: {coredump_storage_result}")
                    logging.info(f"coredump_backtrace_result: {coredump_backtrace_result}")
                    return coredump_storage_result, coredump_backtrace_result

                except Exception as er:
                    logging.error(
                        f"error['cisInfo']['cis_additional_process_hardening']"
                        f"['check_coredump_service_disabled']: {er}")
                    return "Not Configured", "Not Configured"

            def check_aslr_enabled():
                try:
                    aslr_command = "sysctl kernel.randomize_va_space"
                    logging.info(f"aslr_command: '{aslr_command}'")
                    aslr_command_result = subprocess.run(aslr_command, shell=True, stderr=subprocess.PIPE,
                                                         stdout=subprocess.PIPE, universal_newlines=True,
                                                         timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"aslr_command_result: {aslr_command_result}")
                    if aslr_command_result.stdout.strip() == "kernel.randomize_va_space = 2":
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    logging.error(f"error['cisInfo']['cis_additional_process_hardening']['check_aslr_enabled']: {er}")
                    return "Not Configured"

            result["isAutomountingDisabled"] = check_automounting_disabled()
            result["isAslrEnabled"] = check_aslr_enabled()
            result["isCoredumpStorageDisabled"], result[
                "isCoredumpBacktraceDisabled"] = check_coredump_service_disabled()
            result["isPrelinkDisabled"] = check_if_not_installed("prelink", "cis_additional_process_hardening")
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_additional_process_hardening']: {err}")
        return result

    # CIS Section 1.7
    @logger_function
    def cis_selinux_config_info():
        result = {
            "isSeLinuxInstalled": "Not Configured",
            "isSeLinuxNotDisabledInBootloader": "Not Configured",
            "isSeLinuxPolicyConfigured": "Not Configured",
            "isSeLinuxModeEnforcingOrPermissive": "Not Configured",
            "isSeTroubleshootNotInstalled": "Not Configured",
            "isMCSTranslationServiceInstalled": "Not Configured",
            "isSeLinuxEnabledInGrub": "Not Configured",
            "isSeLinuxStateEnforcing": "Not Configured",
            "isPeriodicFileIntegrityImplemented": "Not Configured",
            "isSeLinuxUserExecstackDisabled": "Not Configured",
            "isSeLinuxUserExecheapDisabled": "Not Configured",
            "isSeLinuxUserExecmodEnabled": "Not Configured",
            "isRhnsdDisabled": "Not Configured",
            "isGpgCheckInMainYumEnabled": "Not Configured",
            "isGpgCheckForLocalPackagesEnabled": "Not Configured",
        }
        try:
            def check_selinux_installed():
                try:
                    output = check_if_installed("libselinux", "cis_selinux_config_info")
                    result["isSeLinuxInstalled"] = output
                except Exception as selinux_in_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_selinux_installed']: {selinux_in_err}")

            def check_selinux_disabled_in_bootloader():
                try:
                    output = (
                        extract_shell_info(
                            r'''grep "^\s*linux" /boot/grub2/grub.cfg | grep -E "(selinux=0|enforcing=0)"'''))
                    if output:
                        result["isSeLinuxNotDisabledInBootloader"] = "True"
                    else:
                        result["isSeLinuxNotDisabledInBootloader"] = "False"
                except Exception as selinux_bootloader_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_selinux_disabled_in_bootloader']: {selinux_bootloader_err}")

            def check_selinux_policy_configured():
                try:
                    output = extract_shell_info('grep SELINUXTYPE= /etc/selinux/config')
                    if output == "SELINUXTYPE=targeted":
                        result["isSeLinuxPolicyConfigured"] = "True"
                    else:
                        result["isSeLinuxPolicyConfigured"] = "False"
                except Exception as selinux_policy_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_selinux_policy_configured']: {selinux_policy_err}")

            def check_se_linux_mode_enforcing_or_permissive():
                try:
                    output = extract_info('getenforce')
                    if output == "Enforcing" or output == "Permissive":
                        result["isSeLinuxModeEnforcingOrPermissive"] = "True"
                    else:
                        result["isSeLinuxModeEnforcingOrPermissive"] = "False"
                except Exception as selinux_enforce_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_se_linux_mode_enforcing_or_permissive']: {selinux_enforce_err}")

            def check_se_troubleshoot_installed():
                try:
                    output = check_if_not_installed("setroubleshoot", "cis_selinux_config_info")
                    result["isSeTroubleshootNotInstalled"] = output
                except Exception as setrouble_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_se_troubleshoot_installed']: {setrouble_err}")

            def check_mcs_translation_service_installed():
                try:
                    output = check_if_not_installed("mcstrans", "cis_selinux_config_info")
                    result["isMCSTranslationServiceInstalled"] = output
                except Exception as mcs_error:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']"
                                  f"['check_mcs_translation_service_installed']: {mcs_error}")

            def check_selinux_in_grub():
                try:
                    output = extract_shell_info(
                        r'''grep "^\s*linux" /boot/grub2/grub.cfg | grep -E "(selinux=0|enforcing=0)"''')
                    if "selinux=0" not in output and "enforcing=0" not in output:
                        result["isSeLinuxEnabledInGrub"] = "True"
                    else:
                        result["isSeLinuxEnabledInGrub"] = "False"
                except Exception as grub_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']['check_selinux_in_grub']: {grub_err}")

            def check_selinux_state_enforcing():
                try:
                    output = extract_shell_info(r'''grep -E '^\s*SELINUX=enforcing' /etc/selinux/config''')
                    if "SELINUX=enforcing" in output:
                        result["isSeLinuxStateEnforcing"] = "True"
                    else:
                        result["isSeLinuxStateEnforcing"] = "False"
                except Exception as grub_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']['check_selinux_state_enforcing']: {grub_err}")

            def check_periodic_file_integrity():
                try:
                    # Command to check if AIDE (Advanced Intrusion Detection Environment) is scheduled in cron
                    check_command = "crontab -l | grep aide"
                    output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE,
                                            stdout=subprocess.PIPE, universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    if output.stdout:
                        result["isPeriodicFileIntegrityImplemented"] = "True"
                    else:
                        result["isPeriodicFileIntegrityImplemented"] = "False"

                except Exception as er:
                    logging.error(f"error['cisInfo']['is_periodic_file_integrity_implemented']: {er}")

            def check_selinux_user_execstack_disabled():
                try:
                    output = extract_info(r'''semanage boolean -l | grep selinuxuser_execstack''')
                    if "off" in output:
                        result["isSeLinuxUserExecstackDisabled"] = "True"
                    else:
                        result["isSeLinuxUserExecstackDisabled"] = "False"
                except Exception as execstack_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']"
                        f"['check_selinux_user_execstack_disabled']: {execstack_err}")

            def check_selinux_user_execheap_disabled():
                try:
                    output = extract_info(r'''semanage boolean -l | grep selinuxuser_execheap''')
                    if "off" in output:
                        result["isSeLinuxUserExecheapDisabled"] = "True"
                    else:
                        result["isSeLinuxUserExecheapDisabled"] = "False"
                except Exception as execheap_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']"
                        f"['check_selinux_user_execheap_disabled']: {execheap_err}")

            def check_selinux_user_execmod_enabled():
                try:
                    output = extract_info(r'''semanage boolean -l | grep selinuxuser_execmod''')
                    if "off" not in output:
                        result["isSeLinuxUserExecmodEnabled"] = "True"
                    else:
                        result["isSeLinuxUserExecmodEnabled"] = "False"
                except Exception as execmod_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']"
                        f"['check_selinux_user_execmod_enabled']: {execmod_err}")

            def check_rhnsd_disabled():
                try:
                    output = extract_info(r'''systemctl is-enabled rhnsd''')
                    if "disabled" in output:
                        result["isRhnsdDisabled"] = "True"
                    else:
                        result["isRhnsdDisabled"] = "False"
                except Exception as rhsnd_err:
                    logging.error(f"error['cisInfo']['cis_selinux_config_info']['check_rhnsd_disabled']: {rhsnd_err}")

            def check_gpg_in_main_yum_enabled():
                try:
                    output = extract_shell_info(r'''grep -E '^gpgcheck' /etc/yum.conf''')
                    if "gpgcheck=1" in output:
                        result["isGpgCheckInMainYumEnabled"] = "True"
                    else:
                        result["isGpgCheckInMainYumEnabled"] = "False"
                except Exception as gpg_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']['check_gpg_in_main_yum_enabled']: {gpg_err}")

            def check_gpg_for_local_packages_enabled():
                try:
                    output = extract_shell_info(r'''grep -E '^\s*gpgcheck' /etc/yum.repos.d/*.repo''')
                    if output and "gpgcheck=1" in output:
                        result["isGpgCheckForLocalPackagesEnabled"] = "True"
                    else:
                        result["isGpgCheckForLocalPackagesEnabled"] = "False"
                except Exception as gpg_err:
                    logging.error(
                        f"error['cisInfo']['cis_selinux_config_info']"
                        f"['check_gpg_for_local_packages_enabled']: {gpg_err}")

            check_selinux_installed()
            check_selinux_disabled_in_bootloader()
            check_selinux_policy_configured()
            check_se_linux_mode_enforcing_or_permissive()
            check_se_troubleshoot_installed()
            check_mcs_translation_service_installed()
            check_selinux_in_grub()
            check_selinux_state_enforcing()
            check_periodic_file_integrity()
            check_selinux_user_execstack_disabled()
            check_selinux_user_execheap_disabled()
            check_selinux_user_execmod_enabled()
            check_rhnsd_disabled()
            check_gpg_in_main_yum_enabled()
            check_gpg_for_local_packages_enabled()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_selinux_config_info']: {err}")

        return result

    # CIS Section 2.2
    @logger_function
    def cis_special_purpose_services():
        result = {
            "isXorgX11ServerNotInstalled": "Not Configured",
            "isAvahiDaemonNotInstalled": "Not Configured",
            "isCupsNotInstalled": "Not Configured",
            "isDhcpServerNotInstalled": "Not Configured",
            "isDnsServerNotInstalled": "Not Configured",
            "isVsftpdNotInstalled": "Not Configured",
            "isTftpServerNotInstalled": "Not Configured",
            "isAnyServerNotInstalled": "Not Configured",
            "isDovecotNotInstalled": "Not Configured",
            "isImapdNotInstalled": "Not Configured",
            "isSambaNotInstalled": "Not Configured",
            "isHttpProxyServerNotInstalled": "Not Configured",
            "isSnmpNotInstalled": "Not Configured",
            "isTelNetServerNotInstalled": "Not Configured",
            "isDnsmasqNotInstalled": "Not Configured",
            "isNfsUtilsNotInstalled": "Not Configured",
            "isRpcbindNotInstalled": "Not Configured",
            "isRsyncNotInstalled": "Not Configured",
            "isMtaNotListening": "Not Configured",
            "isHttpServerNotInstalled": "Not Configured",
            "isMailTransferLocalOnly": "Not Configured",
            "isPOPServerNotInstalled": "Not Configured",
            "isPrintServerNotInstalled": "Not Configured",
        }
        try:
            def check_if_mta_configured():
                try:
                    # Check if mta is configured or not
                    check_mta_configured_command = (r"ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\["
                                                    r"?::1\]?):25\s'")

                    logging.info(f"check_installed_command: {check_mta_configured_command}")
                    check_mta_configured_command_result = subprocess.run(check_mta_configured_command, shell=True,
                                                                         stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                                         universal_newlines=True,
                                                                         timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_configured_command_result: {check_mta_configured_command_result}")

                    if (check_mta_configured_command_result.returncode == 0
                            and not check_mta_configured_command_result.stdout):
                        mta_configured_result = "True"
                    else:
                        mta_configured_result = "False"

                    logging.info(f"coredump_service_result: {mta_configured_result}")
                    return mta_configured_result
                except Exception as er:
                    error["cisInfo"]['cis_special_purpose_services']["check_if_mta_configured"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_special_purpose_services']['check_if_mta_configured']: {er}")
                    return "Not Configured"

            result["isXorgX11ServerNotInstalled"] = check_if_not_installed("xorg-x11-server-common",
                                                                           "cis_special_purpose_services")
            result["isAvahiDaemonNotInstalled"] = check_if_not_installed("avahi", "cis_special_purpose_services")
            result["isCupsNotInstalled"] = check_if_not_installed("cups", "cis_special_purpose_services")
            result["isDhcpServerNotInstalled"] = check_if_not_installed("dhcp-server", "cis_special_purpose_services")
            result["isDnsServerNotInstalled"] = check_if_not_installed("bind", "cis_special_purpose_services")
            result["isVsftpdNotInstalled"] = check_if_not_installed("vsftpd", "cis_special_purpose_services")
            result["isTftpServerNotInstalled"] = check_if_not_installed("tftp-server", "cis_special_purpose_services")
            result["isAnyServerNotInstalled"] = check_if_not_installed("httpd nginxr", "cis_special_purpose_services")
            result["isDovecotNotInstalled"] = check_if_not_installed("dovecot",
                                                                     "cis_special_purpose_services")
            result["isImapdNotInstalled"] = check_if_not_installed("cyrus-imapd",
                                                                   "cis_special_purpose_services")
            result["isSambaNotInstalled"] = check_if_not_installed("samba", "cis_special_purpose_services")
            result["isHttpProxyServerNotInstalled"] = check_if_not_installed("squid", "cis_special_purpose_services")
            result["isSnmpNotInstalled"] = check_if_not_installed("net-snmp", "cis_special_purpose_services")
            result["isTelNetServerNotInstalled"] = check_if_not_installed("telnet-server",
                                                                          "cis_special_purpose_services")
            result["isDnsmasqNotInstalled"] = check_if_not_installed("dnsmasq", "cis_special_purpose_services")
            result["isMtaNotListening"] = check_if_mta_configured()
            result["isMailTransferLocalOnly"] = check_if_mta_configured()
            result["isNfsUtilsNotInstalled"] = check_if_not_installed("nfs-utils", "cis_special_purpose_services")
            result["isRpcbindNotInstalled"] = check_if_not_installed("rpcbind", "cis_special_purpose_services")
            result["isRsyncNotInstalled"] = check_if_not_installed("rsync-daemon", "cis_special_purpose_services")
            result["isHttpServerNotInstalled"] = check_if_not_installed("httpd", "cis_special_purpose_services")
            result["isPOPServerNotInstalled"] = check_if_not_installed("dovecot", "cis_special_purpose_services")
            result["isPrintServerNotInstalled"] = check_if_not_installed("cups", "cis_special_purpose_services")

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_special_purpose_services']: {err}")
        return result

    # CIS Section - 2.3
    @logger_function
    def cis_service_clients():
        result = {
            "isTelnetServerNotInstalled": "Not Configured",
            "isTelnetClientNotInstalled": "Not Configured",
            "isTftpClientNotInstalled": "Not Configured",
            "isTftpServerNotInstalled": "Not Configured",
            "isFtpClientNotInstalled": "Not Configured",
            "isFtpServerNotInstalled": "Not Configured",
            "isNisClientNotInstalled": "Not Configured",
            "isNisServerNotInstalled": "Not Configured",
            "isRshClientNotInstalled": "Not Configured",
            "isRshServerNotInstalled": "Not Configured",
            "isTalkClientNotInstalled": "Not Configured",
            "isTalkServerNotInstalled": "Not Configured",
            "isLdapNotInstalled": "Not Configured",
        }
        try:
            result["isTelnetServerNotInstalled"] = check_if_not_installed("telnet-server", "cis_service_clients")
            result["isTelnetClientNotInstalled"] = check_if_not_installed("telnet", "cis_service_clients")
            result["isNisClientNotInstalled"] = check_if_not_installed("ypbind", "cis_service_clients")
            result["isNisServerNotInstalled"] = check_if_not_installed("ypserv", "cis_service_clients")
            result["isRshClientNotInstalled"] = check_if_not_installed("rsh", "cis_service_clients")
            result["isRshServerNotInstalled"] = check_if_not_installed("rsh-server", "cis_service_clients")
            result["isTftpClientNotInstalled"] = check_if_not_installed("tftp", "cis_service_clients")
            result["isTftpServerNotInstalled"] = check_if_not_installed("tftp-server", "cis_service_clients")
            result["isTalkClientNotInstalled"] = check_if_not_installed("talk", "cis_service_clients")
            result["isTalkServerNotInstalled"] = check_if_not_installed("talk-server", "cis_service_clients")
            result["isFtpClientNotInstalled"] = check_if_not_installed("ftp", "cis_service_clients")
            result["isFtpServerNotInstalled"] = check_if_not_installed("vsftpd", "cis_service_clients")
            result["isLdapNotInstalled"] = check_if_not_installed("ldap-utils", "cis_service_clients")

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_service_clients']: {err}")

        return result

    # CIS Section - 3.2
    @logger_function
    def cis_network_configuration():
        result = {
            "isIpForwardingDisabled": "Not Configured",
            "isSendPcketRedirectsDisabled": "Not Configured",
            "isAcceptSourceRouteDisabled": "Not Configured",
            "isIcmpAcceptRedirectsDisabled": "Not Configured",
            "isSecureIcmpRedirectsDisabled": "Not Configured",
            "isLogSuspiciousPacketsEnabled": "Not Configured",
            "isBroadcastIcmpRequestIgnored": "Not Configured",
            "isBogusIcmpResponsesIgnored": "Not Configured",
            "isTcpSynCookiesEnabled": "Not Configured",
            "isIpv6RouterAdvertisementsDisabled": "Not Configured",
            "isIpv6Disabled": "Not Configured",
            "isDccpDisabled": "Not Configured",
            "isSctpDisabled": "Not Configured",
            "isReversePathFilteringEnabled": "Not Configured",
            "isRdsDisabled": "Not Configured",
            "isTipcDisabled": "Not Configured",
            "isWirelessInterfaceDeactivated": "Not Configured",
            "isSystemWideCryptoPolicyFIPS": "Not Configured",
            "isSshToUseSystemCryptoPolicy": "Not Configured",
        }

        def check_ip_forwarding_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.ip_forward")
                output_2 = extract_shell_info(
                    r'grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf '
                    r'/usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')

                output_3 = extract_info('sysctl net.ipv6.conf.all.forwarding')
                output_4 = extract_shell_info(
                    r'grep -E -s "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf '
                    r'/usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')

                if (output_1 == "net.ipv4.ip_forward = 0" or not output_2) \
                        and (output_3 == "net.ipv6.conf.all.forwarding = 0" or not output_4):
                    result["isIpForwardingDisabled"] = "True"
                else:
                    result["isIpForwardingDisabled"] = "False"
            except Exception as ip_forward_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']"
                              f"['check_ip_forwarding_disabled']: {ip_forward_err}")

        def check_send_packet_redirects_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.send_redirects")
                output_2 = extract_info("sysctl net.ipv4.conf.default.send_redirects")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.send_redirects = 0" \
                    or output_3 == "net.ipv4.conf.all.send_redirects = 0") \
                        and (output_2 == "net.ipv4.conf.default.send_redirects = 0" \
                             or output_4 == "net.ipv4.conf.default.send_redirects = 0"):
                    result["isSendPcketRedirectsDisabled"] = "True"
                else:
                    result["isSendPcketRedirectsDisabled"] = "False"
            except Exception as send_packet_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_send_packet_redirects_disabled']: {send_packet_err}")

        def check_accept_source_route_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.accept_source_route")
                output_2 = extract_info("sysctl net.ipv4.conf.default.accept_source_route")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.accept_source_route = 0" \
                    or output_3 == "net.ipv4.conf.all.accept_source_route = 0") \
                    and (output_2 == "net.ipv4.conf.default.accept_source_route = 0" \
                         or output_4 == "net.ipv4.conf.default.accept_source_route = 0"):
                    result["isAcceptSourceRouteDisabled"] = "True"
                else:
                    result["isAcceptSourceRouteDisabled"] = "False"
            except Exception as accept_source_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_accept_source_route_disabled']: {accept_source_err}")

        def check_icmp_accept_redirects_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.accept_redirects")
                output_2 = extract_info("sysctl net.ipv4.conf.default.accept_redirects")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')

                output_5 = extract_info("sysctl net.ipv6.conf.all.accept_redirects")
                output_6 = extract_info("sysctl net.ipv6.conf.default.accept_redirects")

                output_7 = extract_shell_info(
                    r'grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                output_8 = extract_shell_info(
                    r'grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.accept_redirects = 0" \
                    or output_3 == "net.ipv4.conf.all.accept_redirects = 0") \
                    and (output_2 == "net.ipv4.conf.default.accept_redirects = 0" \
                         or output_4 == "net.ipv4.conf.default.accept_redirects = 0") \
                    and (output_5 == "net.ipv6.conf.all.accept_redirects = 0" \
                         or output_7 == "net.ipv6.conf.all.accept_redirects = 0") \
                    and (output_6 == "net.ipv6.conf.default.accept_redirects = 0" \
                         or output_8 == "net.ipv6.conf.default.accept_redirects = 0"):
                    result["isIcmpAcceptRedirectsDisabled"] = "True"
                else:
                    result["isIcmpAcceptRedirectsDisabled"] = "False"
            except Exception as icmp_redirect_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_icmp_accept_redirects_disabled']: {icmp_redirect_err}")

        def check_secure_icmp_redirects_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.secure_redirects")
                output_2 = extract_info("sysctl net.ipv4.conf.default.secure_redirects")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.secure_redirects = 0" \
                    or output_3 == "net.ipv4.conf.all.secure_redirects= 0") \
                        and (output_2 == "net.ipv4.conf.default.secure_redirects = 0" \
                             or output_4 == "net.ipv4.conf.default.secure_redirects= 0"):
                    result["isSecureIcmpRedirectsDisabled"] = "True"
                else:
                    result["isSecureIcmpRedirectsDisabled"] = "False"
            except Exception as secure_icmp_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_secure_icmp_redirects_disabled']: {secure_icmp_err}")

        def check_log_suspicious_packets_enabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.log_martians")
                output_2 = extract_info("sysctl net.ipv4.conf.default.log_martians")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.conf.all.log_martians = 1" \
                    or output_3 == "net.ipv4.conf.all.log_martians = 1") \
                    and (output_2 == "net.ipv4.conf.default.log_martians = 1" \
                        or output_4 == "net.ipv4.conf.default.log_martians = 1"):
                    result["isLogSuspiciousPacketsEnabled"] = "True"
                else:
                    result["isLogSuspiciousPacketsEnabled"] = "False"
            except Exception as suspicious_log_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_log_suspicious_packets_enabled']: {suspicious_log_err}")

        def check_broadcast_icmp_ignored():
            try:
                output_1 = extract_info("sysctl net.ipv4.icmp_echo_ignore_broadcasts")

                output_2 = extract_shell_info(
                    r'grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.icmp_echo_ignore_broadcasts = 1" or
                        output_2 == "net.ipv4.icmp_echo_ignore_broadcasts = 1"):
                    result["isBroadcastIcmpRequestIgnored"] = "True"
                else:
                    result["isBroadcastIcmpRequestIgnored"] = "False"
            except Exception as broadcast_icmp_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']"
                              f"['check_broadcast_icmp_ignored']: {broadcast_icmp_err}")

        def check_bogus_icmp_ignored():
            try:
                output_1 = extract_info("sysctl net.ipv4.icmp_ignore_bogus_error_responses")

                output_2 = extract_shell_info(
                    'grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv4.icmp_ignore_bogus_error_responses = 1"
                        or output_2 == "net.ipv4.icmp_ignore_bogus_error_responses = 1"):
                    result["isBogusIcmpResponsesIgnored"] = "True"
                else:
                    result["isBogusIcmpResponsesIgnored"] = "False"
            except Exception as bogus_icmp_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']"
                              f"['check_bogus_icmp_ignored']: {bogus_icmp_err}")

        def check_tcp_syn_cookies_enabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.tcp_syncookies")

                output_2 = extract_shell_info(r'grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*')

                if output_1 == "net.ipv4.tcp_syncookies = 1" or output_2 == "net.ipv4.tcp_syncookies = 1":
                    result["isTcpSynCookiesEnabled"] = "True"
                else:
                    result["isTcpSynCookiesEnabled"] = "False"
            except Exception as tcp_syn_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']"
                              f"['check_tcp_syn_cookies_enabled']: {tcp_syn_err}")

        def check_ipv6_router_advertisements_disabled():
            try:
                output_1 = extract_info("sysctl net.ipv6.conf.all.accept_ra")
                output_2 = extract_info("sysctl net.ipv6.conf.default.accept_ra")

                output_3 = extract_shell_info(
                    r'grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')
                output_4 = extract_shell_info(
                    r'grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*')

                if (output_1 == "net.ipv6.conf.all.accept_ra = 0" \
                    or output_3 == "net.ipv6.conf.all.accept_ra = 0") \
                        and (output_2 == "net.ipv6.conf.default.accept_ra = 0"\
                             or output_4 == "net.ipv6.conf.default.accept_ra = 0"):
                    result["isIpv6RouterAdvertisementsDisabled"] = "True"
                else:
                    result["isIpv6RouterAdvertisementsDisabled"] = "False"
            except Exception as ip_adv_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_ipv6_router_advertisements_disabled']: {ip_adv_err}")

        def check_ipv6_disabled():
            try:
                srcipt = r'''
                    #!/bin/bash
                    [ -n "$passing" ] && passing=""
                    [ -z "$(grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disable=1)" ] &&
                    passing="true"
                    grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$"
                    /etc/sysctl.conf
                    /etc/sysctl.d/*.conf && grep -Eq
                    "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$"
                    /etc/sysctl.conf /etc/sysctl.d/*.conf && sysctl
                    net.ipv6.conf.all.disable_ipv6 |
                    grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" &&
                    sysctl net.ipv6.conf.default.disable_ipv6 |
                    grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" &&
                    passing="true"
                    if [ "$passing" = true ] ; then
                    echo "PASS"
                    else
                    echo "FAIL"
                    fi
                '''
                result["isIpv6Disabled"] = run_script(srcipt, "cis_network_configuration")

            except Exception as ipv6_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']['check_ipv6_disabled']: {ipv6_err}")

        def check_dccp_disabled():
            try:
                cmd = f"modprobe -n -v dccp"
                output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                logging.info(f"check_mount_system_command_result: {output}")
                cmd2 = f"lsmod | grep dccp"
                output2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True,
                                                  timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE).strip()

                if output.returncode == 0 and output.stdout == "install /bin/true":
                    if not output2:
                        result["isDccpDisabled"] = "True"
                    else:
                        result["isDccpDisabled"] = "False"

            except Exception as dccp_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']['check_dccp_disabled']: {dccp_err}")

        def check_sctp_disabled():
            try:
                cmd = f"modprobe -n -v sctp"
                output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                logging.info(f"check_mount_system_command_result: {output}")
                cmd2 = f"lsmod | grep sctp"
                output2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True,
                                                  timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE).strip()

                logging.info(f"check_sctp_disabled_command_result: {output2}")

                if output.returncode == 0 and output.stdout == "install /bin/true":
                    if not output2:
                        result["isSctpDisabled"] = "True"
                    else:
                        result["isSctpDisabled"] = "False"

            except Exception as sctp_err:
                logging.error(f"error['cisInfo']['cis_network_configuration']['check_sctp_disabled']: {sctp_err}")

        def check_reverse_path_filtering_enabled():
            try:
                output_1 = extract_info("sysctl net.ipv4.conf.all.rp_filter")
                output_2 = extract_info("sysctl net.ipv4.conf.default.rp_filter")

                output_3 = extract_shell_info(
                    r'grep -E -s "^\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*0" /etc/sysctl.conf '
                    r'/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')
                output_4 = extract_shell_info(
                    r'grep -E -s "^\s*net\.ipv4\.conf\.default\.rp_filter\s*=\s*1" /etc/sysctl.conf '
                    r'/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf')

                if (output_1 == "net.ipv4.conf.all.rp_filter = 1" or not output_3) \
                    and (output_2 == "net.ipv4.conf.default.rp_filter = 1" or not output_4):
                    result["isReversePathFilteringEnabled"] = "True"
                else:
                    result["isReversePathFilteringEnabled"] = "False"
            except Exception as secure_icmp_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_reverse_path_filtering_enabled']: {secure_icmp_err}")

        def check_rds_disabled():
            try:
                cmd = f"modprobe -n -v rds"
                output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                logging.info(f"check_mount_system_command_result: {output}")
                cmd2 = f"lsmod | grep rds"
                output2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True,
                                                  timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE).strip()

                logging.info(f"check_sctp_disabled_command_result: {output2}")

                if output.returncode == 0 and output.stdout == "install /bin/true":
                    if not output2:
                        result["isRdsDisabled"] = "True"
                    else:
                        result["isRdsDisabled"] = "False"

            except Exception as secure_icmp_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_rds_disabled']: {secure_icmp_err}")

        def check_tipc_disabled():
            try:
                cmd = f"modprobe -n -v tipc"
                output = subprocess.run(cmd, shell=True, universal_newlines=True,
                                        timeout=TIMEOUT_SUBPROCESS, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                logging.info(f"check_mount_system_command_result: {output}")
                cmd2 = f"lsmod | grep tipc"
                output2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True,
                                                  timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE).strip()

                logging.info(f"check_sctp_disabled_command_result: {output2}")

                if output.returncode == 0 and output.stdout == "install /bin/true":
                    if not output2:
                        result["isTipcDisabled"] = "True"
                    else:
                        result["isTipcDisabled"] = "False"

            except Exception as secure_icmp_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_tipc_disabled']: {secure_icmp_err}")

        def check_wireless_disabled():
            try:
                output = extract_info("nmcli radio all")
                lines_out = output.split('\n')[-1].split()
                if len(lines_out) == 4:
                    if lines_out[0] == lines_out[2] == "enabled" and lines_out[1] == lines_out[3] == "disabled":
                        result["isWirelessInterfaceDeactivated"] = "True"
                    else:
                        result["isWirelessInterfaceDeactivated"] = "False"
                else:
                    result["isWirelessInterfaceDeactivated"] = "False"
            except Exception as wireless_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']['check_wireless_disabled']: {wireless_err}")

        def check_system_wide_crypto_policy_fips():
            try:
                output = extract_shell_info(r"grep -E -i '^\s*(FUTURE|FIPS)\s*(\s+#.*)?$' /etc/crypto-policies/config")
                if "Future" in output or "FIPS" in output:
                    result["isSystemWideCryptoPolicyFIPS"] = "True"
                else:
                    result["isSystemWideCryptoPolicyFIPS"] = "False"

            except Exception as fips_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_system_wide_crypto_policy_fips']: {fips_err}")

        def check_ssh_to_use_system_crypto_policy():
            try:
                output = extract_shell_info(r"grep -E '^\s*CRYPTO_POLICY\s*=\s*' /etc/sysconfig/sshd")
                if "CRYPTO_POLICY=" in output:
                    result["isSshToUseSystemCryptoPolicy"] = "True"
                else:
                    result["isSshToUseSystemCryptoPolicy"] = "False"

            except Exception as fips_err:
                logging.error(
                    f"error['cisInfo']['cis_network_configuration']"
                    f"['check_ssh_to_use_system_crypto_policy']: {fips_err}")

        try:
            check_ip_forwarding_disabled()
            check_send_packet_redirects_disabled()
            check_accept_source_route_disabled()
            check_icmp_accept_redirects_disabled()
            check_secure_icmp_redirects_disabled()
            check_log_suspicious_packets_enabled()
            check_broadcast_icmp_ignored()
            check_bogus_icmp_ignored()
            check_tcp_syn_cookies_enabled()
            check_ipv6_router_advertisements_disabled()
            check_ipv6_disabled()
            check_dccp_disabled()
            check_sctp_disabled()
            check_reverse_path_filtering_enabled()
            check_rds_disabled()
            check_tipc_disabled()
            check_wireless_disabled()
            check_system_wide_crypto_policy_fips()
            check_ssh_to_use_system_crypto_policy()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_network_configuration']: {err}")

        return result

    # CIS Section - 3.4.1
    @logger_function
    def cis_configure_firewall_utility():
        result = {
            "isNftablesNotInstalled": "Not Configured",
            "isSingleFirewallConfInUse": "Not Configured"
        }
        try:
            firewall_script = r"""l_output=""
            l_output2=""
            l_fwd_status=""
            l_nft_status=""
            l_fwutil_status=""

            if rpm -q firewalld >/dev/null 2>&1; then
                l_fwd_status="$(systemctl is-enabled firewalld.service):$(systemctl is-active firewalld.service)"
            fi

            if rpm -q nftables >/dev/null 2>&1; then
                l_nft_status="$(systemctl is-enabled nftables.service):$(systemctl is-active nftables.service)"
            fi

            l_fwutil_status="$l_fwd_status:$l_nft_status"

            case $l_fwutil_status in enabled:active:masked:inactive | enabled:active:disabled:inactive) l_output="\n
            - FirewallD utility is in use, enabled and active\n - NFTables utility is correctly disabled or masked
            and inactive" ;; masked:inactive:enabled:active | disabled:inactive:enabled:active) l_output="\n -
            NFTables utility is in use, enabled and active\n - FirewallD utility is correctly disabled or masked and
            inactive" ;; enabled:active:enabled:active) l_output2="\n - Both FirewallD and NFTables utilities are
            enabled and active" ;; enabled:*:enabled:*) l_output2="\n - Both FirewallD and NFTables utilities are
            enabled" ;; *:active:*:active) l_output2="\n - Both FirewallD and NFTables utilities are enabled" ;;
            :enabled:active) l_output="\n - NFTables utility is in use, enabled, and active\n - FirewallD package is
            not installed" ;; :) l_output2="\n - Neither FirewallD nor NFTables is installed." ;; *:*:) l_output2="\n
            - NFTables package is not installed on the system" ;; *) l_output2="\n - Unable to determine firewall
            state" ;; esac

            if [ -z "$l_output2" ]; then
                echo -e "\n- Audit Results:\n ** PASS **$l_output\n"
            else
                echo -e "\n- Audit Results:\n ** FAIL **$l_output2\n"
            fi"""

            logging.info(f"check_single_firewall_conf_in_use with script")

            result["isNftablesNotInstalled"] = check_if_not_installed("nftables", "cis_configure_firewall_utility")
            result["isSingleFirewallConfInUse"] = run_script(firewall_script, "cis_configure_firewall_utility")
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_firewall_utility']: {err}")
        return result

    # CIS Section - 3.4.2
    @logger_function
    def cis_configure_firewall_rules():
        result = {
            "isFirewallDefaultZoneSet": "Not Configured",
            "atleastOneNftableExists": "Not Configured",
            "nftableBaseChainsExist": "Not Configured",
            "isFirewallLoopbackConfigured": "Not Configured",
        }
        try:
            # cis subsection 3.4.2.1
            def check_firewall_default_zone_set():
                try:
                    logging.info("Running check_single_firewall_conf_in_use()")
                    firewall_script = r"""l_output="" l_output2="" l_zone=""
                if systemctl is-enabled firewalld.service | grep -q 'enabled'; then
                    l_zone="$(firewall-cmd --get-default-zone)"
                    if [ -n "$l_zone" ]; then
                        l_output=" - The default zone is set to: \"$l_zone\""
                    else
                        l_output2=" - The default zone is not set"
                    fi
                else
                    l_output=" - FirewallD is not in use on the system"
                fi
                if [ -z "$l_output2" ]; then
                    echo -e "\n- Audit Results:\n ** PASS **\n$l_output\n"
                else
                    echo -e "\n- Audit Results:\n ** FAIL **\n$l_output2\n"
                fi"""
                    logging.info(f"check_firewall_default_zone_set with script")
                    return run_script(firewall_script, "cis_configure_firewall_rules")
                except Exception as er:
                    error["cisInfo"]["cis_configure_firewall_rules"]["check_firewall_default_zone_set"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_firewall_rules']['check_firewall_default_zone_set']: {er}")
                    return "Not Configured"

            # cis subsection 3.4.2.2
            def check_atleast_one_nftable_exists():
                try:
                    check_nftable_command = "nft list tables"
                    logging.info(f"check_nftable_command: '{check_nftable_command}'")
                    check_nftable_command_result = subprocess.run(check_nftable_command, shell=True,
                                                                  stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                                  universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_nftable_command_result : {check_nftable_command_result}")

                    if check_nftable_command_result.returncode == 0:
                        check_nftable_result = "True"
                    elif check_nftable_command_result.returncode == 1:
                        check_nftable_result = "False"
                    else:
                        check_nftable_result = "Not Configured"

                    logging.info(f"check_nftable_result: {check_nftable_result}")
                    return check_nftable_result
                except Exception as er:
                    error["cisInfo"]['cis_configure_firewall_rules']["check_atleast_one_nftable_exists"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_firewall_rules']['check_atleast_one_nftable_exists']: {er}")
                    return "Not Configured"

            # cis subsection 3.4.2.3
            def check_nftable_base_chains_exist():
                base_chain_result = {
                    "inputChain": "Not Configured",
                    "forwardChain": "Not Configured",
                    "outputChain": "Not Configured",
                }
                try:
                    base_chain_list = ["input", "forward", "output"]
                    for value in base_chain_list:
                        check_nftable_base_chains_command = f"nft list ruleset | grep 'hook {value}'"
                        logging.info(f"check_nftable_base_chains_command: '{check_nftable_base_chains_command}'")
                        check_nftable_base_chains_command_result = subprocess.run(check_nftable_base_chains_command,
                                                                                  shell=True,
                                                                                  stderr=subprocess.PIPE,
                                                                                  stdout=subprocess.PIPE,
                                                                                  universal_newlines=True,
                                                                                  timeout=TIMEOUT_SUBPROCESS)
                        logging.info(
                            f"check_nftable_base_chains_command_result : {check_nftable_base_chains_command_result}")

                        if check_nftable_base_chains_command_result.returncode == 0:
                            check_nftable_base_chains_result = "True"
                        elif check_nftable_base_chains_command_result.returncode == 1:
                            check_nftable_base_chains_result = "False"
                        else:
                            check_nftable_base_chains_result = "Not Configured"
                        base_chain_result[value + "Chain"] = check_nftable_base_chains_result

                    logging.info(f"check_nftable_base_chains_result: {base_chain_result}")
                except Exception as er:
                    error["cisInfo"]['cis_configure_firewall_rules']["check_nftable_base_chains_exist"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_firewall_rules']['check_nftable_base_chains_exist']: {er}")
                return base_chain_result

            # cis subsection 3.4.2.4
            def check_firewall_loopback():
                try:
                    script = r"""l_output="" l_output2="" if nft list ruleset | awk '/hook\s+input\s+/,
                    /\}\s*(#.*)?$/' | grep -Pq --'\H+\h+"lo"\h+accept'; then l_output="$l_output\n - Network traffic
                    to the loopback address is correctly set to accept" else l_output2="$l_output2\n - Network
                    traffic to the loopback address is not set to accept" fi l_ipsaddr="$(nft list ruleset | awk
                    '/filter_IN_public_deny|hook\s+input\s+/,/\}\s*(#.*)?$/' | grep -P --'ip\h+saddr')" if grep -Pq
                    --'ip\h+saddr\h+127\.0\.0\.0\/8\h+(counter\h+packets\h+\d+\h+bytes\h+\d+\h+)?drop' <<<
                    "$l_ipsaddr" || grep -Pq -- 'ip\h+daddr\h+\!\=\h+127\.0\.0\.1\h+ip\h+saddr\h+127\.0\.0\.1\h+drop'
                    <<< "$l_ipsaddr"; then l_output="$l_output\n - IPv4 network traffic from loopback address
                    correctly set to drop" else l_output2="$l_output2\n - IPv4 network traffic from loopback address
                    not set to drop" fi if grep -Pq -- '^\h*0\h*$' /sys/module/ipv6/parameters/disable; then
                    l_ip6saddr="$(nft list ruleset | awk '/filter_IN_public_deny|hook input/,/}/' | grep 'ip6
                    saddr')" if grep -Pq 'ip6\h+saddr\h+::1\h+(counter\h+packets\h+\d+\h+bytes\h+\d+\h+)?drop' <<<
                    "$l_ip6saddr" || grep -Pq --'ip6\h+daddr\h+\!=\h+::1\h+ip6\h+saddr\h+::1\h+drop' <<<
                    "$l_ip6saddr"; then l_output="$l_output\n - IPv6 network traffic from loopback address correctly
                    set to drop" else l_output2="$l_output2\n - IPv6 network traffic from loopback address not set to
                    drop" fi fi if [ -z "$l_output2" ]; then echo -e "\n- Audit Result:\n *** PASS ***\n$l_output"
                    else echo -e "\n- Audit Result:\n *** FAIL ***\n$l_output2\n\n - Correctly set:\n$l_output" fi"""
                    return run_script(script, "check_firewall_loopback")
                except Exception as er:
                    error["cisInfo"]['cis_configure_firewall_rules']["check_firewall_loopback"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_configure_firewall_rules']['check_firewall_loopback']: {er}")
                    return "Not Configured"

            result["isFirewallDefaultZoneSet"] = check_firewall_default_zone_set()
            result["atleastOneNftableExists"] = check_atleast_one_nftable_exists()
            result["nftableBaseChainsExist"] = check_nftable_base_chains_exist()
            result["isFirewallLoopbackConfigured"] = check_firewall_loopback()
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_firewall_rules']: {err}")
        return result

    # CIS Section - 4.1.1
    @logger_function
    def cis_configure_system_auditing():
        # Configure system auditing
        result = {
            "isAuditdInstalled": "Not Configured",
            "isAuditdForProcessesEnabled": "Not Configured",
            "isAuditBacklogLimitSufficient": "Not Configured",
            "isAuditdServiceEnabled": "Not Configured",
            "isAuditdServiceActive": "Not Configured",
        }
        try:
            def check_auditd_processes_enabled():
                is_auditd_processes_enabled_result = "Not Configured"
                try:
                    # Check if auditd_processes is enabled
                    check_auditd_processes_enabled_command = r"grubby --info=ALL | grep -Po '\baudit=1\b'"
                    logging.info(f"check_auditd_processes_enabled command: {check_auditd_processes_enabled_command}")

                    check_auditd_processes_enabled_command_result = subprocess.run(
                        check_auditd_processes_enabled_command,
                        shell=True,
                        stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                        universal_newlines=True,
                        timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_auth_command_result: {check_auditd_processes_enabled_command_result}")
                    logging.info(
                        f"check_auth_command_result: {check_auditd_processes_enabled_command_result.stdout.strip()}")

                    if check_auditd_processes_enabled_command_result.returncode == 0:
                        is_auditd_processes_enabled_result = "True"
                    elif check_auditd_processes_enabled_command_result.returncode == 1:
                        is_auditd_processes_enabled_result = "False"
                    else:
                        is_auditd_processes_enabled_result = "Not Configured"

                    logging.info(f"is_auditd_processes_enabled_result: {is_auditd_processes_enabled_result}")
                except Exception as er:
                    error["cisInfo"]['cis_configure_system_auditing']["check_auditd_processes_enabled"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_system_auditing']['check_auditd_processes_enabled']: {er}")
                return is_auditd_processes_enabled_result

            def check_auditd_service_enabled_and_active():
                is_auditd_service_enabled_result, is_auditd_service_active_result = "Not Configured", "Not Configured"
                try:
                    # Check if auditd_service is enabled
                    check_auditd_service_enabled_command = r"systemctl is-enabled auditd"
                    logging.info(f"check_auditd_service_enabled command: {check_auditd_service_enabled_command}")

                    check_auditd_service_enabled_command_result = subprocess.run(check_auditd_service_enabled_command,
                                                                                 shell=True,
                                                                                 stderr=subprocess.PIPE,
                                                                                 stdout=subprocess.PIPE,
                                                                                 universal_newlines=True,
                                                                                 timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"check_auth_command_result: {check_auditd_service_enabled_command_result}")
                    logging.info(
                        f"check_auth_command_result.stdout.strip(): "
                        f"{check_auditd_service_enabled_command_result.stdout.strip()}")

                    if check_auditd_service_enabled_command_result.returncode == 0:
                        if check_auditd_service_enabled_command_result.stdout.strip() == "enabled":
                            is_auditd_service_enabled_result = "True"
                        else:
                            is_auditd_service_enabled_result = "False"
                    elif check_auditd_service_enabled_command_result.returncode == 1:
                        is_auditd_service_enabled_result = "Not Configured"
                    else:
                        is_auditd_service_enabled_result = "Not Configured"

                    logging.info(f"is_auditd_service_enabled_result: {is_auditd_service_enabled_result}")

                    # Check if auditd_service is active
                    check_auditd_service_active_command = "systemctl is-active auditd"
                    logging.info(f"check_auditd_service_active command: {check_auditd_service_active_command}")

                    check_auditd_service_active_result = subprocess.run(check_auditd_service_active_command, shell=True,
                                                                        stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                                        universal_newlines=True,
                                                                        timeout=TIMEOUT_SUBPROCESS)
                    logging.info(
                        f"check_auditd_service_active_result.stdout.strip(): "
                        f"{check_auditd_service_active_result.stdout.strip()}")

                    if check_auditd_service_active_result.stdout.strip() == "active":
                        logging.info(f"auditd_service is active")
                        is_auditd_service_active_result = "True"
                    elif check_auditd_service_active_result.stdout.strip() == "inactive":
                        logging.info(f"auditd_service is not active")
                        is_auditd_service_active_result = "False"
                    else:
                        logging.info(f"auditd_service is not configured")
                        is_auditd_service_active_result = "Not Configured"

                    logging.info(f"is_auditd_service_active_result: {is_auditd_service_active_result}")
                except Exception as er:
                    error["cisInfo"]['cis_configure_system_auditing']["check_auditd_service_enabled_and_active"] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_system_auditing']"
                        f"['check_auditd_service_enabled_and_active']: "
                        f"{er}")
                return is_auditd_service_enabled_result, is_auditd_service_active_result

            def check_if_audit_backlog_limit_sufficient():
                audit_backlog_limit_sufficient_result = "Not Configured"
                try:
                    # Check if mta is configured or not
                    check_audit_backlog_limit_sufficient_command = \
                        r"grubby --info=ALL | grep -Po '\baudit_backlog_limit=\d+\b'"

                    logging.info(
                        f"check_audit_backlog_limit_sufficient_command: "
                        f"'{check_audit_backlog_limit_sufficient_command}'")
                    check_audit_backlog_limit_sufficient_command_result = subprocess.run(
                        check_audit_backlog_limit_sufficient_command, shell=True,
                        stderr=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True,
                        timeout=TIMEOUT_SUBPROCESS)
                    logging.info(
                        f"check_audit_backlog_limit_sufficient_command_result: "
                        f"{check_audit_backlog_limit_sufficient_command_result}")

                    if "audit_backlog_limit" in check_audit_backlog_limit_sufficient_command_result.stdout.strip():
                        audit_backlog_limit_sufficient_result = "True"
                    else:
                        audit_backlog_limit_sufficient_result = "False"

                    logging.info(f"audit_backlog_limit_sufficient_result: {audit_backlog_limit_sufficient_result}")
                except Exception as er:
                    error["cisInfo"]['cis_configure_system_auditing']["check_if_audit_backlog_limit_sufficient"] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_system_auditing']"
                        f"['check_if_audit_backlog_limit_sufficient']: "
                        f"{er}")
                return audit_backlog_limit_sufficient_result

            result["isAuditdInstalled"] = check_if_installed("audit", "cis_configure_system_auditing")
            result["isAuditdForProcessesEnabled"] = check_auditd_processes_enabled()
            result["isAuditBacklogLimitSufficient"] = check_if_audit_backlog_limit_sufficient()
            result["isAuditdServiceEnabled"], result[
                "isAuditdServiceActive"] = check_auditd_service_enabled_and_active()
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_system_auditing']: {err}")
        return result

    # CIS Section - 4.1.2
    @logger_function
    def cis_logging_and_auditing():
        result = {
            "isAuditLogStorageSizeConfigured": "Not Configured",
            "recordEventsThatModifyDateAndTimeAreCollected": "Not Configured",
            "recordEventsThatModifyUserOrGroupAreCollected": "Not Configured",
            "recordEventsThatModifyNetworkAreCollected": "Not Configured",
            "recordEventsThatModifyMandatoryAccessAreCollected": "Not Configured",
            "isSessionIniationCollected": "Not Configured",
            "isDiscretionaryAccessEventsCollected": "Not Configured",
            "isUnsuccessfulUnauthorizedAccessCollected": "Not Configured",
            "isSuccessfulFilesystemCollected": "Not Configured",
            "isChangeToSystemAdministrativeScopeCollected": "Not Configured",
            "isKernelModuleLoadingAndUnloadingCollected": "Not Configured",
            "isAuditConfigurationImmutable": "Not Configured",
            "isAuditLogsAreNotAutomaticallyDeleted": "Not Configured",
            "isLoginAndLogoutEventsCollected": "Not Configured",
            "isFileDeletionEventsByUserCollected": "Not Configured",
            "isAnyAttemptsToRunChconRecorded": "Not Configured",
            "isWriteLogFilesToPersistentDisk": "Not Configured",
            "isDisableSystemOnAuditLogFull": "Not Configured",
            "isJournaldConfiguredToCompressLargeLogFiles": "Not Configured",
            "isUseOfPrivilegedCommandsCollected": "Not Configured",
        }
        try:
            def check_if_audit_log_storage_size_configured():

                try:
                    # Check if mta is configured or not
                    output = extract_shell_info(r"grep -E '^max_log_file =' /etc/audit/auditd.conf")

                    if "max_log_file" in output:
                        result["isAuditLogStorageSizeConfigured"] = "True"
                    else:
                        result["isAuditLogStorageSizeConfigured"] = "False"

                    logging.info(f"audit_log_storage_size_configured_result: "
                                 f"{result['isAuditLogStorageSizeConfigured']}")
                except Exception as audit_store_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['check_if_audit_log_storage_size_configured']: {audit_store_err}")

            def check_record_events_that_modify_date_and_time_are_collected():
                try:
                    output1 = extract_shell_info(r"grep time-change /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep time-change")

                    match1 = '''\
                        -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
                        -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
                        -a always,exit -F arch=b64 -S clock_settime -k time-change
                        -a always,exit -F arch=b32 -S clock_settime -k time-change
                        -w /etc/localtime -p wa -k time-change\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["recordEventsThatModifyDateAndTimeAreCollected"] = "True"
                    else:
                        result["recordEventsThatModifyDateAndTimeAreCollected"] = "False"
                    logging.info(f"record_events_that_modify_date_and_time_are_collected_result: "
                                 f"{result['recordEventsThatModifyDateAndTimeAreCollected']}")
                except Exception as modify_dt_time_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['check_record_events_that_modify_date_and_time_are_collected']: "
                                  f"{modify_dt_time_err}")

            def check_record_events_that_modify_user_or_group_are_collected():
                try:
                    output1 = extract_shell_info(r"grep identity /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep identity")

                    match1 = '''\
                        -w /etc/group -p wa -k identity
                        -w /etc/passwd -p wa -k identity
                        -w /etc/gshadow -p wa -k identity
                        -w /etc/shadow -p wa -k identity
                        -w /etc/security/opasswd -p wa -k identity\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["recordEventsThatModifyUserOrGroupAreCollected"] = "True"
                    else:
                        result["recordEventsThatModifyUserOrGroupAreCollected"] = "False"
                    logging.info(f"record_events_that_modify_user_or_group_are_collected_result: "
                                 f"{result['recordEventsThatModifyUserOrGroupAreCollected']}")
                except Exception as user_grp_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['check_record_events_that_modify_user_or_group_are_collected']: {user_grp_err}")

            def check_record_events_that_modify_network_are_collected():
                try:
                    output1 = extract_shell_info(r"grep system-locale /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep system-locale")

                    match1 = '''\
                        -w /etc/issue -p wa -k system-locale
                        -w /etc/issue.net -p wa -k system-locale
                        -w /etc/hosts -p wa -k system-locale
                        -w /etc/network -p wa -k system-locale\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["recordEventsThatModifyNetworkAreCollected"] = "True"
                    else:
                        result["recordEventsThatModifyNetworkAreCollected"] = "False"
                    logging.info(f"record_events_that_modify_network_are_collected_result: "
                                 f"{result['recordEventsThatModifyNetworkAreCollected']}")
                except Exception as modify_net_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['check_record_events_that_modify_network_are_collected']: {modify_net_err}")

            def check_record_events_that_modify_the_systems_mandatory_access_controls_are_collected():
                try:
                    output1 = extract_shell_info(r"grep MAC-policy /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep MAC-policy")

                    match1 = '''\
                        -w /etc/apparmor/ -p wa -k MAC-policy
                        -w /etc/apparmor.d/ -p wa -k MAC-policy\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["recordEventsThatModifyMandatoryAccessAreCollected"] = "True"
                    else:
                        result["recordEventsThatModifyMandatoryAccessAreCollected"] = "False"
                    logging.info(f"record_events_that_modify_the_systems_mandatory_access_"
                                 f"controls_are_collected_result: "
                                 f"{result['recordEventsThatModifyMandatoryAccessAreCollected']}")
                except Exception as system_mac_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['recordEventsThatModifyMandatoryAccessAreCollected']: "
                                  f"{system_mac_err}")

            def check_if_session_information_is_collected():
                try:
                    output1 = extract_shell_info(r"grep -E '(session|logins)' /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep '(session|logins)'")

                    match1 = '''\
                        -w /var/run/utmp -p wa -k session
                        -w /var/log/wtmp -p wa -k logins
                        -w /var/log/btmp -p wa -k logins\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["isSessionIniationCollected"] = "True"
                    else:
                        result["isSessionIniationCollected"] = "False"
                    logging.info(f"is_session_information_collected_result: {result['isSessionIniationCollected']}")
                except Exception as session_info_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isSessionIniationCollected']: {session_info_err}")

            def check_if_collect_discretionary_access_control_information_is_collected():
                try:
                    output1 = extract_shell_info(r"grep perm_mod /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'perm_mod'")

                    match1 = '''-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
                    auid!=4294967295 -k perm_mod -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F
                    auid>=1000 -F auid!=4294967295 -k perm_mod -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S
                    fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k
                    perm_mod'''
                    match2 = ''' -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F
                    key=perm_mod -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F
                    key=perm_mod -a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,
                    fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod'''
                    if output1 == match1 and output2 == match2:
                        result["isDiscretionaryAccessEventsCollected"] = "True"
                    else:
                        result["isDiscretionaryAccessEventsCollected"] = "False"
                    logging.info(f"isDiscretionaryAccessEventsCollected result: "
                                 f"{result['isDiscretionaryAccessEventsCollected']}")
                except Exception as access_control_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isDiscretionaryAccessEventsCollected']: "
                                  f"{access_control_err}")

            def check_if_unsuccessful_unauthorized_file_access_attempts_are_collected():
                try:
                    output1 = extract_shell_info(r"grep access /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'access'")

                    match1 = '''\
                        -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
                        ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
                        -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
                        ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
                        -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
                        ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
                        -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
                        ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\
                    '''
                    match2 = '''\
                        -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat
                        EACCES -F auid>=1000 -F auid!=-1 -F key=access
                        -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat
                        EACCES -F auid>=1000 -F auid!=-1 -F key=access
                        -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat
                        EPERM -F auid>=1000 -F auid!=-1 -F key=access
                        -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat
                        EPERM -F auid>=1000 -F auid!=-1 -F key=access\
                    '''
                    if output1 == match1 and output2 == match2:
                        result["isUnsuccessfulUnauthorizedAccessCollected"] = "True"
                    else:
                        result["isUnsuccessfulUnauthorizedAccessCollected"] = "False"
                    logging.info(f"isUnsuccessfulUnauthorizedAccessCollected result: "
                                 f"{result['isUnsuccessfulUnauthorizedAccessCollected']}")
                except Exception as unauth_file_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isUnsuccessfulUnauthorizedAccessCollected']: "
                                  f"{unauth_file_err}")

            def check_if_collect_successful_file_system_actions_are_collected():
                try:
                    output1 = extract_shell_info(r"grep mounts /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'mounts'")

                    match1 = '''\
                    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
                    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts\
                    '''

                    match2 = '''\
                    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts
                    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts\
                    '''
                    if output1 == match1 and output2 == match2:
                        result["isSuccessfulFilesystemCollected"] = "True"
                    else:
                        result["isSuccessfulFilesystemCollected"] = "False"
                    logging.info(f"isSuccessfulFilesystemCollected result: "
                                 f"{result['isSuccessfulFilesystemCollected']}")
                except Exception as file_system_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isSuccessfulFilesystemCollected']: "
                                  f"{file_system_err}")

            def check_if_collect_changes_to_system_administration_scope_are_collected():
                try:
                    output1 = extract_shell_info(r"grep scope /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'scope'")

                    match1 = '''\
                    -w /etc/sudoers -p wa -k scope
                    -w /etc/sudoers.d/ -p wa -k scope\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["isChangeToSystemAdministrativeScopeCollected"] = "True"
                    else:
                        result["isChangeToSystemAdministrativeScopeCollected"] = "False"
                    logging.info(f"isChangeToSystemAdministrativeScopeCollected result: "
                                 f"{result['isChangeToSystemAdministrativeScopeCollected']}")
                except Exception as admin_scope_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isChangeToSystemAdministrativeScopeCollected']: "
                                  f"{admin_scope_err}")

            def check_if_collect_kernel_module_loading_and_unloading_are_collected():
                try:
                    output1 = extract_shell_info(r"grep modules /etc/audit/rules.d/*.rules")
                    output2 = extract_info(r"auditctl -l | grep 'modules'")

                    match1 = '''\
                    -w /sbin/insmod -p x -k modules
                    -w /sbin/rmmod -p x -k modules
                    -w /sbin/modprobe -p x -k modules
                    -a always,exit -F arch=b64 -S init_module -S delete_module -k modules\
                    '''
                    if output1 == match1 and output2 == match1:
                        result["isKernelModuleLoadingAndUnloadingCollected"] = "True"
                    else:
                        result["isKernelModuleLoadingAndUnloadingCollected"] = "False"
                    logging.info(f"isKernelModuleLoadingAndUnloadingCollected result: "
                                 f"{result['isKernelModuleLoadingAndUnloadingCollected']}")

                except Exception as load_unload_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"['isKernelModuleLoadingAndUnloadingCollected']: "
                                  f"{load_unload_err}")

            def check_if_audit_configuration_is_immutable():
                try:
                    output1 = extract_shell_info(r'grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1')

                    if output1 == "-e 2":
                        result["isAuditConfigurationImmutable"] = "True"
                    else:
                        result["isAuditConfigurationImmutable"] = "False"
                    logging.info(f"is_audit_configuration_immutable_result: {result['isAuditConfigurationImmutable']}")
                except Exception as immutable_err:
                    logging.error(f"error['cisInfo']['cis_logging_and_auditing']"
                                  f"["f"'check_if_audit_configuration_is_immutable']: {immutable_err}")

            def check_audit_logs_not_automatically_deleted():
                try:
                    output = extract_shell_info("grep max_log_file_action /etc/audit/auditd.conf")
                    if "max_log_file_action = keep_logs" in output:
                        result["isAuditLogsAreNotAutomaticallyDeleted"] = "True"
                    else:
                        result["isAuditLogsAreNotAutomaticallyDeleted"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_audit_logs_not_automatically_deleted']: {e}")

            def check_login_and_logout_events_collected():
                try:
                    output1 = extract_shell_info("grep logins /etc/audit/rules.d/*.rules")
                    output2 = extract_info("auditctl -l | grep logins")
                    if ("-w /var/log/faillog -p wa -k logins" in output1 and
                            "-w /var/log/lastlog -p wa -k logins" in output2):
                        result["isLoginAndLogoutEventsCollected"] = "True"
                    else:
                        result["isLoginAndLogoutEventsCollected"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_login_and_logout_events_collected']: {e}")

            def check_file_deletion_events_by_user_collected():
                try:
                    output1 = extract_shell_info("grep delete /etc/audit/rules.d/*.rules")
                    output2 = extract_info("auditctl -l | grep delete")

                    if ("-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F" in output1
                            and "auid>=1000 -F auid!=4294967295 -k delete" in output1 and
                            "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F"
                            in output1 and "auid>=1000 -F auid!=4294967295 -k delete" in output1 and
                            "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F"
                            in output2 and "auid>=1000 -F auid!=4294967295 -k delete" in output2 and
                            "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F"
                            in output2 and "auid>=1000 -F auid!=4294967295 -k delete" in output2):
                        result["isFileDeletionEventsByUserCollected"] = "True"
                    else:
                        result["isFileDeletionEventsByUserCollected"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_file_deletion_events_by_user_collected']: {e}")

            def check_any_attempts_to_run_chcon_recorded():
                try:
                    output = extract_shell_info(
                        r"grep -E '^-a\s+always,exit\s+-F\s+path=/usr/bin/chcon\s+-F\s+perm=x' /etc/audit/audit.rules")
                    if output:
                        result["isAnyAttemptsToRunChconRecorded"] = "True"
                    else:
                        result["isAnyAttemptsToRunChconRecorded"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_any_attempts_to_run_chcon_recorded']: {e}")

            def check_write_log_files_to_persistent_disk():
                try:
                    output = extract_shell_info(r"grep -e ^\s*Storage /etc/systemd/journald.conf")
                    if "Storage=persistent" in output:
                        result["isWriteLogFilesToPersistentDisk"] = "True"
                    else:
                        result["isWriteLogFilesToPersistentDisk"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_write_log_files_to_persistent_disk']: {e}")

            def check_disable_system_on_audit_log_full():
                try:
                    output = extract_shell_info(
                        r"grep -E '^\s*admin_space_left_action\s*=\s*halt' /etc/audit/auditd.conf")
                    if "halt" in output:
                        result["isDisableSystemOnAuditLogFull"] = "True"
                    else:
                        result["isDisableSystemOnAuditLogFull"] = "False"
                except Exception as e:
                    logging.error(f"error['cisInfo']['is_disable_system_on_audit_log_full']: {e}")

            def check_journald_configured_to_compress_large_log_files():
                try:
                    output = extract_shell_info(r"grep -e ^\s*Compress /etc/systemd/journald.conf")
                    if "Compress=yes" in output:
                        result["isJournaldConfiguredToCompressLargeLogFiles"] = "True"
                    else:
                        result["isJournaldConfiguredToCompressLargeLogFiles"] = "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_journald_configured_to_compress_large_log_files']: {e}")

            def check_use_of_privileged_commands_collected():
                try:
                    uid_min_command = "awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs"
                    uid_min_result = subprocess.run(uid_min_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)

                    if uid_min_result.returncode != 0:
                        result["isUseOfPrivilegedCommandsCollected"] = "False"
                        return

                    uid_min = uid_min_result.stdout.strip()

                    find_command = f"find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f"
                    find_result = subprocess.run(find_command, shell=True, stderr=subprocess.PIPE,
                                                 stdout=subprocess.PIPE, universal_newlines=True,
                                                 timeout=TIMEOUT_SUBPROCESS)

                    if find_result.returncode != 0:
                        result["isUseOfPrivilegedCommandsCollected"] = "False"
                        return

                    privileged_paths = find_result.stdout.splitlines()
                    audit_rules = []

                    for path in privileged_paths:
                        rule = (f"-a always,exit -F path={path} -F perm=x -F auid>={uid_min} "
                                f"-F auid!=4294967295 -k privileged")
                        audit_rules.append(rule)

                    # Check if all audit rules are present
                    for rule in audit_rules:
                        check_rule_command = f"grep -Fxq \"{rule}\" /etc/audit/rules.d/*.rules"
                        check_rule_result = subprocess.run(check_rule_command, shell=True, stderr=subprocess.PIPE,
                                                           stdout=subprocess.PIPE, universal_newlines=True,
                                                           timeout=TIMEOUT_SUBPROCESS)
                        if check_rule_result.returncode != 0:
                            result["isUseOfPrivilegedCommandsCollected"] = "False"
                            return

                    # Verify with auditctl
                    auditctl_command = "auditctl -l"
                    auditctl_result = subprocess.run(auditctl_command, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)

                    if auditctl_result.returncode != 0:
                        result["isUseOfPrivilegedCommandsCollected"] = "False"
                        return

                    auditctl_output = auditctl_result.stdout
                    for rule in audit_rules:
                        if rule not in auditctl_output:
                            result["isUseOfPrivilegedCommandsCollected"] = "False"
                            return

                    result["isUseOfPrivilegedCommandsCollected"] = "True"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_use_of_privileged_commands_collected']: {e}")

            check_if_audit_log_storage_size_configured()
            check_record_events_that_modify_date_and_time_are_collected()
            check_record_events_that_modify_user_or_group_are_collected()
            check_record_events_that_modify_network_are_collected()
            check_record_events_that_modify_the_systems_mandatory_access_controls_are_collected()
            check_if_session_information_is_collected()
            check_if_collect_discretionary_access_control_information_is_collected()
            check_if_unsuccessful_unauthorized_file_access_attempts_are_collected()
            check_if_collect_successful_file_system_actions_are_collected()
            check_if_collect_changes_to_system_administration_scope_are_collected()
            check_if_collect_kernel_module_loading_and_unloading_are_collected()
            check_if_audit_configuration_is_immutable()
            check_audit_logs_not_automatically_deleted()
            check_login_and_logout_events_collected()
            check_file_deletion_events_by_user_collected()
            check_any_attempts_to_run_chcon_recorded()
            check_write_log_files_to_persistent_disk()
            check_disable_system_on_audit_log_full()
            check_journald_configured_to_compress_large_log_files()
            check_use_of_privileged_commands_collected()

        except Exception as er:
            logging.error(f"error['cisInfo']['cis_logging_and_auditing']: {er}")

        return result

    # CIS Section 5.1
    @logger_function
    def cis_system_access_and_authentication():
        result = {
            "isCronDaemonEnabled": "Not Configured",
            "isPermissionsOnEtcCrontabSet": "Not Configured",
            "isPermissionsOnEtcCronHourlySet": "Not Configured",
            "isPermissionsOnEtcCronDailySet": "Not Configured",
            "isPermissionsOnEtcCronWeeklySet": "Not Configured",
            "isPermissionsOnEtcCronMonthlySet": "Not Configured",
            "isPermissionsOnEtcCronDSet": "Not Configured",
        }
        try:
            def check_if_cron_daemon_is_enabled():
                try:
                    output1 = extract_info(r"systemctl is-enabled crond")
                    output2 = extract_info(r"systemctl is-active crond")
                    if output1 == "enabled" and output2 == "active":
                        result["isCronDaemonEnabled"] = "True"
                    else:
                        result["isCronDaemonEnabled"] = "False"
                    logging.info(f"is_cron_daemon_enabled_result: {result['isCronDaemonEnabled']}")
                except Exception as cron_daemon_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_cron_daemon_is_enabled']: {cron_daemon_err}")

            def check_if_permissions_are_set_on_etc_crontab():
                try:
                    output = extract_shell_info(r"stat /etc/crontab | grep -E '^Access:'")
                    if "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCrontabSet"] = "True"
                    else:
                        result["isPermissionsOnEtcCrontabSet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_crontab_result: {result['isPermissionsOnEtcCrontabSet']}")
                except Exception as crontab_error:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_crontab']: {crontab_error}")

            def check_if_permissions_are_set_on_etc_cron_hourly():
                try:
                    output = extract_shell_info(r"stat /etc/cron.hourly | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronHourlySet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronHourlySet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_hourly_result: "
                                 f"{result['isPermissionsOnEtcCronHourlySet']}")
                except Exception as cron_hourly_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_hourly']: {cron_hourly_err}")

            def check_if_permissions_are_set_on_etc_cron_daily():
                try:
                    output = extract_shell_info(r"stat /etc/cron.daily | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronDailySet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronDailySet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_daily_result: "
                                 f"{result['isPermissionsOnEtcCronDailySet']}")
                except Exception as cron_daily_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_daily']: {cron_daily_err}")

            def check_if_permissions_are_set_on_etc_cron_weekly():
                try:
                    output = extract_shell_info(r"stat /etc/cron.weekly | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronWeeklySet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronWeeklySet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_weekly_result: "
                                 f"{result['isPermissionsOnEtcCronWeeklySet']}")
                except Exception as cron_weekly_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_weekly']: {cron_weekly_err}")

            def check_if_permissions_are_set_on_etc_cron_monthly():
                try:
                    output = extract_shell_info(r"stat /etc/cron.monthly | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronMonthlySet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronMonthlySet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_monthly_result: "
                                 f"{result['isPermissionsOnEtcCronMonthlySet']}")
                except Exception as cron_monthly_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_monthly']: {cron_monthly_err}")

            def check_if_permissions_are_set_on_etc_cron_d():
                try:
                    output = extract_shell_info(r"stat /etc/cron.d | grep -E '^Access:'")
                    if "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                        result["isPermissionsOnEtcCronDSet"] = "True"
                    else:
                        result["isPermissionsOnEtcCronDSet"] = "False"
                    logging.info(f"is_permissions_set_on_etc_cron_d_result: {result['isPermissionsOnEtcCronDSet']}")
                except Exception as permission_on_ceond_err:
                    logging.error(f"error['cisInfo']['cis_system_access_and_authentication']"
                                  f"['check_if_permissions_are_set_on_etc_cron_d']: {permission_on_ceond_err}")

            check_if_cron_daemon_is_enabled()
            check_if_permissions_are_set_on_etc_crontab()
            check_if_permissions_are_set_on_etc_cron_hourly()
            check_if_permissions_are_set_on_etc_cron_daily()
            check_if_permissions_are_set_on_etc_cron_weekly()
            check_if_permissions_are_set_on_etc_cron_monthly()
            check_if_permissions_are_set_on_etc_cron_d()

        except Exception as er:
            logging.error(f"error['cisInfo']['cis_system_access_and_authentication']: {er}")

        return result

    # CIS Section 5.2
    @logger_function
    def cis_configure_ssh_server():
        result = {
            "arePermissionsOnEtcSshdSshdConfigRestrictive": "Not Configured",
            "isSSHPamEnabled": "Not Configured",
            "isSSHRootLoginDisabled": "Not Configured",
            "isSSHHostBasedAuthenticationDisabled": "Not Configured",
            "isSSHPermitEmptyPasswordsDisabled": "Not Configured",
            "isSSHPermitUserEnvironmentDisabled": "Not Configured",
            "isSSHIgnoreRhostsEnabled": "Not Configured",
            "isSSHX11ForwardingDisabled": "Not Configured",
            "isSSHAllowTcpForwardingDisabled": "Not Configured",
            "isSSHMaxAuthTriesSetTo4OrLess": "Not Configured",
            "isSSHMaxSessionSetTo10OrLess": "Not Configured",
            "isSSHLoginGraceTimeSetTo60SecondsOrLess": "Not Configured",
            "isOnlyStrongCiphersAreUsed": "Not Configured",
            "isSSHProtocolSetTo2": "Not Configured",
            "isLogLevelSetToInfo": "Not Configured",
            "isIdleTimeoutIntervalForUserLoginSet": "Not Configured",
            "isStrictModesAreEnabled": "Not Configured",
            "isSSHMaxStartupsConfigured": "Not Configured",
            "isCustomProfileCreated": "Not Configured",
            "isAuthSelectProfileConfigured": "Not Configured",
            "isLoginWithEmptyPasswordPrevented": "Not Configured",
            "isAtCronRestrictedToAuthorizedUsers": "Not Configured",
            "isSSHBannerConfigured": "Not Configured",
            "isSSHCryptoAlgorithmsRestrictedToFIPS": "Not Configured",
            "isSSHKeyExchangeAlgorithmsRestrictedToFIPS": "Not Configured",
        }
        try:
            def check_permissions_are_root_and_restrictive(base_command, permission_limit):
                logging.info("started function: check_permissions_are_root_and_restrictive()")
                try:
                    logging.info(f"base_command: {base_command}")
                    logging.info(f"permission_limit: {permission_limit}")

                    stat_command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                         stdout=subprocess.PIPE,
                                                         universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"stat_command_result: {stat_command_result}")
                    stat_result = stat_command_result.stdout.strip().split()
                    # Check if Uid and Gid are both 0/root and Access is more restrictive
                    if stat_result[2] == '0/root' and stat_result[3] == '0/root' and int(
                            stat_result[1]) <= permission_limit:
                        logging.info(
                            f"All permissions on /etc/ssh/sshd_config are set to {permission_limit} "
                            f"or more restrictive")
                        return "True"
                    else:
                        logging.info(
                            f"Not all permissions on /etc/ssh/sshd_config are set to "
                            f"{permission_limit} or more restrictive")
                        return "False"

                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_permissions_are_root_and_restrictive"] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_ssh_server']"
                        f"['check_permissions_are_root_and_restrictive']: {er}")
                    return "Not Configured"

            def check_ssh_pam():
                try:
                    logging.info("started function: check_ssh_pam()")
                    base_command = (r"""sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) """
                                    r"""/etc/hosts | awk '{ print $1}')" | grep -i usepam""")

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if "usepam yes" in command_result.stdout.strip():
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_pam"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_configure_ssh_server']['check_ssh_pam']: {er}")
                    return "Not Configured"

            def check_ssh_root_login_disabled():
                try:
                    logging.info("started function: check_ssh_root_login_disabled()")
                    base_command = (r"""sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) """
                                    r"""/etc/hosts | awk '{ print $1}')" | grep permitrootlogin""")

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r"""grep -Ei '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config"""

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and command_result.stdout.strip().split()[-1] == "no" and
                            command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"

                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_root_login_disabled"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_ssh_server']['check_ssh_root_login_disabled']: {er}")
                    return "Not Configured"

            def check_ssh_host_based_authentication_disabled():
                try:
                    logging.info("started function: check_ssh_host_based_authentication_disabled")
                    base_command = (r"""sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) """
                                    r"""/etc/hosts | awk '{print $1}')" | grep hostbasedauthentication""")

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r"""grep -Ei '^\s*HostbasedAuthentication\s+yes' /etc/ssh/sshd_config"""

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and command_result.stdout.strip().split()[-1] == "no" and
                            command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"

                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_host_based_authentication_disabled"] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_ssh_server']"
                        f"['check_ssh_host_based_authentication_disabled']: "
                        f"{er}")
                    return "Not Configured"

            def check_ssh_permit_empty_passwords_disabled():
                try:
                    logging.info("started function: check_ssh_permit_empty_passwords_disabled()")
                    base_command = (r'''sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) '''
                                    r'''/etc/hosts | awk '{ print $1}')" | grep permitemptypasswords''')

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r'''grep -Ei '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config'''

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and "permitemptypasswords no" in command_result.stdout.strip()
                            and command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_permit_empty_passwords_disabled"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_ssh_server']"
                        f"['check_ssh_permit_empty_passwords_disabled']: {er}")
                    return "Not Configured"

            def check_ssh_permit_user_environment_disabled():
                try:
                    logging.info("started function: check_ssh_permit_user_environment_disabled()")
                    base_command = (r'''sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) '''
                                    r'''/etc/hosts | awk '{print $1}')" | grep permituserenvironment''')

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r'''grep -Ei '^\s*PermitUserEnvironment\s+yes' /etc/ssh/sshd_config'''

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and "permituserenvironment no" in command_result.stdout.strip()
                            and command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_permit_user_environment_disabled"] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_ssh_server']"
                        f"['check_ssh_permit_user_environment_disabled']: {er}")
                    return "Not Configured"

            def check_ssh_ignore_rhosts_enabled():
                try:
                    logging.info("started function: check_ssh_ignore_rhosts_enabled")
                    base_command = (r'''sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) '''
                                    r'''/etc/hosts | awk '{print $1}')" | grep ignorerhosts''')

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r'''grep -Ei '^\s*ignorerhosts\s+no\b' /etc/ssh/sshd_config'''

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and "ignorerhosts yes" in command_result.stdout.strip() and
                            command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_ignore_rhosts_enabled"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_ssh_server']['check_ssh_ignore_rhosts_enabled']: {er}")
                    return "Not Configured"

            def check_ssh_x11_forwarding_disabled():
                logging.info("started function: check_ssh_x11_forwarding_disabled()")
                try:
                    base_command = (r'''sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) '''
                                    r'''/etc/hosts | awk '{print $1}')" | grep -i x11forwarding''')

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r'''grep -Ei '^\s*x11forwarding\s+yes' /etc/ssh/sshd_config'''

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and "x11forwarding no" in command_result.stdout.strip() and
                            command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_x11_forwarding_disabled"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_ssh_server']['check_ssh_x11_forwarding_disabled']: {er}")
                    return "Not Configured"

            def check_ssh_allow_tcp_forwarding_disabled():
                logging.info("started function: check_ssh_allow_tcp_forwarding_disabled()")
                try:
                    base_command = (r'''sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) '''
                                    r'''/etc/hosts | awk '{print $1}')" | grep -i allowtcpforwarding''')

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r'''grep -Ei '^\s*AllowTcpForwarding\s+yes' /etc/ssh/sshd_config'''

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and "allowtcpforwarding no" in command_result.stdout.strip() and
                            command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_allow_tcp_forwarding_disabled"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_ssh_server']"
                        f"['check_ssh_allow_tcp_forwarding_disabled']: {er}")
                    return "Not Configured"

            def check_ssh_max_auth_tries():
                logging.info("started function: check_ssh_max_auth_tries()")
                try:
                    base_command = (r'''sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) '''
                                    r'''/etc/hosts | awk '{print $1}')" | grep maxauthtries''')

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r'''grep -Ei '^\s*maxauthtries\s+([5-9]|[1-9][0-9]+)' /etc/ssh/sshd_config'''

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and command_result.stdout.strip().split()[-1] <= '4' and
                            command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_max_auth_tries"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_configure_ssh_server']['check_ssh_max_auth_tries']: {er}")
                    return "Not Configured"

            def check_ssh_max_sessions():
                logging.info("started function: check_ssh_max_sessions()")
                try:
                    base_command = (r'''sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) '''
                                    r'''/etc/hosts | awk '{print $1}')" | grep -i maxsessions''')

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r'''grep -Ei '^\s*maxauthtries\s+([5-9]|[1-9][0-9]+)' /etc/ssh/sshd_config'''

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and command_result.stdout.strip().split()[-1] <= '10' and
                            command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_max_sessions"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_configure_ssh_server']['check_ssh_max_sessions']: {er}")
                    return "Not Configured"

            def check_ssh_login_grace_time():
                logging.info("started function: check_ssh_login_grace_time()")
                try:
                    base_command = (r'''sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) '''
                                    r'''/etc/hosts | awk '{print $1}')" | grep logingracetime''')

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    base_command2 = r'''grep -Ei '^\s*maxauthtries\s+([5-9]|[1-9][0-9]+)' /etc/ssh/sshd_config'''

                    logging.info(f"Running command: {base_command2}")
                    command_result2 = subprocess.run(base_command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")

                    if (command_result.returncode == 0 and command_result.stdout.strip().split()[-1] <= '60' and
                            command_result2.returncode == 1):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_ssh_server']["check_ssh_login_grace_time"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_configure_ssh_server']['check_ssh_login_grace_time']: {er}")
                    return "Not Configured"

            def check_if_only_strong_ciphers_are_used():
                logging.info("started function: check_if_only_strong_ciphers_are_used()")
                try:
                    base_command = '''sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) \
                    /etc/hosts | awk '{print $1}')" | grep ciphers'''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    weak_cipher_list = \
                        ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "arcfour128", "arcfour256",
                         "blowfish-cbc", "cast128-cbc", "rijndael-cbc@lysator.liu.se"]

                    cmd_result_list = command_result.stdout.strip().split(",")
                    for cipher in weak_cipher_list:
                        if cipher in cmd_result_list:
                            return "False"
                        else:
                            continue

                    return "True"

                except Exception as er:
                    logging.error(
                        f"error['cisInfo']['cis_configure_ssh_server']['check_if_only_strong_ciphers_are_used']: {er}")
                    return "Not Configured"

            def is_ssh_protocol_set_to_2():
                try:
                    check_protocol_command = "grep '^Protocol' /etc/ssh/sshd_config"
                    check_protocol_result = subprocess.run(check_protocol_command, shell=True, stderr=subprocess.PIPE,
                                                           stdout=subprocess.PIPE, universal_newlines=True,
                                                           timeout=TIMEOUT_SUBPROCESS)

                    if 'Protocol 2' in check_protocol_result.stdout:
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_ssh_protocol_set_to_2']: {e}")
                    return "Not Configured"

            def is_log_level_set_to_info():
                try:
                    check_log_level_command = "sshd -T | grep loglevel"
                    check_log_level_result = subprocess.run(check_log_level_command, shell=True, stderr=subprocess.PIPE,
                                                            stdout=subprocess.PIPE, universal_newlines=True,
                                                            timeout=TIMEOUT_SUBPROCESS)

                    if 'LogLevel INFO' in check_log_level_result.stdout.upper():
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_log_level_set_to_info']: {e}")
                    return "Not Configured"

            def is_idle_timeout_interval_for_user_login_set():
                try:
                    check_timeout_command = "grep -E '^ClientAliveInterval' /etc/ssh/sshd_config"
                    check_timeout_result = subprocess.run(check_timeout_command, shell=True, stderr=subprocess.PIPE,
                                                          stdout=subprocess.PIPE, universal_newlines=True,
                                                          timeout=TIMEOUT_SUBPROCESS)

                    if 'ClientAliveInterval' in check_timeout_result.stdout and int(
                            check_timeout_result.stdout.split()[1]) <= 300:
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_idle_timeout_interval_for_user_login_set']: {e}")
                    return "Not Configured"

            def is_strict_modes_are_enabled():
                try:
                    check_strict_modes_command = "grep -i '^StrictModes' /etc/ssh/sshd_config"
                    check_strict_modes_result = subprocess.run(check_strict_modes_command, shell=True,
                                                               stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                               universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

                    if 'StrictModes yes' in check_strict_modes_result.stdout.lower():
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_strict_modes_are_enabled']: {e}")
                    return "Not Configured"

            def is_ssh_max_startups_configured():
                try:
                    check_max_startups_command = "grep -i '^MaxStartups' /etc/ssh/sshd_config"
                    check_max_startups_result = subprocess.run(check_max_startups_command, shell=True,
                                                               stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                               universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

                    if 'MaxStartups' in check_max_startups_result.stdout:
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_ssh_max_startups_configured']: {e}")
                    return "Not Configured"

            def is_custom_profile_created():
                try:
                    check_profile_command = "grep -E '^Profile' /etc/security/custom_profile"
                    check_profile_result = subprocess.run(check_profile_command, shell=True, stderr=subprocess.PIPE,
                                                          stdout=subprocess.PIPE, universal_newlines=True,
                                                          timeout=TIMEOUT_SUBPROCESS)

                    if check_profile_result.stdout:
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_custom_profile_created']: {e}")
                    return "Not Configured"

            def is_auth_select_profile_configured():
                try:
                    check_auth_profile_command = "authselect current"
                    check_auth_profile_result = subprocess.run(check_auth_profile_command, shell=True,
                                                               stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                               universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

                    if 'Profile ID' in check_auth_profile_result.stdout:
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_auth_select_profile_configured']: {e}")
                    return "Not Configured"

            def is_login_with_empty_password_prevented():
                try:
                    check_empty_password_command = "grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config"
                    check_empty_password_result = subprocess.run(check_empty_password_command, shell=True,
                                                                 stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                                 universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

                    if 'PermitEmptyPasswords no' in check_empty_password_result.stdout.lower():
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_login_with_empty_password_prevented']: {e}")
                    return "Not Configured"

            def is_at_cron_restricted_to_authorized_users():
                try:
                    check_at_cron_command = "ls -l /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny"
                    check_at_cron_result = subprocess.run(check_at_cron_command, shell=True, stderr=subprocess.PIPE,
                                                          stdout=subprocess.PIPE, universal_newlines=True,
                                                          timeout=TIMEOUT_SUBPROCESS)

                    if ('/etc/cron.allow' in check_at_cron_result.stdout or '/etc/at.allow' in
                            check_at_cron_result.stdout):
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_at_cron_restricted_to_authorized_users']: {e}")
                    return "Not Configured"

            def is_ssh_banner_configured():
                try:
                    check_ssh_banner = (r"""sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
                                        /etc/hosts | awk '{print $1}')" | grep banner""")
                    check_ssh_banner_result = subprocess.run(check_ssh_banner, shell=True,
                                                             stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                                             universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)

                    if 'banner /etc/issue.net' in check_ssh_banner_result.stdout.lower():
                        return "True"
                    else:
                        return "False"

                except Exception as e:
                    logging.error(f"error['cisInfo']['is_ssh_banner_configured']: {e}")
                    return "Not Configured"

            def is_ssh_crypto_algorithms_restricted_to_fips():
                try:
                    output = extract_shell_info(
                        r'''grep -E "Ciphers" /etc/ssh/sshd_config | grep -E "aes256-ctr|aes192-ctr|aes128-ctr"'''
                    )

                    if output:
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    logging.error(f"error['cisInfo']['isSSHCryptoAlgorithmsRestrictedToFIPS']: {er}")
                    return "Not Configured"

            def is_ssh_key_exchange_algorithms_restricted_to_fips():
                try:
                    # Check for FIPS-approved key exchange algorithms in SSH configuration
                    output = extract_shell_info(
                        r'''grep -E "KexAlgorithms" /etc/ssh/sshd_config | grep -E "diffie-hellman-group14-sha256|ecdh-sha2-nistp256|ecdh-sha2-nistp384|ecdh-sha2-nistp521"'''
                    )

                    if output:
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    logging.error(f"error['cisInfo']['isSSHKeyExchangeAlgorithmsRestrictedToFIPS']: {er}")
                    return "Not Configured"

            result["arePermissionsOnEtcSshdSshdConfigRestrictive"] = (
                check_permissions_are_root_and_restrictive(r"stat -Lc '%n %a %u/%U %g/%G' /etc/ssh/sshd_config", 600))
            result["isSSHPamEnabled"] = check_ssh_pam()
            result["isSSHRootLoginDisabled"] = check_ssh_root_login_disabled()
            result["isSSHHostBasedAuthenticationDisabled"] = check_ssh_host_based_authentication_disabled()
            result["isSSHPermitEmptyPasswordsDisabled"] = check_ssh_permit_empty_passwords_disabled()
            result["isSSHPermitUserEnvironmentDisabled"] = check_ssh_permit_user_environment_disabled()
            result["isSSHIgnoreRhostsEnabled"] = check_ssh_ignore_rhosts_enabled()
            result["isSSHX11ForwardingDisabled"] = check_ssh_x11_forwarding_disabled()
            result["isSSHAllowTcpForwardingDisabled"] = check_ssh_allow_tcp_forwarding_disabled()
            result["isSSHMaxAuthTriesSetTo4OrLess"] = check_ssh_max_auth_tries()
            result["isSSHMaxSessionSetTo10OrLess"] = check_ssh_max_sessions()
            result['isSSHLoginGraceTimeSetTo60SecondsOrLess'] = check_ssh_login_grace_time()
            result['isOnlyStrongCiphersAreUsed'] = check_if_only_strong_ciphers_are_used()
            result["isSSHProtocolSetTo2"] = is_ssh_protocol_set_to_2()
            result["isLogLevelSetToInfo"] = is_log_level_set_to_info()
            result["isIdleTimeoutIntervalForUserLoginSet"] = is_idle_timeout_interval_for_user_login_set()
            result["isStrictModesAreEnabled"] = is_strict_modes_are_enabled()
            result["isSSHMaxStartupsConfigured"] = is_ssh_max_startups_configured()
            result["isCustomProfileCreated"] = is_custom_profile_created()
            result["isAuthSelectProfileConfigured"] = is_auth_select_profile_configured()
            result["isLoginWithEmptyPasswordPrevented"] = is_login_with_empty_password_prevented()
            result["isAtCronRestrictedToAuthorizedUsers"] = is_at_cron_restricted_to_authorized_users()
            result["isSSHBannerConfigured"] = is_ssh_banner_configured()
            result["isSSHCryptoAlgorithmsRestrictedToFIPS"] = is_ssh_crypto_algorithms_restricted_to_fips()
            result["isSSHKeyExchangeAlgorithmsRestrictedToFIPS"] = is_ssh_key_exchange_algorithms_restricted_to_fips()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_ssh_server']: {err}")
        return result

    # CIS Section 5.3
    @logger_function
    def cis_configure_privilege_escalation():
        """
        Generates the configuration for privilege escalation.

        Returns:
            dict: A dictionary containing the configuration for privilege escalation. The keys
            of the dictionary are the different aspects of privilege escalation, and the values
            are the corresponding configuration status. The possible configuration status values
            are "True", "False", and "Not Configured".

            - "is_sudo_installed": Indicates whether the "sudo" package is installed. - "do_sudo_commands_use_pty":
            Indicates whether sudo commands use pseudo-terminals (pty). - "does_sudo_log_file_exist": Indicates
            whether the sudo log file exists. - "do_users_provide_password_for_privilege_escalation": Indicates
            whether users provide a password for privilege escalation. -
            "is_reauthentication_for_privilege_escalation_not_disabled_globally": Indicates whether reauthentication
            for privilege escalation is disabled globally. - "is_sudo_authentication_timeout_configured": Indicates
            whether the sudo authentication timeout is configured. - "is_access_to_su_command_restricted": Indicates
            whether access to the "su" command is restricted.
        """

        result = {
            "isSudoInstalled": "Not Configured",
            "doSudoCommandsUsePty": "Not Configured",
            "doesSudoLogFileExist": "Not Configured",
            "doUsersProvidePasswordForPrivilegeEscalation": "Not Configured",
            "isReauthenticationForPrivilegeEscalationNotDisabledGlobally": "Not Configured",
            "isSudoAuthenticationTimeoutConfigured": "Not Configured",
            "isAccessToSuCommandRestricted": "Not Configured",
        }
        try:
            def check_sudo_installed():
                logging.info("started function: check_sudo_installed()")
                try:
                    base_command = r'''dnf list sudo | awk "/Installed Packages/{flag=1; next} flag"'''

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if "sudo." in command_result.stdout:
                        return "True"
                    else:
                        return "False"

                except Exception as er:
                    error["cisInfo"]['cis_configure_privilege_escalation']["check_sudo_installed"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_privilege_escalation']['check_sudo_installed']: {er}")
                    return "Not Configured"

            def check_sudo_command_use_pty():
                logging.info("started function: check_sudo_command_use_pty()")
                try:
                    base_command = \
                        r"sudo grep -rPi '^\h*Defaults\h+([^#\n\r]+,)?use_pty(,\h*\h+\h*)*\h*(#.*)?$' /etc/sudoers*"

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    expected_output = "/etc/sudoers:Defaults    use_pty"
                    logging.info(f"command_result.stdout.strip(): {command_result.stdout.strip()}")

                    if expected_output in command_result.stdout.strip():
                        return "True"
                    else:
                        return "False"

                except Exception as er:
                    error["cisInfo"]['cis_configure_privilege_escalation']["check_sudo_command_use_pty"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_privilege_escalation']['check_sudo_command_use_pty']: {er}")
                    return "Not Configured"

            def check_sudo_log_file_exists():
                logging.info("started function: check_sudo_log_file_exists()")
                try:
                    pattern = (
                        r"^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?"
                        r"(,\h*\H+\h*)*\h*(#.*)?$"
                    )

                    # Collect sudoers files (main file + includes)
                    sudoers_files = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")

                    if not sudoers_files:
                        logging.warning("No sudoers files found to check.")
                        return "Not Configured"

                    # Build grep command (no shell=True!)
                    command = ["grep", "-Psi", pattern] + sudoers_files

                    logging.info(f"Running command: {' '.join(command)}")

                    command_result = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=TIMEOUT_SUBPROCESS
                    )

                    logging.info(f"Command stdout: {command_result.stdout.strip()}")
                    logging.debug(f"Command stderr: {command_result.stderr.strip()}")

                    expected_output = "Defaults    logfile=/var/log/sudo.log"
                    if expected_output in command_result.stdout.strip():
                        return "True"
                    else:
                        return "False"

                except Exception as er:
                    error["cisInfo"]['cis_configure_privilege_escalation']["check_sudo_log_file_exists"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_privilege_escalation']['check_sudo_log_file_exists']: {er}"
                    )
                    return "Not Configured"

            def check_users_provide_pwd_for_privilege_escalation():
                logging.info("started function: check_users_provide_pwd_for_privilege_escalation()")
                try:
                    base_command = 'grep -r "^[^#].*NOPASSWD" /etc/sudoers*'

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 1:
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_privilege_escalation'][
                        "check_users_provide_pwd_for_privilege_escalation"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_privilege_escalation']"
                        f"['check_users_provide_pwd_for_privilege_escalation']: {er}")
                    return "Not Configured"

            def check_reauthentication_disabled():

                logging.info("started function: check_reauthentication_disabled()")
                try:
                    base_command = r'grep -r "^[^#].*\!authenticate" /etc/sudoers*'

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 1:
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_privilege_escalation']["check_reauthentication_disabled"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_privilege_escalation']"
                        f"['check_reauthentication_disabled']: {er}")
                    return "Not Configured"

            def check_sudo_authentication_timeout():

                logging.info("started function: check_sudo_authentication_timeout()")
                try:
                    base_command = r'grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers*'

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 1:
                        return "False"
                    else:
                        return "True"
                except Exception as er:
                    error["cisInfo"]['cis_configure_privilege_escalation']["check_sudo_authentication_timeout"] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_privilege_escalation']['check_sudo_authentication_timeout']: "
                        f"{er}")
                    return "Not Configured"

            def check_access_to_su_command_restricted():

                logging.info("started function: check_access_to_su_command_restricted()")
                try:
                    base_command = (r"""grep -Pi"""
                                    r"""'^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)"""
                                    r"""(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$'
                                    /etc/pam.d/su""")

                    logging.info(f"Running command: {base_command}")
                    command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE,
                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")

                    if command_result.returncode == 1:
                        return "False"
                    else:
                        return "True"
                except Exception as er:
                    error["cisInfo"]['cis_configure_privilege_escalation'][
                        "check_access_to_su_command_restricted"] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_privilege_escalation']"
                        f"['check_access_to_su_command_restricted']: "
                        f"{er}")
                    return "Not Configured"

            result["isSudoInstalled"] = check_sudo_installed()
            result["doSudoCommandsUsePty"] = check_sudo_command_use_pty()
            result["doesSudoLogFileExist"] = check_sudo_log_file_exists()
            result["doUsersProvidePasswordForPrivilegeEscalation"] = (
                check_users_provide_pwd_for_privilege_escalation())
            result["isReauthenticationForPrivilegeEscalationNotDisabledGlobally"] = check_reauthentication_disabled()
            result["isSudoAuthenticationTimeoutConfigured"] = check_sudo_authentication_timeout()
            result["isAccessToSuCommandRestricted"] = check_access_to_su_command_restricted()
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_privilege_escalation']: {err}")
        return result

    # CIS Section 5.5
    @logger_function
    def cis_configure_pam():
        result = {
            "arePamCreationRequirementsConfigured": "Not Configured",
            "isLockoutForFailedPasswordsConfigured": "Not Configured",
            "isPasswordReuseLimited": "Not Configured",
            "isPasswordHashingAlgorithmLatest": "Not Configured",
        }
        try:
            def check_pam_creation_requirements_configured():
                logging.info("started function: check_pam_creation_requirements_configured()")
                try:
                    command1 = (r'grep pam_pwquality.so /etc/pam.d/system-auth /etc/pam.d/password-auth | grep '
                                r"'retry'")
                    logging.info(f"Running command: {command1}")
                    command1_result = subprocess.run(command1, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command1_result}")
                    command2 = r"""grep ^ minlen / etc / security / pwquality.conf"""
                    logging.info(f"Running command: {command1}")
                    command2_result = subprocess.run(command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command2_result}")
                    command3 = r"""grep ^minclass /etc/security/pwquality.conf"""
                    logging.info(f"Running command: {command1}")
                    command3_result = subprocess.run(command3, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command3_result}")
                    if (command1_result.returncode == 0 and command2_result.returncode == 0 and
                            command3_result.returncode == 0):
                        return "True"
                    else:
                        return "False"

                except Exception as er:
                    error["cisInfo"]['cis_configure_pam']["check_pam_creation_requirements_configured"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_configure_pam']['check_pam_creation_requirements_configured']: {er}")
                    return "Not Configured"

            def check_lockout_for_failed_passwords():
                logging.info("started function: check_lockout_for_failed_passwords()")
                try:
                    command = r"""grep -E 'deny = ' /etc/security/faillock.conf"""
                    logging.info(f"Running command: {command}")
                    command_result = subprocess.run(command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result}")
                    result_tmp = command_result.stdout.strip().split()[-1]

                    command2 = r"""grep -E 'unlock_time' /etc/security/faillock.conf"""
                    logging.info(f"Running command: {command2}")
                    command_result2 = subprocess.run(command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command_result2}")
                    result_tmp2 = command_result2.stdout.strip().split()[-1]

                    if "1" <= result_tmp <= "5" and (result_tmp2 == "0" or result_tmp2 >= "900"):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_pam']["check_lockout_for_failed_passwords"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_configure_pam']['check_lockout_for_failed_passwords']: {er}")
                    return "Not Configured"

            def check_password_reuse_limited():
                logging.info("started function: check_password_reuse_limited()")
                try:
                    command = (
                        r"""sudo grep -P '^\h*password\h+(requisite|sufficient)\h+(pam_pwhistory\.so|pam_unix\.so)"""
                        r"""\h+([^#\n\r]+\h+)?remember=([5-9]|[1-9][0-9]+)\h*(\h+.*)?$' /etc/pam.d/system-auth""")
                    logging.info(f"Running command: {command}")
                    command_result = subprocess.run(command, shell=True, stderr=subprocess.PIPE,
                                                    stdout=subprocess.PIPE, universal_newlines=True,
                                                    timeout=TIMEOUT_SUBPROCESS)
                    if command_result.returncode != 0:
                        return "False"
                    command_result = subprocess.check_output(command, shell=True, universal_newlines=True,
                                                             timeout=TIMEOUT_SUBPROCESS, stderr=subprocess.PIPE)
                    logging.info(f"Command output: {command_result}")
                    pattern = r'remember=(\d+)'
                    matches = re.findall(pattern, command_result)
                    if all(int(rem) >= 5 for rem in matches):
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    error["cisInfo"]['cis_configure_pam']["check_password_reuse_limited"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_configure_pam']['check_password_reuse_limited']: {er}")
                    return "Not Configured"

            def check_password_hashing_algorithm():
                logging.info("started function: check_password_hashing_algorithm()")
                try:
                    command1 = r"""grep -Ei '^\s*crypt_style\s*=\s*(sha512|yescrypt)\b' /etc/libuser.conf"""
                    logging.info(f"Running command: {command1}")
                    command1_result = subprocess.run(command1, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command1_result}")
                    command2 = r"""grep -Ei '^\s*ENCRYPT_METHOD\s+(SHA512|yescrypt)\b' /etc/login.defs"""
                    logging.info(f"Running command: {command1}")
                    command2_result = subprocess.run(command2, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command2_result}")
                    command3 = (
                        r"""grep -P '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so(\h+[^#\n\r]+)"""
                        r"""?\h+(sha512|yescrypt)\b.*$' /etc/pam.d/password-auth /etc/pam.d/system-auth""")
                    logging.info(f"Running command: {command1}")
                    command3_result = subprocess.run(command3, shell=True, stderr=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, universal_newlines=True,
                                                     timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"Command output: {command3_result}")

                    if ("sha512" in command1_result.stdout.strip().split()[-1] and "SHA512" in
                            command2_result.stdout.strip().split()[
                                -1] and "pam_unix.so" in command3_result.stdout.strip()):
                        return "True"
                    else:
                        return "False"

                except Exception as er:
                    error["cisInfo"]['cis_configure_pam']["check_password_hashing_algorithm"] = repr(er)
                    logging.error(f"error['cisInfo']['cis_configure_pam']['check_password_hashing_algorithm']: {er}")
                    return "Not Configured"

            result["arePamCreationRequirementsConfigured"] = check_pam_creation_requirements_configured()
            result["isLockoutForFailedPasswordsConfigured"] = check_lockout_for_failed_passwords()
            result["isPasswordReuseLimited"] = check_password_reuse_limited()
            result["isPasswordHashingAlgorithmLatest"] = check_password_hashing_algorithm()
        except Exception as err:
            logging.error(f"error['cisInfo']['cis_configure_pam']: {err}")
        return result

    # CIS Section 5.6
    @logger_function
    def cis_user_accounts_environment_details():
        logging.info("Starting function user_accounts_environment_details")
        result = {
            "isPassMinDaysGreaterThan0Days": "Not Configured",
            "isPassMaxDaysLessThan366Days": "Not Configured",
            "isPassWarnAgeGreaterThan6Days": "Not Configured",
            "isInactiveAccountsWithPasswordExpiredLessThan30Days": "Not Configured",
            "didAllUsersChangedPasswordsInPast": "Not Configured",
            "areSystemAccountsSecured": "Not Configured",
            "isDefaultGroupForRootAccountGid0": "Not Configured",
            "isRootPasswordSet": "Not Configured",
            "isStickyBitSetOnAllWorldWritableDirectories": "Not Configured",
            "isMinDaysBetweenPassChangesGreaterThan6": "Not Configured",
            "isDefaultUserUmask027OrMoreRestrictive": "Not Configured",
            "isDefaultUserShellTimeout900SecondsOrLess": "Not Configured",
        }
        try:
            def retrieve_command_output(command_input):
                logging.info(f"started function: retrieve_command_output({command_input})")
                try:
                    base_command = fr"grep {command_input} /etc/login.defs"
                    logging.info(f"base_command: {base_command}")

                    base_command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                         stdout=subprocess.PIPE, universal_newlines=True,
                                                         timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {base_command_result}")

                    if base_command_result.returncode == 0:
                        command_output = base_command_result.stdout.strip().split()[-1]
                        logging.info(f"command_output: {command_output}")
                    else:
                        command_output = "-999"
                        logging.info(f"command_output: {command_output}")

                    logging.info(f"type(command_output): {type(command_output)}")
                    return command_output
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details']['retrieve_command_output'] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']['retrieve_command_output']: {er}")
                    return "Not Configured"

            def check_pass_max_days_less_than_366():
                try:
                    pass_max_days = int(retrieve_command_output("PASS_MAX_DAYS"))
                    logging.info(f"pass_max_days: {pass_max_days} and type(pass_max_days): {type(pass_max_days)}")

                    if pass_max_days != -999:
                        if pass_max_days < 366:
                            return "True"
                        else:
                            return "False"
                    else:
                        return "Not Configured"
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details'][
                        'check_pass_max_days_less_than_366'] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']"
                        f"['check_pass_max_days_less_than_366']: "
                        f"{er}")
                    return "Not Configured"

            def check_pass_min_days_greater_than_0():
                try:
                    pass_min_days = int(retrieve_command_output("PASS_MIN_DAYS"))
                    logging.info(f"pass_min_days: {pass_min_days} and type(pass_min_days): {type(pass_min_days)}")

                    if pass_min_days != -999:
                        if pass_min_days > 0:
                            return "True"
                        else:
                            return "False"
                    else:
                        return "Not Configured"
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details'][
                        'check_pass_min_days_greater_than_0'] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']"
                        f"['check_pass_min_days_greater_than_0']: "
                        f"{er}")
                    return "Not Configured"

            def check_pass_warn_age_greater_than_6():
                try:
                    pass_warn_age = int(retrieve_command_output("PASS_WARN_AGE"))
                    logging.info(f"pass_warn_age: {pass_warn_age} and type(pass_warn_age): {type(pass_warn_age)}")

                    if pass_warn_age != -999:
                        if pass_warn_age > 6:
                            return "True"
                        else:
                            return "False"
                    else:
                        return "Not Configured"
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details'][
                        'check_pass_warn_age_greater_than_6'] = repr(
                        er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']"
                        f"['check_pass_warn_age_greater_than_6']: "
                        f"{er}")
                    return "Not Configured"

            def check_inactive_accounts_with_password_expired_less_than_30():
                logging.info("started function: check_inactive_accounts_with_password_expired_less_than_30()")
                try:
                    base_command = r"useradd -D | grep INACTIVE | awk -F= '{print $2}'"
                    logging.info(f"base_command: {base_command}")

                    subprocess_base_command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                                    stdout=subprocess.PIPE,
                                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {subprocess_base_command_result}")

                    if subprocess_base_command_result.returncode == 0:
                        command_output = subprocess_base_command_result.stdout.strip()
                        if int(command_output) < 31:
                            command_result = "True"
                        else:
                            command_result = "False"
                    else:
                        command_result = "Not Configured"
                    return command_result
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details'][
                        'check_inactive_accounts_with_password_expired_less_than_30'] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']"
                        f"['check_inactive_accounts_with_password_expired_less_than_30']: {er}")
                    return "Not Configured"

            def check_commands_results(base_command):
                logging.info(f"started function: check_commands_results() with base command")
                try:
                    subprocess_base_command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                                    stdout=subprocess.PIPE,
                                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {subprocess_base_command_result}")

                    if subprocess_base_command_result.stdout == "":
                        command_result = "True"
                    else:
                        command_result = "False"
                    return command_result
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details']['check_commands_results'] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']['check_commands_results']: {er}")
                    return "Not Configured"

            def check_all_users_changed_passwords_in_past():
                logging.info("started function: check_all_users_changed_passwords_in_past()")
                # All users should have a password change date in the past
                try:
                    base_command = (
                        r"""awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; do change=$(date """
                        r"""-d "$(sudo chage --list $usr | grep '^Last password change' | cut -d: -f2 | grep"""
                        r""" -v 'never$')" +%s); if [[ "$change" -gt "$(date +%s)" ]]; then echo "User: \"$usr\""""
                        r""" last password change was \"$(sudo chage --list $usr | grep '^Last password change' """
                        r"""| cut -d: -f2)\""; fi; done""")
                    logging.info(f"base_command: {base_command}")
                    logging.info("calling function check_commands_results() from function : "
                                 "check_all_users_changed_passwords_in_past()")
                    return check_commands_results(base_command)
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details'][
                        'check_all_users_changed_passwords_in_past'] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']"
                        f"['check_all_users_changed_passwords_in_past']: {er}")
                    return "Not Configured"

            def are_system_accounts_secured():
                try:
                    # Are system accounts secured
                    base_command = (
                        r'''awk -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<'"$(awk '''
                        r''''/^\s*UID_MIN/{print $2}' /etc/login.defs)"' || $3 == 65534) && '''
                        r'''$7!~/^(\/usr)?\/sbin\/nologin$/) { print $1 }' /etc/passwd'''
                    )

                    logging.info(f"base_command: {base_command}")

                    logging.info(
                        "calling function check_commands_results() from function : are_system_accounts_secured")
                    return check_commands_results(base_command)
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details']['are_system_accounts_secured'] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']['are_system_accounts_secured']:"
                        f" {er}")
                    return "Not Configured"

            def check_default_group_for_root_account_gid_0():
                logging.info("started function: check_default_group_for_root_account_gid_0()")
                try:
                    base_command = r"""grep "^root:" /etc/passwd | cut -f4 -d:"""

                    logging.info(f"base_command: {base_command}")

                    subprocess_base_command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                                    stdout=subprocess.PIPE,
                                                                    universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {subprocess_base_command_result}")

                    if subprocess_base_command_result.returncode == 0:
                        command_output = subprocess_base_command_result.stdout.strip()
                        if command_output == "0":
                            command_result = "True"
                        else:
                            command_result = "False"
                    else:
                        command_result = "Not Configured"

                    return command_result
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details'][
                        'check_default_group_for_root_account_gid_0'] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']"
                        f"['check_default_group_for_root_account_gid_0']: {er}")
                    return "Not Configured"

            def check_root_password_set():
                logging.info("started function: check_root_password_set()")
                try:
                    base_command = r"passwd -S root"
                    logging.info(f"base_command: {base_command}")

                    base_command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                         stdout=subprocess.PIPE,
                                                         universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {base_command_result}")

                    if base_command_result.returncode == 0 and "Password set" in base_command_result.stdout.strip():
                        command_result = "True"
                    else:
                        command_result = "False"

                    logging.info(f"command_result: {command_result}")
                    return command_result
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details']['check_root_password_set'] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']['check_root_password_set']: {er}")
                    return "Not Configured"

            def check_sticky_bit_set():
                logging.info("started function: check_root_password_set()")
                try:
                    base_command = (r"df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' "
                                    r"-xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
                    logging.info(f"base_command: {base_command}")

                    base_command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                         stdout=subprocess.PIPE,
                                                         universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"subprocess_base_command_result: {base_command_result}")

                    if base_command_result.stdout.strip():
                        command_result = "False"
                    else:
                        command_result = "True"

                    logging.info(f"command_result: {command_result}")
                    return command_result
                except Exception as er:
                    error["cisInfo"]['cis_user_accounts_environment_details']['check_root_password_set'] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_user_accounts_environment_details']['check_root_password_set']: {er}")
                    return "Not Configured"

            def is_min_days_between_pass_changes_greater_than_6():
                try:
                    check_min_days_command = r"grep -E '^PASS_MIN_DAYS\s+[7-9]|\s[1-9][0-9]+' /etc/login.defs"
                    check_min_days_result = subprocess.run(check_min_days_command, shell=True, stderr=subprocess.PIPE,
                                                           stdout=subprocess.PIPE, universal_newlines=True,
                                                           timeout=TIMEOUT_SUBPROCESS)

                    if check_min_days_result.returncode == 0 and check_min_days_result.stdout:
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    logging.error(f"error['cisInfo']['is_min_days_between_pass_changes_greater_than_6']: {er}")
                    return "Not Configured"

            def is_default_user_umask_027_or_more_restrictive():
                try:
                    check_umask_command = r"grep -E '^\s*umask\s+0?27' /etc/bashrc /etc/profile /etc/profile.d/*.sh"
                    check_umask_result = subprocess.run(check_umask_command, shell=True, stderr=subprocess.PIPE,
                                                        stdout=subprocess.PIPE, universal_newlines=True,
                                                        timeout=TIMEOUT_SUBPROCESS)

                    if check_umask_result.returncode == 0 and check_umask_result.stdout:
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    logging.error(f"error['cisInfo']['is_default_user_umask_027_or_more_restrictive']: {er}")
                    return "Not Configured"

            def is_default_user_shell_timeout_900_seconds_or_less():
                try:
                    check_timeout_command = (r"grep -E '^\s*TMOUT\s*=\s*[1-9][0-9]{0,2}$' /etc/bashrc "
                                             r"/etc/profile /etc/profile.d/*.sh")
                    check_timeout_result = subprocess.run(check_timeout_command, shell=True, stderr=subprocess.PIPE,
                                                          stdout=subprocess.PIPE, universal_newlines=True,
                                                          timeout=TIMEOUT_SUBPROCESS)

                    if check_timeout_result.returncode == 0 and check_timeout_result.stdout:
                        return "True"
                    else:
                        return "False"
                except Exception as er:
                    logging.error(f"error['cisInfo']['is_default_user_shell_timeout_900_seconds_or_less']: {er}")
                    return "Not Configured"

            result["isPassMaxDaysLessThan366Days"] = check_pass_max_days_less_than_366()
            result["isPassMinDaysGreaterThan0Days"] = check_pass_min_days_greater_than_0()
            result["isPassWarnAgeGreaterThan6Days"] = check_pass_warn_age_greater_than_6()
            result["isInactiveAccountsWithPasswordExpiredLessThan30Days"] = (
                check_inactive_accounts_with_password_expired_less_than_30())
            result["didAllUsersChangedPasswordsInPast"] = check_all_users_changed_passwords_in_past()
            result["areSystemAccountsSecured"] = are_system_accounts_secured()
            result["isDefaultGroupForRootAccountGid0"] = check_default_group_for_root_account_gid_0()
            result["isRootPasswordSet"] = check_root_password_set()
            result["isStickyBitSetOnAllWorldWritableDirectories"] = check_sticky_bit_set()
            result["isMinDaysBetweenPassChangesGreaterThan6"] = is_min_days_between_pass_changes_greater_than_6()
            result["isDefaultUserUmask027OrMoreRestrictive"] = is_default_user_umask_027_or_more_restrictive()
            result["isDefaultUserShellTimeout900SecondsOrLess"] = is_default_user_shell_timeout_900_seconds_or_less()

        except Exception as err:
            logging.error(f"error['cisInfo']['cis_user_accounts_environment_details']: {err}")
        return result

    # CIS Section 6.1
    @logger_function
    def cis_system_file_permissions():
        result = {
            "arePermissionsOnEtcPasswdRestrictive": "Not Configured",
            "arePermissionsOnEtcPasswdDashRestrictive": "Not Configured",
            "arePermissionsOnEtcGroupRestrictive": "Not Configured",
            "arePermissionsOnEtcGroupDashRestrictive": "Not Configured",
            "arePermissionsOnEtcShadowRestrictive": "Not Configured",
            "arePermissionsOnEtcShadowDashRestrictive": "Not Configured",
            "arePermissionsOnEtcGshadowRestrictive": "Not Configured",
            "arePermissionsOnEtcGshadowDashRestrictive": "Not Configured",
        }
        try:
            def check_permissions_are_root_and_restrictive(base_command, permission_limit):
                # Are permissions on /etc/passwd root and restrictive
                logging.info("started function: check_permissions_are_root_and_restrictive()")
                try:
                    logging.info(f"base_command: {base_command}")
                    logging.info(f"permission_limit: {permission_limit}")

                    stat_command_result = subprocess.run(base_command, shell=True, stderr=subprocess.PIPE,
                                                         stdout=subprocess.PIPE,
                                                         universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                    logging.info(f"stat_command_result: {stat_command_result}")
                    stat_result = stat_command_result.stdout.strip().split()
                    # Check if Uid and Gid are both 0/root and Access is more restrictive
                    if stat_result[2] == '0/root' and stat_result[3] == '0/root' and int(
                            stat_result[1]) <= permission_limit:
                        return "True"
                    else:
                        return "False"

                except Exception as er:
                    error["cisInfo"]['cis_system_file_permissions'][
                        "check_permissions_are_root_and_restrictive"] = repr(er)
                    logging.error(
                        f"error['cisInfo']['cis_system_file_permissions']"
                        f"['check_permissions_are_root_and_restrictive']: "
                        f"{er}")
                    return "Not Configured"

            result["arePermissionsOnEtcPasswdRestrictive"] = (
                check_permissions_are_root_and_restrictive(r'''stat -Lc "%n %a %u/%U %g/%G" /etc/passwd''', 644))

            result["arePermissionsOnEtcPasswdDashRestrictive"] = (
                check_permissions_are_root_and_restrictive(r'''stat -Lc "%n %a %u/%U %g/%G" /etc/passwd-''', 644))

            result["arePermissionsOnEtcGroupRestrictive"] = (
                check_permissions_are_root_and_restrictive(r'''stat -Lc "%n %a %u/%U %g/%G" /etc/group''', 644))

            result["arePermissionsOnEtcGroupDashRestrictive"] = (
                check_permissions_are_root_and_restrictive(r'''stat -Lc "%n %a %u/%U %g/%G" /etc/group-''', 644))

            result["arePermissionsOnEtcShadowRestrictive"] = (
                check_permissions_are_root_and_restrictive(r'''stat -Lc "%n %a %u/%U %g/%G" /etc/shadow''', 0))

            result["arePermissionsOnEtcShadowDashRestrictive"] = (
                check_permissions_are_root_and_restrictive(r'''stat -Lc "%n %a %u/%U %g/%G" /etc/shadow-''', 0))

            result["arePermissionsOnEtcGshadowRestrictive"] = (
                check_permissions_are_root_and_restrictive(r'''stat -Lc "%n %a %u/%U %g/%G" /etc/gshadow-''', 0))

            result["arePermissionsOnEtcGshadowDashRestrictive"] = (
                check_permissions_are_root_and_restrictive(r'''stat -Lc "%n %a %u/%U %g/%G" /etc/gshadow-''', 0))
        except Exception as err:
            logging.error(
                f"error['cisInfo']['cis_system_file_permissions']: {err}")
        return result

    # CIS Section 6.2
    @logger_function
    def get_user_and_group_info():
        result = {
            "noUid0OtherThanRoot": "Not Configured",
            "rootPathIntegrityMaintained": "Not Configured",
            "dotFilesAreNotGlobalWritable": "Not Configured",
            "netrcFilesAreNotAcessible": "Not Configured",
            "rhostsFilesAreNotAvailable": "Not Configured",
            "allUsersHaveValidHomeDirectories": "Not Configured",
            "isShadowGroupEmpty": "Not Configured",
        }
        try:
            def root_uid_0():
                try:
                    uid0_output = extract_info("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
                    if uid0_output == "root":
                        result["noUid0OtherThanRoot"] = "True"
                    else:
                        result["noUid0OtherThanRoot"] = "False"
                except Exception as root_uid_0_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['root_uid_0']: {root_uid_0_err}")

            def root_path_integrity():
                try:
                    rootpath_script = '''
                        #!/bin/bash
                        if echo "$PATH" | grep -q "::" ; then
                            echo "Empty Directory in PATH (::)"
                        fi
                        if echo "$PATH" | grep -q ":$" ; then
                            echo "Trailing : in PATH"
                        fi
                        for x in $(echo "$PATH" | tr ":" " ") ; do
                            if [ -d "$x" ] ; then
                                ls -ldH "$x" | awk '\
                                $9 == "." {print "PATH contains current working directory (.)"} \
                                $3 != "root" {print $9, "is not owned by root"} \
                                substr($1,6,1) != "-" {print $9, "is group writable"} \
                                substr($1,9,1) != "-" {print $9, "is world writable"}'
                            else
                                echo "$x is not a directory"
                            fi
                        done
                    '''
                    rootpath_output = run_script_for_output(rootpath_script, "root_path_integrity")
                    if rootpath_output == "root":
                        result["rootPathIntegrityMaintained"] = "True"
                    else:
                        result["rootPathIntegrityMaintained"] = "False"
                except Exception as root_path_integrity_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']"
                        f"['root_path_integrity']: {root_path_integrity_err}")

            def dot_files_writable():
                try:
                    dotfiles_script = r'''
                        #!/bin/bash
                        awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/
                        && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while
                        read -r user dir; do
                            if [ -d "$dir" ]; then
                                for file in "$dir"/.*; do
                                    if [ ! -h "$file" ] && [ -f "$file" ]; then
                                        fileperm=$(stat -L -c "%A" "$file")
                                        if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo
                                            "$fileperm" | cut -c9)" != "-" ]; then
                                            echo "User: \"$user\" file: \"$file\" has permissions:
                                            \"$fileperm\""
                                        fi
                                    fi
                                done
                            fi
                        done
                    '''
                    dotfiles_result = run_script_for_output(dotfiles_script, "dot_files_writable")
                    if dotfiles_result == "Not Configured":
                        result["dotFilesIntegrityMaintained"] = "Not Configured"
                    elif dotfiles_result:
                        result["dotFilesIntegrityMaintained"] = "False"
                    else:
                        result["dotFilesIntegrityMaintained"] = "True"
                except Exception as dot_files_writable_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['dot_files_writable']: {dot_files_writable_err}")

            def netrc_permission():
                try:
                    netrc_script = '''
                        #!/bin/bash
                        grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 !=
                        "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while \
                        read user dir; do
                        if [ ! -d "$dir" ]; then
                        echo "The home directory ($dir) of user $user does not exist."
                        else
                        for file in $dir/.netrc; do
                        if [ ! -h "$file" -a -f "$file" ]; then
                        fileperm=$(ls -ld $file | cut -f1 -d" ")
                        if [ $(echo $fileperm | cut -c5) != "-" ]; then
                        echo "Group Read set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c6) != "-" ]; then
                        echo "Group Write set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c7) != "-" ]; then
                        echo "Group Execute set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c8) != "-" ]; then
                        echo "Other Read set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c9) != "-" ]; then
                        echo "Other Write set on $file"
                        fi
                        if [ $(echo $fileperm | cut -c10) != "-" ]; then
                        echo "Other Execute set on $file"
                        fi
                        fi
                        done
                        fi
                        done
                    '''
                    netrc_result = run_script_for_output(netrc_script, "netrc_permission")
                    if netrc_result == "Not Configured":
                        result["dotFilesIntegrityMaintained"] = "Not Configured"
                    elif netrc_result:
                        result["dotFilesIntegrityMaintained"] = "False"
                    else:
                        result["dotFilesIntegrityMaintained"] = "True"
                except Exception as netrc_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['netrc_permission']: {netrc_err}")

            def rhosts_available():
                try:
                    rhosts_script = r'''
                        #!/bin/bash
                        awk -F: '($1!~/(root|halt|sync|shutdown)/ &&
                        $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {
                        print $1 " " $6 }' /etc/passwd | while read -r user dir; do
                        if [ -d "$dir" ]; then
                        file="$dir/.rhosts"
                        if [ ! -h "$file" ] && [ -f "$file" ]; then
                        echo "User: \"$user\" file: \"$file\" exists"
                        fi
                        fi
                        done
                    '''
                    rhosts_result = run_script_for_output(rhosts_script, "rhosts_available")
                    if rhosts_result == "Not Configured":
                        result["rhostsFilesAreNotAvailable"] = "Not Configured"
                    elif rhosts_result:
                        result["rhostsFilesAreNotAvailable"] = "False"
                    else:
                        result["rhostsFilesAreNotAvailable"] = "True"

                except Exception as rhosts_available_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['rhosts_available']: {rhosts_available_err}")

            def check_users_have_valid_home_dirs():
                try:
                    usr_dir_script = '''
                        #!/bin/bash
                        grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which
                        nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user
                        dir; do
                        if [ ! -d "$dir" ]; then
                        echo "The home directory ($dir) of user $user does not exist."
                        fi
                        done
                    '''
                    usr_dir_result = run_script_for_output(usr_dir_script, "check_users_have_valid_home_dirs")
                    if usr_dir_result:
                        result["allUsersHaveValidHomeDirectories"] = "False"
                    else:
                        result["allUsersHaveValidHomeDirectories"] = "True"

                except Exception as check_users_have_valid_home_dirs_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['check_users_have_valid_home_dirs']: "
                        f"{check_users_have_valid_home_dirs_err}")

            def shadow_group():
                try:
                    shadow_output1 = extract_info("grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group")
                    shadow_output2 = extract_info('''awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd''')
                    if shadow_output1 == "Not Configured" or shadow_output2 == "Not Configured":
                        result["isShadowGroupEmpty"] = "Not Configured"
                    elif not shadow_output1 and not shadow_output2:
                        result["isShadowGroupEmpty"] = "True"
                    else:
                        result["isShadowGroupEmpty"] = "False"

                except Exception as shadow_group_err:
                    logging.error(
                        f"error['cisInfo']['get_user_and_group_info']['shadow_group']: {shadow_group_err}")

            root_uid_0()
            root_path_integrity()
            dot_files_writable()
            netrc_permission()
            rhosts_available()
            shadow_group()
            check_users_have_valid_home_dirs()

        except Exception as err:
            logging.error(
                f"error['cisInfo']['get_user_and_group_info']: {err}")

        return result

    def get_cis_base_and_os_services_info():
        result = {
            "isSmartCardServiceDisabled": "Not Configured",
            "isSmartDiskServiceDisabled": "Not Configured",
            "isInstallHelperServiceDisabled": "Not Configured",
            "isKdumpKernelCrashDisabled": "Not Configured",
            "isBluetoothHostControllerDisabled": "Not Configured",
            "isXinetdServiceDisabled": "Not Configured",
            "isChargenServiceDisabled": "Not Configured",
            "isDaytimeServiceDisabled": "Not Configured",
            "isEchoServiceDisabled": "Not Configured",
            "isTimeServiceDisabled": "Not Configured",
            "isTalkClientServiceDisabled": "Not Configured",
            "isDiscardServiceDisabled": "Not Configured",
        }
        try:
            def smart_card_service_disabled():
                try:
                    cmd = 'systemctl is-enabled pcscd'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in smart_card_service_disabled: {e}")
                    return "Not Configured"

            def smart_disk_service_disabled():
                try:
                    cmd = 'systemctl is-enabled smartd'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in smart_disk_service_disabled: {e}")
                    return "Not Configured"

            def install_helper_service_disabled():
                try:
                    cmd = 'systemctl is-enabled install-helper'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in install_helper_service_disabled: {e}")
                    return "Not Configured"

            def kdump_kernel_crash_disabled():
                try:
                    cmd = 'systemctl is-enabled kdump'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in kdump_kernel_crash_disabled: {e}")
                    return "Not Configured"

            def bluetooth_host_controller_disabled():
                try:
                    cmd = 'systemctl is-enabled bluetooth'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in bluetooth_host_controller_disabled: {e}")
                    return "Not Configured"

            def xinetd_service_disabled():
                try:
                    cmd = 'systemctl is-enabled xinetd'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in xinetd_service_disabled: {e}")
                    return "Not Configured"

            def chargen_service_disabled():
                try:
                    cmd = 'systemctl is-enabled chargen'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in chargen_service_disabled: {e}")
                    return "Not Configured"

            def daytime_service_disabled():
                try:
                    cmd = 'systemctl is-enabled daytime'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in daytime_service_disabled: {e}")
                    return "Not Configured"

            def echo_service_disabled():
                try:
                    cmd = 'systemctl is-enabled echo'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in echo_service_disabled: {e}")
                    return "Not Configured"

            def time_service_disabled():
                try:
                    cmd = 'systemctl is-enabled time'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in time_service_disabled: {e}")
                    return "Not Configured"

            def talk_client_service_disabled():
                try:
                    cmd = 'systemctl is-enabled talk'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in talk_client_service_disabled: {e}")
                    return "Not Configured"

            def discard_service_disabled():
                try:
                    cmd = 'systemctl is-enabled discard'
                    output = extract_info(cmd)
                    return "True" if output == "disabled" else "False"
                except Exception as e:
                    logging.error(f"Error in discard_service_disabled: {e}")
                    return "Not Configured"

            result["isSmartCardServiceDisabled"] = smart_card_service_disabled()
            result["isSmartDiskServiceDisabled"] = smart_disk_service_disabled()
            result["isInstallHelperServiceDisabled"] = install_helper_service_disabled()
            result["isKdumpKernelCrashDisabled"] = kdump_kernel_crash_disabled()
            result["isBluetoothHostControllerDisabled"] = bluetooth_host_controller_disabled()
            result["isXinetdServiceDisabled"] = xinetd_service_disabled()
            result["isChargenServiceDisabled"] = chargen_service_disabled()
            result["isDaytimeServiceDisabled"] = daytime_service_disabled()
            result["isEchoServiceDisabled"] = echo_service_disabled()
            result["isTimeServiceDisabled"] = time_service_disabled()
            result["isTalkClientServiceDisabled"] = talk_client_service_disabled()
            result["isDiscardServiceDisabled"] = discard_service_disabled()

        except Exception as base_service_info_err:
            logging.error(
                f"error['cisInfo']['get_user_and_group_info']['base_service_info']: {base_service_info_err}")

        return result

    def get_cis_process_hardening_info():
        result = {
            "isCoreDumpForAllUsersDisabled": "Not Configured",
            "isRandomVirtualMemoryRegionPlacementEnabled": "Not Configured",
            "isExecShieldInSysctlEnabled": "Not Configured",
            "isDacOnSymLinksEnforced": "Not Configured",
            "isDacOnHardLinksEnforced": "Not Configured",
            "isTpmModuleEnabled": "Not Configured",
        }
        try:
            def core_dump_for_all_users_disabled():
                try:
                    cmd = 'sysctl fs.suid_dumpable'
                    output = extract_info(cmd)
                    return "True" if output == "fs.suid_dumpable = 0" else "False"
                except Exception as e:
                    logging.error(f"Error in core_dump_for_all_users_disabled: {e}")
                    return "Not Configured"

            def random_virtual_memory_region_placement_enabled():
                try:
                    cmd = 'sysctl kernel.randomize_va_space'
                    output = extract_info(cmd)
                    return "True" if output == "kernel.randomize_va_space = 2" else "False"
                except Exception as e:
                    logging.error(f"Error in random_virtual_memory_region_placement_enabled: {e}")
                    return "Not Configured"

            def exec_shield_in_sysctl_enabled():
                try:
                    cmd = 'sysctl kernel.exec-shield'
                    output = extract_info(cmd)
                    return "True" if output == "kernel.exec-shield = 1" else "False"
                except Exception as e:
                    logging.error(f"Error in exec_shield_in_sysctl_enabled: {e}")
                    return "Not Configured"

            def dac_on_symlinks_enforced():
                try:
                    cmd = 'sysctl fs.protected_symlinks'
                    output = extract_info(cmd)
                    return "True" if output == "fs.protected_symlinks = 1" else "False"
                except Exception as e:
                    logging.error(f"Error in dac_on_symlinks_enforced: {e}")
                    return "Not Configured"

            def dac_on_hardlinks_enforced():
                try:
                    cmd = 'sysctl fs.protected_hardlinks'
                    output = extract_info(cmd)
                    return "True" if output == "fs.protected_hardlinks = 1" else "False"
                except Exception as e:
                    logging.error(f"Error in dac_on_hardlinks_enforced: {e}")
                    return "Not Configured"

            def tpm_module_enabled():
                try:
                    cmd = 'sudo dmesg | grep tpm'
                    output = extract_shell_info(cmd)
                    if "tpm_tis" in output:
                        return "True"
                    else:
                        return "False"
                except Exception as e:
                    logging.error(f"Error in tpm_module_enabled: {e}")
                    return "Not Configured"

            result["isCoreDumpForAllUsersDisabled"] = core_dump_for_all_users_disabled()
            result["isRandomVirtualMemoryRegionPlacementEnabled"] = random_virtual_memory_region_placement_enabled()
            result["isExecShieldInSysctlEnabled"] = exec_shield_in_sysctl_enabled()
            result["isDacOnSymLinksEnforced"] = dac_on_symlinks_enforced()
            result["isDacOnHardLinksEnforced"] = dac_on_hardlinks_enforced()
            result["isTpmModuleEnabled"] = tpm_module_enabled()
        except Exception as process_hardening_info_err:
            logging.error(
                f"error['cisInfo']['get_user_and_group_info']['process_hardening_info']: {process_hardening_info_err}")

        return result

    # cis-section 1.8 warning banners----------------------------------------------------
    def get_cis_warning_banners_info():
        result = {
            "isMessageOfTheDayConfigured": "Not Configured",
            "isLocalLoginWarningBannerConfigured": "Not Configured",
            "isRemoteLoginWarningBannerConfigured": "Not Configured",
            "isPermissionOnEtcMotdConfigured": "Not Configured",
            "isPermissionOnEtcIssueConfigured": "Not Configured",
            "isPermissionOnEtcIssueNetConfigured": "Not Configured",
            "isGDMLoginBannerConfigured": "Not Configured",
            "isOsInfoRemovedFromLoginBanner": "Not Configured",
            "isUpdatesPatchesAdditionalSecurityPackagesInstalled": "Not Configured",
        }

        def is_message_of_the_day_configured():
            try:
                output = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/motd''')
                if output:
                    return "False"
                else:
                    return "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_message_of_the_day_configured']: {er}")
                return "Not Configured"

        def is_local_login_warning_banner_configured():
            try:
                output = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/issue''')
                if output:
                    return "False"
                else:
                    return "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_local_login_warning_banner_configured']: {er}")
                return "Not Configured"

        def is_remote_login_warning_banner_configured():
            try:
                output = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net''')
                if output:
                    return "False"
                else:
                    return "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_remote_login_warning_banner_configured']: {er}")
                return "Not Configured"

        def is_permission_on_etc_motd_configured():
            try:
                output = extract_shell_info("stat /etc/motd")
                if "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                    return "True"
                else:
                    return "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_etc_motd_configured']: {er}")
                return "Not Configured"

        def is_permission_on_etc_issue_configured():
            try:
                output = extract_shell_info("stat /etc/issue")
                if "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                    return "True"
                else:
                    return "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_etc_issue_configured']: {er}")
                return "Not Configured"

        def is_permission_on_etc_issue_net_configured():
            try:
                output = extract_shell_info("stat /etc/issue.net")
                if "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" in output:
                    return "True"
                else:
                    return "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_etc_issue_net_configured']: {er}")
                return "Not Configured"

        def is_gdm_login_banner_configured():
            try:
                output = extract_shell_info("cat /etc/gdm3/greeter.dconf-defaults")

                # Split file into lines for safer parsing
                lines = output.splitlines()

                in_gnome_section = False
                banner_enable = False
                banner_text = False

                for line in lines:
                    stripped = line.strip()

                    # Detect start of the GDM login section
                    if stripped == "[org/gnome/login-screen]":
                        in_gnome_section = True
                        continue

                    # Stop checking when we leave the section (optional)
                    if in_gnome_section and stripped.startswith("[") and stripped.endswith("]"):
                        break

                    # Ignore comments and empty lines
                    if stripped.startswith("#") or not stripped:
                        continue

                    # Look for key/value pairs inside the section
                    if in_gnome_section:
                        if re.match(r"^banner-message-enable\s*=\s*true$", stripped):
                            banner_enable = True
                        elif re.match(r"^banner-message-text\s*=\s*['\"].+['\"]$", stripped):
                            banner_text = True

                if banner_enable and banner_text:
                    return "True"
                else:
                    return "False"

            except Exception as er:
                logging.error(f"error['cisInfo']['is_gdm_login_banner_configured']: {er}")
                return "Not Configured"

        def is_updates_patches_additional_security_packages_installed():
            try:
                output = extract_info("dnf check-update --security")
                if output:
                    return "False"
                else:
                    return "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_updates_patches_additional_security_packages_installed']: {er}")
                return "Not Configured"

        def is_os_info_removed_from_login_banner():
            try:
                output_issue = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/issue'''
                )
                output_issue_net = extract_shell_info(
                    r'''grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | 
                    cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net'''
                )

                # If the output is empty for both files, OS info is removed
                if not output_issue and not output_issue_net:
                    return "True"
                else:
                    return "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_os_info_removed_from_login_banner']: {er}")
                return "Not Configured"

        try:
            result["isMessageOfTheDayConfigured"] = is_message_of_the_day_configured()
            result["isLocalLoginWarningBannerConfigured"] = is_local_login_warning_banner_configured()
            result["isRemoteLoginWarningBannerConfigured"] = is_remote_login_warning_banner_configured()
            result["isPermissionOnEtcMotdConfigured"] = is_permission_on_etc_motd_configured()
            result["isPermissionOnEtcIssueConfigured"] = is_permission_on_etc_issue_configured()
            result["isPermissionOnEtcIssueNetConfigured"] = is_permission_on_etc_issue_net_configured()
            result["isGDMLoginBannerConfigured"] = is_gdm_login_banner_configured()
            result["isUpdatesPatchesAdditionalSecurityPackagesInstalled"] = \
                is_updates_patches_additional_security_packages_installed()
            result["isOsInfoRemovedFromLoginBanner"] = is_os_info_removed_from_login_banner()

        except Exception as warning_banners_err:
            logging.error(f"error['cisInfo']['cis_warning_banners_info']: {warning_banners_err}")
        return result

    def get_cis_desktop_conf_info():
        result = {
            "isPermissionOnFileBrowserConfigured": "Not Configured",
            "isFirefoxRemoved": "Not Configured",
            "isImageViewerRemoved": "Not Configured",
            "isPermissionOnGnomeTerminalConfigured": "Not Configured",
            "isPermissionOnGnomeDisksConfigured": "Not Configured",
            "isPermissionOnGnomeControlCenterConfigured": "Not Configured",
            "isTotemRemoved": "Not Configured",
            "isPermissionOnDiskImageMounterConfigured": "Not Configured",
            "isPermissionOnGnomeScreenshotConfigured": "Not Configured",
            "isCheeseRemoved": "Not Configured",
            "isCockpitRemoved": "Not Configured",
            "isTigerVNCRemoved": "Not Configured",
            "isWireSharkRemoved": "Not Configured",
            "isPermissionOnGnomeSoftwareConfigured": "Not Configured",
            "isFileRollerRemoved": "Not Configured",
            "isPermissionOnGnomeSystemMonitorConfigured": "Not Configured",
            "isPermissionOnGnomeLogsConfigured": "Not Configured",
            "isPanelRunDialogDisabled": "Not Configured",
            "isUSBDisabled": "Not Configured",
            "isMobilePhoneDisabled": "Not Configured",
            "isCdDvdDisabled": "Not Configured",
            "isBluetoothDisabled": "Not Configured",
            "isSerialPortDisabled": "Not Configured",
        }

        def is_permission_on_file_browser_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/nautilus"  # Adjust if different file browser is used
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_file_browser_configured']: {er}")
                return "Not Configured"

        def is_firefox_removed():
            try:
                check_command = "rpm -q firefox"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_firefox_removed']: {er}")
                return "Not Configured"

        def is_image_viewer_removed():
            try:
                check_command = "rpm -q eog"  # Assuming Eye of GNOME as image viewer
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_image_viewer_removed']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_terminal_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-terminal"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_terminal_configured']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_disks_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-disks"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_disks_configured']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_control_center_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-control-center"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_control_center_configured']: {er}")
                return "Not Configured"

        def is_totem_removed():
            try:
                check_command = "rpm -q totem"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_totem_removed']: {er}")
                return "Not Configured"

        def is_permission_on_disk_image_mounter_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-disk-utility"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_disk_image_mounter_configured']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_screenshot_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-screenshot"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_screenshot_configured']: {er}")
                return "Not Configured"

        def is_cheese_removed():
            try:
                check_command = "rpm -q cheese"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_cheese_removed']: {er}")
                return "Not Configured"

        def is_cockpit_removed():
            try:
                check_command = "rpm -q cockpit"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_cockpit_removed']: {er}")
                return "Not Configured"

        def is_tiger_vnc_removed():
            try:
                check_command = "rpm -q tigervnc-server"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_tiger_vnc_removed']: {er}")
                return "Not Configured"

        def is_wire_shark_removed():
            try:
                check_command = "rpm -q wireshark"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_wire_shark_removed']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_software_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-software"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_software_configured']: {er}")
                return "Not Configured"

        def is_file_roller_removed():
            try:
                check_command = "rpm -q file-roller"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "False" if output.returncode == 0 else "True"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_file_roller_removed']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_system_monitor_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-system-monitor"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_system_monitor_configured']: {er}")
                return "Not Configured"

        def is_permission_on_gnome_logs_configured():
            try:
                check_command = "stat -Lc '%a' /usr/bin/gnome-logs"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and int(output.stdout.strip()) <= 755 else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_permission_on_gnome_logs_configured']: {er}")
                return "Not Configured"

        def is_panel_run_dialog_disabled():
            try:
                check_command = "gsettings get org.gnome.shell.extensions.dash-to-dock show-apps-at-top"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if output.returncode == 0 and output.stdout.strip() == "false" else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_panel_run_dialog_disabled']: {er}")
                return "Not Configured"

        def is_usb_disabled():
            try:
                check_command = "lsusb"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if not output.stdout else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_usb_disabled']: {er}")
                return "Not Configured"

        def is_mobile_phone_disabled():
            try:
                check_command = "lsusb | grep -i 'mobile'"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if not output.stdout else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_mobile_phone_disabled']: {er}")
                return "Not Configured"

        def is_cd_dvd_disabled():
            try:
                check_command = "lsblk | grep -i 'cdrom'"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if not output.stdout else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_cd_dvd_disabled']: {er}")
                return "Not Configured"

        def is_bluetooth_disabled():
            try:
                check_command = "rfkill list bluetooth"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if "yes" in output.stdout.lower() else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_bluetooth_disabled']: {er}")
                return "Not Configured"

        def is_serial_port_disabled():
            try:
                check_command = "dmesg | grep -i 'ttyS'"
                output = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                        universal_newlines=True, timeout=TIMEOUT_SUBPROCESS)
                return "True" if not output.stdout else "False"
            except Exception as er:
                logging.error(f"error['cisInfo']['is_serial_port_disabled']: {er}")
                return "Not Configured"

        try:
            result["isPermissionOnFileBrowserConfigured"] = is_permission_on_file_browser_configured()
            result["isFirefoxRemoved"] = is_firefox_removed()
            result["isImageViewerRemoved"] = is_image_viewer_removed()
            result["isPermissionOnGnomeTerminalConfigured"] = is_permission_on_gnome_terminal_configured()
            result["isPermissionOnGnomeDisksConfigured"] = is_permission_on_gnome_disks_configured()
            result["isPermissionOnGnomeControlCenterConfigured"] = is_permission_on_gnome_control_center_configured()
            result["isTotemRemoved"] = is_totem_removed()
            result["isPermissionOnDiskImageMounterConfigured"] = is_permission_on_disk_image_mounter_configured()
            result["isPermissionOnGnomeScreenshotConfigured"] = is_permission_on_gnome_screenshot_configured()
            result["isCheeseRemoved"] = is_cheese_removed()
            result["isCockpitRemoved"] = is_cockpit_removed()
            result["isTigerVNCRemoved"] = is_tiger_vnc_removed()
            result["isWireSharkRemoved"] = is_wire_shark_removed()
            result["isPermissionOnGnomeSoftwareConfigured"] = is_permission_on_gnome_software_configured()
            result["isFileRollerRemoved"] = is_file_roller_removed()
            result["isPermissionOnGnomeSystemMonitorConfigured"] = is_permission_on_gnome_system_monitor_configured()
            result["isPermissionOnGnomeLogsConfigured"] = is_permission_on_gnome_logs_configured()
            result["isPanelRunDialogDisabled"] = is_panel_run_dialog_disabled()
            result["isUSBDisabled"] = is_usb_disabled()
            result["isMobilePhoneDisabled"] = is_mobile_phone_disabled()
            result["isCdDvdDisabled"] = is_cd_dvd_disabled()
            result["isBluetoothDisabled"] = is_bluetooth_disabled()
            result["isSerialPortDisabled"] = is_serial_port_disabled()

        except Exception as desktop_conf_err:
            logging.error(f"error['cisInfo']: {desktop_conf_err}")

        return result

    @logger_function
    def get_system_info():
        """
        Generates a system information dictionary.

        Returns:
            dict: A dictionary containing various system information.
        """
        # Initialize the system_info dictionary
        system_info = {}
        html_report_info = {}
        try:
            audit_log_id = get_audit_log_id_info()
            pc_id = get_pc_id()
            host_name = platform.node()

            # ----------------------------------------------------------------
            # miscellaneousInfo
            current_loggedin_user = get_current_loggedin_user()
            current_time = fetch_current_time()

            # ----------------------------------------------------------------
            # pcIdentityInfo
            current_setup_file_version = find_and_extract_current_setup_version()
            os_type = extract_info(['uname', '-s'])
            os_name_info = get_os_name_info()
            serial_number = get_system_serial_number() or get_system_serial_from_file()
            uuid_number = get_device_uuid() or get_device_uuid_from_file()
            motherboard_serial_number = get_motherboard_serial_number() or get_motherboard_serial_from_file()
            ip_address = extract_shell_info('hostname -I')
            is_pc_in_org_domain = check_pc_in_org_domain()
            system_manufacturer_info = extract_shell_info('cat /sys/class/dmi/id/sys_vendor',
                                                          '/sys/class/dmi/id/sys_vendor',
                                                          "system_manufacturer_info")
            system_model_info = extract_shell_info('cat /sys/class/dmi/id/product_name',
                                                   '/sys/class/dmi/id/product_name',
                                                   "system_model_info")
            os_version = get_linux_os_version()

            security_status_info = get_system_security_status(current_loggedin_user)

            if SCAN_TYPE == "LINUX_USB_TRIGGER":
                # ----------------------------------------------------------------
                # usbInfo
                usb_details_info = get_usb_details()

                system_info = {
                    "currentTime": current_time,
                    "pcId": pc_id,
                    "eventTriggerType": SCAN_TYPE,
                    "pcIdentityInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "auditLogId": audit_log_id,
                        "eventTriggerType": SCAN_TYPE,
                        "osType": os_type,
                        "osName": os_name_info,
                        "serialNumber": serial_number,
                        "motherboardSerialNumber": motherboard_serial_number,
                        "ipAddress": ip_address,
                        "hostname": host_name,
                        "connectedToDomainName": is_pc_in_org_domain,
                        "systemManufacturer": system_manufacturer_info,
                        "systemModel": system_model_info,
                        "currentUser": current_loggedin_user,
                        "currentAgentVersion": current_setup_file_version,
                        "osVersion": os_version,
                        "licenseKey": LICENSE_KEY,
                        "securityStatus": security_status_info
                    },
                    "usbInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "usbInfoDetails": usb_details_info,
                    },
                    "errorInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        **error
                    }
                }
            elif (SCAN_TYPE == "LINUX_NETWORK_TRIGGER" or
                  SCAN_TYPE == "LINUX_FIREWALL_TRIGGER" or SCAN_TYPE == "LINUX_BLUETOOTH_TRIGGER"):
                # ----------------------------------------------------------------
                # miscellaneousInfo
                installed_programs = get_installed_programs()

                # ----------------------------------------------------------------
                # networkInfo
                firewall_status, firewall_service = check_firewall_status()
                wifi_info = get_wifi_info()
                ethernet_info = get_ethernet_info()
                bluetooth_info = get_bluetooth_info()
                established_connections_list = get_established_connections()
                open_tcp_ports_list = get_tcp_info()
                dns_info = get_dns_info()
                nac_info = get_nac_info(installed_programs)
                ntp_enabled = is_ntp_server_enabled()

                system_info = {
                    "currentTime": current_time,
                    "pcId": pc_id,
                    "eventTriggerType": SCAN_TYPE,
                    "pcIdentityInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "auditLogId": audit_log_id,
                        "eventTriggerType": SCAN_TYPE,
                        "osType": os_type,
                        "osName": os_name_info,
                        "serialNumber": serial_number,
                        "motherboardSerialNumber": motherboard_serial_number,
                        "ipAddress": ip_address,
                        "hostname": host_name,
                        "connectedToDomainName": is_pc_in_org_domain,
                        "systemManufacturer": system_manufacturer_info,
                        "systemModel": system_model_info,
                        "currentUser": current_loggedin_user,
                        "currentAgentVersion": current_setup_file_version,
                        "osVersion": os_version,
                        "licenseKey": LICENSE_KEY,
                        "securityStatus": security_status_info
                    },
                    "networkInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "firewallStatus": firewall_status,
                        "firewallService": firewall_service,
                        "wifiStatus": wifi_info,
                        "ethernetStatus": ethernet_info,
                        "bluetoothInfo": bluetooth_info,
                        "establishedNetworkConnections": established_connections_list,
                        "openTcpPorts": open_tcp_ports_list,
                        "dnsServer": dns_info,
                        "nacInstalled": nac_info,
                        "ntpDetails": ntp_enabled,
                    },
                    "errorInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        **error
                    }
                }
            else:
                # ----------------------------------------------------------------
                usb_stored_history_info = []
                custodian_name = ""
                if SCAN_TYPE == "LINUX_INSTALLATION_TRIGGER":
                    usb_stored_history_info = get_usb_stored_history()
                    custodian_name = get_custodian_name()

                # ----------------------------------------------------------------
                # miscellaneousInfo
                installed_programs = get_installed_programs()

                # ----------------------------------------------------------------
                # accountInfo
                user_account_details = get_user_account_details(current_loggedin_user)
                is_multiple_admin_acc = get_admin_accounts()
                password_age_status = get_users_password_age()

                # ----------------------------------------------------------------
                # backendInfo
                os_patch_info = get_os_patch_info()
                app_patch_info = get_application_patch_info()
                endpoint_type = get_filtered_hostname()
                filesystem_integrity_info = []
                if SCAN_TYPE == "LINUX_DAILY_TRIGGER" or SCAN_TYPE == "LINUX_INSTALLATION_TRIGGER":
                    filesystem_integrity_info = get_file_integrity_info()

                # ----------------------------------------------------------------
                # cis info
                cis_file_system_configuration_info = cis_file_system_configuration()
                cis_audit_partitions_info = cis_audit_partitions()
                cis_filesystem_integrity_check = cis_check_aide_installed()
                cis_secure_boot_settings_info = cis_secure_boot_settings()
                cis_additional_process_hardening_info = cis_additional_process_hardening()
                cis_selinux_info = cis_selinux_config_info()
                cis_special_purpose_services_info = cis_special_purpose_services()
                cis_service_clients_info = cis_service_clients()
                cis_configure_firewall_info = cis_configure_firewall_utility()
                cis_configure_firewall_rules_info = cis_configure_firewall_rules()
                cis_network_configuration_info = cis_network_configuration()
                cis_system_auditing_info = cis_configure_system_auditing()
                cis_system_access_and_authentication_info = cis_system_access_and_authentication()
                cis_ssh_server_info = cis_configure_ssh_server()
                cis_privilege_escalation_info = cis_configure_privilege_escalation()
                cis_pam_info = cis_configure_pam()
                cis_user_accounts_environment_info = cis_user_accounts_environment_details()
                cis_system_file_permissions_info = cis_system_file_permissions()
                cis_get_user_and_group_info = get_user_and_group_info()
                cis_logging_and_auditing_info = cis_logging_and_auditing()
                cis_base_and_os_services_info = get_cis_base_and_os_services_info()
                cis_process_hardening_info = get_cis_process_hardening_info()
                cis_warning_banners_info = get_cis_warning_banners_info()
                cis_desktop_conf_info = get_cis_desktop_conf_info()

                # ----------------------------------------------------------------
                # hardwareInfo
                processor_info = \
                    extract_shell_info("lscpu | grep 'Model name:' | awk -F: '{print $2}' | awk '{$1=$1;print}'").split(
                        "\n")[0]
                machine_bit_type = platform.architecture()[0]
                machine_type = platform.machine()
                memory_info = get_memory_information()
                bios_version_info = extract_shell_info('cat /sys/class/dmi/id/bios_version',
                                                       '/sys/class/dmi/id/bios_version',
                                                       "bios_version_info")
                sys_time_zone_info = get_time_zone_info()
                bios_battery_serviceable_info = get_bios_battery_serviceable()
                internal_disks_info = get_harddrive_info()
                printer_names_list = list_printer_names()
                scanners_names_list = list_scanner_names()
                high_cpu_usage = get_high_cpu_processes()
                ram_use = get_processes_with_memory_usage()
                nicinfo = nic_info()
                optical_drive_info = get_optical_drive_info()
                tmp_version = get_tpm_version()

                # ----------------------------------------------------------------
                # networkInfo
                firewall_status, firewall_service = check_firewall_status()
                wifi_info = get_wifi_info()
                ethernet_info = get_ethernet_info()
                bluetooth_info = get_bluetooth_info()
                established_connections_list = get_established_connections()
                open_tcp_ports_list = get_tcp_info()
                dns_info = get_dns_info()
                nac_info = get_nac_info(installed_programs)
                ntp_enabled = is_ntp_server_enabled()

                # ----------------------------------------------------------------
                # osInfo
                os_distributor = get_os_name_info()
                os_release = extract_info(['uname', '-r'])
                os_release_name = get_os_release_name(os_distributor)
                os_config_info = extract_shell_info('cat /sys/class/dmi/id/product_name',
                                                    '/sys/class/dmi/id/product_name',
                                                    "os_config_info")
                os_install_date_info = get_os_install_date()
                user_home_dir = get_user_profile_directory(current_loggedin_user)
                user_profile_dir = get_user_profile_directory(current_loggedin_user)
                fetch_startup_programs = get_list_of_startup_programs()
                system_boot_time_info = extract_shell_info("uptime -s")
                boot_device_information = get_boot_device_info()
                shared_dir = list_shared_directories()
                services_info = get_services_info()
                rdp_status = get_rdp_status()
                audit_logs = get_audit_logs()
                av_info = get_antivirus_info(installed_programs, app_patch_info)
                edr_installed = get_edr_installed(installed_programs)

                # ----------------------------------------------------------------
                # Below is the dictionary that will be returned
                system_info = {
                    "currentTime": current_time,
                    "pcId": pc_id,
                    "eventTriggerType": SCAN_TYPE,
                    "pcIdentityInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "auditLogId": audit_log_id,
                        "eventTriggerType": SCAN_TYPE,
                        "osType": os_type,
                        "osName": os_name_info,
                        "serialNumber": serial_number,
                        "motherboardSerialNumber": motherboard_serial_number,
                        "ipAddress": ip_address,
                        "hostname": host_name,
                        "connectedToDomainName": is_pc_in_org_domain,
                        "systemManufacturer": system_manufacturer_info,
                        "systemModel": system_model_info,
                        "currentUser": current_loggedin_user,
                        "currentAgentVersion": current_setup_file_version,
                        "osVersion": os_version,
                        "licenseKey": LICENSE_KEY,
                        "securityStatus": security_status_info
                    },
                    "accountInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "additionalUserDetails": user_account_details,
                        "adminAccountsAreMultiple": is_multiple_admin_acc,
                        "usersPasswordAge": password_age_status,
                    },
                    "backendInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "endpointType": endpoint_type,
                        "installedPrograms": app_patch_info,
                        "osPatchInfo": os_patch_info,
                    },
                    "cisInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "cisFilesystemConfigurationInfo": cis_file_system_configuration_info,
                        "cisAuditPartitionsInfo": cis_audit_partitions_info,
                        "cisFilesystemIntegrityInfo": cis_filesystem_integrity_check,
                        "cisSecureBootSettingsInfo": cis_secure_boot_settings_info,
                        "cisAdditionalProcessHardeningInfo": cis_additional_process_hardening_info,
                        "cisSELinuxConfigureInfo": cis_selinux_info,
                        "cisSpecialPurposeServicesInfo": cis_special_purpose_services_info,
                        "cisServiceClientsInfo": cis_service_clients_info,
                        "cisNetworkConfigurationInfo": cis_network_configuration_info,
                        "cisConfigureFirewallInfo": cis_configure_firewall_info,
                        "cisConfigureFirewallRulesInfo": cis_configure_firewall_rules_info,
                        "cisSystemAuditingInfo": cis_system_auditing_info,
                        "cisLoggingAndAuditingInfo": cis_logging_and_auditing_info,
                        "cisSystemAccessAuthInfo": cis_system_access_and_authentication_info,
                        "cisConfigureSSHServerInfo": cis_ssh_server_info,
                        "cisConfigurePrivilegeEscalationInfo": cis_privilege_escalation_info,
                        "cisConfigurePamInfo": cis_pam_info,
                        "cisUserAccountsEnvironmentInfo": cis_user_accounts_environment_info,
                        "cisSystemFilePermissionsInfo": cis_system_file_permissions_info,
                        "cisGetUserAndGroupInfo": cis_get_user_and_group_info,
                        "cisBaseAndOsServicesInfo": cis_base_and_os_services_info,
                        "cisProcessHardeningInfo": cis_process_hardening_info,
                        "cisWarningBannersInfo": cis_warning_banners_info,
                        "cisDesktopConfInfo": cis_desktop_conf_info,
                    },
                    "hardwareInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "processorInfo": processor_info,
                        "machineBitType": machine_bit_type,
                        "machineType": machine_type,
                        "memoryInformation": memory_info,
                        "biosVersion": bios_version_info,
                        "timeZone": sys_time_zone_info,
                        "biosBatteryServiceable": bios_battery_serviceable_info,
                        "internalHardDrivesInfo": internal_disks_info,
                        "printers": printer_names_list,
                        "scanners": scanners_names_list,
                        "highCpuUsage": high_cpu_usage,
                        "ramUsage": ram_use,
                        "nicDetails": nicinfo,
                        "opticalDriveInfo": optical_drive_info,
                        "deviceUUIDNumber": uuid_number,
                        "tpmVersion": tmp_version
                    },
                    "networkInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "firewallStatus": firewall_status,
                        "firewallService": firewall_service,
                        "wifiStatus": wifi_info,
                        "ethernetStatus": ethernet_info,
                        "bluetoothInfo": bluetooth_info,
                        "establishedNetworkConnections": established_connections_list,
                        "openTcpPorts": open_tcp_ports_list,
                        "dnsServer": dns_info,
                        "nacInstalled": nac_info,
                        "ntpDetails": ntp_enabled,
                    },
                    "osInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "osDistributor": os_distributor,
                        "osRelease": os_release,
                        "osReleaseName": os_release_name,
                        "osVersion": os_version,
                        "osConfiguration": os_config_info,
                        "osInstallationDate": os_install_date_info,
                        "userHomeDirectory": user_home_dir,
                        "userProfileDirectory": user_profile_dir,
                        "startupPrograms": fetch_startup_programs,
                        "systemBootTime": system_boot_time_info,
                        "bootDevice": boot_device_information,
                        "sharedDirectories": shared_dir,
                        "servicesInfo": services_info,
                        "rdpStatus": rdp_status,
                        "auditLogs": audit_logs,
                        "avInfo": av_info,
                        "edrInstalled": edr_installed,
                    },
                    "errorInfo": {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        **error
                    }
                }
                html_report_info = {
                    "currentTime": current_time,
                    "pcId": pc_id,
                    "eventTriggerType": SCAN_TYPE,
                    "pcIdentityInfo": {
                        "osType": os_type,
                        "osName": os_name_info,
                        "serialNumber": serial_number,
                        "motherboardSerialNumber": motherboard_serial_number,
                        "ipAddress": ip_address,
                        "hostname": host_name,
                        "connectedToDomainName": is_pc_in_org_domain,
                        "systemManufacturer": system_manufacturer_info,
                        "systemModel": system_model_info,
                        "currentUser": current_loggedin_user,
                        "currentAgentVersion": current_setup_file_version,
                        "licenseKey": LICENSE_KEY,
                        "securityStatus": security_status_info
                    },
                    "accountInfo": {
                        "additionalUserDetails": user_account_details,
                        "adminAccountsAreMultiple": is_multiple_admin_acc,
                        "usersPasswordAge": password_age_status,
                    },
                    "backendInfo": {
                        "endpointType": endpoint_type,
                        "installedPrograms": app_patch_info,
                        "osPatchInfo": os_patch_info
                    },
                    "cisInfo": {
                        "cisFilesystemConfigurationInfo": cis_file_system_configuration_info,
                        "cisAuditPartitionsInfo": cis_audit_partitions_info,
                        "cisFilesystemIntegrityInfo": cis_filesystem_integrity_check,
                        "cisSecureBootSettingsInfo": cis_secure_boot_settings_info,
                        "cisAdditionalProcessHardeningInfo": cis_additional_process_hardening_info,
                        "cisSELinuxConfigureInfo": cis_selinux_info,
                        "cisSpecialPurposeServicesInfo": cis_special_purpose_services_info,
                        "cisServiceClientsInfo": cis_service_clients_info,
                        "cisNetworkConfigurationInfo": cis_network_configuration_info,
                        "cisConfigureFirewallInfo": cis_configure_firewall_info,
                        "cisConfigureFirewallRulesInfo": cis_configure_firewall_rules_info,
                        "cisSystemAuditingInfo": cis_system_auditing_info,
                        "cisLoggingAndAuditingInfo": cis_logging_and_auditing_info,
                        "cisSystemAccessAuthInfo": cis_system_access_and_authentication_info,
                        "cisConfigureSSHServerInfo": cis_ssh_server_info,
                        "cisConfigurePrivilegeEscalationInfo": cis_privilege_escalation_info,
                        "cisConfigurePamInfo": cis_pam_info,
                        "cisUserAccountsEnvironmentInfo": cis_user_accounts_environment_info,
                        "cisSystemFilePermissionsInfo": cis_system_file_permissions_info,
                        "cisGetUserAndGroupInfo": cis_get_user_and_group_info,
                        "cisBaseAndOsServicesInfo": cis_base_and_os_services_info,
                        "cisProcessHardeningInfo": cis_process_hardening_info,
                        "cisWarningBannersInfo": cis_warning_banners_info,
                        "cisDesktopConfInfo": cis_desktop_conf_info,
                    },
                    "hardwareInfo": {
                        "processorInfo": processor_info,
                        "machineBitType": machine_bit_type,
                        "machineType": machine_type,
                        "memoryInformation": memory_info,
                        "biosVersion": bios_version_info,
                        "timeZone": sys_time_zone_info,
                        "biosBatteryServiceable": bios_battery_serviceable_info,
                        "internalHardDrivesInfo": internal_disks_info,
                        "printers": printer_names_list,
                        "scanners": scanners_names_list,
                        "highCpuUsage": high_cpu_usage,
                        "ramUsage": ram_use,
                        "nicDetails": nicinfo,
                        "opticalDriveInfo": optical_drive_info,
                        "deviceUUIDNumber": uuid_number,
                        "tpmVersion": tmp_version
                    },
                    "networkInfo": {
                        "firewallStatus": firewall_status,
                        "firewallService": firewall_service,
                        "wifiStatus": wifi_info,
                        "ethernetStatus": ethernet_info,
                        "bluetoothInfo": bluetooth_info,
                        "establishedNetworkConnections": established_connections_list,
                        "openTcpPorts": open_tcp_ports_list,
                        "dnsServer": dns_info,
                        "nacInstalled": nac_info,
                        "ntpDetails": ntp_enabled,
                    },
                    "osInfo": {
                        "osDistributor": os_distributor,
                        "osRelease": os_release,
                        "osReleaseName": os_release_name,
                        "osVersion": os_version,
                        "osConfiguration": os_config_info,
                        "osInstallationDate": os_install_date_info,
                        "userHomeDirectory": user_home_dir,
                        "userProfileDirectory": user_profile_dir,
                        "startupPrograms": fetch_startup_programs,
                        "systemBootTime": system_boot_time_info,
                        "bootDevice": boot_device_information,
                        "sharedDirectories": shared_dir,
                        "servicesInfo": services_info,
                        "rdpStatus": rdp_status,
                        "auditLogs": audit_logs,
                        "avInfo": av_info,
                        "edrInstalled": edr_installed,
                    },
                    "errorInfo": {
                        **error
                    }
                }
                if SCAN_TYPE == "LINUX_INSTALLATION_TRIGGER":
                    usb_history_info = {
                        "currentTime": current_time,
                        "pcId": pc_id,
                        "eventTriggerType": SCAN_TYPE,
                        "usbStoredHistory": usb_stored_history_info,
                    }
                    system_info["usbInfo"] = usb_history_info
                    system_info["pcIdentityInfo"]["custodianName"] = custodian_name
                    html_report_info["usbInfo"] = usb_history_info
                    html_report_info["pcIdentityInfo"]["custodianName"] = custodian_name

                if SCAN_TYPE in ("LINUX_DAILY_TRIGGER", "LINUX_INSTALLATION_TRIGGER"):
                    system_info["backendInfo"]["fileIntegrityInfo"] = filesystem_integrity_info
                    html_report_info["backendInfo"]["fileIntegrityInfo"] = filesystem_integrity_info

        except Exception as system_info_error:
            error["miscellaneousInfo"]["system_info"] = repr(system_info_error)
            logging.error(f"Error while generating json: {system_info_error}")

        return system_info, html_report_info

    # calling the get system info function
    return get_system_info()


@logger_function
def get_current_audit_agent_file_hash():
    """
    Calculate SHA-512 hash of the current file.

    Returns:
    str: SHA-512 hash value of the current file, or an empty string if there's an error.
    """
    try:
        current_file_path = AGENT_EXE_FILE_PATH
        logging.info(f"Calculating hash of the current file: {current_file_path}")
        if os.path.exists(current_file_path):
            sha512 = hashlib.sha512()
            with open(current_file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha512.update(chunk)

            current_file_hash = sha512.hexdigest()
            logging.info("Hash calculation completed successfully.")
            return str(current_file_hash)  # Ensure returning a string
        else:
            current_file_path = "./" + AGENT_FILE_NAME
            logging.info(f"Calculating hash of the current file: {current_file_path}")
            sha512 = hashlib.sha512()
            with open(current_file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha512.update(chunk)

            current_file_hash = sha512.hexdigest()
            logging.info("Hash calculation completed successfully.")
            return str(current_file_hash)  # Ensure returning a string
    except Exception as e:
        logging.error(f"Error calculating hash of the current file: {str(e)}")
        return ""


def send_encrypted_log_to_backend_api(encrypted_log, ca_api_url):
    # Log the backend URL
    logging.info(f"Backend URL ->  {ca_api_url}")
    # Sending the POST request to the backend-api
    try:

        logging.info(f"Encrypted Data Length: {len(encrypted_log)}")
        logging.info("Sending the encrypted log to the backend API...")
        # Convert bytes-like object to string using UTF-8 decoding
        encrypted_log_string = encrypted_log.decode('utf-8')

        # Create the API payload
        api_payload = {"encryptedData": encrypted_log_string}
        api_response = requests.post(ca_api_url, json=api_payload, timeout=30, verify=CA_FILE)

        # Log the API response status code and text
        logging.info(f"API Response: {api_response}")
        logging.info(f"API Response Status Code: {api_response.status_code}")
        logging.info(f"API Response Text: {api_response.text}")
        if api_response.status_code == 400:
            if '{"errors":' in api_response.text:
                return "UNINGESTABLE"
        # Return True if the request was successful else return False
        return api_response.ok
    except requests.ConnectionError as conn_error:
        logging.error(f"Connection error occurred: {conn_error}")
        return "CONNECTION_ERROR"
    except requests.Timeout as timeout_error:
        logging.error(f"Request timed out: {timeout_error}")
        return "TIMEOUT_ERROR"
    except requests.RequestException as request_exception:
        logging.error(f"Request exception occurred: {request_exception}")
        return False
    except Exception as backend_api_post_error:
        logging.error(f"An unexpected error occurred: {backend_api_post_error}")
        return False


def encrypt_audit_data(ca_audit_info):
    try:
        # Generate audit hash
        def generate_audit_hash(data):
            try:
                # Encode JSON data
                encode_json_data = data.encode()

                # Generate SHA512 Hash
                hash_object = hashlib.sha512(encode_json_data)

                # Get Hex Digest
                return hash_object.hexdigest()
            except Exception as generate_audit_hash_error:
                logging.error(f"generate_audit_hash_error: {generate_audit_hash_error}")
                return None

        # Generate Audit Hash
        audit_hash = generate_audit_hash(ca_audit_info)
        logging.info(f"Audit hash generated: {audit_hash}")

        if audit_hash is None:
            logging.error(f"Audit hash is None, returning False")
            return False

        # Load and import the RSA public key
        try:
            # Ensure the public key is imported correctly
            public_key = RSA.import_key(CA_PUBLIC_KEY)
        except ValueError as e:
            logging.error(f"Error importing public key: {e}")
            return False

        # Encrypt data with public key
        def encrypt_with_public_key(data):
            try:
                # Ensure data is in bytes before encryption
                data_bytes = data.encode('utf-8') if isinstance(data, str) else data

                # Create a cipher using OAEP with SHA256
                cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

                # Encrypt the data
                encrypted_data = cipher.encrypt(data_bytes)

                # Return base64 encoded encrypted data
                return base64.b64encode(encrypted_data).decode()
            except Exception as encrypt_with_public_key_error:
                logging.error(f"encrypt_with_public_key_error: {encrypt_with_public_key_error}")
                return None

        # Encrypt the audit hash
        encrypted_hash = encrypt_with_public_key(audit_hash)
        logging.info(f"Encrypted audit hash: {encrypted_hash}")

        # Encrypt the agent file hash (assuming get_current_audit_agent_file_hash exists)
        audit_agent_file_hash = get_current_audit_agent_file_hash()
        encrypted_agent_file_hash = encrypt_with_public_key(audit_agent_file_hash)
        logging.info(f"Encrypted agent file hash: {encrypted_agent_file_hash}")

        # Prepare the output data
        audit_log_json = json.loads(ca_audit_info)
        audit_output_data = {
            "auditLog": audit_log_json,
            "auditHash": encrypted_hash,
            "agentFileHash": encrypted_agent_file_hash
        }

        # Write the raw content to the file in VISIBLE_AUDIT_LOGS_DESTINATION_DIRECTORY
        current_time = time.strftime("%d-%m-%Y-%H:%M:%S")
        if LOGS_NEEDED:
            ca_raw_log_output_file_name = (
                os.path.join(VISIBLE_AUDIT_LOGS_DESTINATION_DIRECTORY, f"ca-audit-{SCAN_TYPE}-{current_time}.json"))

            # Write the raw content to the file
            with open(ca_raw_log_output_file_name, 'w') as raw_json_file:
                raw_json_file.write(json.dumps(audit_output_data, indent=4))

        # Encrypt the audit log JSON in chunks
        payload_json_audit_output = json.dumps(audit_output_data)
        chunk_size = 190
        encrypted_chunks = []
        data_bytes = payload_json_audit_output.encode('utf-8')

        # Create the cipher using OAEP with SHA256
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

        # Process data in chunks
        for i in range(0, len(data_bytes), chunk_size):
            chunk = data_bytes[i:i + chunk_size]

            # Encrypt the chunk
            encrypted_chunk = cipher.encrypt(chunk)

            # Append the encrypted chunk to the list
            encrypted_chunks.append(encrypted_chunk)

        # Combine and encode the chunks
        encrypted_data = b''.join(encrypted_chunks)
        encrypted_base64_data = base64.b64encode(encrypted_data)
        logging.info("Final encrypted base64 data prepared.")

        logging.info(f"Encrypted data length: {len(encrypted_base64_data)}")
        logging.info("Sending encrypted log to backend API...")

        if SCAN_TYPE != "LINUX_NETWORK_TRIGGER":
            logging.info("As SCAN_TYPE != 'LINUX_NETWORK_TRIGGER', sending directly to the backend API.")
            log_sent_status = send_encrypted_log_to_backend_api(encrypted_base64_data, BACKEND_API_URL)
            if log_sent_status != "UNINGESTABLE" and log_sent_status is not True:
                current_time = time.strftime("%d-%m-%Y-%H-%M-%S")
                logging.info(f"Since internet is not available, or failed to send the encrypted audit log, for now, "
                             f"creating encrypted audit log file in {ENCRYPTED_AUDIT_LOGS_DIRECTORY}.")

                ca_log_output_file_name = (
                    os.path.join(ENCRYPTED_AUDIT_LOGS_DIRECTORY, f"ca-audit-{current_time}.log"))

                logging.info(f"ca_log_output_file_name: {ca_log_output_file_name}")

                # Write the encrypted content to the file
                with open(ca_log_output_file_name, 'wb') as encrypted_file:
                    encrypted_file.write(encrypted_base64_data)
                return False
            else:
                return True
        else:
            # Create a timestamp for the ca_log_output_file_name
            current_time = time.strftime("%d-%m-%Y-%H-%M-%S")
            logging.info(f"creating encrypted audit log file in {ENCRYPTED_AUDIT_LOGS_DIRECTORY}.")

            ca_log_output_file_name = (
                os.path.join(ENCRYPTED_AUDIT_LOGS_DIRECTORY, f"ca-audit-{current_time}.log"))

            logging.info(f"ca_log_output_file_name: {ca_log_output_file_name}")

            # Write the encrypted content to the file
            with open(ca_log_output_file_name, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_base64_data)

            # Length of ca_log_output_file_name
            logging.info(f"Length of ca_log_output_file_name: {os.path.getsize(ca_log_output_file_name)}")

            def check_log_file():
                try:
                    if os.path.exists(ca_log_output_file_name):
                        if os.path.getsize(ca_log_output_file_name) > 0:
                            logging.info(f"File {ca_log_output_file_name} exists and is not empty.")
                            return True
                        else:
                            logging.warning(f"File {ca_log_output_file_name} exists but is empty.")
                            return False
                    else:
                        logging.warning(f"File {ca_log_output_file_name} does not exist.")
                        return False
                except Exception as check_log_file_error:
                    logging.error(f"File Check Error: {check_log_file_error}")
                    return False

            logging.info(f"Calling check_log_file() function.")
            return check_log_file()
    except Exception as encrypt_audit_data_error:
        logging.error(f"Encryption Error: {encrypt_audit_data_error}")
        return False


def send_remaining_encrypted_log_files_to_backend(var_log_folder, api_url, is_send_file):
    try:
        logging.info("Since, Internet is available. Checking for LOG files...")
        # List log files in the var log folder ending with ".log"
        log_files = [
            os.path.join(var_log_folder, file_name)
            for file_name in os.listdir(var_log_folder)
            if file_name.endswith(".log")
        ]
        # Count of log_files
        log_files_count = len(log_files)
        logging.info(f"Count of LOG files: {log_files_count}")

        # Sort log files by creation time in descending order
        encrypted_log_files_list = sorted(
            log_files,
            key=os.path.getctime
        )
        logging.info(f"All encrypted LOG files present in {var_log_folder}: {encrypted_log_files_list}")
        try:
            logging.info("Looping through all LOG files...")
            for file_name in encrypted_log_files_list:
                if file_name.endswith(".log"):
                    encrypted_log_file_name_with_path = os.path.join(var_log_folder, file_name)
                    logging.info(f"Encrypted Log file path: {encrypted_log_file_name_with_path}")
                    if os.path.exists(encrypted_log_file_name_with_path):
                        try:
                            # Read the encrypted file
                            with open(encrypted_log_file_name_with_path, 'rb') as encrypted_file:
                                encrypted_audit_data_to_send = encrypted_file.read()

                            log_sent_status = False
                            if is_send_file is True:
                                logging.info(f"Sending LOG file to backend API...")
                                logging.info(f"Calling function named "
                                             f"send_encrypted_agent_log_to_bucket_api"
                                             f"(encrypted_audit_data_to_send, BACKEND_API_URL)."
                                             f"to send log named {file_name}.")

                                # log_sent_status = (
                                #     send_encrypted_agent_log_to_bucket_api(encrypted_log_file_name_with_path,
                                #                                            api_url))
                            else:
                                logging.info(f"Successfully read LOG data from file.")
                                logging.info(f"Calling function named "
                                             f"send_encrypted_log_to_backend_api(encrypted_audit_data_to_send, "
                                             f"BACKEND_API_URL)."
                                             f"to send log named {file_name}.")

                                log_sent_status = send_encrypted_log_to_backend_api(encrypted_audit_data_to_send,
                                                                                    api_url)

                            logging.info(f"Log sent status: {log_sent_status}")

                            if log_sent_status is True or log_sent_status == "UNINGESTABLE":
                                logging.info(f"Successfully sent LOG data to backend API.")
                                os.remove(encrypted_log_file_name_with_path)
                                logging.info(f"Successfully deleted LOG file: "
                                             f"{encrypted_log_file_name_with_path}")
                            elif log_sent_status == "CONNECTION_ERROR" or log_sent_status == "TIMEOUT_ERROR":
                                logging.error(f"Failed to send LOG data to backend API.")
                                break
                            else:
                                logging.warning(f"Failed to send LOG data to backend API.")

                        except Exception as backend_api_error:
                            logging.error(f"Error while sending LOG data to backend API: "
                                          f"{repr(backend_api_error)}")
        except Exception as maintain_at_backend_error:
            logging.error(f"Error in maintaining log files: {repr(maintain_at_backend_error)}")

    except Exception as log_maintain_at_backend_error:
        logging.error(f"Error in function->send_remaining_encrypted_log_files_to_backend: "
                      f"{repr(log_maintain_at_backend_error)}")

    return None


def generate_visible_agent_log_file(logged_messages):
    # Write the raw content to the file in VISIBLE_AUDIT_LOGS_DESTINATION_DIRECTORY
    try:
        current_log_time = time.strftime("%d-%m-%Y-%H-%M-%S")
        ca_raw_agent_log_output_file_name = (
            os.path.join(VISIBLE_AGENT_LOGS_DESTINATION_DIRECTORY,
                         f"ca-agent-{SCAN_TYPE}-{current_log_time}.log"))
        with open(ca_raw_agent_log_output_file_name, "w") as ca_raw_agent_logger_file:
            ca_raw_agent_logger_file.write(logged_messages)
    except Exception as gen_vis_agent_err:
        logging.error(f"Error in generating visible agent log: "
                      f"{repr(gen_vis_agent_err)}")


if __name__ == "__main__":
    try:
        if platform.system() == "Linux":
            # Setup the logger
            setup_logger_sucessful_status, logger_output_holder = setup_logger_function()
            if setup_logger_sucessful_status:
                logging.info("----------------------------------------------------------------------------------------")
                get_hostname_from_env()
                add_audit_info_to_log()
                add_process_id_to_maintain()
                start_time = datetime.now()
                start_time_formatted = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                logging.info(f"Starting Linux Agent for trigger-type - {SCAN_TYPE}")
                lic_key = get_lic_key_from_env()
                logging.info(f"license key found: {lic_key}")
                os_distributor_name = get_os_distributor_name()
                logging.info(f"Extracted os-distributor name: {os_distributor_name}")
                if os_distributor_name == "ubuntu":
                    audit_system_info, html_report = get_ubuntu_system_info()
                else:
                    audit_system_info, html_report = get_redhat_system_info()

                audit_info = json.dumps(audit_system_info, indent=4)
                # current_agent_version = audit_system_info['pcIdentityInfo']['currentAgentVersion']
                # logging.info(f"Linux Agent extraction completed for version {current_agent_version}.")

                # ----- Generating HTML report ------------------------------------------------------------------
                try:
                    if html_report:
                        html_table = generate_html(json.loads(json.dumps(html_report, indent=4)))
                        output_html_log_file_name = "CA-Audit-Report.html"
                        output_html_log_file_name_path = os.path.join(LOGS_DESTINATION_DIRECTORY,
                                                                      output_html_log_file_name)

                        # Write the HTML table to the output HTML file
                        with open(output_html_log_file_name_path, "w") as output_html_file:
                            output_html_file.write(html_table)
                except Exception as generate_html_error:
                    logging.error(f"Error while generating HTML report: {repr(generate_html_error)}")

                # ----- Encrypting and sending logs to backend API ----------------------------------------------
                try:
                    logging.info(f"Storing logs at path: {LOGS_DESTINATION_DIRECTORY}")
                    if not os.path.exists(LOGS_DESTINATION_DIRECTORY):
                        logging.info(f"Since {LOGS_DESTINATION_DIRECTORY} does not exist. Creating it.")
                        os.mkdir(LOGS_DESTINATION_DIRECTORY)

                    if not os.path.exists(ENCRYPTED_AUDIT_LOGS_DIRECTORY):
                        logging.info(f"Since {ENCRYPTED_AUDIT_LOGS_DIRECTORY} does not exist. Creating it.")
                        os.mkdir(ENCRYPTED_AUDIT_LOGS_DIRECTORY)

                    if LOGS_NEEDED:
                        if not os.path.exists(VISIBLE_AUDIT_LOGS_DESTINATION_DIRECTORY):
                            logging.info(
                                f"Since {VISIBLE_AUDIT_LOGS_DESTINATION_DIRECTORY} does not exist. Creating it.")
                            os.mkdir(VISIBLE_AUDIT_LOGS_DESTINATION_DIRECTORY)

                        if not os.path.exists(VISIBLE_AGENT_LOGS_DESTINATION_DIRECTORY):
                            logging.info(
                                f"Since {VISIBLE_AGENT_LOGS_DESTINATION_DIRECTORY} does not exist. Creating it.")
                            os.mkdir(VISIBLE_AGENT_LOGS_DESTINATION_DIRECTORY)

                        if not os.path.exists(ENCRYPTED_AGENT_LOGS_DIRECTORY):
                            logging.info(f"Since {ENCRYPTED_AGENT_LOGS_DIRECTORY} does not exist. Creating it.")
                            os.mkdir(ENCRYPTED_AGENT_LOGS_DIRECTORY)

                    # Encrypt audit log
                    logging.info(f"Encrypting audit log.")
                    encrypt_audit_data(audit_info)
                    if SCAN_TYPE in ("LINUX_NETWORK_TRIGGER", "LINUX_DAILY_TRIGGER", "LINUX_INTERVAL_TRIGGER"):
                        logging.info(f"Sending audit logs to backend API.")
                        logging.info("Calling function send_remaining_encrypted_log_files_to_backend()")
                        send_remaining_encrypted_log_files_to_backend(ENCRYPTED_AUDIT_LOGS_DIRECTORY,
                                                                      BACKEND_API_URL, False)
                        logging.info(f"Sending logs to backend API completed.")
                except Exception as encrypt_and_send_logs_error:
                    logging.error(f"Error while encrypting and sending logs to backend API: "
                                  f"{repr(encrypt_and_send_logs_error)}")

                # --------------------------Send CyberAuditor Notification Toast in LINUX----------------------
                if SCAN_TYPE in ("LINUX_INTERVAL_TRIGGER", "LINUX_DAILY_TRIGGER", "LINUX_INSTALLATION_TRIGGER"):
                    try:
                        icon_path = DESTINATION_WORKING_DIRECTORY + "ca-icon.ico"
                        audit_notif_title = 'Alert!'
                        audit_notif_message = f"Hi {platform.node()},\nyour system has been audited by CyberAuditor."
                        notification_status = send_linux_notification(audit_notif_title, audit_notif_message,
                                                                      icon_path)
                        logging.info(f"notification_status: {notification_status}")
                    except Exception as mainblockerror:
                        logging.error(f"mainblockerror: {mainblockerror}")
                # ---------------------------------------------------------------------------------------------

                try:
                    # Get the end time
                    end_time = datetime.now()

                    # Log the end of the Linux Agent
                    logging.info(f'Linux Agent Script ends at {end_time}')

                    # Calculate the total execution time
                    total_execution_time = end_time - start_time

                    # Log the total execution time
                    logging.info(f'Linux Agent Script total execution time: {total_execution_time}')
                    logging.info(
                        "--------------------------------------------------------------------------------------")
                    agent_logged_messages = logger_output_holder.getvalue()
                    logger_output_holder.truncate(0)
                    if LOGS_NEEDED:
                        generate_visible_agent_log_file(agent_logged_messages)
                except Exception as log_block_err:
                    print(f"Error in logs block: {repr(log_block_err)}")
            else:
                print(f"Error setting up the logger. setup_logger_sucessful_status: {setup_logger_sucessful_status}")
        else:
            print("This script is only for Linux.")
    except Exception as mainerror:
        print(f"Error occured in audit-agent.exe script: {mainerror}")

# Script completes here
