import pyudev
import time
import json
import logging
import os
import re
from datetime import datetime
import pytz
import requests  # For Telegram integration
from threading import Thread
from colorama import init, Fore, Style  # For colored console output
import psutil  # For network interface monitoring
import socket  # For AF_INET in psutil
import subprocess  # For ADB queries
import getpass  # To check if running as root

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# === Configuration ===
# IMPORTANT: Replace these with your actual Telegram Bot Token and Chat ID
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"  # <<<<<<< REPLACE THIS!
TELEGRAM_CHAT_ID = 123456789  # <<<<<<< REPLACE THIS! (Must be an integer)

# Check if Telegram is configured
TELEGRAM_CONFIGURED = TELEGRAM_BOT_TOKEN != "YOUR_TELEGRAM_BOT_TOKEN" and TELEGRAM_CHAT_ID != 123456789
if not TELEGRAM_CONFIGURED:
    print(f"{Fore.YELLOW}[!] Warning: Telegram bot token or chat ID not configured. Telegram notifications will be disabled.{Style.RESET_ALL}")

# Check if running as root (required for blocking devices)
if getpass.getuser() != 'root':
    print(f"{Fore.YELLOW}[!] Warning: This script requires root privileges for device blocking. Please run with sudo.{Style.RESET_ALL}")

# IST Timezone for logging timestamps
IST = pytz.timezone("Asia/Kolkata")

def current_time_ist():
    """Returns the current time in IST (Indian Standard Time)."""
    return datetime.now(pytz.utc).astimezone(IST)

# Paths and folders for logs and data
LOG_DIR = "logs"
KNOWN_LOG = os.path.join(LOG_DIR, "known_usb_activity.json")
ANON_DIR = os.path.join(LOG_DIR, "anonymous_devices")  # Dedicated for unknown device details
ACTIVITY_LOG = os.path.join(LOG_DIR, "activity.log")  # General activity log
WHITELIST_FILE = "whitelist.json"

# Ensure log directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(ANON_DIR, exist_ok=True)

# Logging setup
logging.basicConfig(
    filename=ACTIVITY_LOG,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - Cyber_Buddy: %(message)s'  # Added "Cyber_Buddy:" for clarity
)
logger = logging.getLogger("Cyber_Buddy")

# Global variable to store known network interfaces
initial_net_interfaces = set()

# --- Helper Functions ---

def escape_markdown_v2(text):
    """Escapes special characters for Telegram MarkdownV2."""
    if text is None:
        return "N/A"
    # Characters that need escaping: _, *, [, ], (, ), ~, `, >, #, +, -, =, |, {, }, ., !
    return text.replace('_', '\\_').replace('*', '\\*').replace('[', '\\[').replace(']', '\\]').replace('(', '\\(').replace(')', '\\)').replace('~', '\\~').replace('`', '\\`').replace('>', '\\>').replace('#', '\\#').replace('+', '\\+').replace('-', '\\-').replace('=', '\\=').replace('|', '\\|').replace('{', '\\{').replace('}', '\\}').replace('.', '\\.').replace('!', '\\!')

def send_telegram_message(message):
    """Sends a message to the configured Telegram chat asynchronously."""
    if not TELEGRAM_CONFIGURED:
        logger.warning("Telegram notification skipped: Bot token or chat ID not configured.")
        return
    def send():
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "MarkdownV2"}
        try:
            resp = requests.post(url, data=payload, timeout=10)
            if resp.status_code == 200:
                logger.info("Telegram alert sent successfully.")
            else:
                logger.warning(f"Telegram alert failed: {resp.status_code} - {resp.text}")
        except requests.exceptions.Timeout:
            logger.error("Telegram message send timed out.")
        except requests.exceptions.ConnectionError:
            logger.error("Telegram message send failed: Connection error (No internet or Telegram API unreachable).")
        except Exception as e:
            logger.error(f"Telegram message send failed: {e}")
    Thread(target=send).start()

def capture_initial_network_interfaces():
    """Captures the set of active network interface names."""
    global initial_net_interfaces
    initial_net_interfaces = set(psutil.net_if_addrs().keys())
    logger.debug(f"Initial network interfaces captured: {initial_net_interfaces}")

def get_new_network_interfaces(timeout=5):
    """
    Checks for new network interfaces that appeared since initial capture.
    Returns a list of new interface names.
    """
    new_interfaces = []
    end_time = time.time() + timeout
    while time.time() < end_time:
        current_interfaces = set(psutil.net_if_addrs().keys())
        newly_added = current_interfaces - initial_net_interfaces
        if newly_added:
            new_interfaces = list(newly_added)
            logger.info(f"Detected new network interfaces: {new_interfaces}")
            return new_interfaces
        time.sleep(0.5)  # Poll every 0.5 seconds
    logger.debug("No new network interfaces detected within timeout.")
    return new_interfaces

def get_removed_network_interfaces(timeout=5):
    """
    Checks for removed network interfaces since initial capture.
    Returns a list of removed interface names.
    """
    removed_interfaces = []
    end_time = time.time() + timeout
    while time.time() < end_time:
        current_interfaces = set(psutil.net_if_addrs().keys())
        disappeared = initial_net_interfaces - current_interfaces
        if disappeared:
            removed_interfaces = list(disappeared)
            logger.info(f"Detected removed network interfaces: {removed_interfaces}")
            return removed_interfaces
        time.sleep(0.5)  # Poll every 0.5 seconds
    logger.debug("No removed network interfaces detected within timeout.")
    return removed_interfaces

def get_network_info_for_interface(interface_name):
    """Retrieves MAC and IPv4 address for a given network interface."""
    addresses = psutil.net_if_addrs()
    if interface_name in addresses:
        mac_address = None
        ip_address = None
        for addr in addresses[interface_name]:
            if addr.family == psutil.AF_LINK:  # MAC address
                mac_address = addr.address
            elif addr.family == socket.AF_INET:  # IPv4 address
                ip_address = addr.address
        return mac_address, ip_address
    return None, None

def get_adb_device_info(serial_number=None):
    """
    Attempts to get Wi-Fi MAC and IP address for an Android device via ADB.
    Requires ADB to be installed and the device authorized.
    """
    logger.info(f"Attempting ADB query for serial: {serial_number if serial_number else 'any connected device'}")
    try:
        adb_devices_output = subprocess.run(["adb", "devices"], capture_output=True, text=True, check=True, timeout=5).stdout
        
        target_device_id = None
        for line in adb_devices_output.splitlines():
            if "\tdevice" in line:  # Checks if device is connected and authorized
                device_id = line.split('\t')[0].strip()
                if serial_number and device_id == serial_number:
                    target_device_id = device_id
                    break
                elif not serial_number:  # If no specific serial, just take the first authorized
                    target_device_id = device_id
                    break
        
        if not target_device_id:
            logger.info("No authorized ADB device found matching the serial number or no device connected.")
            return None, None  # Device not found or not authorized via ADB

        # Get IP Address (assuming wlan0 for Wi-Fi)
        ip_cmd = ["adb", "-s", target_device_id, "shell", "ip addr show wlan0"]
        ip_output = subprocess.run(ip_cmd, capture_output=True, text=True, check=True, timeout=5).stdout
        ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", ip_output)
        ip_address = ip_match.group(1) if ip_match else "N/A"

        # Get MAC Address (assuming wlan0 for Wi-Fi)
        mac_cmd = ["adb", "-s", target_device_id, "shell", "ip link show wlan0"]
        mac_output = subprocess.run(mac_cmd, capture_output=True, text=True, check=True, timeout=5).stdout
        mac_match = re.search(r"link/ether ([0-9A-Fa-f:]{17})", mac_output)
        mac_address = mac_match.group(1) if mac_match else "N/A"

        logger.info(f"ADB info for {target_device_id}: MAC={mac_address}, IP={ip_address}")
        return mac_address, ip_address

    except subprocess.TimeoutExpired:
        logger.warning("ADB command timed out. Device might be slow to respond or not properly set up.")
        return None, None
    except subprocess.CalledProcessError as e:
        logger.warning(f"ADB command failed for {serial_number}: {e}. Ensure ADB is installed and device is authorized. Stderr: {e.stderr.strip()}")
        return None, None
    except FileNotFoundError:
        logger.error("ADB not found. Please install Android SDK Platform-Tools and ensure adb is in PATH.")
        return None, None
    except Exception as e:
        logger.error(f"Error getting ADB device info for {serial_number}: {e}")
        return None, None

# --- Whitelist Management Functions ---

def load_whitelist():
    """Loads the whitelist of allowed USB devices from a JSON file."""
    try:
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, dict) and "allowed_devices" in data:
                    return data["allowed_devices"]
                else:
                    logger.error(f"{WHITELIST_FILE} has unexpected format. Re-creating.")
        
        with open(WHITELIST_FILE, "w") as f:
            json.dump({"allowed_devices": []}, f, indent=4)
        return []
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from {WHITELIST_FILE}. Creating a new empty whitelist.")
        with open(WHITELIST_FILE, "w") as f:
            json.dump({"allowed_devices": []}, f, indent=4)
        return []
    except Exception as e:
        logger.error(f"Error loading whitelist: {e}")
        return []

def save_whitelist(whitelist):
    """Saves the current whitelist to a JSON file."""
    try:
        with open(WHITELIST_FILE, "w") as f:
            json.dump({"allowed_devices": whitelist}, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving whitelist: {e}")

def is_whitelisted(dev_id, serial, whitelist):
    """Checks if a given device (by ID and serial) is in the whitelist."""
    for entry in whitelist:
        if entry.get("device_id") == dev_id and entry.get("serial") == serial:
            return True
    return False

# --- Logging and Alerting Functions ---

def log_known_usb_activity(dev_id, serial, connected_since):
    """Logs the usage duration of a known (whitelisted) USB device."""
    duration = (current_time_ist() - connected_since).total_seconds()
    entry = {
        "device_id": dev_id,
        "serial": serial,
        "connected_at": connected_since.strftime("%Y-%m-%d %H:%M:%S %Z%z"),
        "disconnected_at": current_time_ist().strftime("%Y-%m-%d %H:%M:%S %Z%z"),
        "duration_seconds": round(duration, 2)
    }
    data = []
    if os.path.exists(KNOWN_LOG) and os.path.getsize(KNOWN_LOG) > 0:
        try:
            with open(KNOWN_LOG, "r") as f:
                data = json.load(f)
            if not isinstance(data, list):
                logger.warning(f"Known USB activity log {KNOWN_LOG} is not a list. Resetting.")
                data = []
        except json.JSONDecodeError:
            logger.warning(f"Known USB activity log {KNOWN_LOG} is corrupted or empty. Starting fresh.")
            data = []
        except Exception as e:
            logger.error(f"Error reading known USB activity log: {e}")
            data = []
    
    data.append(entry)
    try:
        with open(KNOWN_LOG, "w") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Known USB {dev_id} (serial {serial}) used for {duration:.2f} seconds.")
    except Exception as e:
        logger.error(f"Error writing known USB activity log: {e}")

def log_and_alert_unknown_device(device, dev_id, serial, mac_address=None, ip_address=None):
    """Logs unknown device information, sends Telegram alert, and attempts to block it."""
    timestamp = current_time_ist().strftime("%Y-%m-%d %H:%M:%S %Z%z")
    
    device_info = {
        "timestamp": timestamp,
        "device_id": dev_id,
        "serial": serial,
        "vendor": device.get("ID_VENDOR", "Unknown"),
        "model": device.get("ID_MODEL", "Unknown"),
        "product": device.get("ID_PRODUCT", "Unknown"),
        "vendor_id": device.get("ID_VENDOR_ID", "0000"),
        "model_id": device.get("ID_MODEL_ID", "0000"),
        "device_path": device.device_node,
        "usb_driver": device.get("ID_USB_DRIVER", "N/A"),
        "devtype": device.get("DEVTYPE", "N/A"),
        "subsystem": device.get("SUBSYSTEM", "N/A"),
        "driver": device.get("DRIVER", "N/A"),
        "sys_path": device.sys_path,
        "mac_address": mac_address,  # Include MAC if found
        "ip_address": ip_address,    # Include IP if found
        "properties": {k: v for k, v in device.items() if k not in ["DEVPATH", "MAJOR", "MINOR", "SEQNUM", "SUBSYSTEM", "UDEV_LOG", "ACTION"]}
    }

    file_name = f"unknown_{dev_id.replace(':', '-')}_{current_time_ist().strftime('%Y%m%d%H%M%S')}.json"
    file_path = os.path.join(ANON_DIR, file_name)
    
    try:
        with open(file_path, 'w') as f:
            json.dump(device_info, f, indent=4)
        logger.info(f"Detailed unknown device info saved to: {file_path}")
    except Exception as e:
        logger.error(f"Error saving unknown device info to file {file_path}: {e}")

    # Prepare Telegram alert message
    alert_msg_parts = [
        f"🚨 *ALERT\\! Unknown USB Device Detected\\!* 🚨\n",
        f"*Time:* `{escape_markdown_v2(timestamp)}`",
        f"*Device ID \\(VID:PID\\):* `{escape_markdown_v2(dev_id)}`",
        f"*Serial Number:* `{escape_markdown_v2(serial)}`",
        f"*Vendor:* `{escape_markdown_v2(device_info['vendor'])}`",
        f"*Model:* `{escape_markdown_v2(device_info['model'])}`",
        f"*Type:* `{escape_markdown_v2(device_info['usb_driver'])}`"
    ]
    if mac_address:
        alert_msg_parts.append(f"*MAC Address:* `{escape_markdown_v2(mac_address)}`")
    if ip_address:
        alert_msg_parts.append(f"*IP Address:* `{escape_markdown_v2(ip_address)}`")
    
    alert_msg_parts.append("\n*Action:* Attempted to block connection\\.")
    alert_msg_parts.append(f"\\(Details in logs and `{escape_markdown_v2(file_path)}`\\)")

    alert_msg = "\n".join(alert_msg_parts)
    
    # Log to main activity.log (plain text, concise)
    logger.warning(f"UNKNOWN DEVICE DETECTED: {dev_id} (Serial: {serial}). "
                   f"MAC: {mac_address if mac_address else 'N/A'}, IP: {ip_address if ip_address else 'N/A'}. "
                   f"Detailed info in '{file_path}'. Attempting to block.")
    
    # Print to console in RED (minimal info for security)
    print(f"{Fore.RED}\n!!! ALERT: UNKNOWN USB DEVICE DETECTED !!!")
    print(f"{Fore.RED}  Time: {timestamp}")
    if mac_address:
        print(f"{Fore.RED}  MAC: {mac_address}")
    if ip_address:
        print(f"{Fore.RED}  IP: {ip_address}")
    print(f"{Fore.RED}  Attempting to block device...{Style.RESET_ALL}")

    send_telegram_message(alert_msg)

    # Attempt to block device by setting authorized to 0 (requires root)
    dev_sys_path = device.sys_path
    authorized_path = os.path.join(dev_sys_path, 'authorized')
    if os.path.exists(authorized_path):
        try:
            with open(authorized_path, 'w') as f:
                f.write('0')
            logger.info(f"Successfully blocked unknown device by setting authorized to 0: {dev_id}")
            print(f"{Fore.GREEN}  Successfully blocked device.{Style.RESET_ALL}")
        except PermissionError:
            logger.warning(f"Permission denied to block unknown device {dev_id}. Run the script as root for blocking capabilities.")
            print(f"{Fore.YELLOW}  WARNING: Permission denied. Run as root to enable blocking.{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"Failed to block unknown device {dev_id}: {e}")
            print(f"{Fore.YELLOW}  WARNING: Failed to block device: {e}{Style.RESET_ALL}")
    else:
        logger.warning(f"Authorized file not found for {dev_id} (serial: {serial}); cannot disable device.")
        print(f"{Fore.YELLOW}  WARNING: Authorized file not found for blocking.{Style.RESET_ALL}")
        send_telegram_message(f"🚫 *Warning:* Could not find authorized file for unknown device `{escape_markdown_v2(dev_id)}` \\({escape_markdown_v2(serial)}\\)\\. Automatic blocking may not have been successful\\.")

# --- Whitelist Management Menu Functions ---

def whitelist_adder():
    """Interactive function to add a device to the whitelist."""
    print(f"{Fore.CYAN}\n--- Whitelist Adder ---{Style.RESET_ALL}")
    
    device_type = ""
    while not device_type or device_type.strip() == "":
        device_type = input(f"{Fore.YELLOW}Enter device type (e.g., pendrive, mobile, keyboard, mouse, other): {Style.RESET_ALL}").strip().lower()
        if not device_type:
            print(f"{Fore.RED}[!] Device type cannot be empty. Please enter a valid type.{Style.RESET_ALL}")

    choice = input(f"{Fore.YELLOW}Do you want to connect the device now for auto-detection? (y/n): {Style.RESET_ALL}").strip().lower()

    whitelist = load_whitelist()

    if choice == 'y':
        print(f"{Fore.YELLOW}\n[!] Connect your device now and wait for detection (max 15 seconds)...{Style.RESET_ALL}")
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by("usb")
        
        device_detected = False
        start_time = time.time()
        while time.time() - start_time < 15:
            device = monitor.poll(timeout=1)
            if device and device.action == "add" and device.get("DEVTYPE") == "usb_device":
                vid = device.get("ID_VENDOR_ID", "").upper()
                pid = device.get("ID_MODEL_ID", "").upper()
                dev_id = f"{vid}:{pid}"
                serial = device.get("ID_SERIAL_SHORT", "N/A")
                
                if not (vid and pid and vid != "0000" and pid != "0000") or serial == "N/A" or not serial.strip():
                    print(f"{Fore.YELLOW}[!] Auto-detected device has incomplete or generic ID/Serial (VID:{vid}, PID:{pid}, Serial:{serial}). "
                          "Cannot reliably whitelist. Please ensure the device has unique identifiers or try manual entry if appropriate.{Style.RESET_ALL}")
                    logger.warning(f"Skipping auto-whitelist for device with generic/missing IDs: VID={vid}, PID={pid}, Serial={serial}")
                    continue
                
                print(f"{Fore.GREEN}\n[+] Detected device:{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    Device ID (VID:PID): {dev_id}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    Serial: {serial}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    Vendor Name: {device.get('ID_VENDOR', 'Unknown')}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    Model Name: {device.get('ID_MODEL', 'Unknown')}{Style.RESET_ALL}")
                
                if is_whitelisted(dev_id, serial, whitelist):
                    print(f"{Fore.YELLOW}[*] Device {dev_id} (serial {serial}) is already in the whitelist.{Style.RESET_ALL}")
                else:
                    entry = {"device_id": dev_id, "serial": serial, "type": device_type,
                             "vendor_name": device.get('ID_VENDOR', 'Unknown'),
                             "model_name": device.get('ID_MODEL', 'Unknown')}
                    whitelist.append(entry)
                    save_whitelist(whitelist)
                    print(f"{Fore.GREEN}[+] Successfully whitelisted device: {entry}{Style.RESET_ALL}")
                    logger.info(f"Device auto-whitelisted: {entry}")
                device_detected = True
                break
        
        if not device_detected:
            print(f"{Fore.YELLOW}[!] No new unique USB device detected within the timeout. Please ensure the device was connected after starting this process.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] If auto-detection fails, you can try adding it manually with its specific VID:PID and Serial.{Style.RESET_ALL}")

    else:  # Manual entry
        print(f"{Fore.CYAN}\n[+] Enter device details manually:{Style.RESET_ALL}")
        
        dev_id = ""
        while True:
            dev_id = input(f"{Fore.YELLOW}Enter device ID (VID:PID, e.g., '1234:5678', 4 hex chars each): {Style.RESET_ALL}").strip().upper()
            parts = dev_id.split(':')
            if len(parts) == 2 and all(len(p) == 4 and all(c in '0123456789ABCDEF' for c in p) for p in parts):
                break
            print(f"{Fore.RED}[!] Invalid Device ID format. Please use VID:PID (e.g., 1234:5678), "
                  "where VID and PID are 4 hexadecimal characters.{Style.RESET_ALL}")

        serial = ""
        while not serial or serial.strip() == "":
            serial = input(f"{Fore.YELLOW}Enter device serial number (case-sensitive, or type 'N/A'): {Style.RESET_ALL}").strip()
            if not serial:
                print(f"{Fore.RED}[!] Serial number cannot be empty. Please enter a value or 'N/A'.{Style.RESET_ALL}")
            
        if is_whitelisted(dev_id, serial, whitelist):
            print(f"{Fore.YELLOW}[*] Device {dev_id} (serial {serial}) is already in the whitelist.{Style.RESET_ALL}")
        else:
            entry = {"device_id": dev_id, "serial": serial, "type": device_type,
                     "vendor_name": "Manually Added", "model_name": "Manually Added"}
            whitelist.append(entry)
            save_whitelist(whitelist)
            print(f"{Fore.GREEN}[+] Successfully whitelisted device: {entry}{Style.RESET_ALL}")
            logger.info(f"Device manually whitelisted: {entry}")

def whitelist_remover():
    """Interactive function to remove a device from the whitelist by serial number."""
    print(f"{Fore.CYAN}\n--- Whitelist Remover ---{Style.RESET_ALL}")
    whitelist = load_whitelist()
    if not whitelist:
        print(f"{Fore.RED}Whitelist is currently empty. Nothing to remove.{Style.RESET_ALL}")
        return

    print(f"{Fore.GREEN}Current Whitelist:{Style.RESET_ALL}")
    sorted_wl = sorted(whitelist, key=lambda x: (x.get('device_id', 'N/A'), x.get('serial', 'N/A')))
    print(f"{Fore.LIGHTBLUE_EX}{'#':<3} {'Device ID':<12} {'Serial':<25} {'Type':<15} {'Vendor':<20} {'Model':<20}{Style.RESET_ALL}")
    print("-" * 100)
    for idx, device in enumerate(sorted_wl, 1):
        print(f"{idx:<3} {device.get('device_id', 'N/A').ljust(12)} "
              f"{device.get('serial', 'N/A').ljust(25)} "
              f"{device.get('type', 'N/A').ljust(15)} "
              f"{device.get('vendor_name', 'N/A').ljust(20)} "
              f"{device.get('model_name', 'N/A').ljust(20)}")
    print("-" * 100)

    serial_to_remove = ""
    while not serial_to_remove or serial_to_remove.strip() == "":
        serial_to_remove = input(f"{Fore.YELLOW}\nEnter the serial number of the device to remove (must not be empty): {Style.RESET_ALL}").strip()
        if not serial_to_remove:
            print(f"{Fore.RED}[!] Serial number cannot be empty. Please enter a value.{Style.RESET_ALL}")

    initial_len = len(whitelist)
    new_whitelist = [entry for entry in whitelist if entry.get("serial") != serial_to_remove]

    if len(new_whitelist) < initial_len:
        save_whitelist(new_whitelist)
        print(f"{Fore.GREEN}[-] Device with serial '{serial_to_remove}' removed from whitelist.{Style.RESET_ALL}")
        logger.info(f"Device removed from whitelist: Serial '{serial_to_remove}'")
    else:
        print(f"{Fore.YELLOW}[!] No device found with serial '{serial_to_remove}' in the whitelist.{Style.RESET_ALL}")
        logger.info(f"Attempted to remove non-existent device from whitelist: Serial '{serial_to_remove}'")

# --- Main USB Monitoring Function ---

def monitor_usb():
    """Starts the continuous USB device monitoring process."""
    whitelist = load_whitelist()
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by("usb")

    connected_devices = {}  # Dictionary to store (dev_id, serial) -> connected_since_timestamp for known devices

    # Capture initial network interfaces before starting monitoring
    capture_initial_network_interfaces()

    print(f"{Fore.MAGENTA}\n[*] Starting USB monitoring... Press Ctrl+C to stop and return to menu.{Style.RESET_ALL}")
    logger.info("USB monitoring started.")

    try:
        for device in iter(monitor.poll, None):
            if device.action == "add" and device.get("DEVTYPE") == "usb_device":
                vid = device.get("ID_VENDOR_ID", "0000").upper()
                pid = device.get("ID_MODEL_ID", "0000").upper()
                dev_id = f"{vid}:{pid}"
                serial = device.get("ID_SERIAL_SHORT", "N/A")
                connected_since = current_time_ist()

                print(f"{Fore.BLUE}\n[INFO] Device Connected: {dev_id} (Serial: {serial}) at {connected_since.strftime('%H:%M:%S')}{Style.RESET_ALL}")
                logger.info(f"USB Device CONNECTED: {dev_id} (Serial: {serial})")
                
                current_mac = None
                current_ip = None

                # === Attempt to get MAC/IP ===
                # 1. Wait a moment and check for new network interfaces (e.g., tethering)
                print(f"{Fore.YELLOW}  Attempting to detect network interfaces (e.g., tethering)...{Style.RESET_ALL}")
                new_interfaces = get_new_network_interfaces(timeout=3)  # Give it 3 seconds
                if new_interfaces:
                    # Take the first new interface detected
                    current_mac, current_ip = get_network_info_for_interface(new_interfaces[0])
                    if current_mac and current_ip:
                        print(f"{Fore.GREEN}  Detected new network interface '{new_interfaces[0]}' via tethering: MAC={current_mac}, IP={current_ip}{Style.RESET_ALL}")
                        logger.info(f"Network info via tethering: MAC={current_mac}, IP={current_ip}")
                    else:
                        print(f"{Fore.YELLOW}  New network interface '{new_interfaces[0]}' found, but no MAC/IP yet.{Style.RESET_ALL}")
                
                # 2. If no network interface detected, try ADB (if likely a mobile device)
                # Add more common mobile vendor IDs: Samsung(04E8), OPPO/realme(22D9), Google(18D1), HTC(0BB4), Huawei(12D1), Xiaomi(2717), etc.
                mobile_vendors = ("04E8", "22D9", "18D1", "0BB4", "12D1", "2717", "04F2")
                if not current_mac and not current_ip and vid.startswith(mobile_vendors):
                    print(f"{Fore.YELLOW}  Attempting ADB query (if Android mobile device)...{Style.RESET_ALL}")
                    adb_mac, adb_ip = get_adb_device_info(serial)
                    if adb_mac and adb_ip:
                        current_mac = adb_mac
                        current_ip = adb_ip
                        print(f"{Fore.GREEN}  Detected Android device via ADB: MAC={current_mac}, IP={current_ip}{Style.RESET_ALL}")
                        logger.info(f"Network info via ADB: MAC={current_mac}, IP={current_ip}")
                    else:
                        print(f"{Fore.YELLOW}  ADB query did not return MAC/IP or device not authorized.{Style.RESET_ALL}")
                # === End MAC/IP attempt ===

                if is_whitelisted(dev_id, serial, whitelist):
                    connected_devices[(dev_id, serial)] = connected_since
                    logger.info(f"Status: Recognized and ALLOWED device: {dev_id} (serial: {serial}).")
                    telegram_text = f"✅ *Known USB Device Connected:*\n\n" \
                                    f"*ID:* `{escape_markdown_v2(dev_id)}`\n" \
                                    f"*Serial:* `{escape_markdown_v2(serial)}`\n" \
                                    f"*Time:* `{escape_markdown_v2(connected_since.strftime('%Y-%m-%d %H:%M:%S %Z%z'))}`"
                    if current_mac:
                        telegram_text += f"\n*MAC Address:* `{escape_markdown_v2(current_mac)}`"
                    if current_ip:
                        telegram_text += f"\n*IP Address:* `{escape_markdown_v2(current_ip)}`"
                    send_telegram_message(telegram_text)
                else:
                    log_and_alert_unknown_device(device, dev_id, serial, current_mac, current_ip)

                # Update initial_net_interfaces if new ones were detected
                if new_interfaces:
                    initial_net_interfaces.update(new_interfaces)

            elif device.action == "remove" and device.get("DEVTYPE") == "usb_device":
                vid = device.get("ID_VENDOR_ID", "0000").upper()
                pid = device.get("ID_MODEL_ID", "0000").upper()
                dev_id = f"{vid}:{pid}"
                serial = device.get("ID_SERIAL_SHORT", "N/A")
                key = (dev_id, serial)

                print(f"{Fore.BLUE}[INFO] Device Disconnected: {dev_id} (Serial: {serial}) at {current_time_ist().strftime('%H:%M:%S')}{Style.RESET_ALL}")
                logger.info(f"USB Device DISCONNECTED: {dev_id} (Serial: {serial})")

                if key in connected_devices:
                    connected_since = connected_devices.pop(key)
                    log_known_usb_activity(dev_id, serial, connected_since)
                    telegram_text = f"🔌 *Known USB Device Disconnected:*\n\n" \
                                    f"*ID:* `{escape_markdown_v2(dev_id)}`\n" \
                                    f"*Serial:* `{escape_markdown_v2(serial)}`\n" \
                                    f"*Connected Since:* `{escape_markdown_v2(connected_since.strftime('%Y-%m-%d %H:%M:%S %Z%z'))}`\n" \
                                    f"*Disconnected At:* `{escape_markdown_v2(current_time_ist().strftime('%Y-%m-%d %H:%M:%S %Z%z'))}`"
                    send_telegram_message(telegram_text)
                else:
                    logger.info(f"Status: Device removed (not actively tracked during this session or unknown): {dev_id} (serial: {serial})")

                # Check for removed network interfaces after disconnect
                removed_interfaces = get_removed_network_interfaces(timeout=3)
                if removed_interfaces:
                    initial_net_interfaces.difference_update(removed_interfaces)

    except KeyboardInterrupt:
        print(f"{Fore.CYAN}\n[Cyber_Buddy] Monitoring stopped. Returning to menu...\n{Style.RESET_ALL}")
        logger.info("USB monitoring stopped by user.")
    except Exception as e:
        logger.critical(f"An unexpected error occurred during USB monitoring: {e}", exc_info=True)
        send_telegram_message(f"⛔ *CRITICAL ERROR in Cyber\\_Buddy Monitoring\\!*\n\n`{escape_markdown_v2(str(e))}`\n\nCheck logs for details\\.")

# --- Main Menu Function ---

def main_menu():
    """Displays the main menu and handles user input."""
    print(f"{Fore.GREEN}Starting Cyber_Buddy...{Style.RESET_ALL}")
    if TELEGRAM_CONFIGURED:
        print(f"{Fore.GREEN}Attempting to send Telegram test alert...{Style.RESET_ALL}")
        send_telegram_message(f"🤖 *Cyber\\_Buddy* is online and Telegram alerts are working\\!")
        time.sleep(2)
    else:
        print(f"{Fore.YELLOW}Skipping Telegram test alert due to unconfigured settings.{Style.RESET_ALL}")
        time.sleep(1)

    while True:
        print("\n" + "="*30)
        print(f"{Fore.MAGENTA}  Cyber_Buddy Main Menu  {Style.RESET_ALL}")
        print("="*30)
        print(f"{Fore.CYAN}1. Start USB Monitoring")
        print("2. Add device to whitelist")
        print("3. Show current whitelist")
        print("4. Remove device from whitelist")
        print("5. View Activity Log (General)")
        print("6. View Known USB Activity Log")
        print("7. View Anonymous Device Logs (Summarized)")
        print(f"8. Exit{Style.RESET_ALL}")
        print("="*30)
        
        choice = input(f"{Fore.BLUE}Choose an option (1-8): {Style.RESET_ALL}").strip()

        if choice == "1":
            os.system("clear || cls")  # Clear terminal for Linux/macOS or Windows
            print(f"{Fore.CYAN}=== Cyber_Buddy - USB HID Attack Detection System ==={Style.RESET_ALL}")
            monitor_usb()

        elif choice == "2":
            whitelist_adder()

        elif choice == "3":
            wl = load_whitelist()
            if not wl:
                print(f"{Fore.YELLOW}\nWhitelist is empty.{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}\n--- Current Whitelist ---{Style.RESET_ALL}")
                sorted_wl = sorted(wl, key=lambda x: (x.get('device_id', 'N/A'), x.get('serial', 'N/A')))
                print(f"{Fore.LIGHTBLUE_EX}{'#':<3} {'Device ID':<12} {'Serial':<25} {'Type':<15} {'Vendor':<20} {'Model':<20}{Style.RESET_ALL}")
                print("-" * 110)
                for idx, device in enumerate(sorted_wl, 1):
                    print(f"{idx:<3} {device.get('device_id', 'N/A').ljust(12)} "
                          f"{device.get('serial', 'N/A').ljust(25)} "
                          f"{device.get('type', 'N/A').ljust(15)} "
                          f"{device.get('vendor_name', 'N/A').ljust(20)} "
                          f"{device.get('model_name', 'N/A').ljust(20)}")
                print("-" * 110)

        elif choice == "4":
            whitelist_remover()

        elif choice == "5":
            if os.path.exists(ACTIVITY_LOG) and os.path.getsize(ACTIVITY_LOG) > 0:
                print(f"{Fore.GREEN}\n--- Contents of {ACTIVITY_LOG} ---{Style.RESET_ALL}")
                try:
                    with open(ACTIVITY_LOG, "r") as f:
                        print(f.read())
                except Exception as e:
                    print(f"{Fore.RED}Error reading log file: {e}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}\n{ACTIVITY_LOG} not found or is empty.{Style.RESET_ALL}")

        elif choice == "6":
            if os.path.exists(KNOWN_LOG) and os.path.getsize(KNOWN_LOG) > 0:
                print(f"{Fore.GREEN}\n--- Contents of {KNOWN_LOG} ---{Style.RESET_ALL}")
                try:
                    data = json.load(open(KNOWN_LOG, "r"))
                    if isinstance(data, list):
                        sorted_data = sorted(data, key=lambda x: (x.get('connected_at', ''), x.get('device_id', '')), reverse=True)
                        # Print in a more readable table-like format
                        print(f"{Fore.LIGHTBLUE_EX}{'Time Connected':<25} {'Time Disconnected':<25} {'Device ID':<12} {'Serial':<25} {'Duration (s)':<15}{Style.RESET_ALL}")
                        print("-" * 105)
                        for entry in sorted_data:
                            print(f"{entry.get('connected_at', 'N/A').split(' IST')[0]:<25} "  # Strip timezone for brevity
                                  f"{entry.get('disconnected_at', 'N/A').split(' IST')[0]:<25} "
                                  f"{entry.get('device_id', 'N/A').ljust(12)} "
                                  f"{entry.get('serial', 'N/A').ljust(25)} "
                                  f"{str(entry.get('duration_seconds', 'N/A')).ljust(15)}")
                        print("-" * 105)
                    else:
                        print(f"{Fore.RED}Error: {KNOWN_LOG} contains malformed data (not a list).{Style.RESET_ALL}")
                except json.JSONDecodeError:
                    print(f"{Fore.RED}Error: {KNOWN_LOG} is corrupted or empty.{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error reading known activity log: {e}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}\n{KNOWN_LOG} not found or is empty.{Style.RESET_ALL}")
        
        elif choice == "7":
            print(f"{Fore.GREEN}\n--- Anonymous Device Logs (Summarized from {ANON_DIR}) ---{Style.RESET_ALL}")
            anon_files = [f for f in os.listdir(ANON_DIR) if f.endswith('.json')]
            if not anon_files:
                print(f"{Fore.YELLOW}No anonymous device log files found.{Style.RESET_ALL}")
            else:
                anon_files.sort()
                print(f"{Fore.LIGHTBLUE_EX}{'#':<3} {'Filename':<35} {'Timestamp':<25} {'Device ID':<12} {'Serial':<25} {'Vendor/Model':<30} {'MAC/IP':<35}{Style.RESET_ALL}")
                print("-" * 170)
                for idx, filename in enumerate(anon_files):
                    file_path = os.path.join(ANON_DIR, filename)
                    try:
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                            timestamp = data.get('timestamp', 'N/A').split(' IST')[0]  # Strip timezone
                            dev_id = data.get('device_id', 'N/A')
                            serial = data.get('serial', 'N/A')
                            vendor_model = f"{data.get('vendor', 'Unknown')}/{data.get('model', 'Unknown')}"
                            mac_ip = ""
                            if data.get('mac_address'):
                                mac_ip += f"MAC:{data['mac_address']}"
                            if data.get('ip_address'):
                                if mac_ip: mac_ip += " "
                                mac_ip += f"IP:{data['ip_address']}"
                            if not mac_ip:
                                mac_ip = "N/A"
                            
                            print(f"{idx+1:<3} {filename:<35} {timestamp:<25} {dev_id:<12} {serial:<25} {vendor_model:<30} {mac_ip:<35}")
                    except json.JSONDecodeError:
                        print(f"{Fore.RED}{idx+1:<3} {filename:<35} {'<CORRUPTED JSON>':<130}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}{idx+1:<3} {filename:<35} {f'<ERROR: {e}>':<130}{Style.RESET_ALL}")
                print("-" * 170)
                print(f"{Fore.YELLOW}\nNote: Full details for each anonymous device are in their respective JSON files in '{ANON_DIR}'.{Style.RESET_ALL}")

        elif choice == "8":
            print(f"{Fore.CYAN}Exiting Cyber_Buddy. Goodbye!{Style.RESET_ALL}")
            logger.info("Cyber_Buddy exited.")
            break

        else:
            print(f"{Fore.RED}Invalid choice. Please enter a number from 1 to 8.{Style.RESET_ALL}")
        time.sleep(0.5)

if __name__ == "__main__":
    main_menu()
