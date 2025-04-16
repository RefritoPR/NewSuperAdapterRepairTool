import os
import re
import json
import logging
import smtplib
import sqlite3
from datetime import datetime
from email.message import EmailMessage
from typing import List, Dict, Any
from mac_vendor_lookup import MacLookup
from scapy.all import ARP, sniff
from cryptography.fernet import Fernet
import subprocess

# Constants
BLACKLIST_FILE = "blacklist.json.enc"
DB_FILE = "logs.db"
ARP_REQUEST_THRESHOLD = 10
DEFAULT_INTERFACE = "eth0"

# Modules
class Config:
    """Class to handle environment variable configuration"""
    def __init__(self):
        self.EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
        self.EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
        self.SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.example.com")
        self.SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
        self.ALERT_RECIPIENT = os.getenv("ALERT_RECIPIENT", "admin@example.com")
        self.FERNET_KEY = os.getenv("FERNET_KEY")
        self.NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", DEFAULT_INTERFACE)

        self.validate()

    def validate(self):
        """Validate critical environment variables"""
        if not all([self.EMAIL_USERNAME, self.EMAIL_PASSWORD, self.FERNET_KEY]):
            raise EnvironmentError("Critical environment variables are missing. Please check your configuration.")

# Initialize configuration
config = Config()

# Set file permissions (restrict access)
os.umask(0o077)

# Setup logging
logging.basicConfig(filename="audit_log.txt", level=logging.INFO)

# Encryption setup
fernet = Fernet(config.FERNET_KEY)

def init_db():
    """Initialize the SQLite database"""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                mac TEXT,
                ip TEXT,
                vendor TEXT,
                alert_type TEXT
            )
        ''')
        conn.commit()

def validate_mac(mac: str) -> None:
    """Validate MAC address format"""
    if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac):
        raise ValueError("Invalid MAC address format")

def run_subprocess(command_list: List[str]) -> None:
    """Run a subprocess command securely"""
    try:
        if not all(re.fullmatch(r'[\w\-/]+', arg) for arg in command_list):
            raise ValueError("Unsafe subprocess argument detected")
        subprocess.run(command_list, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Subprocess failed: {e}")

def send_email_alert(subject: str, body: str) -> None:
    """Send a secure email alert"""
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = config.EMAIL_USERNAME
        msg["To"] = config.ALERT_RECIPIENT
        msg.add_header("X-Mailer", "TrafficMonitor")

        with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT) as server:
            server.starttls()
            server.login(config.EMAIL_USERNAME, config.EMAIL_PASSWORD)
            server.send_message(msg)
            logging.info("[INFO] Email alert sent.")
    except Exception as e:
        logging.error(f"[ERROR] Failed to send alert: {e}")

def load_blacklist() -> List[Dict[str, Any]]:
    """Load blacklist from encrypted file"""
    if not os.path.exists(BLACKLIST_FILE):
        return []
    with open(BLACKLIST_FILE, 'rb') as f:
        encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

def save_blacklist(blacklist: List[Dict[str, Any]]) -> None:
    """Save blacklist to an encrypted file"""
    data = json.dumps(blacklist).encode()
    encrypted = fernet.encrypt(data)
    with open(BLACKLIST_FILE, 'wb') as f:
        f.write(encrypted)

def process_packet(packet) -> None:
    """Process captured packets and log suspicious activity"""
    if packet.haslayer(ARP):
        mac = packet[ARP].hwsrc
        ip = packet[ARP].psrc

        try:
            validate_mac(mac)
        except ValueError:
            logging.warning(f"[WARNING] Invalid MAC format detected: {mac}")
            return

        try:
            vendor = MacLookup().lookup(mac)
        except Exception:
            vendor = "Unknown"

        timestamp = datetime.now().isoformat()
        alert_type = "ARP Flood"

        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT INTO events (timestamp, mac, ip, vendor, alert_type) VALUES (?, ?, ?, ?, ?)",
                         (timestamp, mac, ip, vendor, alert_type))
            conn.commit()

        send_email_alert("[ALERT] ARP Activity Detected", f"MAC: {mac}\nIP: {ip}\nVendor: {vendor}")

def main() -> None:
    """Main entry point for the application"""
    init_db()
    logging.info("[START] Monitoring initialized.")
    try:
        sniff(iface=config.NETWORK_INTERFACE, store=False, prn=process_packet, filter="arp")
    except Exception as e:
        logging.error(f"[ERROR] Packet sniffing failed: {e}")

if __name__ == "__main__":
    main()
