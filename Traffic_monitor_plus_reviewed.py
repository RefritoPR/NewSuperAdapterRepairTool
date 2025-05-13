"""
Traffic_monitor_plus_reviewed.py
Hardened and optimized version of Traffic_monitor_plus.py.

Features:
- Enhanced logging
- Robust error handling
- Improved performance
- Secure practices
"""

import os
import re
import json
import time
import logging
import smtplib
import sqlite3
from datetime import datetime
from email.message import EmailMessage
from mac_vendor_lookup import MacLookup
from scapy.all import ARP, sniff
import subprocess
from cryptography.fernet import Fernet
from threading import Thread
from queue import Queue

# Load environment variables
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.example.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
ALERT_RECIPIENT = os.getenv("ALERT_RECIPIENT", "admin@example.com")
FERNET_KEY = os.getenv("FERNET_KEY")  # Must be securely set
BLACKLIST_FILE = "blacklist.json.enc"
DB_FILE = "logs.db"
ARP_REQUEST_THRESHOLD = 10
INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")

# Set file permissions (restrict access)
os.umask(0o077)

# Setup logging
logging.basicConfig(
    filename="audit_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Encryption setup
fernet = Fernet(FERNET_KEY)

# Initialize SQLite database
def init_db():
    """Initialize the SQLite database."""
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
        logging.info("[INFO] Database initialized.")

# Validate MAC address format
def validate_mac(mac):
    """Validate the format of a MAC address."""
    if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac):
        raise ValueError("Invalid MAC address format")

# Secure subprocess wrapper
def run_subprocess(command_list):
    """Run subprocess commands securely."""
    try:
        if not all(re.fullmatch(r'[\w\-/]+', arg) for arg in command_list):
            raise ValueError("Unsafe subprocess argument detected")
        subprocess.run(command_list, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Subprocess failed: {e}")

# Send secure email alert
def send_email_alert(subject, body):
    """Send an email alert securely."""
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_USERNAME
        msg["To"] = ALERT_RECIPIENT
        msg.add_header("X-Mailer", "TrafficMonitor")

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.send_message(msg)
            logging.info("[INFO] Email alert sent.")
    except Exception as e:
        logging.error(f"[ERROR] Failed to send alert: {e}")

# Load blacklist from encrypted file
def load_blacklist():
    """Load the blacklist from an encrypted file."""
    if not os.path.exists(BLACKLIST_FILE):
        return []
    with open(BLACKLIST_FILE, 'rb') as f:
        encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

# Save blacklist securely
def save_blacklist(blacklist):
    """Save the blacklist securely to an encrypted file."""
    data = json.dumps(blacklist).encode()
    encrypted = fernet.encrypt(data)
    with open(BLACKLIST_FILE, 'wb') as f:
        f.write(encrypted)

# Process packets and log suspicious activity
def process_packet(packet):
    """Process a single network packet for suspicious activity."""
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

        # Check against blacklist
        blacklist = load_blacklist()
        is_blacklisted = any(entry.get("mac") == mac or entry.get("ip") == ip for entry in blacklist)

        if is_blacklisted:
            alert_type = "Blacklist Match"
            subject = "[ALERT] Blacklisted MAC/IP Detected"
            body = f"BLACKLISTED DEVICE DETECTED!\nMAC: {mac}\nIP: {ip}\nVendor: {vendor}\nTime: {timestamp}"
            send_email_alert(subject, body)
            logging.warning(f"[WARNING] Blacklisted MAC/IP detected: {mac} / {ip}")

        # Log to database
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT INTO events (timestamp, mac, ip, vendor, alert_type) VALUES (?, ?, ?, ?, ?)",
                         (timestamp, mac, ip, vendor, alert_type))

        if not is_blacklisted:
            send_email_alert("[ALERT] ARP Activity Detected", f"MAC: {mac}\nIP: {ip}\nVendor: {vendor}")

# Packet processing queue
packet_queue = Queue()

def packet_worker():
    """Worker thread to process packets from the queue."""
    while True:
        packet = packet_queue.get()
        if packet is None:
            break
        process_packet(packet)
        packet_queue.task_done()

# Main entry point
def main():
    """Main function to start packet monitoring."""
    init_db()
    logging.info("[START] Monitoring initialized.")

    # Start worker thread
    thread = Thread(target=packet_worker, daemon=True)
    thread.start()

    try:
        sniff(iface=INTERFACE, store=False, prn=lambda pkt: packet_queue.put(pkt))
    except Exception as e:
        logging.error(f"[ERROR] Packet sniffing failed: {e}")

    # Stop worker thread
    packet_queue.put(None)
    thread.join()

if __name__ == "__main__":
    main()
